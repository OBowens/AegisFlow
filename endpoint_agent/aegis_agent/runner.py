"""The agent loop: enroll once, then repeatedly poll -> filter -> spool
-> batch-send, with backoff on transient failure.

Time and randomness are injected (``sleep``, ``rng``) so the whole loop
is testable on Linux with a ``FakeEventSource`` and a stub client, with
no real sleeping.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field

from .backoff import compute_delay
from .client import (
    SERVER_MAX_EVENTS_PER_BATCH,
    AuthError,
    EnrollResult,
    PermanentError,
    TransientError,
)
from .events import to_ingest_event

_LOG = logging.getLogger("aegis_agent.runner")


@dataclass
class RunnerSettings:
    send_interval: tuple[float, float] = (60.0, 120.0)
    max_batch: int = 250
    max_batch_bytes: int = 1_000_000
    # A single tick drains the spool with repeated sends rather than one
    # batch, so a backlog clears at backend speed instead of
    # max_batch/send_interval. Capped so one tick cannot run for minutes:
    # 20 * 250 = 5000 events/tick, ~3300/min, far above any realistic
    # endpoint's filtered-in rate.
    max_batches_per_tick: int = 20
    backoff_base: float = 5.0
    backoff_cap: float = 300.0
    enroll_max_attempts: int = 0  # 0 = retry forever


@dataclass
class TickStats:
    read: int = 0
    kept: int = 0
    suppressed: int = 0
    held_back: int = 0
    sent: int = 0
    rejected: int = 0
    send_failed: bool = False


@dataclass
class AgentRunner:
    source: object
    filters: object
    spool: object
    client: object
    display_name: str
    settings: RunnerSettings = field(default_factory=RunnerSettings)
    sleep: object = time.sleep
    rng: random.Random = field(default_factory=random.Random)
    logger: logging.Logger = _LOG

    _failures: int = field(default=0, init=False)
    _enrolled: EnrollResult | None = field(default=None, init=False)

    # -- enrollment ------------------------------------------------

    def enroll_once(self) -> EnrollResult:
        attempt = 0
        while True:
            attempt += 1
            try:
                result = self.client.enroll(self.display_name)
            except TransientError as exc:
                if self.settings.enroll_max_attempts and attempt >= self.settings.enroll_max_attempts:
                    raise
                delay = compute_delay(
                    attempt,
                    base=self.settings.backoff_base,
                    cap=self.settings.backoff_cap,
                    rng=self.rng.random,
                )
                self.logger.warning(
                    "enroll attempt %d failed (%s); retrying in %.0fs", attempt, exc, delay
                )
                self.sleep(delay)
                continue

            self._enrolled = result
            if result.name_was_adjusted:
                self.logger.warning(
                    "enrolled as %r -- the server adjusted the requested name %r "
                    "(another endpoint in this organization already uses it)",
                    result.display_name,
                    self.display_name,
                )
            else:
                self.logger.info(
                    "enrolled as %r (endpoint id %d)", result.display_name, result.endpoint_id
                )
            return result

    # -- one iteration -------------------------------------------

    def poll_once(self, stats: TickStats) -> None:
        bookmarks = self.spool.load_bookmarks()
        records = self.source.read_new_events(bookmarks)
        stats.read = len(records)
        if not records:
            return

        # Backpressure: never store more than the buffer can hold. When it
        # is full we stop advancing a channel's bookmark at its first
        # kept-but-unstorable event, so those events stay in the Windows
        # Event Log and are re-read once the buffer drains. Suppressed
        # events need no storage, so their bookmark still advances.
        capacity = self.spool.remaining_capacity()
        kept: list[dict] = []
        new_bookmarks = dict(bookmarks)
        blocked_channels: set[str] = set()

        for record in records:  # sorted by (channel, record_id)
            channel = record.channel
            if channel in blocked_channels:
                stats.held_back += 1
                continue

            decision = self.filters.decide(record)
            if decision.action == "keep":
                if len(kept) >= capacity:
                    blocked_channels.add(channel)
                    stats.held_back += 1
                    continue
                kept.append(to_ingest_event(record))
            else:
                stats.suppressed += 1
                self.logger.info(
                    "filtered event_id=%s record_id=%s rule=%s reason=%s",
                    record.event_id,
                    record.record_id,
                    decision.rule,
                    decision.reason,
                )
                self.logger.debug("filtered detail: %s", to_ingest_event(record))

            new_bookmarks[channel] = max(new_bookmarks.get(channel, 0), record.record_id)

        stats.kept = len(kept)
        if stats.held_back:
            self.logger.warning(
                "local buffer full (%d/%d); %d event(s) held in the Event Log until it drains",
                self.spool.depth() + len(kept),
                self.spool.max_events,
                stats.held_back,
            )
        self.spool.append(kept, bookmarks=new_bookmarks)

    def send_batch_once(self, stats: TickStats) -> str:
        """Send at most one batch. Returns 'sent', 'empty', 'failed' or
        'rejected'. ``drain`` loops on this.
        """
        batch = self.spool.pending_batch(
            max_count=min(self.settings.max_batch, SERVER_MAX_EVENTS_PER_BATCH),
            max_bytes=self.settings.max_batch_bytes,
        )
        if not batch:
            return "empty"

        try:
            accepted = self.client.send_batch(batch)
        except AuthError as exc:
            self._failures += 1
            stats.send_failed = True
            self.logger.error(
                "ingest rejected the token (401): %s -- keeping %d event(s) buffered",
                exc,
                self.spool.depth(),
            )
            return "failed"
        except PermanentError as exc:
            stats.rejected += len(batch)
            self.spool.reject(batch, f"HTTP {exc.status}: {exc.body}")
            self._failures = 0  # a payload problem, not a transport problem
            return "rejected"
        except TransientError as exc:
            self._failures += 1
            stats.send_failed = True
            self.logger.warning(
                "ingest send failed (%s); %d event(s) still buffered", exc, self.spool.depth()
            )
            return "failed"

        self.spool.ack(batch)
        self._failures = 0
        stats.sent += accepted
        self.logger.info(
            "ingest accepted %d event(s); %d still buffered", accepted, self.spool.depth()
        )
        return "sent"

    def drain(self, stats: TickStats) -> None:
        """Send batches until the spool is empty, a send fails, or the
        per-tick cap is reached.
        """
        for _ in range(max(1, self.settings.max_batches_per_tick)):
            outcome = self.send_batch_once(stats)
            if outcome in ("empty", "failed"):
                return
        if self.spool.depth():
            self.logger.info(
                "drain hit the %d-batch per-tick cap; %d event(s) carry to next tick",
                self.settings.max_batches_per_tick,
                self.spool.depth(),
            )

    def tick(self) -> TickStats:
        stats = TickStats()
        # Drain first so any space freed this tick is available to the
        # poll's backpressure check; poll; then drain again to send what
        # was just collected without waiting a whole interval.
        self.drain(stats)
        try:
            self.poll_once(stats)
        except Exception:
            self.logger.exception("poll failed; will retry next tick")
        self.drain(stats)
        return stats

    def next_delay(self) -> float:
        if self._failures > 0:
            return compute_delay(
                self._failures,
                base=self.settings.backoff_base,
                cap=self.settings.backoff_cap,
                rng=self.rng.random,
            )
        low, high = self.settings.send_interval
        return self.rng.uniform(low, high)

    # -- loop ---------------------------------------------------

    def run_forever(self, *, max_ticks: int | None = None, should_stop=None) -> None:
        if self._enrolled is None:
            self.enroll_once()
        completed = 0
        while True:
            self.tick()
            completed += 1
            if max_ticks is not None and completed >= max_ticks:
                return
            if should_stop is not None and should_stop():
                return
            self.sleep(self.next_delay())
