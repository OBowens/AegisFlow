"""Durable local buffer + read bookmarks.

A filtered-in event is written (and fsync'd) to ``pending.jsonl`` before
the runner advances the per-channel read bookmark in ``state.json``. So
a crash at any point loses nothing: on restart the spool reloads
``pending.jsonl``, and the Windows source resumes from the last durably
recorded bookmark. De-duplication by ``agent_event_id`` makes the
append idempotent, covering the crash-after-append-before-bookmark case.

Events are stored already in ingest-API shape (see
``events.to_ingest_event``); the spool file is literally the request
body, minus the ``{"events": [...]}`` wrapper.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

_LOG = logging.getLogger("aegis_agent.spool")


def _event_id(event: dict) -> str:
    return event["payload"]["agent_event_id"]


class Spool:
    def __init__(self, state_dir, *, max_events: int = 50_000, logger: logging.Logger | None = None):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.pending_path = self.dir / "pending.jsonl"
        self.state_path = self.dir / "state.json"
        self.rejected_dir = self.dir / "rejected"
        self.max_events = max_events
        self.log = logger or _LOG
        self._pending: list[dict] = self._load_pending()
        self._ids: set[str] = {_event_id(event) for event in self._pending}

    # -- reads ----------------------------------------------------------

    def depth(self) -> int:
        return len(self._pending)

    def remaining_capacity(self) -> int:
        """How many more events fit before ``max_events``. The runner
        uses this for backpressure so nothing is ever dropped to stay
        under the cap.
        """
        return max(0, self.max_events - len(self._pending))

    def load_bookmarks(self) -> dict[str, int]:
        if not self.state_path.exists():
            return {}
        try:
            payload = json.loads(self.state_path.read_text("utf-8"))
            return {str(k): int(v) for k, v in payload.get("bookmarks", {}).items()}
        except (json.JSONDecodeError, ValueError, OSError):
            self.log.warning("spool: state.json unreadable; resuming from zero bookmarks")
            return {}

    def pending_batch(self, *, max_count: int, max_bytes: int) -> list[dict]:
        """The next slice to send: at most ``max_count`` events and, once
        more than one event is included, at most ``max_bytes`` of encoded
        JSON. A single oversized event is still returned alone -- it
        cannot be split, and holding it back forever would wedge the
        queue.
        """
        batch: list[dict] = []
        size = 0
        for event in self._pending:
            encoded = len(json.dumps(event).encode("utf-8")) + 1
            if batch and (len(batch) >= max_count or size + encoded > max_bytes):
                break
            batch.append(event)
            size += encoded
            if len(batch) >= max_count:
                break
        return batch

    # -- writes -------------------------------------------------------

    def append(self, events: list[dict], *, bookmarks: dict[str, int]) -> int:
        """Add filtered-in events (idempotently), then persist bookmarks.
        Returns the number of genuinely new events written.

        Nothing is ever dropped here. Staying under ``max_events`` is the
        runner's job (it applies backpressure via
        :meth:`remaining_capacity`). If the cap is somehow exceeded
        anyway, the events are kept -- losing a filtered-in event is the
        one thing this buffer exists to prevent -- and the breach is
        logged for investigation.
        """
        added = 0
        for event in events:
            identity = _event_id(event)
            if identity in self._ids:
                continue
            self._pending.append(event)
            self._ids.add(identity)
            added += 1

        if len(self._pending) > self.max_events:
            self.log.error(
                "spool: depth %d exceeds max_events %d despite backpressure; keeping all",
                len(self._pending),
                self.max_events,
            )

        if added:
            self._flush_pending()
        # Bookmarks are saved only after pending.jsonl is durable, so we
        # never record "read past here" for an event that isn't stored.
        self._save_bookmarks(bookmarks)
        return added

    def ack(self, events: list[dict]) -> None:
        acked = {_event_id(event) for event in events}
        if not acked:
            return
        self._pending = [event for event in self._pending if _event_id(event) not in acked]
        self._ids -= acked
        self._flush_pending()

    def reject(self, events: list[dict], detail: str = "") -> Path:
        """Quarantine a batch the server rejected as malformed (HTTP 400)
        to ``rejected/`` and drop it from the queue, so one poison event
        cannot block every later batch. The full events + server response
        are kept on disk for inspection.
        """
        self.rejected_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")
        path = self.rejected_dir / f"{stamp}.json"
        _atomic_write(path, json.dumps({"detail": detail, "events": events}, indent=2))
        self.ack(events)
        self.log.error("spool: quarantined %d rejected event(s) -> %s", len(events), path)
        return path

    # -- internals --------------------------------------------------

    def _load_pending(self) -> list[dict]:
        if not self.pending_path.exists():
            return []
        events: list[dict] = []
        for line in self.pending_path.read_text("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                _event_id(event)  # structural check
            except (json.JSONDecodeError, KeyError, TypeError):
                self.log.warning("spool: skipping unparseable pending line")
                continue
            events.append(event)
        return events

    def _flush_pending(self) -> None:
        body = "".join(json.dumps(event) + "\n" for event in self._pending)
        _atomic_write(self.pending_path, body)

    def _save_bookmarks(self, bookmarks: dict[str, int]) -> None:
        _atomic_write(
            self.state_path,
            json.dumps({"bookmarks": {str(k): int(v) for k, v in bookmarks.items()}}, indent=2),
        )


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
