"""In-memory event source for tests and ``--dry-run`` demos."""

from __future__ import annotations

from ..events import EventRecord
from .base import EventSource


class FakeEventSource(EventSource):
    """Serves pre-scripted batches of :class:`EventRecord`.

    Each ``read_new_events`` call pops the next scripted batch and
    applies the same bookmark filtering the real source is required to
    do, so tests exercise that contract too. When the script is
    exhausted it keeps returning ``[]``.
    """

    def __init__(self, batches: list[list[EventRecord]] | None = None):
        self._batches: list[list[EventRecord]] = [list(batch) for batch in (batches or [])]
        self.calls = 0

    def add_batch(self, records: list[EventRecord]) -> None:
        self._batches.append(list(records))

    def read_new_events(self, bookmarks: dict[str, int]) -> list[EventRecord]:
        self.calls += 1
        batch = self._batches.pop(0) if self._batches else []
        fresh = [
            record
            for record in batch
            if record.record_id > bookmarks.get(record.channel, 0)
        ]
        fresh.sort(key=lambda record: (record.channel, record.record_id))
        return fresh
