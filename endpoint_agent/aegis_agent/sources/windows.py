"""The real Windows Event Log source (``win32evtlog``).

THIS MODULE IS NOT EXERCISED BY THE TEST SUITE. The Linux dev/CI box has
no ``pywin32`` and no Event Log, so the ``win32evtlog`` query/render
calls below are the one piece of Part 2 that must be verified by hand on
a real Windows host -- see ``endpoint_agent/README.md`` ->
"Manual verification on Windows".

Everything this module produces is a plain :class:`EventRecord`, and the
XML it feeds to :func:`parse_event_xml` is the same shape captured in
``tests/fixtures/`` and parsed there. So the parsing, filtering,
buffering and shipping around this call are all covered on Linux; only
the ~30 lines that actually talk to the OS are not.

``import win32evtlog`` is deferred to construction time so that importing
``aegis_agent`` (and running the test suite) works fine on Linux.
"""

from __future__ import annotations

import logging

from ..events import (
    POWERSHELL_CHANNEL,
    POWERSHELL_SCRIPT_BLOCK_EVENT_ID,
    PROCESS_CREATION_EVENT_ID,
    SECURITY_CHANNEL,
    EventParseError,
    EventRecord,
    parse_event_xml,
)
from .base import EventSource

_LOG = logging.getLogger("aegis_agent.source.windows")

# channel -> the event ids we subscribe to on it
CHANNEL_EVENT_IDS: dict[str, tuple[int, ...]] = {
    SECURITY_CHANNEL: (PROCESS_CREATION_EVENT_ID,),
    POWERSHELL_CHANNEL: (POWERSHELL_SCRIPT_BLOCK_EVENT_ID,),
}


def _load_win32evtlog():
    try:
        import win32evtlog  # type: ignore
    except ImportError as exc:  # pragma: no cover - Windows-only path
        raise RuntimeError(
            "pywin32 is required to read the Windows Event Log: pip install pywin32"
        ) from exc
    return win32evtlog


class WindowsEventLogSource(EventSource):  # pragma: no cover - requires Windows
    def __init__(self, *, max_events_per_read: int = 2000, logger: logging.Logger | None = None):
        self._w = _load_win32evtlog()
        self._max = max_events_per_read
        self.log = logger or _LOG

    def read_new_events(self, bookmarks: dict[str, int]) -> list[EventRecord]:
        records: list[EventRecord] = []
        for channel, event_ids in CHANNEL_EVENT_IDS.items():
            last_seen = bookmarks.get(channel, 0)
            try:
                records.extend(self._read_channel(channel, event_ids, last_seen))
            except Exception:
                self.log.exception("failed reading channel %s", channel)
        records.sort(key=lambda record: (record.channel, record.record_id))
        return records

    def _read_channel(self, channel: str, event_ids: tuple[int, ...], last_seen: int) -> list[EventRecord]:
        w = self._w
        id_clause = " or ".join(f"EventID={eid}" for eid in event_ids)
        # Filter on event id in the query; filter on record id in Python
        # (XPath support for EventRecordID comparisons is inconsistent
        # across Windows builds, and being explicit here is cheap).
        query = f"*[System[({id_clause})]]"
        handle = w.EvtQuery(
            channel,
            w.EvtQueryChannelPath | w.EvtQueryReverseDirection,
            query,
            None,
        )

        out: list[EventRecord] = []
        oldest_seen = None
        reached_bookmark = False
        while not reached_bookmark and len(out) < self._max:
            try:
                events = w.EvtNext(handle, 64)
            except Exception:
                break
            if not events:
                break
            for event in events:
                xml_text = w.EvtRender(event, w.EvtRenderEventXml)
                try:
                    record = parse_event_xml(xml_text)
                except EventParseError as exc:
                    self.log.warning("skipping unparseable %s event: %s", channel, exc)
                    continue
                oldest_seen = record.record_id
                if record.record_id <= last_seen:
                    # Reverse (newest-first) scan: once we reach the
                    # bookmark, everything older is already handled.
                    reached_bookmark = True
                    break
                out.append(record)

        # If we scanned the whole channel (or hit our per-read cap) without
        # ever reaching the bookmark, and the oldest record still present
        # is newer than it, the Event Log has wrapped past events we never
        # collected -- a real, unavoidable gap. Say so, loudly and with a
        # number, rather than let it pass silently.
        if last_seen and not reached_bookmark and oldest_seen and oldest_seen > last_seen + 1:
            self.log.error(
                "GAP on %s: Event Log has rotated past record %d; oldest still present is %d "
                "-- ~%d event(s) were lost before the agent could read them",
                channel,
                last_seen,
                oldest_seen,
                oldest_seen - last_seen - 1,
            )

        out.sort(key=lambda record: record.record_id)
        return out
