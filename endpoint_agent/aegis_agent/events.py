"""Normalized event model + Windows Event Log XML parsers.

``EventRecord`` is the single seam between Windows-specific code
(``sources/windows.py``, which we cannot exercise on the Linux dev box)
and everything downstream (filtering, buffering, HTTP). Every test in
this package works with ``EventRecord`` instances, either parsed from
captured XML fixtures or built directly.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

PROCESS_CREATION_EVENT_ID = 4688
POWERSHELL_SCRIPT_BLOCK_EVENT_ID = 4104

SECURITY_CHANNEL = "Security"
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


class EventParseError(ValueError):
    """Raised when a chunk of Event Log XML cannot be understood.

    The Windows source catches this per-event, logs it, and skips the
    one bad record rather than stalling the whole read.
    """


@dataclass(frozen=True)
class EventRecord:
    event_id: int
    channel: str
    record_id: int
    occurred_at: datetime  # always tz-aware UTC
    computer: str
    data: dict = field(default_factory=dict)

    @property
    def channel_prefix(self) -> str:
        return self.channel.split("/", 1)[0] if self.channel else "Unknown"

    @property
    def event_type(self) -> str:
        """The value sent as ``event_type`` to the ingest API. Kept under
        the server's 100-char limit.
        """
        return f"{self.channel_prefix}/{self.event_id}"[:100]

    @property
    def agent_event_id(self) -> str:
        """Stable per-event identity, for de-duplication in the spool and
        (later) on the backend. A record id is unique within one channel
        on one machine.
        """
        return f"{self.computer}|{self.channel}|{self.record_id}"


def to_ingest_event(record: EventRecord) -> dict:
    """Render an :class:`EventRecord` into the exact dict the ingest API
    expects: ``{event_type, occurred_at, payload}``. The spool stores
    events already in this shape, so the spool file *is* the request body.
    """
    occurred = record.occurred_at.astimezone(timezone.utc)
    return {
        "event_type": record.event_type,
        "occurred_at": occurred.isoformat().replace("+00:00", "Z"),
        "payload": {
            "agent_event_id": record.agent_event_id,
            "channel": record.channel,
            "record_id": record.record_id,
            "computer": record.computer,
            "data": dict(record.data),
        },
    }


# --- XML parsing -----------------------------------------------------------

def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent, name: str):
    if parent is None:
        return None
    for element in parent:
        if _localname(element.tag) == name:
            return element
    return None


def _text(element) -> str:
    if element is None or element.text is None:
        return ""
    return element.text.strip()


_TIME_RE = re.compile(r"^(?P<base>.*T\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?(?P<tz>Z|[+-]\d{2}:?\d{2})?$")


def parse_system_time(value: str | None) -> datetime:
    """Parse an Event Log ``TimeCreated/@SystemTime``.

    Windows writes 100-nanosecond precision (7 fractional digits) and a
    trailing ``Z``; ``datetime.fromisoformat`` only takes 3 or 6. Trim to
    microseconds and normalize the zone marker, then hand off.
    """
    if not value or not value.strip():
        raise EventParseError("event has no TimeCreated/@SystemTime")
    match = _TIME_RE.match(value.strip())
    if not match:
        raise EventParseError(f"unparseable SystemTime: {value!r}")
    base = match.group("base")
    frac = match.group("frac")
    tz = match.group("tz") or "Z"
    if frac:
        base = f"{base}.{(frac + '000000')[:6]}"
    iso = base + ("+00:00" if tz == "Z" else tz)
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError as exc:
        raise EventParseError(f"unparseable SystemTime: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event_data(root) -> dict:
    out: dict[str, str] = {}
    data_container = _child(root, "EventData")
    if data_container is None:
        return out
    for element in data_container:
        if _localname(element.tag) != "Data":
            continue
        name = element.get("Name")
        if not name:
            continue
        out[name] = element.text if element.text is not None else ""
    return out


def _clean(mapping: dict) -> dict:
    return {key: value for key, value in mapping.items() if value not in ("", None)}


def _normalize_4688(data: dict) -> dict:
    def value(key: str) -> str:
        return (data.get(key) or "").strip()

    return _clean(
        {
            "new_process_name": value("NewProcessName"),
            "new_process_id": value("NewProcessId"),
            "parent_process_name": value("ParentProcessName"),
            "creator_process_id": value("ProcessId"),
            "command_line": value("CommandLine"),
            "subject_user_name": value("SubjectUserName"),
            "subject_domain_name": value("SubjectDomainName"),
            "subject_user_sid": value("SubjectUserSid"),
            "token_elevation_type": value("TokenElevationType"),
            "mandatory_label": value("MandatoryLabel"),
            "target_user_name": value("TargetUserName"),
        }
    )


def _normalize_4104(data: dict) -> dict:
    def as_int(key: str):
        raw = (data.get(key) or "").strip()
        try:
            return int(raw)
        except ValueError:
            return None

    return _clean(
        {
            "script_block_text": data.get("ScriptBlockText") or "",
            "script_block_id": (data.get("ScriptBlockId") or "").strip(),
            "message_number": as_int("MessageNumber"),
            "message_total": as_int("MessageTotal"),
            "path": (data.get("Path") or "").strip(),
        }
    )


_NORMALIZERS = {
    PROCESS_CREATION_EVENT_ID: _normalize_4688,
    POWERSHELL_SCRIPT_BLOCK_EVENT_ID: _normalize_4104,
}


def parse_event_xml(xml_text: str) -> EventRecord:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise EventParseError(f"invalid event XML: {exc}") from exc

    system = _child(root, "System")
    if system is None:
        raise EventParseError("event XML has no <System> element")

    try:
        event_id = int(_text(_child(system, "EventID")))
    except ValueError as exc:
        raise EventParseError("event XML has no usable <EventID>") from exc

    try:
        record_id = int(_text(_child(system, "EventRecordID")))
    except ValueError as exc:
        raise EventParseError("event XML has no usable <EventRecordID>") from exc

    time_created = _child(system, "TimeCreated")
    occurred_at = parse_system_time(
        time_created.get("SystemTime") if time_created is not None else None
    )

    raw_data = _event_data(root)
    normalizer = _NORMALIZERS.get(event_id)
    data = normalizer(raw_data) if normalizer else _clean(
        {key.lower(): (value or "").strip() for key, value in raw_data.items()}
    )

    return EventRecord(
        event_id=event_id,
        channel=_text(_child(system, "Channel")),
        record_id=record_id,
        occurred_at=occurred_at,
        computer=_text(_child(system, "Computer")),
        data=data,
    )
