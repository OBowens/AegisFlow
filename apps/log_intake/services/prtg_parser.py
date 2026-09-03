"""Parser for PRTG sensor status exports (CSV, one sensor reading per row).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/prtg_50.csv, a hand-authored synthetic sample (see
that fixture set's own README) -- NOT a real PRTG export. Column names and
value ranges below reflect that fixture only.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

PRTG monitors infrastructure (network gear, hypervisors, backup jobs,
environmental sensors), not user activity, so there is no username field to
extract -- `account` is always "" here, which is the expected/applicable
value for this format rather than a parsing gap.

The `status` column is PRTG's own sensor status (Up/Down/Warning/Paused/
Unknown) and is a closed, structured vocabulary -- all five values PRTG
defines appear in the fixture, so severity_hint and confidence_score are
both driven directly off it via a lookup table, with no free-text inference
needed. This is why confidence here is uniformly high (0.9) for every row:
unlike a log line that has to be pattern-matched, a PRTG status column is
already the classification.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from io import StringIO


@dataclass
class ParsedPRTGEvent:
    """Mirrors the non-relational fields of log_intake.models.ParsedAlert."""

    timestamp: datetime | None
    affected_system: str
    account: str
    source_ip: str | None
    destination_ip: str | None
    event_type: str
    severity_hint: str
    raw_message: str
    normalized_summary: str
    confidence_score: float
    source_tool: str = "prtg"


# PRTG's own sensor status vocabulary -> our severity_hint.
_STATUS_SEVERITY = {
    "up": "low",
    "down": "high",
    "warning": "medium",
    "paused": "low",  # a paused sensor is intentionally silenced, not itself an alert
    "unknown": "medium",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("_", text.lower()).strip("_") or "sensor"


def parse_prtg_log(raw_text: str, *, source_tool: str = "prtg") -> list[ParsedPRTGEvent]:
    """Parse a PRTG sensor-status CSV export into one event per row."""

    reader = csv.DictReader(StringIO(raw_text))
    events: list[ParsedPRTGEvent] = []

    for row in reader:
        if not any((value or "").strip() for value in row.values()):
            continue
        events.append(_to_event(row, source_tool))

    return events


def _to_event(row: dict, source_tool: str) -> ParsedPRTGEvent:
    status = (row.get("status") or "").strip()
    status_key = status.lower()
    device = (row.get("device") or "").strip() or "Unknown system"
    sensor = (row.get("sensor") or "").strip()
    message = (row.get("message") or "").strip()
    last_value = (row.get("last_value") or "").strip()
    unit = (row.get("unit") or "").strip()

    if status_key in _STATUS_SEVERITY:
        event_type = f"sensor_{status_key}"
        severity_hint = _STATUS_SEVERITY[status_key]
        confidence = 0.9
    else:
        event_type = f"sensor_{_slugify(status) if status else 'status_unknown'}"
        severity_hint = "unknown"
        confidence = 0.5

    timestamp = _parse_timestamp(row.get("datetime"))

    value_part = f"{last_value} {unit}".strip()
    summary = f"{sensor} on {device} is {status}: {message}"
    if value_part:
        summary = f"{summary} ({value_part})"
    summary = summary.strip() + "."

    return ParsedPRTGEvent(
        timestamp=timestamp,
        affected_system=device,
        account="",
        source_ip=None,
        destination_ip=None,
        event_type=event_type,
        severity_hint=severity_hint,
        raw_message=", ".join(f"{key}={value}" for key, value in row.items()),
        normalized_summary=summary[:255],
        confidence_score=round(confidence, 2),
        source_tool=source_tool,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
