"""Parser for Windows Security event exports (JSON lines, one event per line).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/windows_security_50.jsonl, a hand-authored synthetic
sample (see that fixture set's own README) -- NOT a real Windows Event Log
export. The field names (TimeCreated, EventID, Computer, TargetUserName,
etc.) match the standard Windows Security auditing schema, and the EventIDs
below are real, well-known Windows Security event IDs (4624 = successful
logon, 4625 = failed logon, and so on) -- but the mapping has only been
exercised against this synthetic fixture, not a live export.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Unlike Graylog (services/graylog_parser.py), where the same message text can
appear at different severities, Windows Security events carry a numeric
EventID that is a stable, structured classification field on its own --
`Message` is a human-readable restatement of what EventID already encodes,
not an independent signal. So event_type, a baseline severity, and
confidence are all driven by a lookup table keyed on EventID, built from the
15 distinct EventIDs present in the fixture. Windows' own `Level` field
(Information/Warning) is used only as the fallback for an EventID this
table doesn't recognize.

A few EventIDs are deliberately given a higher severity_hint than their
Windows `Level` would suggest (4648 explicit-credential logon, 4672 special
privileges assigned, 4720/4722 account created/enabled, 4728/4732 group
membership changes are all Level=Information here) because they are
commonly-watched identity/privilege-change indicators in security
monitoring, not because the fixture's Level field says so. GroupName is
present on only 1 of 7 group-membership rows in this fixture, which isn't
enough to justify a privileged-group-aware severity heuristic -- group
membership changes are scored uniformly instead of guessing from that one
data point.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedWindowsSecurityEvent:
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
    source_tool: str = "windows"


# EventID -> (event_type, severity_hint, confidence).
_EVENT_META: dict[int, tuple[str, str, float]] = {
    4624: ("successful_logon", "low", 0.98),
    4625: ("logon_failure", "medium", 0.98),
    4634: ("logoff", "low", 0.98),
    4648: ("explicit_credential_logon", "medium", 0.97),
    4672: ("privileged_logon", "medium", 0.97),
    4688: ("process_created", "low", 0.97),
    4720: ("account_created", "medium", 0.97),
    4722: ("account_enabled", "medium", 0.97),
    4725: ("account_disabled", "medium", 0.97),
    4728: ("group_added_global_group", "medium", 0.97),
    4732: ("group_added_local_group", "medium", 0.97),
    4740: ("account_lockout", "high", 0.98),
    4768: ("kerberos_ticket_requested", "low", 0.97),
    4769: ("kerberos_service_ticket_requested", "low", 0.97),
    4771: ("kerberos_preauth_failed", "medium", 0.98),
}

_LEVEL_SEVERITY = {
    "information": "low",
    "warning": "medium",
    "error": "high",
    "critical": "critical",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("_", text.lower()).strip("_") or "windows_event"


def parse_windows_security_log(
    raw_text: str, *, source_tool: str = "windows"
) -> list[ParsedWindowsSecurityEvent]:
    """Parse Windows Security JSON-lines exports into one event per record."""

    events: list[ParsedWindowsSecurityEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(record, dict):
            continue

        events.append(_to_event(record, source_tool))

    return events


def _to_event(record: dict, source_tool: str) -> ParsedWindowsSecurityEvent:
    event_id = record.get("EventID")
    message = record.get("Message") or ""
    level = str(record.get("Level") or "").lower()

    meta = _EVENT_META.get(event_id) if isinstance(event_id, int) else None
    if meta:
        event_type, severity_hint, confidence = meta
    else:
        event_type = _slugify(message) if message else "windows_event"
        severity_hint = _LEVEL_SEVERITY.get(level, "unknown")
        confidence = 0.5

    affected_system = record.get("Computer") or "Unknown system"
    account = record.get("TargetUserName") or ""
    source_ip = record.get("IpAddress")
    destination_ip = None  # Windows Security events describe the local host, not a connection pair

    timestamp = _parse_timestamp(record.get("TimeCreated"))

    summary_bits = [message or event_type.replace("_", " ")]
    if account:
        summary_bits.append(f"(account '{account}')")
    subject = record.get("SubjectUserName")
    if subject:
        summary_bits.append(f"by '{subject}'")
    if source_ip:
        summary_bits.append(f"from {source_ip}")
    failure_reason = record.get("FailureReason")
    if failure_reason:
        summary_bits.append(f"-- {failure_reason}")
    summary = " ".join(summary_bits) + f" on {affected_system}."

    return ParsedWindowsSecurityEvent(
        timestamp=timestamp,
        affected_system=affected_system,
        account=account,
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=event_type,
        severity_hint=severity_hint,
        raw_message=json.dumps(record, ensure_ascii=False),
        normalized_summary=summary[:255],
        confidence_score=round(confidence, 2),
        source_tool=source_tool,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
