"""Parser for Graylog message exports (JSON lines, one flattened message per line).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/graylog_50.jsonl, a hand-authored synthetic sample
(see that fixture set's own README) -- NOT a real Graylog export. Field
names and value ranges below reflect that fixture only.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Graylog aggregates many upstream sources (sshd, a firewall, Windows, an app,
Postgres, a backup tool) into one flat message shape, so unlike Wazuh there
is no single structured taxonomy field to key off of -- `facility` narrows
things down, but the actual event has to be read out of `message` (free
text) plus whatever extra fields that source happened to attach.

Severity is handled uniformly across facilities via the numeric `level`
field (standard syslog severity, 0=most severe .. 7=least), since that's
the field a real Graylog deployment would alert on -- *except* for the
facilities where a more specific signal is trusted instead: firewall,
which carries its own explicit `severity` string, and backup/postgres/
windows, where `level` does not track the human meaning of `message` at
all in this fixture (e.g. "backup job completed" and "backup job failed"
can carry the same level; postgres's "too many connections" appears at
three different levels; windows's "Account locked out" appears at two).
For those three, severity_hint is derived from the same message-based
classification that already drives event_type (_BACKUP_MESSAGE_EVENT_TYPES
/ _POSTGRES_MESSAGE_EVENT_TYPES / _WINDOWS_MESSAGE_EVENT_TYPES), mirroring
how backup_report_parser.py's _STATUS_SEVERITY maps VM Result -> severity
-- `level` is only used as the fallback when the message isn't recognized.
sshd and application were checked against this same fixture and found
consistent (every distinct message/http_status maps to exactly one level
there), so they're left driven by `level` as-is.

confidence_score is highest where a structured field drives the whole
classification (firewall's action/severity, application's http_status,
sshd's Accepted/Failed keyword), and lower for facilities (windows, backup,
postgres) where a small fixed vocabulary of free-text messages is the only
signal -- notably `event_id` on windows-facility rows is present but
inconsistent with `message` in this fixture, so it is carried in
raw_message only and is not used to drive event_type.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedGraylogEvent:
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
    source_tool: str = "graylog"


_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
SSHD_ACCEPTED_RE = re.compile(rf"^Accepted password for (?P<user>\S+) from {_IP} port (?P<port>\d+) ssh2$")
SSHD_FAILED_RE = re.compile(rf"^Failed password for (?P<user>\S+) from {_IP} port (?P<port>\d+) ssh2$")

_WINDOWS_MESSAGE_EVENT_TYPES = {
    "account locked out": "account_lockout",
    "user logon successful": "successful_logon",
    "user logon failed": "logon_failure",
    "group membership changed": "group_membership_change",
}

# account_lockout is the most alert-worthy (hit a lockout threshold --
# possible brute force/compromise); successful_logon is routine/benign;
# logon_failure and group_membership_change sit in between (a single
# failed attempt or a privilege change worth a look, not yet alarming).
_WINDOWS_MESSAGE_SEVERITY = {
    "account locked out": "high",
    "user logon successful": "low",
    "user logon failed": "medium",
    "group membership changed": "medium",
}

_BACKUP_MESSAGE_EVENT_TYPES = {
    "snapshot cleanup warning": "backup_snapshot_cleanup_warning",
    "backup job failed": "backup_job_failed",
    "backup job completed": "backup_job_completed",
}

# Same completed/warning/failed distinction as backup_report_parser.py's
# _STATUS_SEVERITY (SUCCESS -> low, WARNING -> medium, FAILED -> high),
# keyed by the same lowercase message text as _BACKUP_MESSAGE_EVENT_TYPES
# above so the two stay in lockstep.
_BACKUP_MESSAGE_SEVERITY = {
    "snapshot cleanup warning": "medium",
    "backup job failed": "high",
    "backup job completed": "low",
}

_POSTGRES_MESSAGE_EVENT_TYPES = {
    "checkpoint complete": "db_checkpoint_complete",
    "too many connections": "db_connection_limit_reached",
}

# checkpoint complete is routine background maintenance; too many
# connections is a real capacity/availability concern -- never "low",
# unlike level alone would sometimes claim (it appeared at low/medium/high
# in this fixture depending purely on level, for the same message).
_POSTGRES_MESSAGE_SEVERITY = {
    "checkpoint complete": "low",
    "too many connections": "medium",
}

_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _severity_from_level(level: object) -> str:
    if not isinstance(level, int):
        return "unknown"
    if level <= 2:
        return "critical"
    if level == 3:
        return "high"
    if level == 4:
        return "medium"
    return "low"


def parse_graylog_log(raw_text: str, *, source_tool: str = "graylog") -> list[ParsedGraylogEvent]:
    """Parse Graylog JSON-lines message exports into one event per message."""

    events: list[ParsedGraylogEvent] = []
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


def _to_event(record: dict, source_tool: str) -> ParsedGraylogEvent:
    facility = record.get("facility") or ""
    message = record.get("message") or ""
    affected_system = record.get("source") or "Unknown system"
    level_severity = _severity_from_level(record.get("level"))

    account = ""
    source_ip = None
    destination_ip = None
    event_type: str | None = None
    severity_hint = level_severity
    confidence = 0.4  # fallback for anything unrecognized

    if facility == "sshd":
        match = SSHD_ACCEPTED_RE.match(message)
        if match:
            event_type = "successful_login"
            account = match.group("user")
            source_ip = match.group("ip")
            confidence = 0.95
        else:
            match = SSHD_FAILED_RE.match(message)
            if match:
                event_type = "failed_login"
                account = match.group("user")
                source_ip = match.group("ip")
                confidence = 0.95

    elif facility == "firewall":
        src_ip = record.get("src_ip")
        dst_ip = record.get("dst_ip")
        action = record.get("action")
        severity_field = record.get("severity")
        if isinstance(src_ip, str) or isinstance(action, str):
            event_type = f"ips_{action}" if action else "ips_alert"
            source_ip = src_ip
            destination_ip = dst_ip
            confidence = 0.95
            if isinstance(severity_field, str) and severity_field.lower() in _VALID_SEVERITIES:
                severity_hint = severity_field.lower()

    elif facility == "application":
        http_status = record.get("http_status")
        if isinstance(http_status, int):
            event_type = f"http_response_{http_status}"
            source_ip = record.get("client_ip")
            confidence = 0.93

    elif facility == "backup":
        lowered_message = message.strip().lower()
        mapped = _BACKUP_MESSAGE_EVENT_TYPES.get(lowered_message)
        if mapped:
            event_type = mapped
            severity_hint = _BACKUP_MESSAGE_SEVERITY[lowered_message]
            confidence = 0.8

    elif facility == "postgres":
        lowered_message = message.strip().lower()
        mapped = _POSTGRES_MESSAGE_EVENT_TYPES.get(lowered_message)
        if mapped:
            event_type = mapped
            severity_hint = _POSTGRES_MESSAGE_SEVERITY[lowered_message]
            confidence = 0.8

    elif facility == "windows":
        lowered_message = message.strip().lower()
        mapped = _WINDOWS_MESSAGE_EVENT_TYPES.get(lowered_message)
        if mapped:
            event_type = mapped
            severity_hint = _WINDOWS_MESSAGE_SEVERITY[lowered_message]
            confidence = 0.65

    if event_type is None:
        # Unrecognized facility/message combination -- keep the record
        # visible rather than dropping it, but flag it as low confidence.
        event_type = f"{facility}_event" if facility else "graylog_event"

    timestamp = _parse_timestamp(record.get("timestamp"))

    summary_bits = [message or event_type.replace("_", " ")]
    if account:
        summary_bits.append(f"(user '{account}')")
    if source_ip:
        summary_bits.append(f"from {source_ip}")
    if destination_ip:
        summary_bits.append(f"to {destination_ip}")
    summary = " ".join(summary_bits) + f" on {affected_system}."

    return ParsedGraylogEvent(
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
