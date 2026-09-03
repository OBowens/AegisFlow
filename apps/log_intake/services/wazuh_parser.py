"""Parser for Wazuh alert exports (JSON lines, one alert object per line).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/wazuh_50.jsonl, a hand-authored synthetic sample (see
that fixture set's own README) -- NOT a real Wazuh export. Field names and
value ranges below reflect that fixture, not a live Wazuh manager. Field
names come straight from Wazuh's own alert JSON schema (rule/agent/manager/
data/syscheck), so a real export is expected to line up closely, but this
has not been checked against one.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Wazuh alerts are already one well-formed JSON object per event -- there's no
multi-line correlation to do here (contrast with linux_auth_parser.py, which
has to stitch multiple sshd log lines into one connection). The interpretive
work in this parser is entirely in mapping rule.id -> a normalized
event_type and mapping rule.level -> our five-value severity_hint, both via
lookup tables built from the rule IDs observed in the fixture. An unrecognized
rule.id still parses (severity falls back to a level-only bucket, event_type
falls back to a slugified rule description) but at reduced confidence, since
the mapping wasn't verified against that rule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedWazuhEvent:
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
    source_tool: str = "wazuh"


# rule.id -> (event_type, confidence). Built from the rule IDs actually
# present in the fixture; confidence is high because the id is a stable,
# structured field, not something inferred from free text.
_RULE_EVENT_TYPES: dict[str, tuple[str, float]] = {
    "1002": ("service_stopped", 0.95),
    "5710": ("invalid_user_login_attempt", 0.97),
    "5712": ("repeated_ssh_auth_failure", 0.97),
    "5715": ("successful_login", 0.97),
    "550": ("file_integrity_alert", 0.97),
    "87105": ("malware_detected", 0.97),
    "5103": ("password_changed", 0.9),
    "18107": ("windows_login_failure", 0.9),
    "31166": ("web_auth_failure", 0.97),
    "31101": ("web_server_error", 0.9),
}

# rule.level buckets, matching Wazuh's own documented severity groupings.
def _severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    return _SLUG_RE.sub("_", text.lower()).strip("_") or "wazuh_event"


def parse_wazuh_log(raw_text: str, *, source_tool: str = "wazuh") -> list[ParsedWazuhEvent]:
    """Parse Wazuh JSON-lines alert exports into one event per alert."""

    events: list[ParsedWazuhEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(alert, dict):
            continue

        events.append(_to_event(alert, source_tool))

    return events


def _to_event(alert: dict, source_tool: str) -> ParsedWazuhEvent:
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    syscheck = alert.get("syscheck") or {}

    rule_id = str(rule.get("id")) if rule.get("id") is not None else None
    description = rule.get("description") or ""
    level = rule.get("level")
    if not isinstance(level, int):
        level = 0

    event_type, confidence = _RULE_EVENT_TYPES.get(rule_id, (None, None))
    if event_type is None:
        # Unrecognized rule id: fall back to the rule description itself
        # rather than guessing at a taxonomy we haven't verified.
        event_type = _slugify(description) if description else "wazuh_event"
        confidence = 0.5

    severity_hint = _severity_from_level(level)

    affected_system = agent.get("name") or agent.get("ip") or "Unknown system"
    account = data.get("srcuser") or ""
    source_ip = data.get("srcip")
    destination_ip = None  # not present anywhere in the Wazuh alert schema seen in this fixture

    timestamp = _parse_timestamp(alert.get("timestamp"))

    summary_bits = [description or event_type.replace("_", " ").title()]
    if account:
        summary_bits.append(f"for '{account}'")
    if source_ip:
        summary_bits.append(f"from {source_ip}")
    if data.get("url"):
        summary_bits.append(f"({data['url']}, status {data.get('status')})")
    if syscheck.get("path"):
        summary_bits.append(f"[{syscheck.get('event')}: {syscheck['path']}]")
    if data.get("threat"):
        summary_bits.append(f"threat={data['threat']} file={data.get('file')}")
    summary = " ".join(summary_bits) + f" on {affected_system}."

    return ParsedWazuhEvent(
        timestamp=timestamp,
        affected_system=affected_system,
        account=account,
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=event_type,
        severity_hint=severity_hint,
        raw_message=json.dumps(alert, ensure_ascii=False),
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
        return None
