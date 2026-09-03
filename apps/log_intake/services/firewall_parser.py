"""Parser for FortiGate-style firewall logs (plain text, key=value per line).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/firewall_fortigate_style_50.log, a hand-authored
synthetic sample -- NOT a real FortiGate export. Field names and value
ranges below reflect that fixture, not a live firewall. The key=value shape
itself (date/time/devname/devid/type/subtype/level plus subtype-specific
fields) mirrors FortiGate's real documented log format, so a genuine export
is expected to line up closely, but this has not been checked against one.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Unlike the JSON/CSV formats already parsed (Wazuh, Graylog, PRTG, SSL
Certificate), this is plain text: one event per line, but each line is a
flat "key=value key=\"quoted value\" ..." record rather than structured
JSON. `_parse_kv_line` tokenizes that into a dict; everything downstream
works off that dict the same way the JSON parsers work off a decoded
object.

Every line already carries `type`/`subtype` (utm/virus, utm/dns,
utm/webfilter, utm/ips, traffic/forward, event/vpn, event/system in this
fixture), so -- like Wazuh's rule.id -- there is a real structured field to
dispatch on rather than inferring category from free text. The judgment
calls are entirely in how each subtype's severity is scored, since
FortiGate's own `level` field (notice/warning/alert/critical) is a log
*verbosity* level, not a security severity, and doesn't map cleanly onto
ours:

- virus: always "critical". A `virus=`/`filename=` pair firing at all means
  the antivirus engine had a positive identification; whether the action
  was "blocked" doesn't change how seriously that's treated here.
- ips (intrusion prevention): FortiGate already ships its own
  `severity=critical|high|medium` field for these, and it happens to use
  the exact same three words we do -- so it's used directly rather than
  reinvented.
- webfilter: scored by `category`, not just blocked/passthrough. The
  fixture's "Malicious Websites" category is a materially different signal
  than "Business" or "Unrated" (those look like routine acceptable-use
  policy blocks, not threat intel hits) -- so "Malicious Websites" is
  scored higher, and a "passthrough" (the user clicked through a warning
  page) on that category is scored higher still than an outright block,
  since it means a person actually reached a known-malicious site.
- dns: every line in this fixture is a DNS query that already matched a
  malicious/suspicious-domain filter (that's *why* it was logged at all,
  under a UTM security subtype rather than routine query logging) --
  action="pass" means that flagged query was let through, which is a worse
  outcome than action="block" stopping it. So pass scores higher than
  block here, deliberately inverted from the usual "block=bad" instinct.
- traffic/forward: ordinary allow/deny flow logs. Both are scored "low" --
  this is bulk connection accounting, not a security detection, regardless
  of whether the specific connection was accepted or denied by policy.
- vpn (SSL VPN login failures): reason="sslvpn_login_unknown_user" scores
  higher than "bad_password"/"sslvpn_login_permission_denied", on the
  theory that a wrong password is at least consistent with a real,
  existing account being mistyped, while probing for accounts that don't
  exist is a clearer enumeration/attack signal.
- event/system "Administrator login failed": always "high". This is a
  failed login against the firewall's own admin control plane, not a
  downstream host -- FortiGate's own log already marks these
  level="critical".

`affected_system` is likewise a judgment call: for the traffic-content
subtypes (virus/dns/webfilter/ips/traffic) it's the internal LAN endpoint
(`srcip`) that generated or received the traffic. For the two
control-plane subtypes (vpn, system) there is no relevant internal host --
the target of the event is the firewall's own admin/VPN gateway -- so
`devname` is used instead.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedFirewallEvent:
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
    source_tool: str = "firewall"


_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

_WEBFILTER_MALICIOUS_CATEGORY = "malicious websites"

_VPN_REASON_SEVERITY = {
    "sslvpn_login_unknown_user": "high",
    "bad_password": "medium",
    "sslvpn_login_permission_denied": "medium",
}


def parse_fortigate_firewall_log(
    raw_text: str, *, source_tool: str = "firewall"
) -> list[ParsedFirewallEvent]:
    """Parse a FortiGate-style key=value firewall log into one event per line."""

    events: list[ParsedFirewallEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        fields = _parse_kv_line(line)
        if not fields or "subtype" not in fields:
            continue

        events.append(_to_event(fields, line, source_tool))

    return events


def _parse_kv_line(line: str) -> dict:
    fields: dict[str, str] = {}
    for match in _KV_RE.finditer(line):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        fields[key] = value
    return fields


def _to_event(fields: dict, raw_line: str, source_tool: str) -> ParsedFirewallEvent:
    subtype = fields.get("subtype", "")
    devname = fields.get("devname", "Unknown system")
    src_ip = _safe_ip(fields.get("srcip"))
    dst_ip = _safe_ip(fields.get("dstip"))
    timestamp = _parse_timestamp(fields.get("date"), fields.get("time"))

    if subtype == "virus":
        event_type = "malware_blocked" if fields.get("action") == "blocked" else "malware_detected"
        severity_hint = "critical"
        confidence = 0.97
        affected_system = devname if src_ip is None else fields["srcip"]
        account = ""
        summary = (
            f"Malware '{fields.get('virus', 'unknown')}' in file "
            f"'{fields.get('filename', 'unknown')}' from {fields.get('srcip', 'unknown host')} "
            f"to {fields.get('dstip', 'unknown destination')} -- {fields.get('action', 'unknown action')}."
        )

    elif subtype == "dns":
        action = fields.get("action", "")
        blocked = action in ("block", "blocked")
        event_type = "dns_query_blocked" if blocked else "dns_query_allowed"
        severity_hint = "medium" if blocked else "high"
        confidence = 0.9
        affected_system = fields.get("srcip", devname)
        account = ""
        summary = (
            f"DNS query for '{fields.get('query', 'unknown domain')}' from "
            f"{fields.get('srcip', 'unknown host')} -- {action or 'unknown action'}."
        )

    elif subtype == "webfilter":
        action = fields.get("action", "")
        category = fields.get("category", "")
        is_malicious_category = category.strip().lower() == _WEBFILTER_MALICIOUS_CATEGORY
        passthrough = action == "passthrough"
        event_type = "web_category_bypassed" if passthrough else "web_category_blocked"
        if is_malicious_category:
            severity_hint = "critical" if passthrough else "high"
        else:
            severity_hint = "medium" if passthrough else "low"
        confidence = 0.9
        affected_system = fields.get("srcip", devname)
        account = ""
        summary = (
            f"Web request to '{fields.get('hostname', 'unknown host')}' "
            f"(category: {category or 'unknown'}) from {fields.get('srcip', 'unknown host')} "
            f"-- {action or 'unknown action'}."
        )

    elif subtype == "ips":
        fortigate_severity = (fields.get("severity") or "").lower()
        event_type = "intrusion_blocked" if fields.get("action") == "blocked" else "intrusion_detected"
        severity_hint = fortigate_severity if fortigate_severity in ("critical", "high", "medium", "low") else "high"
        confidence = 0.95
        affected_system = fields.get("srcip", devname)
        account = ""
        summary = (
            f"IPS signature '{fields.get('attack', 'unknown attack')}' from "
            f"{fields.get('srcip', 'unknown host')} to {fields.get('dstip', 'unknown host')}:"
            f"{fields.get('dstport', '?')} -- {fields.get('action', 'unknown action')}."
        )

    elif subtype == "forward":
        action = fields.get("action", "")
        event_type = "traffic_denied" if action == "deny" else "traffic_allowed"
        severity_hint = "low"
        confidence = 0.6
        affected_system = fields.get("srcip", devname)
        account = ""
        summary = (
            f"Traffic from {fields.get('srcip', 'unknown host')} to "
            f"{fields.get('dstip', 'unknown host')}:{fields.get('dstport', '?')} "
            f"({fields.get('service', 'unknown service')}) -- {action or 'unknown action'}."
        )

    elif subtype == "vpn":
        reason = fields.get("reason", "")
        event_type = "vpn_login_failure"
        severity_hint = _VPN_REASON_SEVERITY.get(reason, "medium")
        confidence = 0.92
        affected_system = devname
        account = fields.get("user", "")
        summary = (
            f"SSL VPN login failed for user '{fields.get('user', 'unknown')}' from "
            f"{fields.get('srcip', 'unknown host')} -- {reason or 'unknown reason'}."
        )

    elif subtype == "system" and "Administrator login failed" in fields.get("msg", ""):
        event_type = "admin_login_failure"
        severity_hint = "high"
        confidence = 0.95
        affected_system = devname
        account = fields.get("user", "")
        summary = (
            f"Administrator login failed for user '{fields.get('user', 'unknown')}' from "
            f"{fields.get('srcip', 'unknown host')} on {devname}."
        )

    else:
        event_type = f"{fields.get('type', 'firewall')}_{subtype}_event"
        severity_hint = "unknown"
        confidence = 0.4
        affected_system = fields.get("srcip", devname)
        account = fields.get("user", "")
        summary = fields.get("msg", raw_line)[:255]

    return ParsedFirewallEvent(
        timestamp=timestamp,
        affected_system=affected_system,
        account=account,
        source_ip=src_ip,
        destination_ip=dst_ip,
        event_type=event_type,
        severity_hint=severity_hint,
        raw_message=raw_line,
        normalized_summary=summary[:255],
        confidence_score=round(confidence, 2),
        source_tool=source_tool,
    )


def _safe_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _parse_timestamp(date_value: str | None, time_value: str | None) -> datetime | None:
    if not date_value or not time_value:
        return None
    try:
        return datetime.strptime(f"{date_value} {time_value}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
