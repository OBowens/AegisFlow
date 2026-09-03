"""Parser for Linux sshd authentication logs (journalctl / auth.log format).

This is a standalone parser: it takes raw log text in and returns a list of
``ParsedSSHEvent`` dataclass instances out. It does not touch the database
or any Django models, so it can be exercised directly in tests before being
wired into the upload pipeline.

sshd almost never says everything about one connection attempt on a single
line. A single scan against this host typically looks like:

    Invalid user test from 119.41.148.202 port 51592
    Received disconnect from 119.41.148.202 port 51592:11: Bye Bye [preauth]
    Disconnected from invalid user test 119.41.148.202 port 51592 [preauth]

All three lines share the same sshd worker PID and describe one connection,
not three events. This parser groups lines by that PID and emits exactly one
event per connection, using the most specific line seen to decide the
event_type, and using "Received disconnect" / "Disconnected from" /
"Connection closed|reset by" lines only to enrich (username, final outcome)
the connection already opened by an earlier line -- or, if journalctl's
window truncated the start of the connection, to originate the event
themselves.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ParsedSSHEvent:
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
    source_tool: str = "linux"


# --- line-level patterns -----------------------------------------------

LINE_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<process>[\w.\-()]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
_PORT = r"port (?P<port>\d+)"

INVALID_USER_RE = re.compile(rf"^Invalid user (?P<user>\S*) from {_IP} {_PORT}$")
ACCEPTED_RE = re.compile(
    rf"^Accepted (?P<method>publickey|password|keyboard-interactive/pam) "
    rf"for (?P<user>\S+) from {_IP} {_PORT}"
)
FAILED_PASSWORD_RE = re.compile(
    rf"^Failed password for (?:invalid user )?(?P<user>\S+) from {_IP} {_PORT}"
)
DISCONNECTED_FROM_RE = re.compile(
    rf"^Disconnected from (?:(?P<kind>invalid user|authenticating user) (?P<user>\S*) )?{_IP} {_PORT}"
)
CONNECTION_TORNDOWN_RE = re.compile(
    rf"^Connection (?P<action>closed|reset) by "
    rf"(?:(?P<kind>invalid user|authenticating user) (?P<user>\S*) )?{_IP} {_PORT}"
)
RECEIVED_DISCONNECT_RE = re.compile(
    rf"^Received disconnect from {_IP} {_PORT}:\d+: (?P<reason>.*?)(?: \[preauth\])?$"
)
BANNER_EXCHANGE_RE = re.compile(
    rf"^banner exchange: Connection from {_IP} {_PORT}: (?P<detail>.*)$"
)

# Ordered worst -> best so a higher-ranked event never gets clobbered by a
# less specific follow-up line for the same connection.
_RANK = {"disconnect": 0, "invalid_user_probe": 1, "failed_login": 2, "successful_login": 3}

_SEVERITY_BY_EVENT = {
    "disconnect": "low",
    "invalid_user_probe": "low",
    "failed_login": "medium",
    "successful_login": "low",
}


@dataclass
class _Connection:
    pid: str
    host: str = ""
    first_timestamp: datetime | None = None
    ip: str | None = None
    port: str | None = None
    username: str | None = None
    method: str | None = None
    event_type: str = "disconnect"
    confidence: float = 0.6
    raw_lines: list[str] = field(default_factory=list)


def parse_linux_auth_log(raw_text: str, *, source_tool: str = "linux") -> list[ParsedSSHEvent]:
    """Parse sshd auth-log text into one ParsedSSHEvent per connection."""

    connections: dict[str, _Connection] = {}
    order: list[str] = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        header = LINE_RE.match(line)
        if not header or header.group("process") != "sshd" or not header.group("pid"):
            # Non-sshd lines (sudo invocations, systemd-logind, pam session
            # bookkeeping) and malformed lines carry no remote-auth signal.
            continue

        pid = header.group("pid")
        conn = connections.get(pid)
        if conn is None:
            conn = _Connection(pid=pid, host=header.group("host"))
            connections[pid] = conn
            order.append(pid)

        timestamp = _parse_timestamp(header.group("timestamp"))
        if conn.first_timestamp is None:
            conn.first_timestamp = timestamp

        message = header.group("message")
        conn.raw_lines.append(message)
        _apply_message(conn, message)

    events = []
    for pid in order:
        conn = connections[pid]
        if conn.ip is None:
            # Nothing extractable (e.g. a bare "error: kex_exchange_..."
            # line with no companion line for this pid) -- not alertable.
            continue
        events.append(_to_event(conn, source_tool))
    return events


def _apply_message(conn: _Connection, message: str) -> None:
    match = ACCEPTED_RE.match(message)
    if match:
        conn.method = match.group("method")
        _upgrade(
            conn,
            event_type="successful_login",
            user=match.group("user"),
            ip=match.group("ip"),
            port=match.group("port"),
            confidence=0.99,
        )
        return

    match = FAILED_PASSWORD_RE.match(message)
    if match:
        _upgrade(
            conn,
            event_type="failed_login",
            user=match.group("user"),
            ip=match.group("ip"),
            port=match.group("port"),
            confidence=0.95,
        )
        return

    match = INVALID_USER_RE.match(message)
    if match:
        _upgrade(
            conn,
            event_type="invalid_user_probe",
            user=match.group("user") or None,
            ip=match.group("ip"),
            port=match.group("port"),
            confidence=0.95,
        )
        return

    match = DISCONNECTED_FROM_RE.match(message) or CONNECTION_TORNDOWN_RE.match(message)
    if match:
        kind = match.group("kind")
        if kind == "invalid user":
            _upgrade(
                conn,
                event_type="invalid_user_probe",
                user=match.group("user") or None,
                ip=match.group("ip"),
                port=match.group("port"),
                confidence=0.9,
            )
        elif kind == "authenticating user":
            # sshd never logs an explicit "failed" here -- we infer failure
            # because the connection was torn down mid-authentication
            # against a real account, with no Accepted line for this pid.
            _upgrade(
                conn,
                event_type="failed_login",
                user=match.group("user") or None,
                ip=match.group("ip"),
                port=match.group("port"),
                confidence=0.8,
            )
        else:
            _upgrade(
                conn,
                event_type="disconnect",
                user=None,
                ip=match.group("ip"),
                port=match.group("port"),
                confidence=0.6,
            )
        return

    match = RECEIVED_DISCONNECT_RE.match(message)
    if match:
        _upgrade(
            conn,
            event_type="disconnect",
            user=None,
            ip=match.group("ip"),
            port=match.group("port"),
            confidence=0.6,
        )
        return

    match = BANNER_EXCHANGE_RE.match(message)
    if match:
        _upgrade(
            conn,
            event_type="disconnect",
            user=None,
            ip=match.group("ip"),
            port=match.group("port"),
            confidence=0.6,
        )
        return

    # Unrecognized sshd line for this pid (e.g. "error: kex_exchange_...",
    # or a pam_unix session line for an already-authenticated connection).
    # Keep it in raw_lines for context; it doesn't change classification.


def _upgrade(
    conn: _Connection,
    *,
    event_type: str,
    ip: str | None,
    port: str | None,
    confidence: float,
    user: str | None,
) -> None:
    if ip and not _valid_ip(ip):
        ip = None

    new_rank = _RANK[event_type]
    cur_rank = _RANK[conn.event_type]
    if new_rank > cur_rank:
        conn.event_type = event_type
        conn.confidence = confidence
    elif new_rank == cur_rank:
        conn.confidence = max(conn.confidence, confidence)

    if user:
        conn.username = user
    if ip and not conn.ip:
        conn.ip = ip
    if port and not conn.port:
        conn.port = port


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _to_event(conn: _Connection, source_tool: str) -> ParsedSSHEvent:
    severity = _SEVERITY_BY_EVENT[conn.event_type]
    if conn.event_type == "successful_login" and conn.method != "publickey":
        # Password/keyboard-interactive auth succeeding is worth a closer
        # look even when it's not itself an attack.
        severity = "medium"

    account = conn.username or ""
    raw_message = "\n".join(conn.raw_lines)
    port_part = f":{conn.port}" if conn.port else ""

    if conn.event_type == "successful_login":
        summary = (
            f"Successful SSH login for '{account}' via {conn.method} "
            f"from {conn.ip}{port_part}."
        )
    elif conn.event_type == "failed_login":
        summary = (
            f"SSH authentication attempt against existing account '{account}' "
            f"from {conn.ip}{port_part} did not complete."
        )
    elif conn.event_type == "invalid_user_probe":
        who = f"'{account}'" if account else "a blank username"
        summary = f"SSH login probe for nonexistent user {who} from {conn.ip}{port_part}."
    else:
        summary = f"SSH connection from {conn.ip}{port_part} terminated before authentication."

    return ParsedSSHEvent(
        timestamp=conn.first_timestamp,
        affected_system=conn.host,
        account=account,
        source_ip=conn.ip,
        destination_ip=None,
        event_type=conn.event_type,
        severity_hint=severity,
        raw_message=raw_message,
        normalized_summary=summary[:255],
        confidence_score=round(conn.confidence, 2),
        source_tool=source_tool,
    )


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
