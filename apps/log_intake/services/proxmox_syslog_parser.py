"""Parser for Proxmox VE syslog (plain text, standard "Mon DD HH:MM:SS host
process[pid]: message" syslog lines).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/proxmox_syslog_50.log, a hand-authored synthetic
sample -- NOT a real Proxmox export. Field names, process names, and
message shapes below reflect that fixture only.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Same header shape as linux_auth_parser's sshd lines
("<ts> <host> <process>[<pid>]: <message>"), but unlike sshd there's no
multi-line connection to stitch together -- every line here is already a
complete, standalone event. The real parsing judgment is in the fact that
`process` alone doesn't tell you what an event means: pvedaemon covers four
completely different message shapes (routine task completions, VM
migrations, and both successful and failed authentication), so dispatch is
two-level -- process name first, then a message-shape regex within it.

WHAT'S SECURITY/OPS-RELEVANT VS. NOISE, and why, per process:

- pvedaemon: "authentication failure" (someone's credentials were rejected
  against the Proxmox API) and "successful auth" are the actual security
  signal here. "end task UPID:..." lines are routine admin/automation
  activity completing (start/stop a VM, etc.) -- logged for audit, not
  because anything went wrong -- so those are scored low. "migration of VM
  N to <host> finished successfully" is likewise routine, expected cluster
  activity (an admin or DRS-equivalent moved a VM), not an anomaly.
- vzdump (Proxmox's own backup tool): ERROR lines are a real, high-severity
  ops signal -- this fixture's failures are all the same underlying cause
  ("storage 'backup-nas' is not available"), i.e. the backup target itself
  is unreachable, which is exactly the kind of thing that should surface
  loudly rather than get buried in routine syslog volume. INFO "Finished
  Backup" lines are scored low, same as any other routine success.
- kernel: `vmbr0: port N(tapXXXiY) entered <state> state` bridge/STP
  messages are treated as noise (low severity). Ports on a hypervisor's
  virtual bridge cycle through blocking -> forwarding as VMs start and
  stop, and "disabled state" happens whenever a VM's tap interface is torn
  down on shutdown -- none of the three states seen in this fixture
  (forwarding/disabled/blocking) is abnormal on its own without much more
  context (how often, which port, correlated with what). Scoring these low
  rather than dropping them keeps the signal available for anyone who
  wants to correlate bridge churn against something else, without it
  competing for attention against real findings.
- pvestatd: periodic `storage '<name>' usage NN%` telemetry. Scored low by
  default, but bumped to medium at >=90% -- a real, if simple, capacity
  threshold rather than treating every stats line as equally uninteresting
  (the fixture has three readings at/above that line: 94%, 90%, 92%).
- corosync: `[TOTEM] A new membership (N) was formed` is a cluster quorum
  membership change -- a node joined, left, or the cluster reformed.
  There's no way to tell planned maintenance from an unplanned node drop
  from the message alone, so this is scored medium (worth surfacing,
  not treated as certain, not treated as noise) rather than guessed either
  direction.

affected_system is the Proxmox node (`host`) for node/cluster-scoped
events (auth, bridge, storage, cluster membership) since those are
properties of that node. For the VM-lifecycle messages (task completion,
migration, backup) it's "VM <vmid>" instead -- what actually matters for
those is which guest was affected, not which physical node happened to
run the command.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class ParsedProxmoxEvent:
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
    source_tool: str = "proxmox"


LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w.\-()]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)

_END_TASK_RE = re.compile(
    r"^<(?P<user>[^>]+)> end task UPID:(?P<node>[^:]+):(?P<taskid>[^:]+):"
    r"(?P<tasktype>[^:]+):(?P<vmid>[^:]+):(?P<taskuser>[^:]+):\s*(?P<result>\w+)$"
)
_AUTH_FAILURE_RE = re.compile(
    r"^authentication failure; rhost=(?P<rhost>\S+) user=(?P<user>\S+) msg=(?P<msg>.*)$"
)
_SUCCESSFUL_AUTH_RE = re.compile(r"^<(?P<user>[^>]+)> successful auth$")
_MIGRATION_RE = re.compile(
    r"^migration of VM (?P<vmid>\d+) to (?P<target>\S+) finished successfully$"
)
_BRIDGE_STATE_RE = re.compile(
    r"^vmbr\d+: port \d+\((?P<iface>[^)]+)\) entered (?P<state>\w+) state$"
)
_BACKUP_OK_RE = re.compile(r"^INFO: Finished Backup of VM (?P<vmid>\d+) \((?P<duration>[\d:]+)\)$")
_BACKUP_ERROR_RE = re.compile(r"^ERROR: Backup of VM (?P<vmid>\d+) failed - (?P<reason>.*)$")
_STORAGE_USAGE_RE = re.compile(r"^storage '(?P<storage>[^']+)' usage (?P<pct>\d+)%$")
_MEMBERSHIP_RE = re.compile(r"^\[TOTEM ?\]\s*A new membership \((?P<membership_id>\d+)\) was formed$")

_STORAGE_WARNING_THRESHOLD = 90


def parse_proxmox_syslog(raw_text: str, *, source_tool: str = "proxmox") -> list[ParsedProxmoxEvent]:
    """Parse Proxmox VE syslog text into one event per line."""

    events: list[ParsedProxmoxEvent] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue

        header = LINE_RE.match(line)
        if not header:
            continue

        events.append(_to_event(header, source_tool))

    return events


def _to_event(header: re.Match, source_tool: str) -> ParsedProxmoxEvent:
    process = header.group("process")
    message = header.group("message")
    host = header.group("host")
    timestamp = _parse_timestamp(header.group("month"), header.group("day"), header.group("time"))

    if process == "pvedaemon":
        return _parse_pvedaemon(message, host, timestamp, header.group(0), source_tool)
    if process == "vzdump":
        return _parse_vzdump(message, host, timestamp, header.group(0), source_tool)
    if process == "kernel":
        return _parse_kernel(message, host, timestamp, header.group(0), source_tool)
    if process == "pvestatd":
        return _parse_pvestatd(message, host, timestamp, header.group(0), source_tool)
    if process == "corosync":
        return _parse_corosync(message, host, timestamp, header.group(0), source_tool)

    return ParsedProxmoxEvent(
        timestamp=timestamp,
        affected_system=host,
        account="",
        source_ip=None,
        destination_ip=None,
        event_type=f"{process}_event",
        severity_hint="unknown",
        raw_message=header.group(0),
        normalized_summary=message[:255],
        confidence_score=0.4,
        source_tool=source_tool,
    )


def _parse_pvedaemon(message, host, timestamp, raw_line, source_tool):
    match = _END_TASK_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=f"VM {match.group('vmid')}",
            account=match.group("user"),
            source_ip=None,
            destination_ip=None,
            event_type=f"vm_task_{match.group('tasktype')}",
            severity_hint="low",
            raw_message=raw_line,
            normalized_summary=(
                f"Task {match.group('tasktype')} on VM {match.group('vmid')} by "
                f"{match.group('user')} -- {match.group('result')}."
            )[:255],
            confidence_score=0.9,
            source_tool=source_tool,
        )

    match = _AUTH_FAILURE_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=host,
            account=match.group("user"),
            source_ip=_safe_ip(match.group("rhost")),
            destination_ip=None,
            event_type="authentication_failure",
            severity_hint="medium",
            raw_message=raw_line,
            normalized_summary=(
                f"Authentication failure for '{match.group('user')}' from "
                f"{match.group('rhost')} on {host}."
            )[:255],
            confidence_score=0.93,
            source_tool=source_tool,
        )

    match = _SUCCESSFUL_AUTH_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=host,
            account=match.group("user"),
            source_ip=None,
            destination_ip=None,
            event_type="successful_login",
            severity_hint="low",
            raw_message=raw_line,
            normalized_summary=f"Successful authentication for '{match.group('user')}' on {host}."[:255],
            confidence_score=0.85,
            source_tool=source_tool,
        )

    match = _MIGRATION_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=f"VM {match.group('vmid')}",
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="vm_migration_completed",
            severity_hint="low",
            raw_message=raw_line,
            normalized_summary=(
                f"VM {match.group('vmid')} migrated to {match.group('target')} successfully."
            )[:255],
            confidence_score=0.9,
            source_tool=source_tool,
        )

    return _fallback_event("pvedaemon", message, host, timestamp, raw_line, source_tool)


def _parse_vzdump(message, host, timestamp, raw_line, source_tool):
    match = _BACKUP_OK_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=f"VM {match.group('vmid')}",
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="backup_success",
            severity_hint="low",
            raw_message=raw_line,
            normalized_summary=(
                f"Backup of VM {match.group('vmid')} finished in {match.group('duration')}."
            )[:255],
            confidence_score=0.92,
            source_tool=source_tool,
        )

    match = _BACKUP_ERROR_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=f"VM {match.group('vmid')}",
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="backup_failed",
            severity_hint="high",
            raw_message=raw_line,
            normalized_summary=(
                f"Backup of VM {match.group('vmid')} failed -- {match.group('reason')}."
            )[:255],
            confidence_score=0.92,
            source_tool=source_tool,
        )

    return _fallback_event("vzdump", message, host, timestamp, raw_line, source_tool)


def _parse_kernel(message, host, timestamp, raw_line, source_tool):
    match = _BRIDGE_STATE_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=host,
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="network_bridge_state_change",
            severity_hint="low",
            raw_message=raw_line,
            normalized_summary=(
                f"Bridge interface {match.group('iface')} on {host} entered "
                f"{match.group('state')} state."
            )[:255],
            confidence_score=0.7,
            source_tool=source_tool,
        )

    return _fallback_event("kernel", message, host, timestamp, raw_line, source_tool)


def _parse_pvestatd(message, host, timestamp, raw_line, source_tool):
    match = _STORAGE_USAGE_RE.match(message)
    if match:
        pct = int(match.group("pct"))
        severity = "medium" if pct >= _STORAGE_WARNING_THRESHOLD else "low"
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=host,
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="storage_usage_report",
            severity_hint=severity,
            raw_message=raw_line,
            normalized_summary=(
                f"Storage '{match.group('storage')}' on {host} at {pct}% usage."
            )[:255],
            confidence_score=0.85,
            source_tool=source_tool,
        )

    return _fallback_event("pvestatd", message, host, timestamp, raw_line, source_tool)


def _parse_corosync(message, host, timestamp, raw_line, source_tool):
    match = _MEMBERSHIP_RE.match(message)
    if match:
        return ParsedProxmoxEvent(
            timestamp=timestamp,
            affected_system=host,
            account="",
            source_ip=None,
            destination_ip=None,
            event_type="cluster_membership_change",
            severity_hint="medium",
            raw_message=raw_line,
            normalized_summary=(
                f"Cluster membership reformed (membership {match.group('membership_id')}) "
                f"observed on {host}."
            )[:255],
            confidence_score=0.8,
            source_tool=source_tool,
        )

    return _fallback_event("corosync", message, host, timestamp, raw_line, source_tool)


def _fallback_event(process, message, host, timestamp, raw_line, source_tool):
    return ParsedProxmoxEvent(
        timestamp=timestamp,
        affected_system=host,
        account="",
        source_ip=None,
        destination_ip=None,
        event_type=f"{process}_event",
        severity_hint="unknown",
        raw_message=raw_line,
        normalized_summary=message[:255],
        confidence_score=0.4,
        source_tool=source_tool,
    )


def _safe_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_timestamp(month: str, day: str, time_value: str) -> datetime | None:
    month_number = _MONTHS.get(month)
    if not month_number:
        return None
    try:
        hour, minute, second = (int(part) for part in time_value.split(":"))
    except ValueError:
        return None

    # Classic syslog timestamps carry no year. Assume the current year,
    # unless that would place the event in the future (relative to now),
    # in which case it must actually be from last year -- the standard
    # heuristic for year-less syslog timestamps.
    now = datetime.now()
    candidate = datetime(now.year, month_number, int(day), hour, minute, second)
    if candidate > now + timedelta(days=1):
        candidate = candidate.replace(year=now.year - 1)
    return candidate
