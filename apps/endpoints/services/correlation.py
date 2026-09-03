"""Deterministic correlation rules over stored EndpointEvent rows.

No AI here. These rules decide *which* clusters of an endpoint's
process-creation (4688) and PowerShell script-block (4104) events are
worth sending to AI triage -- frequency/pattern/indicator based, not
"every kept event escalates". Part 2's agent already dropped the
verifiably-safe noise locally; everything stored is "kept but not
confirmed", so a burst or a high-signal command line here is a real
signal worth a closer look.

``find_correlation_candidates`` returns a :class:`ScanResult`: the
flagged clusters plus the full set of event ids the scan considered (so
the caller can mark them ``correlation_scanned_at`` and not re-process
them).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from django.utils import timezone

from apps.endpoints.models import EndpointEvent

# The two event_type strings the agent sends (see
# endpoint_agent/aegis_agent/events.py::EventRecord.event_type).
EVENT_TYPE_PROCESS_CREATION = "Security/4688"
EVENT_TYPE_SCRIPT_BLOCK = "Microsoft-Windows-PowerShell/4104"

# Hits within this gap of each other are one cluster (one candidate);
# same time-gap-split idea as apps/incidents/services/grouping.py.
CLUSTER_GAP = timedelta(minutes=30)
# Non-triggering context events this close to a cluster are attached too.
CLUSTER_PADDING = timedelta(minutes=15)

# One scan will not pull more than this many unscanned events into
# memory. A larger backlog is drained over successive runs -- the
# remainder is simply left unscanned, never dropped.
MAX_EVENTS_PER_SCAN = 50_000

_LOLBINS = frozenset(
    {
        "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe",
        "schtasks.exe", "installutil.exe", "msbuild.exe", "regasm.exe",
        "regsvcs.exe",
    }
)
_OFFICE_PARENTS = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "msaccess.exe"}
)
_SHELL_CHILDREN = frozenset(
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe",
    }
)

LOLBIN_BURST_THRESHOLD = 3
LOLBIN_BURST_WINDOW = timedelta(minutes=10)
SCRIPT_BLOCK_BURST_THRESHOLD = 10
SCRIPT_BLOCK_BURST_WINDOW = timedelta(minutes=5)


@dataclass(frozen=True)
class RuleHit:
    rule: str
    reason: str
    event_ids: tuple[int, ...]
    at: object  # datetime of the earliest triggering event


@dataclass
class CandidateSpec:
    endpoint: object
    organization: object
    events: list  # EndpointEvent rows, chronological
    trigger_summary: str

    @property
    def first_event_at(self):
        return self.events[0].occurred_at

    @property
    def last_event_at(self):
        return self.events[-1].occurred_at


@dataclass
class ScanResult:
    candidates: list[CandidateSpec] = field(default_factory=list)
    scanned_event_ids: set[int] = field(default_factory=set)
    overflowed: bool = False


# --- helpers -------------------------------------------------------------

def _data(event) -> dict:
    payload = event.payload or {}
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def _basename(path: str) -> str:
    path = (path or "").strip().lower().replace("/", "\\")
    return path.rsplit("\\", 1)[-1]


def _command_line(event) -> str:
    return (_data(event).get("command_line") or "").lower()


def _script_text(event) -> str:
    return (_data(event).get("script_block_text") or "").lower()


def _is_process_event(event) -> bool:
    return event.event_type == EVENT_TYPE_PROCESS_CREATION


def _is_script_block_event(event) -> bool:
    return event.event_type == EVENT_TYPE_SCRIPT_BLOCK


def _contains_all(haystack: str, needles) -> bool:
    return all(n in haystack for n in needles)


# --- individual rules --------------------------------------------------
# Each rule takes the endpoint's chronological event list and returns
# zero or more RuleHits.

_SUSPICIOUS_CMDLINE_SINGLE = (
    ("frombase64string",),
    ("-encodedcommand",),
    ("-enc ",),
    ("downloadstring",),
    ("downloadfile",),
    ("net.webclient",),
    ("iex(",),
    ("iex (",),
    ("invoke-expression",),
    ("start-bitstransfer",),
)
_SUSPICIOUS_CMDLINE_COMBO = (
    ("certutil", "-decode"),
    ("certutil", "-urlcache"),
    ("bitsadmin", "/transfer"),
    ("invoke-webrequest", "-outfile"),
)
_STEALTH_FLAG_A = ("-nop", "-noprofile")
_STEALTH_FLAG_B = ("-w hidden", "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass")


def rule_suspicious_process_command_line(events) -> list[RuleHit]:
    hits = []
    for event in events:
        if not _is_process_event(event):
            continue
        cmd = _command_line(event)
        if not cmd:
            continue
        matched = None
        for needles in _SUSPICIOUS_CMDLINE_SINGLE + _SUSPICIOUS_CMDLINE_COMBO:
            if _contains_all(cmd, needles):
                matched = " ".join(needles).strip()
                break
        if matched is None and any(a in cmd for a in _STEALTH_FLAG_A) and any(
            b in cmd for b in _STEALTH_FLAG_B
        ):
            matched = "hidden/no-profile execution flags"
        if matched:
            hits.append(
                RuleHit(
                    rule="suspicious_process_command_line",
                    reason=(
                        f"process-creation command line for "
                        f"{_basename(_data(event).get('new_process_name', '')) or 'a process'} "
                        f"contains {matched!r}"
                    ),
                    event_ids=(event.id,),
                    at=event.occurred_at,
                )
            )
    return hits


_DEFENSE_EVASION_COMBOS = (
    (("vssadmin", "delete", "shadow"), "shadow-copy deletion (vssadmin)"),
    (("wmic", "shadowcopy", "delete"), "shadow-copy deletion (wmic)"),
    (("wevtutil", "cl "), "event-log clearing (wevtutil cl)"),
    (("wevtutil", "clear-log"), "event-log clearing (wevtutil clear-log)"),
    (("add-mppreference", "exclusion"), "Defender exclusion added"),
    (("set-mppreference", "-disable"), "Defender protection disabled"),
    (("net ", "user ", "/add"), "local user account created (net user /add)"),
    (("net ", "localgroup", "administrators", "/add"), "account added to local Administrators"),
    (("reg ", " add ", "\\run"), "Run-key persistence (reg add)"),
    (("schtasks", "/create"), "scheduled task created (schtasks /create)"),
    (("bcdedit", "recoveryenabled"), "recovery disabled (bcdedit)"),
)


def rule_defense_evasion_command(events) -> list[RuleHit]:
    hits = []
    for event in events:
        if not _is_process_event(event):
            continue
        cmd = _command_line(event)
        if not cmd:
            continue
        for needles, label in _DEFENSE_EVASION_COMBOS:
            if _contains_all(cmd, needles):
                hits.append(
                    RuleHit(
                        rule="defense_evasion_command",
                        reason=f"defense-evasion command: {label}",
                        event_ids=(event.id,),
                        at=event.occurred_at,
                    )
                )
                break
    return hits


def rule_lolbin_burst(events) -> list[RuleHit]:
    lolbin_events = [
        event
        for event in events
        if _is_process_event(event)
        and _basename(_data(event).get("new_process_name", "")) in _LOLBINS
    ]
    hits = []
    for i, anchor in enumerate(lolbin_events):
        window = [
            event
            for event in lolbin_events[i:]
            if event.occurred_at - anchor.occurred_at <= LOLBIN_BURST_WINDOW
        ]
        if len(window) >= LOLBIN_BURST_THRESHOLD:
            names = sorted({_basename(_data(e).get("new_process_name", "")) for e in window})
            hits.append(
                RuleHit(
                    rule="lolbin_burst",
                    reason=(
                        f"{len(window)} dual-use utility launches within "
                        f"{int(LOLBIN_BURST_WINDOW.total_seconds() // 60)} min ({', '.join(names)})"
                    ),
                    event_ids=tuple(e.id for e in window),
                    at=anchor.occurred_at,
                )
            )
            break  # one burst hit per endpoint per scan is enough
    return hits


def rule_office_spawns_shell(events) -> list[RuleHit]:
    hits = []
    for event in events:
        if not _is_process_event(event):
            continue
        data = _data(event)
        parent = _basename(data.get("parent_process_name", ""))
        child = _basename(data.get("new_process_name", ""))
        if parent in _OFFICE_PARENTS and child in _SHELL_CHILDREN:
            hits.append(
                RuleHit(
                    rule="office_spawns_shell",
                    reason=f"{parent} spawned {child}",
                    event_ids=(event.id,),
                    at=event.occurred_at,
                )
            )
    return hits


_SCRIPT_BLOCK_INDICATORS = (
    "frombase64string", "[system.convert]::frombase64",
    "invoke-expression", "iex ", "iex(", "iex (",
    "net.webclient", "downloadstring", "downloadfile", "invoke-webrequest",
    "start-bitstransfer",
    "reflection.assembly", "[reflection.assembly]",
    "virtualalloc", "writeprocessmemory", "createremotethread",
    "[runtime.interopservices.marshal]",
    "amsiutils", "amsiinitfailed", "amsicontext",
    "invoke-mimikatz", "sekurlsa", "-membertype win32",
    "system.management.automation.amsi",
)


def rule_suspicious_script_block(events) -> list[RuleHit]:
    hits = []
    for event in events:
        if not _is_script_block_event(event):
            continue
        text = _script_text(event)
        if not text:
            continue
        matched = next((ind for ind in _SCRIPT_BLOCK_INDICATORS if ind in text), None)
        if matched:
            hits.append(
                RuleHit(
                    rule="suspicious_script_block",
                    reason=f"PowerShell script block contains {matched!r}",
                    event_ids=(event.id,),
                    at=event.occurred_at,
                )
            )
    return hits


def rule_script_block_burst(events) -> list[RuleHit]:
    sb_events = [event for event in events if _is_script_block_event(event)]
    for i, anchor in enumerate(sb_events):
        window = [
            event
            for event in sb_events[i:]
            if event.occurred_at - anchor.occurred_at <= SCRIPT_BLOCK_BURST_WINDOW
        ]
        if len(window) >= SCRIPT_BLOCK_BURST_THRESHOLD:
            return [
                RuleHit(
                    rule="script_block_burst",
                    reason=(
                        f"{len(window)} PowerShell script blocks within "
                        f"{int(SCRIPT_BLOCK_BURST_WINDOW.total_seconds() // 60)} min"
                    ),
                    event_ids=tuple(e.id for e in window),
                    at=anchor.occurred_at,
                )
            ]
    return []


_RULES = (
    rule_suspicious_process_command_line,
    rule_defense_evasion_command,
    rule_lolbin_burst,
    rule_office_spawns_shell,
    rule_suspicious_script_block,
    rule_script_block_burst,
)


# --- orchestration ----------------------------------------------------

def _cluster_hits_by_time(hits: list[RuleHit]) -> list[list[RuleHit]]:
    ordered = sorted(hits, key=lambda h: h.at)
    clusters: list[list[RuleHit]] = []
    current: list[RuleHit] = []
    for hit in ordered:
        if current and (hit.at - current[-1].at) > CLUSTER_GAP:
            clusters.append(current)
            current = []
        current.append(hit)
    if current:
        clusters.append(current)
    return clusters


def _format_trigger_summary(hits: list[RuleHit]) -> str:
    by_rule: dict[str, list[str]] = defaultdict(list)
    for hit in hits:
        by_rule[hit.rule].append(hit.reason)
    lines = []
    for rule, reasons in by_rule.items():
        unique = list(dict.fromkeys(reasons))
        shown = "; ".join(unique[:5])
        if len(unique) > 5:
            shown += f"; (+{len(unique) - 5} more)"
        lines.append(f"{rule}: {shown}")
    return "\n".join(lines)


def find_correlation_candidates(
    *, now=None, max_events_per_scan: int = MAX_EVENTS_PER_SCAN
) -> ScanResult:
    now = now or timezone.now()
    base_qs = (
        EndpointEvent.objects.filter(correlation_scanned_at__isnull=True)
        .select_related("endpoint", "endpoint__organization", "organization")
        .order_by("endpoint_id", "occurred_at", "id")
    )
    events = list(base_qs[:max_events_per_scan])
    result = ScanResult(overflowed=len(events) == max_events_per_scan and base_qs.count() > max_events_per_scan)

    by_endpoint: dict[int, list] = defaultdict(list)
    for event in events:
        by_endpoint[event.endpoint_id].append(event)

    for endpoint_events in by_endpoint.values():
        result.scanned_event_ids.update(event.id for event in endpoint_events)

        hits: list[RuleHit] = []
        for rule in _RULES:
            hits.extend(rule(endpoint_events))
        if not hits:
            continue

        endpoint = endpoint_events[0].endpoint
        by_id = {event.id: event for event in endpoint_events}
        for cluster_hits in _cluster_hits_by_time(hits):
            start = min(h.at for h in cluster_hits) - CLUSTER_PADDING
            end = max(h.at for h in cluster_hits) + CLUSTER_PADDING
            triggering_ids = {eid for hit in cluster_hits for eid in hit.event_ids}

            cluster_events = [
                event
                for event in endpoint_events
                if start <= event.occurred_at <= end or event.id in triggering_ids
            ]
            cluster_events.sort(key=lambda event: (event.occurred_at, event.id))

            result.candidates.append(
                CandidateSpec(
                    endpoint=endpoint,
                    organization=endpoint.organization,
                    events=cluster_events,
                    trigger_summary=_format_trigger_summary(cluster_hits),
                )
            )

    return result
