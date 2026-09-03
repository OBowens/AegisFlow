"""Parser for plain-text backup job reports (multi-line stanzas per job).

SYNTHETIC FIXTURE DATA: this module was built and tested exclusively against
apps/log_intake/fixtures/backup_report_60_lines.log, a hand-authored
synthetic sample -- NOT a real backup system export. Field names and value
ranges below reflect that fixture only.

STATUS: Synthetic Fixture Passed / Real Sample Validation Pending

Format: one stanza per backup job, separated by a line of dashes. Each
stanza has job-level `Key: value` fields (Job Name, Server, Start Time,
End Time, Status), followed by one or more repeated VM-level blocks (VM
Name, Result, Backup Size, and an optional Message or Error line).
`_parse_stanzas` is a small line-by-line state machine that reads that
shape directly -- there's no JSON/CSV structure to lean on here, so the
job/VM boundaries are inferred from which keys appear (a second
"VM Name:" line means a new VM block started; a dashed line closes the
job).

THE CENTRAL JUDGMENT CALL -- job Status vs. VM Result can disagree:

Reading the real fixture turned up three distinct disagreement shapes
across its 8 jobs, not just one:

1. Job Status says WARNING/FAILED and a VM Result explains it (e.g. job 6:
   Status=FAILED, and VM APP01 within it has Result=FAILED with an Error
   line). Unsurprising -- the job-level status is just propagating the
   worst VM result.
2. Job Status says WARNING but *every* VM in that job has Result=SUCCESS
   (jobs 1 and 3 in the fixture). The job-level rollup is flagging
   something that isn't attributable to any individual VM at all.
3. Job Status says WARNING but a VM within it has Result=FAILED (job 8:
   Status=WARNING, yet VM FILE01 has Result=FAILED with a real Error
   message, "Permission denied writing backup archive."). Here the
   job-level status *under-states* the worst thing that actually
   happened.

Collapsing to job-level Status alone would silently lose case 3 entirely --
a real per-VM failure hiding behind a merely-WARNING job. Collapsing to
VM-level Result alone would lose case 2 -- a job-level problem with no
VM to pin it on. So this parser does not collapse either way:

- One event is emitted per VM Result (the primary, most granular signal --
  severity_hint is driven by that VM's own Result, never by the job's
  Status). If the job's Status disagrees with this specific VM's Result,
  that's noted directly in the VM event's normalized_summary text (see
  case 3) so the disagreement is visible without needing a second event.
- An additional, separate event is emitted only for case 2: when the
  job's Status is *worse* than every VM Result in that job (nothing
  explains it). That event is tagged `backup_job_..._unexplained`,
  scoped to the job's Server rather than any one VM, and given a lower
  confidence_score (0.65 vs. 0.92) than the VM-level events, since it
  represents the parser flagging a reporting gap rather than relaying a
  directly reported fact.

Severity mapping (SUCCESS -> low, WARNING -> medium, FAILED -> high) keeps
"critical" reserved for active compromise-type findings elsewhere in this
pipeline (malware, critical IPS hits) rather than routine ops failures --
consistent with how the pre-existing generic fallback parser already
classified "backup failed" as a HIGH_TERMS phrase, not a critical one.

account is always "" and destination_ip is always None: there is no user
identity or network destination concept in a backup job report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ParsedBackupEvent:
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
    source_tool: str = "backup"


_STATUS_RANK = {"success": 0, "warning": 1, "failed": 2}
_STATUS_SEVERITY = {"success": "low", "warning": "medium", "failed": "high"}


@dataclass
class _JobStanza:
    job_name: str = ""
    server: str = ""
    start_time: str = ""
    end_time: str = ""
    status: str = ""
    vms: list[dict] = field(default_factory=list)


def parse_backup_report_log(
    raw_text: str, *, source_tool: str = "backup"
) -> list[ParsedBackupEvent]:
    """Parse a multi-line backup job report into one event per VM result,
    plus one extra event per job whose overall Status isn't explained by
    any individual VM Result (see module docstring, case 2)."""

    events: list[ParsedBackupEvent] = []
    for stanza in _parse_stanzas(raw_text):
        events.extend(_to_events(stanza, source_tool))

    return events


def _parse_stanzas(raw_text: str) -> list[_JobStanza]:
    stanzas: list[_JobStanza] = []
    job = _JobStanza()
    current_vm: dict | None = None

    def flush_vm():
        nonlocal current_vm
        if current_vm is not None and current_vm.get("name"):
            job.vms.append(current_vm)
        current_vm = None

    def flush_job():
        nonlocal job
        flush_vm()
        if job.job_name:
            stanzas.append(job)
        job = _JobStanza()

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if set(line) <= {"-"} and len(line) >= 5:
            flush_job()
            continue

        if set(line) <= {"="} and len(line) >= 5:
            continue

        if ": " not in line:
            continue

        key, value = line.split(": ", 1)
        key = key.strip()
        value = value.strip()

        if key == "Job Name":
            job.job_name = value
        elif key == "Server":
            job.server = value
        elif key == "Start Time":
            job.start_time = value
        elif key == "End Time":
            job.end_time = value
        elif key == "Status":
            job.status = value
        elif key == "VM Name":
            flush_vm()
            current_vm = {"name": value}
        elif key == "Result" and current_vm is not None:
            current_vm["result"] = value
        elif key == "Backup Size" and current_vm is not None:
            current_vm["size"] = value
        elif key == "Message" and current_vm is not None:
            current_vm["message"] = value
        elif key == "Error" and current_vm is not None:
            current_vm["error"] = value

    flush_job()
    return stanzas


def _to_events(stanza: _JobStanza, source_tool: str) -> list[ParsedBackupEvent]:
    events: list[ParsedBackupEvent] = []
    timestamp = _parse_timestamp(stanza.end_time)
    job_status_key = stanza.status.strip().lower()

    worst_vm_rank = -1
    for vm in stanza.vms:
        result_key = vm.get("result", "").strip().lower()
        worst_vm_rank = max(worst_vm_rank, _STATUS_RANK.get(result_key, 0))

        detail = vm.get("error") or vm.get("message") or ""
        summary = (
            f"Backup of {vm.get('name', 'unknown VM')} on {stanza.server or 'unknown server'} "
            f"({stanza.job_name or 'unknown job'}) -- {vm.get('result', 'UNKNOWN')}"
        )
        if vm.get("size"):
            summary += f" ({vm['size']})"
        if detail:
            summary += f": {detail}"
        if job_status_key and job_status_key != result_key:
            summary += f" (job reported {stanza.status} overall)"

        events.append(
            ParsedBackupEvent(
                timestamp=timestamp,
                affected_system=vm.get("name", "Unknown system"),
                account="",
                source_ip=None,
                destination_ip=None,
                event_type=f"backup_{result_key or 'unknown'}",
                severity_hint=_STATUS_SEVERITY.get(result_key, "unknown"),
                raw_message=_render_vm_raw_message(stanza, vm),
                normalized_summary=summary[:255],
                confidence_score=0.92,
                source_tool=source_tool,
            )
        )

    job_status_rank = _STATUS_RANK.get(job_status_key, 0)
    if stanza.vms and job_status_rank > worst_vm_rank:
        events.append(
            ParsedBackupEvent(
                timestamp=timestamp,
                affected_system=stanza.server or "Unknown system",
                account="",
                source_ip=None,
                destination_ip=None,
                event_type=f"backup_job_{job_status_key or 'unknown'}_unexplained",
                severity_hint=_STATUS_SEVERITY.get(job_status_key, "unknown"),
                raw_message=_render_job_raw_message(stanza),
                normalized_summary=(
                    f"Job {stanza.job_name or 'unknown job'} on {stanza.server or 'unknown server'} "
                    f"reported overall status {stanza.status}, but no individual VM result "
                    f"explains it (worst VM result was "
                    f"{'SUCCESS' if worst_vm_rank <= 0 else 'WARNING'})."
                )[:255],
                confidence_score=0.65,
                source_tool=source_tool,
            )
        )

    return events


def _render_vm_raw_message(stanza: _JobStanza, vm: dict) -> str:
    parts = [
        f"Job Name: {stanza.job_name}",
        f"Server: {stanza.server}",
        f"Status: {stanza.status}",
        f"VM Name: {vm.get('name', '')}",
        f"Result: {vm.get('result', '')}",
    ]
    if vm.get("size"):
        parts.append(f"Backup Size: {vm['size']}")
    if vm.get("message"):
        parts.append(f"Message: {vm['message']}")
    if vm.get("error"):
        parts.append(f"Error: {vm['error']}")
    return ", ".join(parts)


def _render_job_raw_message(stanza: _JobStanza) -> str:
    return (
        f"Job Name: {stanza.job_name}, Server: {stanza.server}, "
        f"Status: {stanza.status}, VM count: {len(stanza.vms)}"
    )


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
