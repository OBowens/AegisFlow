"""Context-gathering for the Endpoint Triage agent: given one
``EndpointCorrelationCandidate``, lay out the flagged event cluster --
the deterministic reason it was flagged, the process-creation and
PowerShell script-block events themselves, and a rough baseline for how
much activity this endpoint normally produces -- as one plain-text
prompt section.

No AI provider is called here; this only builds the prompt string. See
apps/ai_core/modules/endpoint_triage.py for the piece that sends it and
parses the verdict. Real hostnames / usernames / paths in the text are
pseudonymized by apps/ai_core/sanitizer.py inside
AnthropicProvider.send_message(), same as every other module.
"""

from __future__ import annotations

from datetime import timedelta

from apps.endpoints.models import EndpointEvent

# Caps, in the same spirit as analyst_context.MAX_EVIDENCE_ITEMS: keep the
# prompt bounded even when a burst is large.
MAX_PROCESS_EVENTS = 40
MAX_SCRIPT_BLOCKS = 25
MAX_SCRIPT_BLOCK_CHARS = 2000

_PROCESS_EVENT_TYPE = "Security/4688"
_SCRIPT_BLOCK_EVENT_TYPE = "Microsoft-Windows-PowerShell/4104"


def build_endpoint_triage_context(candidate) -> str:
    sections = [
        _overview_section(candidate),
        _trigger_section(candidate),
        _process_events_section(candidate),
        _script_blocks_section(candidate),
        _baseline_section(candidate),
    ]
    return "\n\n".join(section for section in sections if section)


def _data(event) -> dict:
    payload = event.payload or {}
    data = payload.get("data")
    return data if isinstance(data, dict) else {}


def _computer(event) -> str:
    return (event.payload or {}).get("computer", "") or ""


def _overview_section(candidate) -> str:
    endpoint = candidate.endpoint
    lines = [
        "## Endpoint",
        f"Name: {endpoint.display_name}",
        f"Organization: {candidate.organization.name}",
        f"Endpoint last check-in: {endpoint.last_seen or 'Unknown'}",
        f"Flagged event window: {candidate.first_event_at} to {candidate.last_event_at}",
        f"Events in this cluster: {candidate.event_count}",
    ]
    return "\n".join(lines)


def _trigger_section(candidate) -> str:
    return (
        "## Why This Was Flagged\n"
        "These are the deterministic local correlation rules that fired -- "
        "not a judgement of severity, just what matched:\n"
        f"{candidate.trigger_summary}"
    )


def _sorted_events(candidate):
    return sorted(candidate.events.all(), key=lambda e: (e.occurred_at, e.id))


def _process_events_section(candidate) -> str:
    events = [e for e in _sorted_events(candidate) if e.event_type == _PROCESS_EVENT_TYPE]
    if not events:
        return "## Process-Creation Events (4688)\nNone in this cluster."

    lines = [
        "## Process-Creation Events (4688)",
        f"{len(events)} process-creation event(s):",
    ]
    for event in events[:MAX_PROCESS_EVENTS]:
        data = _data(event)
        bits = [f"[{event.occurred_at}]"]
        if _computer(event):
            bits.append(f"host={_computer(event)}")
        if data.get("subject_user_name"):
            bits.append(f"user={data['subject_user_name']}")
        bits.append(f"image={data.get('new_process_name') or '(unknown)'}")
        if data.get("parent_process_name"):
            bits.append(f"parent={data['parent_process_name']}")
        line = "- " + " ".join(bits)
        if data.get("command_line"):
            line += f"\n    cmdline: {data['command_line']}"
        lines.append(line)

    remaining = len(events) - MAX_PROCESS_EVENTS
    if remaining > 0:
        lines.append(f"...and {remaining} more process-creation event(s) not shown.")
    return "\n".join(lines)


def _script_blocks_section(candidate) -> str:
    events = [e for e in _sorted_events(candidate) if e.event_type == _SCRIPT_BLOCK_EVENT_TYPE]
    if not events:
        return "## PowerShell Script Blocks (4104)\nNone in this cluster."

    lines = [
        "## PowerShell Script Blocks (4104)",
        f"{len(events)} script-block event(s):",
    ]
    for event in events[:MAX_SCRIPT_BLOCKS]:
        data = _data(event)
        header_bits = [f"[{event.occurred_at}]"]
        if _computer(event):
            header_bits.append(f"host={_computer(event)}")
        if data.get("path"):
            header_bits.append(f"path={data['path']}")
        text = (data.get("script_block_text") or "").strip()
        if len(text) > MAX_SCRIPT_BLOCK_CHARS:
            text = text[:MAX_SCRIPT_BLOCK_CHARS] + f"... [truncated, {len(text)} chars total]"
        lines.append("- " + " ".join(header_bits))
        lines.append(f"    {text or '(empty)'}")

    remaining = len(events) - MAX_SCRIPT_BLOCKS
    if remaining > 0:
        lines.append(f"...and {remaining} more script-block event(s) not shown.")
    return "\n".join(lines)


def _baseline_section(candidate) -> str:
    """A rough sense of whether this cluster is a spike: how many events
    this endpoint produced in the equal-length window immediately before
    the flagged one.
    """
    span = candidate.last_event_at - candidate.first_event_at
    if span < timedelta(minutes=1):
        span = timedelta(minutes=1)
    prior_start = candidate.first_event_at - span
    prior_count = EndpointEvent.objects.filter(
        endpoint=candidate.endpoint,
        occurred_at__gte=prior_start,
        occurred_at__lt=candidate.first_event_at,
    ).count()

    minutes = max(int(span.total_seconds() // 60), 1)
    return (
        "## Baseline\n"
        f"This cluster spans about {minutes} minute(s) and contains "
        f"{candidate.event_count} event(s). In the {minutes} minute(s) immediately "
        f"before it, this endpoint produced {prior_count} event(s) that reached the "
        f"platform (i.e. that survived the agent's local noise filtering)."
    )
