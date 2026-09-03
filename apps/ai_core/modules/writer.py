"""Writer agent: gathers the same full incident context the Analyst agent
uses (evidence, gap/risk findings, matching SOP, etc -- see
apps/ai_core/services/analyst_context.py), asks Claude to write specific,
incident-grounded response steps, and runs every generated step through
the deterministic approval gate (apps/playbooks/services/approval_gate.py)
before returning.

This replaces the fixed, incident-agnostic 6-step list every playbook
otherwise gets (apps/playbooks/services/generator.py::_ensure_playbook_steps)
with steps actually written for this incident's specific evidence -- and,
when a matching SOP exists, grounded in its real content instead of
generic advice.

Also handles the standalone, no-incident case (a free-typed scenario
description, e.g. "Ask for Custom Playbook" on the Response Playbook
page): pass `scenario_text` instead of `incident` and the same
generation/parsing/approval-gate pipeline runs unchanged, just gathering
context from apps.ai_core.services.custom_playbook_context instead of
apps.ai_core.services.analyst_context. One shared pipeline rather than a
second near-identical function, since only the context-gathering step
actually differs between the two cases.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.ai_core.services.custom_playbook_context import build_custom_scenario_context
from apps.incidents.models import IncidentGroup
from apps.playbooks.services.approval_gate import requires_human_approval
from apps.playbooks.services.text_parsing import parse_action_text, unique_items

WRITER_SYSTEM_PREAMBLE = (
    "You are a security response playbook writer for a small business's security "
    "team. Using only the context provided below, write specific, actionable "
    "response steps for this exact incident or scenario -- grounded in the real "
    "evidence or details given, not generic advice. If a matching SOP or "
    "checklist is included in the context, base your steps on its real content "
    "(reference its specific actions) rather than inventing generic guidance "
    "when real guidance is already available. Do not invent details that are "
    "not present in the context.\n\n"
    "Respond with ONLY the steps, one per line, as a numbered list (1. ..., "
    "2. ...), 4 to 8 steps, each one specific imperative sentence. No preamble, "
    "no headings, no commentary -- numbered steps only."
)


def run_playbook_generation(
    incident: IncidentGroup | None = None,
    *,
    scenario_text: str | None = None,
    organization=None,
    provider=None,
) -> dict:
    """Gather context for either `incident` or a free-typed
    `scenario_text` (exactly one must be given), ask the AI provider to
    write response steps, and return a structured result ready to
    display and persist.

    `organization` is only used (and only meaningful) with
    `scenario_text` -- it scopes the critical-system lookup in
    build_custom_scenario_context to that organization's own registry.

    Each returned step is run through requires_human_approval() so
    callers don't need to re-derive that themselves -- this applies the
    same way regardless of which context path produced the steps.

    Same provider contract and error behavior as run_incident_analysis /
    run_incident_question in apps/ai_core/modules/analyst.py.
    """
    if incident is not None and scenario_text:
        raise ValueError("run_playbook_generation takes either incident or scenario_text, not both.")
    if incident is None and not scenario_text:
        raise ValueError("run_playbook_generation requires either incident or a non-empty scenario_text.")

    provider = provider or AnthropicProvider()

    if incident is not None:
        context = build_incident_context(incident)
        prompt_organization = incident.organization
    else:
        context = build_custom_scenario_context(scenario_text, organization=organization)
        prompt_organization = organization

    prompt = f"{WRITER_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=prompt_organization)
    step_texts = unique_items(parse_action_text(response_text))

    return {
        "incident_id": incident.id if incident is not None else None,
        "model": provider.model,
        "steps": [
            {"action": step_text, "requires_approval": requires_human_approval(step_text)}
            for step_text in step_texts
        ],
        "generated_at": timezone.now(),
    }
