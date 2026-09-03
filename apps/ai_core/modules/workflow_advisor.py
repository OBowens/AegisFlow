"""Workflow Advisor agent: recommends a concrete "do this next" step for
the current stage of the guided Understand/Verify/Respond/Resolve
workflow, and answers on-demand "how do I do this" follow-up questions
scoped to that specific recommended step.

Reuses the exact same context-gathering pipeline as the Analyst agent
(apps/ai_core/services/analyst_context.py::build_incident_context) --
evidence, gap/risk findings, human-recorded verification results, and
guidance already given at earlier stages are all already assembled
there, so this module adds no new context pipeline, only a "which stage"
framing on top of it.

Same real, callable pattern as apps/ai_core/modules/analyst.py,
risk_advisor.py, and readiness_advisor.py -- the only thing standing
between this and a live response is ANTHROPIC_API_KEY being configured
-- see apps/ai_core/providers/anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentGroup

# The grounding rule every AI feature in this app follows ("do not invent
# details that are not present in the context"), extended here with the
# workflow-specific requirement that guidance never gets to assert
# something happened just because it would be convenient for the next
# step -- it must stay phrased as an action to take or check, and be
# explicit about what verification has and has not actually confirmed.
WORKFLOW_GROUNDING_RULE = (
    "Phrase your recommendation as an action to take or check (for example "
    "'Check whether...', 'Confirm...', 'Review...'), never as an assertion "
    "of fact about what has happened. Be explicit about what verification "
    "has and has not actually confirmed so far -- do not imply something "
    "is true just because it would be convenient for the next step. Do not "
    "invent details that are not present in the context."
)

WORKFLOW_NEXT_STEP_SYSTEM_PREAMBLE = (
    "You are a security workflow guide helping an analyst move through a "
    "structured incident response process (Understand, Verify, Respond, "
    "Resolve) for a small business's security team. Using only the "
    "context provided below -- including any guidance already given at "
    "earlier stages -- tell the analyst the single most useful, concrete "
    "next action for the CURRENT stage named below. " + WORKFLOW_GROUNDING_RULE
)

WORKFLOW_STEP_QA_SYSTEM_PREAMBLE = (
    "You are a security workflow guide answering a follow-up question "
    "about how to carry out a specific recommended step in a structured "
    "incident response process, for a small business's security team. "
    "Using only the context provided below -- including the current "
    "recommended step -- answer the question. " + WORKFLOW_GROUNDING_RULE +
    " If the evidence in the context does not support a confident answer, "
    "say so plainly instead of guessing."
)


def _stage_label(stage: str) -> str:
    return stage.title()


def run_workflow_next_step(incident: IncidentGroup, stage: str, *, provider=None) -> dict:
    """Gather context for `incident` (including guidance already given at
    earlier stages), send it to the AI provider framed for `stage`, and
    return a structured result ready to display.

    Same provider contract and error behavior as run_incident_analysis in
    apps/ai_core/modules/analyst.py.
    """
    provider = provider or AnthropicProvider()

    context = build_incident_context(incident)
    prompt = (
        f"{WORKFLOW_NEXT_STEP_SYSTEM_PREAMBLE}\n\n{context}\n\n"
        f"## Current Stage\n{_stage_label(stage)}"
    )

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "stage": stage,
        "model": provider.model,
        "next_step": response_text.strip(),
        "generated_at": timezone.now(),
    }


def run_workflow_step_question(
    incident: IncidentGroup, stage: str, step_text: str, question: str, *, provider=None
) -> dict:
    """Gather context for `incident` (same as run_workflow_next_step),
    append the current recommended step and `question`, send it to the AI
    provider, and return a structured result ready to display.

    Mirrors run_incident_question in analyst.py, scoped to the specific
    recommended step for `stage` rather than the whole incident.
    """
    provider = provider or AnthropicProvider()

    context = build_incident_context(incident)
    prompt = (
        f"{WORKFLOW_STEP_QA_SYSTEM_PREAMBLE}\n\n{context}\n\n"
        f"## Current Stage\n{_stage_label(stage)}\n\n"
        f"## Current Recommended Step\n{step_text}\n\n"
        f"## Question\n{question}"
    )

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "stage": stage,
        "model": provider.model,
        "question": question,
        "answer": response_text.strip(),
        "generated_at": timezone.now(),
    }
