"""Readiness Advisor agent: gathers the organization's real readiness
score, per-domain status, and active contradictions
(apps/ai_core/services/readiness_context.py), sends it to the configured
AI provider, and returns a structured, display-ready explanation.

Also handles on-demand follow-up questions about that same organization's
readiness (run_readiness_question), mirroring run_risk_question in
risk_advisor.py and run_incident_question in analyst.py.

Same real, callable pattern as apps/ai_core/modules/analyst.py and
writer.py -- the only thing standing between this and a live response is
ANTHROPIC_API_KEY being configured -- see apps/ai_core/providers/
anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.readiness_context import build_readiness_context
from apps.organizations.models import Organization

READINESS_ADVISOR_SYSTEM_PREAMBLE = (
    "You are a disaster-readiness advisor explaining a preparedness score to a "
    "non-technical small-business owner. Using only the context provided below, "
    "explain in plain language: why the score is what it is, which domains are "
    "dragging it down and why, and what to prioritize first. Do not invent "
    "details that are not present in the context."
)

READINESS_QA_SYSTEM_PREAMBLE = (
    "You are a disaster-readiness advisor answering a follow-up question about "
    "an organization's overall preparedness for a non-technical small-business "
    "owner. Using only the context provided below, answer the question. If the "
    "evidence in the context does not support a confident answer, say so "
    "plainly instead of guessing -- do not invent details that are not present "
    "in the context."
)


def run_readiness_explanation(organization: Organization, *, provider=None) -> dict:
    """Gather readiness context for `organization`, send it to the AI
    provider, and return a structured result ready to display.

    Same provider contract and error behavior as run_incident_analysis
    in apps/ai_core/modules/analyst.py: `provider` defaults to a real
    AnthropicProvider(), and RuntimeError (e.g. missing API key)
    propagates uncaught so a caller displaying the result knows the
    explanation wasn't actually generated.
    """
    provider = provider or AnthropicProvider()

    context = build_readiness_context(organization)
    prompt = f"{READINESS_ADVISOR_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=organization)

    return {
        "organization_id": organization.id,
        "model": provider.model,
        "explanation": response_text.strip(),
        "generated_at": timezone.now(),
    }


def run_readiness_question(organization: Organization, question: str, *, provider=None) -> dict:
    """Gather readiness context for `organization` (same as
    run_readiness_explanation), append `question`, send it to the AI
    provider, and return a structured result ready to display.

    Mirrors run_risk_question in risk_advisor.py exactly, scoped to
    Organization the same way run_readiness_explanation is.
    """
    provider = provider or AnthropicProvider()

    context = build_readiness_context(organization)
    prompt = f"{READINESS_QA_SYSTEM_PREAMBLE}\n\n{context}\n\n## Question\n{question}"

    response_text = provider.send_message(prompt, organization=organization)

    return {
        "organization_id": organization.id,
        "model": provider.model,
        "question": question,
        "answer": response_text.strip(),
        "generated_at": timezone.now(),
    }
