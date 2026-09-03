"""Risk Advisor agent: gathers a single gap/risk pair's real detail
(apps/ai_core/services/risk_context.py), sends it to the configured AI
provider, and returns a structured, display-ready narration explaining
why it matters, what evidence supports it, and what to do about it.
Also handles on-demand follow-up questions about that same gap/risk pair
(run_risk_question), mirroring run_incident_question in analyst.py.

Same real, callable pattern as apps/ai_core/modules/analyst.py, writer.py,
and readiness_advisor.py -- the only thing standing between this and a
live response is ANTHROPIC_API_KEY being configured -- see
apps/ai_core/providers/anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.risk_context import build_risk_context
from apps.risk.models import GapFinding

RISK_ADVISOR_SYSTEM_PREAMBLE = (
    "You are a security risk advisor explaining a specific control gap and its "
    "risk assessment to a small business's security team. Using only the context "
    "provided below, explain in plain language: why this gap matters, what "
    "evidence supports it, and what to actually do about it first. Do not invent "
    "details that are not present in the context."
)

RISK_QA_SYSTEM_PREAMBLE = (
    "You are a security risk advisor answering a follow-up question about a "
    "specific control gap and its risk assessment for a small business's "
    "security team. Using only the context provided below, answer the "
    "question. If the evidence in the context does not support a confident "
    "answer, say so plainly instead of guessing -- do not invent details that "
    "are not present in the context."
)


def run_risk_narration(gap: GapFinding, *, provider=None) -> dict:
    """Gather context for `gap` (and its paired risk assessment, if any),
    send it to the AI provider, and return a structured result ready to
    display.

    Same provider contract and error behavior as run_incident_analysis
    in apps/ai_core/modules/analyst.py.
    """
    provider = provider or AnthropicProvider()

    context = build_risk_context(gap)
    prompt = f"{RISK_ADVISOR_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=gap.organization)

    return {
        "gap_id": gap.id,
        "model": provider.model,
        "narration": response_text.strip(),
        "generated_at": timezone.now(),
    }


def run_risk_question(gap: GapFinding, question: str, *, provider=None) -> dict:
    """Gather context for `gap` (same as run_risk_narration), append
    `question`, send it to the AI provider, and return a structured
    result ready to display.

    Mirrors run_incident_question in apps/ai_core/modules/analyst.py
    exactly, scoped to GapFinding the same way run_risk_narration is.
    """
    provider = provider or AnthropicProvider()

    context = build_risk_context(gap)
    prompt = f"{RISK_QA_SYSTEM_PREAMBLE}\n\n{context}\n\n## Question\n{question}"

    response_text = provider.send_message(prompt, organization=gap.organization)

    return {
        "gap_id": gap.id,
        "model": provider.model,
        "question": question,
        "answer": response_text.strip(),
        "generated_at": timezone.now(),
    }
