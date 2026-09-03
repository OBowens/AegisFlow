"""Prioritizer agent: gathers an organization's real open incidents and
their paired risk assessments, capped and ranked
(apps/ai_core/services/priority_context.py), sends that to the
configured AI provider, and returns a structured, display-ready ranked
briefing of what to fix first and why.

Same real, callable pattern as apps/ai_core/modules/analyst.py,
risk_advisor.py, and readiness_advisor.py -- the only thing standing
between this and a live response is ANTHROPIC_API_KEY being configured
-- see apps/ai_core/providers/anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.priority_context import build_priority_context
from apps.organizations.models import Organization

PRIORITIZER_SYSTEM_PREAMBLE = (
    "You are a security triage advisor helping a small business's security team "
    "decide what to work on next. Using only the context provided below, produce "
    "a short ranked list (most urgent first) of what to fix first, and for each "
    "item briefly explain why -- citing the real severity, risk score, and age "
    "given in the context. If the list below is a capped view of a larger total, "
    "say so plainly rather than implying it's the complete picture. Do not invent "
    "details that are not present in the context."
)


def run_priority_briefing(organization: Organization, *, provider=None) -> dict:
    """Gather open-incident/risk context for `organization`, send it to
    the AI provider, and return a structured result ready to display.

    Same provider contract and error behavior as run_incident_analysis
    in apps/ai_core/modules/analyst.py.
    """
    provider = provider or AnthropicProvider()

    context = build_priority_context(organization)
    prompt = f"{PRIORITIZER_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=organization)

    return {
        "organization_id": organization.id,
        "model": provider.model,
        "briefing": response_text.strip(),
        "generated_at": timezone.now(),
    }
