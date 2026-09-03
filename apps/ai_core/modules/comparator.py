"""Incident Comparator agent: gathers two incidents' full real context
plus a precomputed shared-data-points summary
(apps/ai_core/services/comparison_context.py), sends it to the
configured AI provider, and returns a structured comparison: shared
patterns, genuine differences, and an explicit, evidence-bounded read on
whether the two incidents are likely related or coincidental.

Same real, callable pattern as apps/ai_core/modules/analyst.py,
risk_advisor.py, readiness_advisor.py, and prioritizer.py -- the only
thing standing between this and a live response is ANTHROPIC_API_KEY
being configured -- see apps/ai_core/providers/anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.comparison_context import build_comparison_context
from apps.incidents.models import IncidentGroup

COMPARATOR_SYSTEM_PREAMBLE = (
    "You are a security analyst assistant comparing two incidents for a small "
    "business's security team. Using only the context provided below, identify: "
    "shared patterns (timing, affected systems, accounts, source IPs), genuine "
    "differences between the two incidents, and an explicit judgment of whether "
    "they are likely related (e.g. the same actor or campaign) or more likely "
    "coincidental. State your confidence plainly, and do not assert a link the "
    "evidence does not support -- if the evidence is inconclusive, say so instead "
    "of guessing. Do not invent details that are not present in the context."
)


def run_incident_comparison(
    incident: IncidentGroup, other_incident: IncidentGroup, *, provider=None
) -> dict:
    """Gather context for both `incident` and `other_incident`, send it
    to the AI provider, and return a structured result ready to display.

    Same provider contract and error behavior as run_incident_analysis
    in apps/ai_core/modules/analyst.py.
    """
    provider = provider or AnthropicProvider()

    context = build_comparison_context(incident, other_incident)
    prompt = f"{COMPARATOR_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "other_incident_id": other_incident.id,
        "model": provider.model,
        "comparison": response_text.strip(),
        "generated_at": timezone.now(),
    }
