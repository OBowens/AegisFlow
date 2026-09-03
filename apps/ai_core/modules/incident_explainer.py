"""Incident Explainer agent: reuses build_incident_context -- the exact
same context the Analyst agent uses (apps/ai_core/modules/analyst.py) --
and rewrites it for a specific non-analyst audience, rather than
building two near-identical agent modules that would each re-implement
the same evidence/gap/risk/source-IP gathering.

Two audiences today, driven by AUDIENCE_PREAMBLES:
- "plain_language": a non-technical business owner, jargon-free.
- "management": an executive audience deciding on resourcing/priority,
  framed around business impact and risk exposure.

Same real, callable pattern as apps/ai_core/modules/analyst.py,
risk_advisor.py, readiness_advisor.py, prioritizer.py, and
comparator.py -- the only thing standing between this and a live
response is ANTHROPIC_API_KEY being configured -- see
apps/ai_core/providers/anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentGroup

PLAIN_LANGUAGE_PREAMBLE = (
    "You are explaining a security incident to a non-technical small business "
    "owner who has no security background. Using only the context provided "
    "below, explain in plain, everyday language: what happened, why it "
    "matters, and what should happen next. Avoid technical jargon -- if a "
    "technical term (like 'source IP', 'brute force', 'MFA') is unavoidable, "
    "explain what it means in plain words the first time you use it. Do not "
    "invent details that are not present in the context."
)

MANAGEMENT_PREAMBLE = (
    "You are briefing a non-technical executive or management audience on a "
    "security incident so they can decide on resourcing and priority. Using "
    "only the context provided below, frame your summary around business "
    "impact and risk exposure: what is at risk, the potential consequence if "
    "it goes unaddressed, and a clear recommended action with its urgency. "
    "Keep deep technical detail to a minimum -- focus on what a decision-maker "
    "needs to know. Do not invent details that are not present in the context."
)

AUDIENCE_PREAMBLES = {
    "plain_language": PLAIN_LANGUAGE_PREAMBLE,
    "management": MANAGEMENT_PREAMBLE,
}


def run_incident_explanation(incident: IncidentGroup, audience: str, *, provider=None) -> dict:
    """Gather context for `incident` (same as run_incident_analysis),
    send it to the AI provider with an audience-specific system preamble,
    and return a structured result ready to display.

    `audience` must be one of AUDIENCE_PREAMBLES's keys (see
    IncidentExplanation.Audience in apps/incidents/models.py). Same
    provider contract and error behavior as run_incident_analysis in
    apps/ai_core/modules/analyst.py.
    """
    if audience not in AUDIENCE_PREAMBLES:
        raise ValueError(f"Unknown audience: {audience!r}. Expected one of {sorted(AUDIENCE_PREAMBLES)}.")

    provider = provider or AnthropicProvider()

    context = build_incident_context(incident)
    prompt = f"{AUDIENCE_PREAMBLES[audience]}\n\n{context}"

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "audience": audience,
        "model": provider.model,
        "explanation": response_text.strip(),
        "generated_at": timezone.now(),
    }
