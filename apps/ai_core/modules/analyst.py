"""Analyst agent: gathers full incident context, sends it to the configured
AI provider, and returns a structured, display-ready result.

Unlike the other modules in this package (loglens.py, riskscope.py, etc --
each marked NOT WIRED UP / placeholder design sketches at the top of their
own file, per the 2026-08-24 investigation), this is real, callable code.
The only thing standing between this and a live response is
ANTHROPIC_API_KEY being configured -- see apps/ai_core/providers/
anthropic_provider.py.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.incidents.models import IncidentGroup

ANALYST_SYSTEM_PREAMBLE = (
    "You are a security analyst assistant reviewing an incident for a small "
    "business's security team. Using only the context provided below, give a "
    "concise assessment: what happened, how serious it is, and the 2-3 most "
    "important next actions. If the context includes Prior Source-IP Activity, "
    "explicitly address whether that pattern (how many prior incidents, how "
    "many distinct systems, over what span of time) suggests reconnaissance or "
    "a repeat actor rather than a one-off, and factor that into your severity "
    "and next-action guidance. Do not invent details that are not present in "
    "the context."
)

QUESTION_SYSTEM_PREAMBLE = (
    "You are a security analyst assistant answering a follow-up question "
    "about a specific incident for a small business's security team. Using "
    "only the context provided below, answer the question. If the evidence "
    "in the context does not support a confident answer, say so plainly "
    "instead of guessing -- do not invent details that are not present in "
    "the context."
)


def run_incident_analysis(incident: IncidentGroup, *, provider=None) -> dict:
    """Gather context for `incident`, send it to the AI provider, and
    return a structured result ready to display.

    `provider` defaults to a real AnthropicProvider() (reading
    ANTHROPIC_API_KEY from the environment), but accepts anything with a
    `.send_message(prompt) -> str` method and a `.model` attribute --
    tests pass a fake/mocked one here instead of hitting the network.

    Raises whatever the provider raises (e.g. RuntimeError if the API key
    isn't configured); this function doesn't swallow that, since a caller
    displaying the result needs to know analysis wasn't actually run.
    """
    provider = provider or AnthropicProvider()

    context = build_incident_context(incident)
    prompt = f"{ANALYST_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "model": provider.model,
        "analysis": response_text.strip(),
        "generated_at": timezone.now(),
    }


def run_incident_question(incident: IncidentGroup, question: str, *, provider=None) -> dict:
    """Gather context for `incident`, append `question`, send it to the AI
    provider, and return a structured result ready to display.

    Same provider contract and error behavior as run_incident_analysis --
    see that function's docstring.
    """
    provider = provider or AnthropicProvider()

    context = build_incident_context(incident)
    prompt = f"{QUESTION_SYSTEM_PREAMBLE}\n\n{context}\n\n## Question\n{question}"

    response_text = provider.send_message(prompt, organization=incident.organization)

    return {
        "incident_id": incident.id,
        "model": provider.model,
        "question": question,
        "answer": response_text.strip(),
        "generated_at": timezone.now(),
    }
