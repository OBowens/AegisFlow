"""App Assistant agent: answers general "how do I use this app"
questions using the static app-reference corpus
(apps/ai_core/services/app_assistant_context.py), not live
incident/risk/readiness data. Same real, callable pattern as
analyst.py/risk_advisor.py/readiness_advisor.py -- the only thing
standing between this and a live response is ANTHROPIC_API_KEY.

This is the one Q&A agent in this package with no per-request context
variation: build_app_assistant_context() returns the same fixed text
every time, so the grounding rule here is about staying inside that
fixed reference material at all (and pointing scoped questions to the
right scoped assistant instead of guessing), not staying inside one
object's evidence the way analyst.py/risk_advisor.py must.
"""

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.app_assistant_context import (
    APP_ASSISTANT_CORPUS_VERSION,
    build_app_assistant_context,
)
from apps.organizations.models import Organization

APP_ASSISTANT_SYSTEM_PREAMBLE = (
    "You are AegisFlow AI's in-app assistant, answering general questions "
    "about how to use the AegisFlow AI application itself -- navigation, "
    "the guided incident workflow, and terminology -- for a user of this "
    "security operations platform. Using only the app-reference material "
    "provided below, answer the question. That material describes the "
    "app's own features, not any specific incident, risk, or "
    "organization's live data -- if the question asks about a particular "
    "incident, alert, risk, or readiness score, say so plainly and point "
    "the user to that item's own page and its own \"Ask AegisFlow\" "
    "question box instead of guessing. If a question asks about "
    "something not covered in the material below, say plainly that it "
    "isn't covered instead of guessing."
)


def run_app_assistant_question(organization: Organization, question: str, *, provider=None) -> dict:
    """Send `question` plus the static app-reference corpus to the AI
    provider and return a structured result ready to display. Mirrors
    run_readiness_question in readiness_advisor.py, except the context
    is fixed reference text instead of anything gathered from
    `organization` -- `organization` here is only used for AI-call
    rate limiting/audit scoping, same as every other module.
    """
    provider = provider or AnthropicProvider()

    context = build_app_assistant_context()
    prompt = f"{APP_ASSISTANT_SYSTEM_PREAMBLE}\n\n{context}\n\n## Question\n{question}"

    response_text = provider.send_message(prompt, organization=organization)

    return {
        "organization_id": organization.id,
        "model": provider.model,
        "question": question,
        "answer": response_text.strip(),
        "corpus_version": APP_ASSISTANT_CORPUS_VERSION,
        "generated_at": timezone.now(),
    }
