"""Endpoint Triage agent: takes one flagged event cluster
(``EndpointCorrelationCandidate``), sends its context to the AI
provider, and returns a structured verdict -- escalate or benign, plus
severity, summary and reasoning.

Same real, callable pattern as apps/ai_core/modules/analyst.py: gather
context -> build prompt -> provider.send_message() -> handle response.
The provider runs the Sanitizer automatically (hostnames / usernames /
paths in the event payloads are pseudonymized before the call and
rehydrated in the reply).

Unlike the prose modules, this one needs a machine-readable answer, so
the model is asked for a strict JSON object and the reply is parsed. A
reply that cannot be parsed into a valid verdict is treated as a failed
call (raises ``RuntimeError``) -- never coerced into a guessed verdict.
The caller records that as an honest "not yet triaged" state and retries
on the next scan.
"""

from __future__ import annotations

import json
import re

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.endpoint_triage_context import build_endpoint_triage_context
from apps.endpoints.models import EndpointCorrelationCandidate

TRIAGE_SYSTEM_PREAMBLE = (
    "You are a security triage assistant for a small business's security team. "
    "Below is a cluster of Windows endpoint events (process creations and/or "
    "PowerShell script blocks) that local rules flagged as unusual. Local "
    "noise-filtering has already removed the known-safe activity, so what "
    "remains is 'not confirmed safe', not necessarily malicious. Using ONLY "
    "the context provided, decide whether this cluster genuinely warrants a "
    "human analyst's attention now.\n\n"
    "Respond with ONLY a JSON object, no prose before or after, no code fence, "
    "with exactly these keys:\n"
    '  "verdict": "escalate" or "benign"\n'
    '  "severity": one of "low", "high", "medium", "critical" (your severity '
    "estimate if a human should look; use \"low\" if verdict is benign)\n"
    '  "summary": one or two sentences a busy analyst can read at a glance\n'
    '  "reasoning": a short paragraph citing the specific events that drove '
    "your decision\n"
    "Do not invent details that are not in the context. If the evidence is "
    "genuinely ambiguous, lean towards \"escalate\" with a lower severity so a "
    "human makes the final call."
)

_VALID_VERDICTS = {"escalate", "benign"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def run_endpoint_triage(candidate: EndpointCorrelationCandidate, *, provider=None) -> dict:
    """Gather context for ``candidate``, send it to the AI provider, and
    return ``{verdict, severity, summary, reasoning, model, generated_at}``.

    Raises ``RuntimeError`` on any provider failure (missing key, network,
    timeout, ...) *and* on a response that is not a valid JSON verdict --
    the caller's ``except RuntimeError`` path treats both the same way.
    """
    provider = provider or AnthropicProvider()

    context = build_endpoint_triage_context(candidate)
    prompt = f"{TRIAGE_SYSTEM_PREAMBLE}\n\n{context}"

    response_text = provider.send_message(prompt, organization=candidate.organization)
    parsed = _parse_verdict(response_text)

    return {
        "candidate_id": candidate.id,
        "model": provider.model,
        "verdict": parsed["verdict"],
        "severity": parsed["severity"],
        "summary": parsed["summary"],
        "reasoning": parsed["reasoning"],
        "generated_at": timezone.now(),
    }


def _parse_verdict(response_text: str) -> dict:
    raw = _FENCE_RE.sub("", (response_text or "").strip())
    # Be forgiving of a stray sentence around the JSON: take the outermost
    # brace pair if a bare json.loads fails.
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            raise RuntimeError(
                f"Endpoint triage response was not JSON: {response_text[:200]!r}"
            )
        try:
            data = json.loads(match.group(0))
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"Endpoint triage response was not valid JSON: {exc}"
            ) from exc

    if not isinstance(data, dict):
        raise RuntimeError("Endpoint triage response JSON was not an object.")

    verdict = str(data.get("verdict", "")).strip().lower()
    if verdict not in _VALID_VERDICTS:
        raise RuntimeError(f"Endpoint triage response had an invalid verdict: {verdict!r}")

    summary = str(data.get("summary", "")).strip()
    reasoning = str(data.get("reasoning", "")).strip()
    if not summary or not reasoning:
        raise RuntimeError("Endpoint triage response was missing summary or reasoning.")

    severity = str(data.get("severity", "")).strip().lower()
    if verdict == "escalate" and severity not in _VALID_SEVERITIES:
        raise RuntimeError(
            f"Endpoint triage escalation had an invalid severity: {severity!r}"
        )
    if severity not in _VALID_SEVERITIES:
        severity = "low"

    return {
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "reasoning": reasoning,
    }
