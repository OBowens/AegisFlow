"""Report Writer agent: one shared module for all 5 on-demand
GeneratedReport types (Executive, Technical, Incident, Risk,
Readiness), dispatching on `report_type` to a type-specific
context-gathering function and system preamble.

This is NOT a single-context "same data, reframed" module like
apps.ai_core.modules.incident_explainer -- Executive and Risk
genuinely need organization-wide aggregate data that doesn't exist
anywhere else (apps/ai_core/services/executive_context.py and
risk_report_context.py, new), while Technical and Incident are the
"same data reframed" pair here and both reuse build_incident_context
verbatim, and Readiness reuses build_readiness_context verbatim. See
the 2026-08-27 architecture investigation for the full reasoning on
where these boundaries actually are.

Same real, callable pattern as apps/ai_core/modules/analyst.py,
risk_advisor.py, readiness_advisor.py, prioritizer.py, comparator.py,
and incident_explainer.py -- the only thing standing between this and a
live response is ANTHROPIC_API_KEY being configured -- see
apps/ai_core/providers/anthropic_provider.py.
"""

import re

from django.utils import timezone

from apps.ai_core.providers.anthropic_provider import AnthropicProvider
from apps.ai_core.services.analyst_context import build_incident_context
from apps.ai_core.services.executive_context import build_executive_context
from apps.ai_core.services.readiness_context import build_readiness_context
from apps.ai_core.services.risk_report_context import build_risk_report_context
from apps.reports.models import GeneratedReport

# Every report type's output must stay compatible with
# apps.reports.views._build_preview_sections, which regex-extracts a
# section literally titled "Impact" and a bullet list under a section
# literally titled "Recommended Actions" for the Reports page's preview
# pane. Rather than loosen that parsing (which several other report
# bodies already rely on -- see the "Impact:" / "Recommended Actions:"
# convention baked into apps/reports/tests.py's own fixture and
# apps/reports/services/generator.py's deterministic body), every
# preamble below ends with this same structural instruction.
_FORMAT_INSTRUCTIONS = (
    "Structure your response as: one short paragraph summarizing the report "
    "(do not give this paragraph its own heading or title), then a section "
    "titled exactly \"Impact\" explaining what is at stake, then a section "
    "titled exactly \"Recommended Actions\" with 3 to 6 bullet points (each "
    "line starting with \"-\"), one concrete action per line. Write section "
    "titles as plain text on their own line, not markdown headings -- no "
    "leading \"#\" characters. Do not invent details that are not present in "
    "the context."
)

REPORT_PREAMBLES = {
    GeneratedReport.ReportType.EXECUTIVE: (
        "You are writing an executive report for a small business's leadership "
        "on their organization's overall security posture. Using only the "
        "context provided below, summarize the state of open incidents, the "
        "highest risk findings, and disaster readiness in terms a non-technical "
        "decision-maker can act on. "
        + _FORMAT_INSTRUCTIONS
    ),
    GeneratedReport.ReportType.TECHNICAL: (
        "You are writing a technical report for a security team's own records "
        "on a specific incident. Using only the context provided below, give a "
        "detailed technical account: the evidence, the gap and risk findings, "
        "and any matching SOP guidance, written for a technical analyst "
        "audience. "
        + _FORMAT_INSTRUCTIONS
    ),
    GeneratedReport.ReportType.INCIDENT: (
        "You are writing a formal incident report documenting a specific "
        "security incident for the record. Using only the context provided "
        "below, write a case-report-style account: what happened, the "
        "evidence and timeline, and how it was assessed, suitable for filing "
        "alongside the incident. "
        + _FORMAT_INSTRUCTIONS
    ),
    GeneratedReport.ReportType.RISK: (
        "You are writing a risk report for a small business's security team "
        "summarizing risk exposure across the organization. Using only the "
        "context provided below, describe the overall risk picture and the "
        "highest-scoring risk findings, and what to prioritize. "
        + _FORMAT_INSTRUCTIONS
    ),
    GeneratedReport.ReportType.READINESS: (
        "You are writing a disaster-readiness report for a small business "
        "summarizing their preparedness. Using only the context provided "
        "below, explain the overall readiness score, which domains are "
        "dragging it down, and what to prioritize. "
        + _FORMAT_INSTRUCTIONS
    ),
}

# Executive and Risk take an Organization and need a new aggregate
# rollup (executive_context.py / risk_report_context.py) that doesn't
# exist anywhere else. Readiness also takes an Organization but reuses
# readiness_context.py unchanged -- it already is the right org-wide
# rollup, built for readiness_advisor. Technical and Incident both take
# an IncidentGroup and reuse build_incident_context unchanged -- same
# underlying evidence/gap/risk/SOP context analyst.py, writer.py, and
# incident_explainer.py all already use, just written up differently.
REPORT_CONTEXT_BUILDERS = {
    GeneratedReport.ReportType.EXECUTIVE: build_executive_context,
    GeneratedReport.ReportType.RISK: build_risk_report_context,
    GeneratedReport.ReportType.READINESS: build_readiness_context,
    GeneratedReport.ReportType.TECHNICAL: build_incident_context,
    GeneratedReport.ReportType.INCIDENT: build_incident_context,
}


def run_report_generation(report_type: str, target, *, provider=None) -> dict:
    """Gather context for `target` (an Organization for Executive/Risk/
    Readiness, an IncidentGroup for Technical/Incident -- see
    REPORT_CONTEXT_BUILDERS), send it to the AI provider with a
    type-specific system preamble, and return a structured result ready
    to persist as a GeneratedReport.

    Same provider contract and error behavior as run_incident_analysis
    in apps/ai_core/modules/analyst.py.
    """
    if report_type not in REPORT_CONTEXT_BUILDERS:
        raise ValueError(
            f"Unknown report_type: {report_type!r}. Expected one of {sorted(REPORT_CONTEXT_BUILDERS)}."
        )

    provider = provider or AnthropicProvider()

    context_builder = REPORT_CONTEXT_BUILDERS[report_type]
    context = context_builder(target)
    prompt = f"{REPORT_PREAMBLES[report_type]}\n\n{context}"

    # `target` is an Organization for Executive/Risk/Readiness and an
    # IncidentGroup (which has `.organization`) for Technical/Incident.
    prompt_organization = getattr(target, "organization", target)
    response_text = provider.send_message(prompt, organization=prompt_organization)
    report_text = response_text.strip()

    return {
        "report_type": report_type,
        "model": provider.model,
        "report_text": report_text,
        "summary": _first_paragraph(report_text),
        "generated_at": timezone.now(),
    }


_MARKDOWN_HEADING_LINE_RE = re.compile(r"^#{1,6}\s*\S.*$")


def _first_paragraph(text: str) -> str:
    # Skip a lone markdown title line ("## Executive Summary") -- models
    # reliably prepend one even when told to lead with a summary
    # paragraph (confirmed against real generated output), and without
    # this the GeneratedReport.summary field ends up being just that
    # heading instead of an actual summary.
    for paragraph in text.replace("\r\n", "\n").split("\n\n"):
        cleaned = paragraph.strip()
        if not cleaned:
            continue
        if "\n" not in cleaned and _MARKDOWN_HEADING_LINE_RE.match(cleaned):
            continue
        return cleaned
    return ""
