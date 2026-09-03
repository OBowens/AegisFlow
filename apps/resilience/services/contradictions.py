from datetime import timedelta

from django.utils import timezone

from apps.resilience.models import ReadinessAnswer
from apps.risk.models import GapFinding, RiskAssessment

# Narrow first pass: only these words count as an answer claiming
# something is fine. Anything else is left alone rather than guessed at.
POSITIVE_CLAIM_TERMS = ("yes", "working", "in place")

CONTRADICTION_LOOKBACK_DAYS = 30


def find_contradictions_for_organization(organization, lookback_days=CONTRADICTION_LOOKBACK_DAYS):
    """Cross-check readiness answers claiming something is fine against
    recent GapFinding/RiskAssessment rows on the same topic. When both
    exist, surface the conflict explicitly (both texts, side by side)
    instead of silently trusting the answer or the finding.
    """
    cutoff = timezone.now() - timedelta(days=lookback_days)
    answers = ReadinessAnswer.objects.filter(organization=organization).order_by("-created_at")

    recent_gaps = list(GapFinding.objects.filter(organization=organization, created_at__gte=cutoff))
    recent_risks = list(RiskAssessment.objects.filter(organization=organization, created_at__gte=cutoff))

    conflicts = []
    for answer in answers:
        if not _claims_something_is_fine(answer.answer_text):
            continue

        topic = _topic_for_text(f"{answer.question_text} {answer.answer_text}")
        if topic is None:
            continue

        for gap in recent_gaps:
            if _topic_for_text(f"{gap.gap_name} {gap.description}") == topic:
                conflicts.append(_build_conflict(answer, topic, finding=gap, finding_type="gap"))

        for risk in recent_risks:
            if _topic_for_text(f"{risk.risk_title} {risk.reasoning}") == topic:
                conflicts.append(_build_conflict(answer, topic, finding=risk, finding_type="risk"))

    return conflicts


def _claims_something_is_fine(answer_text):
    lowered = (answer_text or "").lower()
    return any(term in lowered for term in POSITIVE_CLAIM_TERMS)


def _topic_for_text(text):
    lowered = (text or "").lower()
    if "backup" in lowered or "restore" in lowered:
        return "backup"
    if "authentication" in lowered or "mfa" in lowered or "login" in lowered or "password" in lowered:
        return "authentication"
    if "malware" in lowered or "ransomware" in lowered or "compromised" in lowered:
        return "malware"
    if "availability" in lowered or "outage" in lowered or "timeout" in lowered or "unavailable" in lowered:
        return "availability"
    if "critical" in lowered or "recovery" in lowered:
        return "critical_systems"
    return None


def _build_conflict(answer, topic, *, finding, finding_type):
    if finding_type == "gap":
        finding_text = f"{finding.gap_name}: {finding.description}"
    else:
        finding_text = f"{finding.risk_title}: {finding.reasoning}"

    return {
        "topic": topic,
        "answer": answer,
        "answer_question": answer.question_text,
        "answer_text": answer.answer_text,
        "finding": finding,
        "finding_type": finding_type,
        "finding_text": finding_text,
        "finding_created_at": finding.created_at,
    }
