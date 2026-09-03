from apps.risk.models import GapFinding, RiskAssessment


def create_risk_findings_for_incidents(incidents):
    created_risks = []

    for incident in incidents:
        existing_risks = list(incident.risk_assessments.order_by("id"))
        if existing_risks:
            created_risks.extend(existing_risks)
            continue

        gap_name, gap_description, risk_title, reasoning = _build_gap_and_risk_content(incident)
        gap, _ = GapFinding.objects.get_or_create(
            organization=incident.organization,
            incident=incident,
            gap_name=gap_name,
            defaults={
                "description": gap_description,
                "affected_system": incident.affected_systems,
                "source": GapFinding.Source.LOG_BASED,
                "evidence": incident.summary,
                "priority": _severity_to_priority(incident.severity),
            },
        )
        risk, _ = RiskAssessment.objects.get_or_create(
            organization=incident.organization,
            incident=incident,
            gap=gap,
            risk_title=risk_title,
            defaults={
                "likelihood": _severity_to_likelihood(incident.severity),
                "impact": _severity_to_impact(incident.severity),
                "risk_level": _severity_to_risk_level(incident.severity),
                "reasoning": reasoning,
                "recommended_priority": _severity_to_recommended_priority(incident.severity),
            },
        )
        created_risks.append(risk)

    return created_risks


def _build_gap_and_risk_content(incident):
    incident_type = (incident.incident_type or "").lower()
    title = (incident.title or "").lower()
    summary = (incident.summary or "").lower()
    combined = " ".join([incident_type, title, summary])

    if "authentication" in combined or "failed login" in combined or "brute force" in combined:
        return (
            "Authentication monitoring or MFA evidence needs review",
            "Authentication-related alerts suggest login controls, MFA evidence, or monitoring coverage should be reviewed.",
            "Authentication control exposure",
            "Repeated authentication activity can increase the likelihood of unauthorized access if MFA, lockout controls, or escalation monitoring are weak.",
        )
    if "backup" in combined:
        return (
            "Backup or restore assurance gap",
            "Backup failure evidence suggests recovery readiness and restore assurance need review.",
            "Recovery assurance risk",
            "Backup failures reduce confidence that critical systems can be restored during outages, ransomware, or disaster scenarios.",
        )
    if "malware" in combined or "ransomware" in combined or "compromised" in combined:
        return (
            "Endpoint protection or containment readiness gap",
            "Potential malware activity suggests containment readiness and endpoint protection controls should be reviewed.",
            "Malware containment risk",
            "Malware-related signals increase the risk of lateral movement, ransomware escalation, and recovery disruption without timely containment.",
        )
    if "availability" in combined or "timeout" in combined or "unavailable" in combined or "outage" in combined:
        return (
            "Availability and resilience gap",
            "Service degradation or outage indicators suggest resilience and continuity controls should be reviewed.",
            "Service continuity risk",
            "Availability issues can interrupt operations and expose recovery dependencies if resilience controls are weak.",
        )
    return (
        "Security evidence review needed",
        "The incident needs additional evidence review to confirm whether monitoring, controls, or process gaps are present.",
        "Incident review risk",
        "Incomplete evidence or unresolved alerts can hide operational and security weaknesses until reviewed by a human analyst.",
    )


def _severity_to_priority(severity):
    mapping = {
        "low": GapFinding.Priority.LOW,
        "medium": GapFinding.Priority.MEDIUM,
        "high": GapFinding.Priority.HIGH,
        "critical": GapFinding.Priority.CRITICAL,
    }
    return mapping.get(severity, GapFinding.Priority.MEDIUM)


def _severity_to_likelihood(severity):
    mapping = {
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 4,
    }
    return mapping.get(severity, 3)


def _severity_to_impact(severity):
    mapping = {
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 4,
    }
    return mapping.get(severity, 3)


def _severity_to_risk_level(severity):
    mapping = {
        "low": RiskAssessment.Level.LOW,
        "medium": RiskAssessment.Level.MEDIUM,
        "high": RiskAssessment.Level.HIGH,
        "critical": RiskAssessment.Level.CRITICAL,
    }
    return mapping.get(severity, RiskAssessment.Level.MEDIUM)


def _severity_to_recommended_priority(severity):
    mapping = {
        "low": RiskAssessment.RecommendedPriority.LOW,
        "medium": RiskAssessment.RecommendedPriority.MEDIUM,
        "high": RiskAssessment.RecommendedPriority.HIGH,
        "critical": RiskAssessment.RecommendedPriority.URGENT,
    }
    return mapping.get(severity, RiskAssessment.RecommendedPriority.MEDIUM)
