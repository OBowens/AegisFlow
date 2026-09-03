from apps.resilience.models import DisasterReadinessFinding


def create_readiness_findings_for_risks(risks):
    created_findings = []

    for risk in risks:
        content = _build_readiness_content(risk)
        if not content:
            continue

        readiness_issue, disaster_impact, recovery_concern = content
        finding, _ = DisasterReadinessFinding.objects.get_or_create(
            organization=risk.organization,
            incident=risk.incident,
            risk=risk,
            readiness_issue=readiness_issue,
            defaults={
                "disaster_impact": disaster_impact,
                "recovery_concern": recovery_concern,
                "source": DisasterReadinessFinding.Source.LOG_BASED,
                "priority": _risk_to_priority(risk.risk_level),
            },
        )
        created_findings.append(finding)

    return created_findings


def _build_readiness_content(risk):
    combined = " ".join(
        [
            (risk.risk_title or "").lower(),
            (risk.reasoning or "").lower(),
            (risk.incident.title.lower() if risk.incident else ""),
        ]
    )

    if "backup" in combined or "restore" in combined:
        return (
            "Backup recovery readiness concern",
            "Backup disruption could slow recovery during hurricane season, extended power loss, or ransomware response.",
            "Recovery confidence is reduced until backup success and restore readiness are confirmed.",
        )
    if "availability" in combined or "outage" in combined or "timeout" in combined or "unavailable" in combined:
        return (
            "Continuity and outage resilience concern",
            "Availability issues may affect continuity during power, internet, or infrastructure disruption.",
            "Service continuity planning should confirm fallback procedures and recovery ownership.",
        )
    if "malware" in combined or "ransomware" in combined or "compromised" in combined:
        return (
            "Disaster recovery and business continuity concern",
            "Malware-related incidents may impair core systems and increase recovery pressure during concurrent disasters or outages.",
            "Containment and restoration readiness should be reviewed before an operational emergency compounds the impact.",
        )
    if "critical" in combined or "recovery" in combined:
        return (
            "Critical system recovery concern",
            "Critical system risk can amplify disruption during hurricane, network, or power events.",
            "Recovery priorities, owners, and manual fallback plans should be verified.",
        )
    return None


def _risk_to_priority(risk_level):
    mapping = {
        "low": DisasterReadinessFinding.Priority.LOW,
        "medium": DisasterReadinessFinding.Priority.MEDIUM,
        "high": DisasterReadinessFinding.Priority.HIGH,
        "critical": DisasterReadinessFinding.Priority.CRITICAL,
    }
    return mapping.get(risk_level, DisasterReadinessFinding.Priority.MEDIUM)
