from collections import defaultdict
from datetime import timedelta

from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.incidents.services.confidence import compute_incident_confidence

# Consecutive alerts in the same (event_type, affected_system, severity)
# bucket more than this far apart start a new incident instead of being
# folded into the same one -- a burst stays one incident, but genuinely
# separated activity doesn't silently merge.
TIME_GAP_SPLIT_THRESHOLD = timedelta(hours=2)


def group_alerts_for_upload(uploaded_log_file):
    existing_incidents = (
        IncidentGroup.objects.filter(evidence_items__alert__uploaded_file=uploaded_log_file)
        .distinct()
        .order_by("id")
    )
    if existing_incidents.exists():
        return list(existing_incidents)

    alerts = list(uploaded_log_file.parsed_alerts.order_by("id"))
    grouped_alerts = defaultdict(list)

    for alert in alerts:
        grouped_alerts[
            (
                alert.event_type or "log_event",
                alert.affected_system or "Unknown system",
                alert.severity_hint or "low",
            )
        ].append(alert)

    created_incidents = []

    for (event_type, affected_system, severity), members in grouped_alerts.items():
        for cluster in _split_by_time_gap(members):
            timestamps = [alert.timestamp for alert in cluster if alert.timestamp]
            incident = IncidentGroup.objects.create(
                organization=uploaded_log_file.organization,
                title=_build_incident_title(event_type, affected_system, severity, cluster),
                incident_type=event_type,
                severity=severity,
                status=IncidentGroup.Status.OPEN,
                affected_systems=affected_system,
                summary=_build_incident_summary(cluster, affected_system),
                ai_reasoning=(
                    "Grouped deterministically for the MVP demo using event type, "
                    "affected system, severity, and time-gap splitting."
                ),
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
                confidence=compute_incident_confidence(cluster),
            )
            IncidentEvidence.objects.bulk_create(
                [
                    IncidentEvidence(
                        incident=incident,
                        alert=alert,
                        evidence_reason=(
                            "Alert matched the same event type, affected system, and severity "
                            "signature during deterministic grouping."
                        ),
                    )
                    for alert in cluster
                ]
            )
            created_incidents.append(incident)

    return created_incidents


def _split_by_time_gap(members):
    """Split a same-bucket group of alerts into time-clustered sub-groups.

    Alerts with a timestamp are sorted chronologically and split wherever
    the gap to the next alert exceeds TIME_GAP_SPLIT_THRESHOLD, so a burst
    of activity stays one incident but genuinely separated activity forms
    its own. Alerts with no timestamp can't be placed in that ordering, so
    they fall back to the pre-existing behavior: they're all kept together
    as a single additional cluster, unsplit.
    """
    dated = sorted((alert for alert in members if alert.timestamp), key=lambda alert: alert.timestamp)
    undated = [alert for alert in members if not alert.timestamp]

    clusters = []
    current_cluster = []
    for alert in dated:
        if current_cluster and (alert.timestamp - current_cluster[-1].timestamp) > TIME_GAP_SPLIT_THRESHOLD:
            clusters.append(current_cluster)
            current_cluster = []
        current_cluster.append(alert)
    if current_cluster:
        clusters.append(current_cluster)

    if undated:
        clusters.append(undated)

    return clusters


def _build_incident_title(event_type, affected_system, severity, members):
    combined_text = " ".join(
        [event_type.replace("_", " ")] + [alert.raw_message.lower() for alert in members]
    )

    if "authentication" in event_type or "failed login" in combined_text or "brute force" in combined_text:
        return f"{severity.title()} severity authentication activity on {affected_system}"
    if "backup" in event_type or "backup failed" in combined_text:
        return f"Backup failure detected on {affected_system}"
    if "firewall" in event_type or "denied" in combined_text:
        return f"Firewall denied traffic pattern on {affected_system}"
    if "malware" in event_type or "ransomware" in combined_text or "compromised" in combined_text:
        return f"Potential malware activity on {affected_system}"
    if "availability" in event_type or "timeout" in combined_text or "unavailable" in combined_text:
        return f"Availability issue detected on {affected_system}"
    return f"{severity.title()} severity log activity on {affected_system}"


def _build_incident_summary(members, affected_system):
    sample_message = members[0].normalized_summary if members else "No alert details available."
    return (
        f"{len(members)} parsed alert(s) were grouped into one incident for {affected_system}. "
        f"Representative alert: {sample_message}"
    )
