from datetime import timedelta

from django.utils import timezone

from apps.incidents.models import IncidentSourceIPLink
from apps.log_intake.models import ParsedAlert

SOURCE_IP_LOOKBACK_DAYS = 90


def link_source_ip_matches_for_incidents(incidents):
    """For each incident, check whether its alerts' source_ip values also
    appear in alerts from OTHER uploads within the lookback window. When
    they do, persist an explicit link to the prior incident(s) involved
    instead of leaving the connection to surface only as a silent, separate
    incident.
    """
    created_links = []
    for incident in incidents:
        created_links.extend(_link_source_ip_matches_for_incident(incident))
    return created_links


def _link_source_ip_matches_for_incident(incident):
    existing_links = list(incident.source_ip_links.all())
    if existing_links:
        return existing_links

    source_ips = _collect_source_ips(incident)
    if not source_ips:
        return []

    own_uploaded_file_ids = set(
        incident.evidence_items.values_list("alert__uploaded_file_id", flat=True)
    )
    cutoff = timezone.now() - timedelta(days=SOURCE_IP_LOOKBACK_DAYS)

    candidate_alerts = (
        ParsedAlert.objects.filter(
            organization=incident.organization,
            source_ip__in=source_ips,
        )
        .exclude(uploaded_file_id__in=own_uploaded_file_ids)
        .prefetch_related("incident_links__incident")
        .order_by("timestamp", "created_at")
    )

    created_links = []
    seen_related_incident_ids = set()

    for alert in candidate_alerts:
        effective_time = alert.timestamp or alert.created_at
        if effective_time < cutoff:
            continue

        for evidence in alert.incident_links.all():
            related_incident = evidence.incident
            if related_incident.id == incident.id:
                continue
            if related_incident.id in seen_related_incident_ids:
                continue

            seen_related_incident_ids.add(related_incident.id)
            created_links.append(
                IncidentSourceIPLink.objects.create(
                    incident=incident,
                    related_incident=related_incident,
                    source_ip=alert.source_ip,
                    matched_alert=alert,
                )
            )

    return created_links


def _collect_source_ips(incident):
    return sorted(
        set(
            incident.evidence_items.exclude(alert__source_ip__isnull=True).values_list(
                "alert__source_ip", flat=True
            )
        )
    )
