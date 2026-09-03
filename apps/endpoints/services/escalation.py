"""Turn a triaged, escalate-verdict correlation candidate into work in
the queue.

Sustained suspicious activity on one endpoint spans many 10-minute
correlation windows, so this does NOT blindly mint a new incident per
cluster. If the endpoint already has an *open* endpoint-activity
incident (another candidate is linked to it), the new candidate is
attached to that incident and the incident is updated -- one growing
incident, not a pile of near-duplicates. A resolved/closed incident
does not capture new activity; that starts a fresh one.

The incident carries no ``IncidentEvidence`` rows -- that join model is
``ParsedAlert``-only. The evidence is the linked
``EndpointCorrelationCandidate`` rows (``incident.endpoint_correlation_candidates``);
Part 5 renders that. The incident detail view already tolerates zero
``IncidentEvidence``.

Updating an existing incident only ever touches ``severity`` (upward),
``title``, ``summary`` and ``last_seen`` -- never ``status``,
``assigned_to`` or ``workflow_state``, so an analyst's investigation
state is preserved.
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from apps.incidents.models import IncidentGroup

INCIDENT_TYPE = "endpoint_activity"

# An incident in one of these states still absorbs new activity for the
# same endpoint. Once RESOLVED/CLOSED, new activity is a new incident.
OPEN_INCIDENT_STATUSES = (
    IncidentGroup.Status.OPEN,
    IncidentGroup.Status.INVESTIGATING,
    IncidentGroup.Status.CONTAINED,
)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@transaction.atomic
def escalate_candidate(candidate, triage_result: dict) -> tuple[IncidentGroup, bool]:
    """``triage_result`` is the dict from
    ``apps.ai_core.modules.endpoint_triage.run_endpoint_triage`` -- it
    only reaches here when a real call completed with verdict
    ``escalate``. Returns ``(incident, created)`` where ``created`` is
    False when the candidate was attached to a pre-existing open
    incident for the same endpoint.
    """
    existing = (
        IncidentGroup.objects.filter(
            endpoint_correlation_candidates__endpoint=candidate.endpoint,
            incident_type=INCIDENT_TYPE,
            status__in=OPEN_INCIDENT_STATUSES,
        )
        .distinct()
        .order_by("id")
        .first()
    )
    if existing is not None:
        return _attach_to_incident(existing, candidate, triage_result), False
    return _create_incident(candidate, triage_result), True


def _create_incident(candidate, triage_result: dict) -> IncidentGroup:
    endpoint = candidate.endpoint
    severity = triage_result["severity"]
    incident = IncidentGroup.objects.create(
        organization=candidate.organization,
        title=f"{severity.title()} endpoint activity on {endpoint.display_name}",
        incident_type=INCIDENT_TYPE,
        severity=severity,
        status=IncidentGroup.Status.OPEN,
        affected_systems=endpoint.display_name,
        summary=triage_result["summary"],
        ai_reasoning=triage_result["reasoning"],
        # No fabricated confidence: there is no per-event confidence
        # signal to derive one from, same rule as
        # compute_incident_confidence returning None.
        confidence=None,
        first_seen=candidate.first_event_at,
        last_seen=candidate.last_event_at,
    )
    candidate.incident = incident
    candidate.save(update_fields=["incident", "updated_at"])
    return incident


def _attach_to_incident(incident, candidate, triage_result: dict) -> IncidentGroup:
    candidate.incident = incident
    candidate.save(update_fields=["incident", "updated_at"])

    changed = ["updated_at"]

    if candidate.last_event_at and (
        incident.last_seen is None or candidate.last_event_at > incident.last_seen
    ):
        incident.last_seen = candidate.last_event_at
        changed.append("last_seen")

    new_severity = triage_result["severity"]
    if _SEVERITY_RANK.get(new_severity, 0) > _SEVERITY_RANK.get(incident.severity, 0):
        incident.severity = new_severity
        incident.title = (
            f"{new_severity.title()} endpoint activity on {candidate.endpoint.display_name}"
        )
        changed += ["severity", "title"]

    stamp = timezone.localtime(candidate.last_event_at or timezone.now()).strftime(
        "%Y-%m-%d %H:%M"
    )
    incident.summary = (
        f"{incident.summary}\n\nUpdate {stamp}: {triage_result['summary']}".strip()
    )
    changed.append("summary")

    incident.save(update_fields=changed)
    return incident
