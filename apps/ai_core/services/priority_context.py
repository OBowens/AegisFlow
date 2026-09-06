"""Context-gathering for the Prioritizer agent ("what should I fix
first?"): given an Organization, pull its open incidents together into
one structured, ranked, plain-text prompt section.

Two things this does that a flat "top N incidents" list does not:

* **Grouping by affected system.** A real org routinely has several
  near-duplicate incidents for the same host (a "malware activity" and a
  "critical log activity" incident on the same server, say). Left
  ungrouped, those eat several slots of a small cap for what is really
  one piece of work. Incidents that share an affected system are joined
  into one :class:`PriorityCluster` (connected components over the
  shared-system graph), and the cap is spent on *distinct* clusters.

* **An explicit coverage statement.** The cap can hide lower-severity
  work, but it should not make the model hedge about hidden *worse*
  work when there is none. The overview says plainly whether every open
  Critical- (and High-) severity incident is shown, so the model only
  caveats when the cap genuinely truncates the most urgent tier.

Cluster ranking: max severity in the cluster, then the strongest paired
risk (recommended-priority tier, then risk score), then the age of the
oldest incident in the cluster, then lowest incident id as a final
deterministic tie-break. Incidents within a cluster are ordered the same
way.

This does not call any AI provider; it only builds the prompt text. See
apps/ai_core/modules/prioritizer.py for the piece that sends this to a
provider and handles the response. apps.core.views reuses
:func:`rank_open_incident_groups` so the dashboard's "priority incidents"
list and hero call-to-action agree with this ranking rather than running
their own.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from django.db.models import Prefetch
from django.utils import timezone

from apps.incidents.models import IncidentGroup
from apps.risk.models import RiskAssessment

# At most this many clusters in the briefing, and at most this many
# incidents listed within any one cluster (the rest are summarised as
# "...and N more"). Grouping first means these bounds cover more real
# ground than a flat incident cap of the same size.
MAX_PRIORITY_GROUPS = 6
MAX_INCIDENTS_PER_GROUP = 5

_OPEN_STATUSES = [IncidentGroup.Status.OPEN, IncidentGroup.Status.INVESTIGATING]

_SEVERITY_RANK = {
    IncidentGroup.Severity.CRITICAL: 4,
    IncidentGroup.Severity.HIGH: 3,
    IncidentGroup.Severity.MEDIUM: 2,
    IncidentGroup.Severity.LOW: 1,
}

_RECOMMENDED_PRIORITY_RANK = {
    RiskAssessment.RecommendedPriority.URGENT: 4,
    RiskAssessment.RecommendedPriority.HIGH: 3,
    RiskAssessment.RecommendedPriority.MEDIUM: 2,
    RiskAssessment.RecommendedPriority.LOW: 1,
}

_SYSTEM_SPLIT_RE = re.compile(r"[,;/\n|]+")


def _split_systems(raw: str) -> list[str]:
    if not raw:
        return []
    return [piece.strip() for piece in _SYSTEM_SPLIT_RE.split(raw) if piece.strip()]


def _plural(count: int) -> str:
    return "" if count == 1 else "s"


def _severity_label(severity: str) -> str:
    return dict(IncidentGroup.Severity.choices).get(severity, severity)


def _incident_risk_key(incident) -> tuple[int, int]:
    """``(recommended-priority rank, risk score)`` of this incident's
    strongest paired risk assessment; ``(0, 0)`` when it has none."""
    best = (0, 0)
    for risk in incident.risk_assessments.all():
        key = (
            _RECOMMENDED_PRIORITY_RANK.get(risk.recommended_priority, 0),
            risk.likelihood * risk.impact,
        )
        if key > best:
            best = key
    return best


def _incident_best_risk(incident):
    """The single RiskAssessment that :func:`_incident_risk_key` selected,
    for display; ``None`` when the incident has no risk assessment."""
    best_risk = None
    best_key = (-1, -1, 0)
    for risk in incident.risk_assessments.all():
        key = (
            _RECOMMENDED_PRIORITY_RANK.get(risk.recommended_priority, 0),
            risk.likelihood * risk.impact,
            -risk.id,
        )
        if key > best_key:
            best_key, best_risk = key, risk
    return best_risk


def _incident_sort_key(incident):
    priority_rank, score = _incident_risk_key(incident)
    return (
        -_SEVERITY_RANK.get(incident.severity, 0),
        -priority_rank,
        -score,
        incident.created_at,
        incident.id,
    )


@dataclass
class PriorityCluster:
    """One unit of work: a set of open incidents that share at least one
    affected system, ranked most urgent first."""

    incidents: list = field(default_factory=list)
    systems: list = field(default_factory=list)  # display labels, sorted

    @property
    def lead_incident(self):
        return self.incidents[0]

    @property
    def max_severity(self) -> str:
        return max(
            self.incidents, key=lambda i: _SEVERITY_RANK.get(i.severity, 0)
        ).severity

    @property
    def best_risk_key(self) -> tuple[int, int]:
        return max((_incident_risk_key(i) for i in self.incidents), default=(0, 0))

    @property
    def oldest_created_at(self):
        return min(i.created_at for i in self.incidents)

    @property
    def sort_key(self):
        max_severity_rank = max(
            _SEVERITY_RANK.get(i.severity, 0) for i in self.incidents
        )
        priority_rank, score = self.best_risk_key
        return (
            -max_severity_rank,
            -priority_rank,
            -score,
            self.oldest_created_at,
            min(i.id for i in self.incidents),
        )


def rank_open_incident_groups(organization) -> list[PriorityCluster]:
    """Every open incident for ``organization``, grouped by shared
    affected system and returned as clusters ordered most urgent first.
    Not capped -- callers take the slice they need."""
    incidents = list(
        IncidentGroup.objects.filter(
            organization=organization, status__in=_OPEN_STATUSES
        )
        .defer("summary", "ai_reasoning", "workflow_state")
        .prefetch_related(
            Prefetch(
                "risk_assessments",
                queryset=RiskAssessment.objects.only(
                    "id",
                    "incident_id",
                    "risk_title",
                    "risk_level",
                    "recommended_priority",
                    "likelihood",
                    "impact",
                ),
            )
        )
    )

    clusters = _cluster_by_shared_system(incidents)
    for cluster in clusters:
        cluster.incidents.sort(key=_incident_sort_key)
    clusters.sort(key=lambda cluster: cluster.sort_key)
    return clusters


def _cluster_by_shared_system(incidents) -> list[PriorityCluster]:
    parent = list(range(len(incidents)))

    def find(x: int) -> int:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    first_index_for_system: dict[str, int] = {}
    systems_per_incident: list[list[str]] = []
    for i, incident in enumerate(incidents):
        systems = _split_systems(incident.affected_systems)
        systems_per_incident.append(systems)
        for system in systems:
            key = system.lower()
            if key in first_index_for_system:
                union(first_index_for_system[key], i)
            else:
                first_index_for_system[key] = i

    grouped: dict[int, list[int]] = {}
    for i in range(len(incidents)):
        grouped.setdefault(find(i), []).append(i)

    clusters: list[PriorityCluster] = []
    for member_indexes in grouped.values():
        labels: list[str] = []
        seen: set[str] = set()
        for idx in member_indexes:
            for system in systems_per_incident[idx]:
                key = system.lower()
                if key not in seen:
                    seen.add(key)
                    labels.append(system)
        clusters.append(
            PriorityCluster(
                incidents=[incidents[idx] for idx in member_indexes],
                systems=sorted(labels, key=str.lower),
            )
        )
    return clusters


def build_priority_context(organization) -> str:
    clusters = rank_open_incident_groups(organization)
    total_open = sum(len(cluster.incidents) for cluster in clusters)
    shown_clusters = clusters[:MAX_PRIORITY_GROUPS]

    open_by_severity: Counter = Counter()
    for cluster in clusters:
        for incident in cluster.incidents:
            open_by_severity[incident.severity] += 1

    shown_by_severity: Counter = Counter()
    shown_incident_count = 0
    for cluster in shown_clusters:
        for incident in cluster.incidents[:MAX_INCIDENTS_PER_GROUP]:
            shown_by_severity[incident.severity] += 1
            shown_incident_count += 1

    sections = [
        _overview_section(
            organization,
            total_open,
            len(clusters),
            len(shown_clusters),
            shown_incident_count,
            open_by_severity,
            shown_by_severity,
        ),
        _clusters_section(shown_clusters),
    ]
    return "\n\n".join(sections)


def _overview_section(
    organization,
    total_open,
    group_count,
    shown_group_count,
    shown_incident_count,
    open_by_severity,
    shown_by_severity,
):
    lines = [
        "## Open Incident Overview",
        f"Organization: {organization.name}",
        f"Total open incidents: {total_open}",
    ]
    if total_open == 0:
        lines.append("No open incidents right now.")
        return "\n".join(lines)

    coverage = _coverage_statement(
        total_open, shown_incident_count, open_by_severity, shown_by_severity
    )
    if coverage:
        lines.append(coverage)

    if shown_incident_count < total_open:
        lines.append(
            f"Showing {shown_group_count} of {group_count} incident group(s) "
            f"below, covering {shown_incident_count} of {total_open} open "
            "incidents, ranked by severity, then risk, then age."
        )
    else:
        lines.append(
            f"All {total_open} open incident(s) are shown below, grouped into "
            f"{group_count} group(s) by affected system and ranked by severity, "
            "then risk, then age."
        )
    return "\n".join(lines)


def _coverage_statement(
    total_open, shown_incident_count, open_by_severity, shown_by_severity
):
    """The explicit fact that stops the model hedging about hidden worse
    work when there is none -- and tells it to hedge when there is."""
    if shown_incident_count >= total_open:
        return None  # the "all shown" overview line already says everything

    critical = IncidentGroup.Severity.CRITICAL
    high = IncidentGroup.Severity.HIGH
    open_critical = open_by_severity.get(critical, 0)
    shown_critical = shown_by_severity.get(critical, 0)
    open_high = open_by_severity.get(high, 0)
    shown_high = shown_by_severity.get(high, 0)

    if open_critical and shown_critical < open_critical:
        hidden = open_critical - shown_critical
        return (
            f"COVERAGE: {shown_critical} of {open_critical} open "
            f"Critical-severity incidents are shown below -- {hidden} Critical "
            "incident(s) are NOT listed. This is a partial view of the most "
            "urgent tier; say so plainly."
        )

    if not open_critical and open_high and shown_high < open_high:
        hidden = open_high - shown_high
        return (
            "COVERAGE: there are no open Critical-severity incidents. "
            f"{shown_high} of {open_high} open High-severity incidents are "
            f"shown below -- {hidden} High incident(s) are not listed."
        )

    covered = []
    if open_critical:
        covered.append(f"every open Critical-severity incident ({open_critical})")
    if open_high:
        covered.append(f"every open High-severity incident ({open_high})")
    if not covered:
        return (
            "COVERAGE: there are no open Critical- or High-severity incidents. "
            "The groups below are the most urgent open work -- nothing more "
            "severe is hidden by the cap."
        )
    return (
        "COVERAGE: the groups below include "
        + " and ".join(covered)
        + ". Every open incident not shown below is severity Medium or lower. "
        "Do not suggest that a more urgent incident might be hidden -- the most "
        "severe work is fully represented here."
    )


def _clusters_section(clusters):
    if not clusters:
        return "## Open Incidents\nNone."

    now = timezone.now()
    lines = ["## Open Incidents (grouped by affected system, most urgent first)"]
    for rank, cluster in enumerate(clusters, start=1):
        systems_label = ", ".join(cluster.systems) if cluster.systems else "Unknown system"
        shown = cluster.incidents[:MAX_INCIDENTS_PER_GROUP]
        hidden = len(cluster.incidents) - len(shown)
        count = len(cluster.incidents)

        header_bits = [f"max severity {_severity_label(cluster.max_severity)}"]
        _, best_score = cluster.best_risk_key
        if best_score:
            header_bits.append(f"highest risk {best_score}/25")
        oldest_days = max((now - cluster.oldest_created_at).days, 0)
        header_bits.append(f"oldest open {oldest_days} day{_plural(oldest_days)}")

        lines.append(
            f"{rank}. {systems_label} -- {count} open incident{_plural(count)} "
            f"({', '.join(header_bits)})"
        )
        for incident in shown:
            days_open = max((now - incident.created_at).days, 0)
            lines.append(
                f'   - Incident #{incident.id} "{incident.title}" -- '
                f"severity={incident.get_severity_display()}, "
                f"status={incident.get_status_display()}, "
                f"open for {days_open} day{_plural(days_open)}"
            )
            risk = _incident_best_risk(incident)
            if risk:
                lines.append(
                    f"       Risk: {risk.risk_title} (score={risk.risk_score}/25, "
                    f"level={risk.get_risk_level_display()}, "
                    f"recommended priority={risk.get_recommended_priority_display()})"
                )
            else:
                lines.append("       Risk: no formal risk assessment recorded yet.")
        if hidden > 0:
            lines.append(
                f"   - ...and {hidden} more open incident{_plural(hidden)} on "
                "this system not shown."
            )
    return "\n".join(lines)
