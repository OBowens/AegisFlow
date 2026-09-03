"""One-time backfill: re-derive severity_hint on already-persisted
graylog-sourced ParsedAlert rows using the current graylog_parser logic
(see the facility == "backup" severity fix), without re-running the
upload/parse pipeline. Also cascades to IncidentGroup.severity (and, since some incident titles
embed the severity word, .title too) for any incident whose evidence
changed -- both are snapshots taken once at grouping time
(apps/incidents/services/grouping.py), not live-derived values, so they'd
otherwise keep showing the pre-fix severity forever, and the title would
end up contradicting the corrected severity pill.

Each ParsedAlert row's raw_message is exactly the single JSON line
graylog_parser originally produced it from (json.dumps(record, ...) in
_to_event), so feeding it back through the public parse_graylog_log()
entry point re-derives a fresh event with today's logic -- no private
functions, no re-reading the original uploaded file. Only severity_hint
is ever written on ParsedAlert; event_type, confidence_score, etc. are
left exactly as originally parsed.

An incident's new severity is the worst (highest-ranked) severity_hint
across its current evidence, mirroring grouping.py's own assumption that
every alert in one incident shares a single severity -- only incidents
with at least one alert whose severity_hint actually changes are touched.
The new title is recomputed with grouping.py's own _build_incident_title,
fed the incident's current incident_type/affected_systems/evidence, so it
stays byte-for-byte what grouping would produce today -- no reimplemented
title logic to drift out of sync.

Defaults to a dry run (report only, no writes). Pass --apply to write.

Usage:
    python manage.py backfill_graylog_severity            # dry run
    python manage.py backfill_graylog_severity --apply     # write changes
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.incidents.models import IncidentEvidence, IncidentGroup
from apps.incidents.services.grouping import _build_incident_title
from apps.log_intake.models import ParsedAlert
from apps.log_intake.services.graylog_parser import parse_graylog_log

_SEVERITY_RANK = {"unknown": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}


class Command(BaseCommand):
    help = (
        "Re-derive severity_hint for existing graylog-sourced ParsedAlert rows "
        "using the current graylog_parser logic, and cascade the change to "
        "IncidentGroup.severity for any incident whose evidence changed. Dry "
        "run by default; pass --apply to write changes."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Actually update the affected rows. Without this flag, only reports what would change.",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]

        alert_changes = self._find_alert_changes()
        self._report_alert_changes(alert_changes)

        # Scoped from live evidence data (not "alerts changed in this run")
        # so this stays correct and idempotent on a re-run after the
        # ParsedAlert half has already been applied -- the incident-level
        # gap wouldn't otherwise be detected once alert_changes is empty.
        incident_changes = self._find_incident_changes(alert_changes)
        self._report_incident_changes(incident_changes)

        if not alert_changes and not incident_changes:
            return

        if not apply_changes:
            self.stdout.write(
                self.style.NOTICE("Dry run only -- pass --apply to write these changes.")
            )
            return

        with transaction.atomic():
            for alert, _old_severity, new_severity in alert_changes:
                alert.severity_hint = new_severity
                alert.save(update_fields=["severity_hint"])
            for incident, _old_severity, new_severity, _old_title, new_title in incident_changes:
                incident.severity = new_severity
                incident.title = new_title
                incident.save(update_fields=["severity", "title"])

        self.stdout.write(
            self.style.SUCCESS(
                f"Updated {len(alert_changes)} ParsedAlert row(s) and "
                f"{len(incident_changes)} IncidentGroup row(s)."
            )
        )

    def _find_alert_changes(self):
        alerts = ParsedAlert.objects.filter(source_tool="graylog").order_by("id")
        changes = []
        unparseable = []

        for alert in alerts:
            events = parse_graylog_log(alert.raw_message, source_tool=alert.source_tool)
            if not events:
                unparseable.append(alert.id)
                continue

            recomputed_severity = events[0].severity_hint
            if recomputed_severity != alert.severity_hint:
                changes.append((alert, alert.severity_hint, recomputed_severity))

        self._unparseable_alert_ids = unparseable
        self._scanned_alert_count = alerts.count()
        return changes

    def _report_alert_changes(self, alert_changes):
        self.stdout.write(f"Scanned {self._scanned_alert_count} graylog-sourced ParsedAlert row(s).")
        if self._unparseable_alert_ids:
            self.stdout.write(
                self.style.WARNING(
                    f"Skipped {len(self._unparseable_alert_ids)} row(s) with unparseable "
                    f"raw_message: {self._unparseable_alert_ids}"
                )
            )

        if not alert_changes:
            self.stdout.write(self.style.SUCCESS("No ParsedAlert rows need a severity_hint change."))
            return

        self.stdout.write(f"{len(alert_changes)} ParsedAlert row(s) would change severity_hint:")
        for alert, old_severity, new_severity in alert_changes:
            self.stdout.write(
                f"  alert id={alert.id} event_type={alert.event_type} "
                f"affected_system={alert.affected_system} {old_severity} -> {new_severity}"
            )

    def _find_incident_changes(self, alert_changes):
        # Effective severity per alert: the pending new value if this run is
        # about to change it, otherwise whatever's already in the DB (which
        # already reflects any earlier, already-applied run).
        updated_severity_by_alert_id = {alert.id: new for alert, _old, new in alert_changes}

        candidate_incident_ids = (
            IncidentEvidence.objects.filter(alert__source_tool="graylog")
            .values_list("incident_id", flat=True)
            .distinct()
        )

        changes = []
        for incident in IncidentGroup.objects.filter(id__in=candidate_incident_ids).order_by("id"):
            evidence_alerts = [evidence.alert for evidence in incident.evidence_items.select_related("alert")]
            if not evidence_alerts:
                continue

            effective_severities = [
                updated_severity_by_alert_id.get(alert.id, alert.severity_hint)
                for alert in evidence_alerts
            ]
            worst_severity = max(
                effective_severities, key=lambda severity: _SEVERITY_RANK.get(severity, -1)
            )
            if worst_severity == incident.severity:
                continue

            new_title = _build_incident_title(
                incident.incident_type,
                incident.affected_systems,
                worst_severity,
                evidence_alerts,
            )
            changes.append((incident, incident.severity, worst_severity, incident.title, new_title))

        return changes

    def _report_incident_changes(self, incident_changes):
        if not incident_changes:
            return

        self.stdout.write(
            f"{len(incident_changes)} IncidentGroup row(s) would change severity "
            "(recomputed as the worst severity across current evidence) and title:"
        )
        for incident, old_severity, new_severity, old_title, new_title in incident_changes:
            self.stdout.write(f"  incident id={incident.id} severity {old_severity} -> {new_severity}")
            if old_title != new_title:
                self.stdout.write(f"    title {old_title!r} -> {new_title!r}")
