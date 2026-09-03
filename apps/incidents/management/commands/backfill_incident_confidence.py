"""One-time backfill: compute IncidentGroup.confidence for existing
incidents that predate apps/incidents/services/grouping.py wiring in
compute_incident_confidence() at creation time -- every incident grouped
before that change has confidence=None, same as the "T"/"A" contamination
incident that originally surfaced the fabricated-confidence bug.

Uses the exact same compute_incident_confidence() function real new
incidents get at grouping time, fed the incident's current linked
evidence (IncidentEvidence -> ParsedAlert.confidence_score) -- not a
separate/duplicated computation. Only ever touches incidents where
confidence is currently NULL; never recomputes or overwrites a value
that's already set. Incidents with no confidence-scored evidence stay
correctly unset (no value is invented) -- that is not a "skip due to
error", it's the same "don't show a confidence figure backed by
nothing" rule the whole feature exists to enforce.

Defaults to a dry run (report only, no writes). Pass --apply to write.

Usage:
    python manage.py backfill_incident_confidence            # dry run
    python manage.py backfill_incident_confidence --apply     # write changes
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from apps.incidents.models import IncidentGroup
from apps.incidents.services.confidence import compute_incident_confidence

SAMPLE_SIZE = 10


class Command(BaseCommand):
    help = (
        "Compute and persist IncidentGroup.confidence for existing incidents "
        "that predate the real confidence-scoring wiring (confidence currently "
        "NULL), from each incident's actual linked evidence. Dry run by "
        "default; pass --apply to write changes."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Actually update the affected rows. Without this flag, only reports what would change.",
        )

    def handle(self, *args, **options):
        apply_changes = options["apply"]

        candidates = IncidentGroup.objects.filter(confidence__isnull=True).order_by("id")
        total_candidates = candidates.count()

        changes = []
        no_signal = []

        for incident in candidates:
            evidence_alerts = [
                evidence.alert for evidence in incident.evidence_items.select_related("alert")
            ]
            computed = compute_incident_confidence(evidence_alerts)
            if computed is None:
                no_signal.append(incident)
            else:
                changes.append((incident, computed))

        self.stdout.write(f"Scanned {total_candidates} incident(s) with confidence currently unset.")
        self.stdout.write(
            f"{len(no_signal)} of those have no confidence-scored evidence and would stay "
            "unset -- not a skip, the correct outcome."
        )

        if not changes:
            self.stdout.write(self.style.SUCCESS("No incidents have real evidence to compute a confidence value from."))
            return

        self.stdout.write(f"{len(changes)} incident(s) would get a real, computed confidence value:")
        for incident, computed in changes[:SAMPLE_SIZE]:
            self.stdout.write(
                f"  incident id={incident.id} title={incident.title!r} "
                f"severity={incident.severity} evidence={incident.evidence_items.count()} "
                f"confidence: None -> {computed}"
            )
        if len(changes) > SAMPLE_SIZE:
            self.stdout.write(f"  ... and {len(changes) - SAMPLE_SIZE} more not shown.")

        if not apply_changes:
            self.stdout.write(
                self.style.NOTICE("Dry run only -- pass --apply to write these changes.")
            )
            return

        with transaction.atomic():
            for incident, computed in changes:
                incident.confidence = computed
                incident.save(update_fields=["confidence"])

        self.stdout.write(self.style.SUCCESS(f"Updated {len(changes)} IncidentGroup row(s)."))
