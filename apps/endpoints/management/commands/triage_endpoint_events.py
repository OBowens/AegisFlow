"""Run one correlation + AI-triage pass over recent Windows endpoint
events (feature Part 3).

Intended to be run on an interval by host cron, e.g. every 10 minutes:

    */10 * * * * cd /path/to/app && venv/bin/python manage.py triage_endpoint_events

This is deliberately a plain management command -- the repo has no
scheduled-job framework, and the only periodic-work precedent is the
``backfill_*`` commands. All logic lives in
``apps.endpoints.services.triage_run`` so it is testable without the
command.

    --dry-run          correlate and print candidates; write nothing, call no AI
    --max-candidates N  cap AI triage calls this run (default 8), so one run
                        cannot exhaust the shared hourly AI budget
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.endpoints.services.triage_run import DEFAULT_MAX_CANDIDATES, run_triage_scan


class Command(BaseCommand):
    help = "Correlate recent endpoint events and AI-triage the flagged clusters."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-candidates",
            type=int,
            default=DEFAULT_MAX_CANDIDATES,
            help=f"Max AI triage calls this run (default {DEFAULT_MAX_CANDIDATES}).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Correlate and print candidates only; write nothing, call no AI.",
        )

    def handle(self, *args, **options):
        report = run_triage_scan(
            max_candidates=options["max_candidates"],
            dry_run=options["dry_run"],
        )
        style = self.style.WARNING if report.dry_run else self.style.SUCCESS
        self.stdout.write(style(report.as_summary()))
