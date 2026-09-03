"""Manual testing tool for linux_auth_parser -- not part of the real pipeline.

Usage:
    python manage.py try_linux_parser /path/to/auth.log
"""

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.log_intake.services.linux_auth_parser import parse_linux_auth_log


class Command(BaseCommand):
    help = "Parse a Linux sshd auth log with linux_auth_parser and print the resulting events."

    def add_arguments(self, parser):
        parser.add_argument("file_path", type=str, help="Path to a sshd/journalctl auth log file")

    def handle(self, *args, **options):
        file_path = Path(options["file_path"]).expanduser()
        if not file_path.is_file():
            raise CommandError(f"No such file: {file_path}")

        raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
        events = parse_linux_auth_log(raw_text)

        if not events:
            self.stdout.write(self.style.WARNING("No events parsed from this file."))
            return

        for event in events:
            timestamp = event.timestamp.isoformat() if event.timestamp else "unknown-time"
            username = event.account or "-"
            self.stdout.write(
                f"{timestamp}  "
                f"user={username:<20} "
                f"event={event.event_type:<20} "
                f"severity={event.severity_hint:<8} "
                f"confidence={event.confidence_score:<5} "
                f"ip={event.source_ip}"
            )

        self.stdout.write(self.style.SUCCESS(f"\nParsed {len(events)} event(s) from {file_path}"))
