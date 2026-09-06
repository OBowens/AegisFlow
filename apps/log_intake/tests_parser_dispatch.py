"""End-to-end coverage for apps.log_intake.services.parser.DEDICATED_PARSERS
dispatch -- confirms that source types with a dedicated, format-aware parser
actually route to it through the real parse_uploaded_log() entry point,
rather than silently falling through to the generic extension-based parser.

The generic fallback path never sets confidence_score (it isn't part of the
kwargs passed to ParsedAlert.objects.create() in that branch), so a non-null
confidence_score on the resulting alerts is itself proof the dedicated
parser ran.
"""

from pathlib import Path

from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.ai_core.models import AliasMapping
from apps.log_intake.models import ParsedAlert, UploadedLogFile
from apps.log_intake.services.parser import parse_uploaded_log
from apps.organizations.models import Organization

FIXTURES_DIR = Path(settings.BASE_DIR) / "apps" / "log_intake" / "fixtures"


class DedicatedParserDispatchTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def _upload(self, *, file_name, source_type, fixture_name):
        return UploadedLogFile.objects.create(
            organization=self.organization,
            file_name=file_name,
            source_type=source_type,
            storage_path=str(FIXTURES_DIR / fixture_name),
            status=UploadedLogFile.Status.UPLOADED,
        )

    def test_firewall_dispatches_to_fortigate_parser(self):
        uploaded_file = self._upload(
            file_name="firewall.log",
            source_type=UploadedLogFile.SourceType.FIREWALL,
            fixture_name="firewall_fortigate_style_50.log",
        )

        alerts = parse_uploaded_log(uploaded_file)

        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.source_ip == "10.20.15.87" for alert in alerts))
        self.assertTrue(any(alert.destination_ip == "203.0.113.22" for alert in alerts))
        self.assertEqual(
            ParsedAlert.objects.filter(uploaded_file=uploaded_file).count(), len(alerts)
        )

    def test_backup_dispatches_to_backup_report_parser(self):
        uploaded_file = self._upload(
            file_name="backup.log",
            source_type=UploadedLogFile.SourceType.BACKUP,
            fixture_name="backup_report_60_lines.log",
        )

        alerts = parse_uploaded_log(uploaded_file)

        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.affected_system == "pbs01.example.local" for alert in alerts))
        self.assertTrue(any("Weekly-Full" in alert.raw_message for alert in alerts))

    def test_proxmox_dispatches_to_proxmox_syslog_parser(self):
        uploaded_file = self._upload(
            file_name="proxmox.log",
            source_type=UploadedLogFile.SourceType.PROXMOX,
            fixture_name="proxmox_syslog_50.log",
        )

        alerts = parse_uploaded_log(uploaded_file)

        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.source_ip == "198.51.100.44" for alert in alerts))
        self.assertTrue(any(alert.affected_system in {"pve01", "pve02", "pve03"} for alert in alerts))

    def test_source_types_without_a_dedicated_parser_still_use_the_generic_path(self):
        uploaded_file = UploadedLogFile.objects.create(
            organization=self.organization,
            file_name="other.log",
            source_type=UploadedLogFile.SourceType.OTHER,
            storage_path=str(FIXTURES_DIR / "firewall_fortigate_style_50.log"),
            status=UploadedLogFile.Status.UPLOADED,
        )

        alerts = parse_uploaded_log(uploaded_file)

        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is None for alert in alerts))


class DedicatedParserUploadViewTestCase(AuthedTestCase):
    """Drives the real /log_intake/upload/ view (form -> save -> parse ->
    group -> ...), same as a user uploading a file in the browser, for
    each of the 3 newly-wired source types.
    """

    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )
        self.stored_files = []
        self.addCleanup(self._delete_stored_files)

    def _delete_stored_files(self):
        for uploaded_file in UploadedLogFile.objects.filter(pk__in=self.stored_files):
            path = Path(settings.PRIVATE_UPLOAD_ROOT) / uploaded_file.storage_path
            path.unlink(missing_ok=True)

    def _post_upload(self, *, fixture_name, upload_name, source_type):
        fixture_bytes = (FIXTURES_DIR / fixture_name).read_bytes()
        response = self.client.post(
            reverse("log_intake:upload"),
            {
                "log_file": SimpleUploadedFile(upload_name, fixture_bytes),
                "source_type": source_type,
                "notes": "",
            },
        )
        self.assertEqual(response.status_code, 302)

        uploaded_file = UploadedLogFile.objects.get(file_name=upload_name)
        self.stored_files.append(uploaded_file.id)
        return uploaded_file

    def test_firewall_upload_dispatches_and_parses(self):
        uploaded_file = self._post_upload(
            fixture_name="firewall_fortigate_style_50.log",
            upload_name="e2e_firewall.log",
            source_type=UploadedLogFile.SourceType.FIREWALL,
        )

        self.assertEqual(uploaded_file.source_type, UploadedLogFile.SourceType.FIREWALL)
        alerts = list(ParsedAlert.objects.filter(uploaded_file=uploaded_file))
        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.source_ip == "10.20.15.87" for alert in alerts))

        results_response = self.client.get(
            reverse("log_intake:results", args=[uploaded_file.id])
        )
        self.assertEqual(results_response.status_code, 200)
        # The alert summary renders through {% alias_prose %}, so the source
        # IP shows as its stable alias, never the real value.
        ip_alias = AliasMapping.objects.get(
            organization=uploaded_file.organization,
            identifier_type="IP",
            real_value="10.20.15.87",
        )
        self.assertContains(results_response, ip_alias.display_alias)
        self.assertNotContains(results_response, "10.20.15.87")

    def test_backup_upload_dispatches_and_parses(self):
        uploaded_file = self._post_upload(
            fixture_name="backup_report_60_lines.log",
            upload_name="e2e_backup.log",
            source_type=UploadedLogFile.SourceType.BACKUP,
        )

        self.assertEqual(uploaded_file.source_type, UploadedLogFile.SourceType.BACKUP)
        alerts = list(ParsedAlert.objects.filter(uploaded_file=uploaded_file))
        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.affected_system == "pbs01.example.local" for alert in alerts))

        results_response = self.client.get(
            reverse("log_intake:results", args=[uploaded_file.id])
        )
        self.assertEqual(results_response.status_code, 200)

    def test_proxmox_upload_dispatches_and_parses(self):
        uploaded_file = self._post_upload(
            fixture_name="proxmox_syslog_50.log",
            upload_name="e2e_proxmox.log",
            source_type=UploadedLogFile.SourceType.PROXMOX,
        )

        self.assertEqual(uploaded_file.source_type, UploadedLogFile.SourceType.PROXMOX)
        alerts = list(ParsedAlert.objects.filter(uploaded_file=uploaded_file))
        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(alert.confidence_score is not None for alert in alerts))
        self.assertTrue(any(alert.source_ip == "198.51.100.44" for alert in alerts))

        results_response = self.client.get(
            reverse("log_intake:results", args=[uploaded_file.id])
        )
        self.assertEqual(results_response.status_code, 200)
