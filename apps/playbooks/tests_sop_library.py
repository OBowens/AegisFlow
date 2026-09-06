from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.audit.models import AuditLog

from .models import SOPChecklist


class SOPLibraryPageTestCase(AuthedTestCase):
    def setUp(self):
        self.url = reverse("playbooks:sops")
        self.sop = SOPChecklist.objects.create(
            name="Credential Review",
            incident_type="failed_login",
            checklist_items="Confirm the alert\nReview login history",
            version="1.3",
            is_active=True,
        )

    def test_library_uses_real_records_and_selected_preview(self):
        response = self.client.get(f"{self.url}?sop={self.sop.id}")

        self.assertContains(response, "SOP Library")
        self.assertContains(response, "Credential Review", count=2)
        self.assertContains(response, "Confirm the alert")
        self.assertContains(response, "Approved SOPs")
        self.assertNotContains(response, "Account Compromise")

    def test_search_filters_real_sops(self):
        SOPChecklist.objects.create(
            name="Backup Restore",
            incident_type="backup_failure",
            checklist_items="Check backup media",
            version="1.0",
        )

        response = self.client.get(f"{self.url}?q=Credential")

        self.assertContains(response, "Credential Review")
        self.assertNotContains(response, "Backup Restore")

    def test_created_sop_is_audited_draft(self):
        user = get_user_model().objects.create_user(username="analyst")
        self.client.force_login(user)

        response = self.client.post(
            self.url,
            {
                "name": "New Procedure",
                "incident_type": "sensor_down",
                "version": "1.0",
                "checklist_text": "Confirm scope\nNotify owner",
            },
        )

        self.assertEqual(response.status_code, 302)
        created = SOPChecklist.objects.get(name="New Procedure")
        self.assertFalse(created.is_active)
        self.assertTrue(
            AuditLog.objects.filter(
                action="sop_draft_created", target_id=str(created.id)
            ).exists()
        )

    def test_text_upload_creates_draft_without_fake_extraction(self):
        response = self.client.post(
            self.url,
            {
                "name": "Uploaded Checklist",
                "incident_type": "malware",
                "version": "1.0",
                "checklist_file": SimpleUploadedFile(
                    "procedure.txt", b"Isolate endpoint\nCollect logs", content_type="text/plain"
                ),
            },
        )

        self.assertEqual(response.status_code, 302)
        created = SOPChecklist.objects.get(name="Uploaded Checklist")
        self.assertFalse(created.is_active)
        self.assertEqual(created.checklist_items, "Isolate endpoint\nCollect logs")

    def test_binary_upload_is_rejected_with_friendly_error_not_500(self):
        # A real .doc is an OLE compound file full of NUL bytes. Previously this
        # decoded to a lossy string, slipped past the empty check, and 500'd at
        # INSERT ("A string literal cannot contain NUL (0x00) characters").
        doc_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512 + b"SOP body"

        response = self.client.post(
            self.url,
            {
                "name": "Binary Upload",
                "incident_type": "malware",
                "version": "1.0",
                "checklist_file": SimpleUploadedFile(
                    "procedure.doc", doc_bytes, content_type="application/msword"
                ),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "look like a plain text file")
        self.assertFalse(SOPChecklist.objects.filter(name="Binary Upload").exists())

    def test_text_file_with_embedded_nul_byte_is_rejected(self):
        response = self.client.post(
            self.url,
            {
                "name": "Nul Text",
                "incident_type": "malware",
                "version": "1.0",
                "checklist_file": SimpleUploadedFile(
                    "procedure.txt", b"Step one\x00Step two", content_type="text/plain"
                ),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "look like a plain text file")
        self.assertFalse(SOPChecklist.objects.filter(name="Nul Text").exists())

    def test_oversized_file_is_rejected_by_size_cap(self):
        oversized = SimpleUploadedFile(
            "huge.txt", b"a" * (61 * 1024 * 1024), content_type="text/plain"
        )

        response = self.client.post(
            self.url,
            {
                "name": "Oversized Upload",
                "incident_type": "malware",
                "version": "1.0",
                "checklist_file": oversized,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "That file is too large")
        self.assertFalse(SOPChecklist.objects.filter(name="Oversized Upload").exists())
