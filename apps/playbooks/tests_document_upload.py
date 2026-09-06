"""Coverage for .docx / PDF SOP checklist uploads.

The SOP Library upload accepts a plain UTF-8 text file, a modern Word
.docx, or a PDF. Text extraction for the latter two lives in
apps/playbooks/services/document_extraction.py; this file covers both
that service directly and the form/view path end to end, including the
honest-failure cases (scanned PDF, corrupt file, legacy .doc, over the
size/page/item bounds).

Small binary fixtures live in apps/playbooks/tests_fixtures/ and were
generated once (see the commit that added them):
  * sample_checklist.docx  -- 5 real checklist paragraphs
  * sample_checklist.pdf   -- the same 5 lines as a text PDF
  * scanned_no_text.pdf    -- a valid one-page PDF with no text operators
  * protected.pdf          -- sample_checklist.pdf, user password "s3cret"
"""

import io
import zipfile
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.playbooks.models import SOPChecklist
from apps.playbooks.services.document_extraction import (
    DocumentParseError,
    extract_checklist_text,
    sniff_document_kind,
)

FIXTURES = Path(__file__).parent / "tests_fixtures"

EXPECTED_LINES = (
    "Isolate the affected workstation from the network\n"
    "Collect volatile memory and a full disk image\n"
    "Notify the security lead and the system owner\n"
    "Reset credentials for every account used on the host\n"
    "Document all actions taken with timestamps"
)

_WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_CONTENT_TYPES = (
    '<?xml version="1.0"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>'
)


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _build_docx(document_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _docx_with_paragraphs(lines) -> bytes:
    body = "".join(f"<w:p><w:r><w:t>{line}</w:t></w:r></w:p>" for line in lines)
    return _build_docx(
        f'<?xml version="1.0"?><w:document xmlns:w="{_WORD_NS}"><w:body>{body}</w:body></w:document>'
    )


def _many_page_pdf(page_count: int) -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(page_count):
        writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


class SniffDocumentKindTests(TestCase):
    def test_pdf_magic(self):
        self.assertEqual(sniff_document_kind(b"%PDF-1.7\n..."), "pdf")

    def test_zip_magic_is_docx(self):
        self.assertEqual(sniff_document_kind(b"PK\x03\x04\x14\x00"), "docx")

    def test_plain_text_is_none(self):
        self.assertIsNone(sniff_document_kind(b"Step one\nStep two"))

    def test_legacy_doc_ole_magic_is_none(self):
        # A .doc is an OLE compound file -- not our concern, stays on the
        # plain-text path where it fails the strict decode.
        self.assertIsNone(sniff_document_kind(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))


class ExtractChecklistTextTests(TestCase):
    def test_docx_extracts_one_line_per_paragraph(self):
        result = extract_checklist_text("docx", _fixture("sample_checklist.docx"))
        self.assertEqual(result, EXPECTED_LINES)

    def test_pdf_extracts_one_line_per_row(self):
        result = extract_checklist_text("pdf", _fixture("sample_checklist.pdf"))
        self.assertEqual(result, EXPECTED_LINES)

    def test_docx_strips_bullets_and_numbering(self):
        raw = _docx_with_paragraphs(["1. First step", "- Second step", "• Third step"])
        self.assertEqual(
            extract_checklist_text("docx", raw), "First step\nSecond step\nThird step"
        )

    def test_scanned_pdf_with_no_text_layer_is_rejected(self):
        with self.assertRaises(DocumentParseError) as ctx:
            extract_checklist_text("pdf", _fixture("scanned_no_text.pdf"))
        self.assertIn("No readable text found in this PDF", str(ctx.exception))

    def test_empty_docx_is_rejected(self):
        with self.assertRaises(DocumentParseError) as ctx:
            extract_checklist_text("docx", _docx_with_paragraphs([]))
        self.assertIn("No readable text", str(ctx.exception))

    def test_password_protected_pdf_is_rejected(self):
        with self.assertRaises(DocumentParseError) as ctx:
            extract_checklist_text("pdf", _fixture("protected.pdf"))
        self.assertIn("password-protected", str(ctx.exception))

    def test_corrupt_docx_raises_document_parse_error_not_a_crash(self):
        with self.assertRaises(DocumentParseError):
            extract_checklist_text("docx", _fixture("sample_checklist.docx")[:150])

    def test_zip_that_is_not_a_word_document_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "not a word doc")
        with self.assertRaises(DocumentParseError):
            extract_checklist_text("docx", buf.getvalue())

    def test_corrupt_pdf_raises_document_parse_error_not_a_crash(self):
        with self.assertRaises(DocumentParseError):
            extract_checklist_text("pdf", b"%PDF-1.4\n" + b"\xde\xad\xbe\xef" * 64)

    def test_docx_with_a_doctype_declaration_is_rejected(self):
        raw = _build_docx(
            '<?xml version="1.0"?><!DOCTYPE w:document ['
            '<!ENTITY x "boom">]>'
            f'<w:document xmlns:w="{_WORD_NS}"><w:body>'
            "<w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>"
        )
        with self.assertRaises(DocumentParseError):
            extract_checklist_text("docx", raw)

    def test_pdf_over_the_page_limit_is_rejected_not_truncated(self):
        with self.assertRaises(DocumentParseError) as ctx:
            extract_checklist_text("pdf", _many_page_pdf(55))
        self.assertIn("55 pages", str(ctx.exception))

    def test_docx_over_the_item_limit_is_rejected_not_truncated(self):
        raw = _docx_with_paragraphs([f"Step {n}" for n in range(2100)])
        with self.assertRaises(DocumentParseError) as ctx:
            extract_checklist_text("docx", raw)
        self.assertIn("2000 checklist items", str(ctx.exception))

    def test_docx_size_guard_runs_before_any_member_is_decompressed(self):
        # document.xml's central-directory entry claims ~45 MB uncompressed
        # (over MAX_DOCX_MEMBER_UNCOMPRESSED) but deflates tiny. The guard
        # must reject from ZipInfo.file_size *before* archive.read() inflates
        # anything -- proven here by making archive.read() blow up if called.
        bomb = _build_docx("<x/>" + " " * (45 * 1024 * 1024))

        def _fail_on_read(self, *args, **kwargs):
            raise AssertionError("archive.read() called before the size guard")

        with mock.patch.object(zipfile.ZipFile, "read", _fail_on_read):
            with self.assertRaises(DocumentParseError):
                extract_checklist_text("docx", bomb)


class SOPDocumentUploadViewTests(AuthedTestCase):
    def setUp(self):
        self.url = reverse("playbooks:sops")

    def _post(self, filename, content, content_type):
        return self.client.post(
            self.url,
            {
                "name": f"Upload {filename}",
                "incident_type": "malware",
                "version": "1.0",
                "checklist_file": SimpleUploadedFile(filename, content, content_type=content_type),
            },
        )

    def test_real_docx_upload_creates_draft_with_extracted_lines(self):
        response = self._post(
            "procedure.docx",
            _fixture("sample_checklist.docx"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.assertEqual(response.status_code, 302)
        created = SOPChecklist.objects.get(name="Upload procedure.docx")
        self.assertFalse(created.is_active)
        self.assertEqual(created.checklist_items, EXPECTED_LINES)

    def test_real_pdf_upload_creates_draft_with_extracted_lines(self):
        response = self._post(
            "procedure.pdf", _fixture("sample_checklist.pdf"), "application/pdf"
        )
        self.assertEqual(response.status_code, 302)
        created = SOPChecklist.objects.get(name="Upload procedure.pdf")
        self.assertFalse(created.is_active)
        self.assertEqual(created.checklist_items, EXPECTED_LINES)

    def test_scanned_pdf_shows_honest_error_and_creates_no_row(self):
        response = self._post(
            "scan.pdf", _fixture("scanned_no_text.pdf"), "application/pdf"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No readable text found in this PDF")
        self.assertFalse(SOPChecklist.objects.filter(name="Upload scan.pdf").exists())

    def test_corrupt_docx_shows_friendly_error_not_a_crash(self):
        response = self._post(
            "broken.docx",
            _fixture("sample_checklist.docx")[:150],
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "couldn&#x27;t be read as a Word document")
        self.assertFalse(SOPChecklist.objects.filter(name="Upload broken.docx").exists())

    def test_corrupt_pdf_shows_friendly_error_not_a_crash(self):
        response = self._post(
            "broken.pdf", b"%PDF-1.4\n" + b"\xde\xad\xbe\xef" * 64, "application/pdf"
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "couldn&#x27;t be read as a PDF")
        self.assertFalse(SOPChecklist.objects.filter(name="Upload broken.pdf").exists())

    def test_legacy_doc_still_rejected_with_the_existing_plain_text_message(self):
        # Regression: a binary .doc must not quietly start being accepted
        # now that .docx/PDF are. OLE magic -> not PDF, not ZIP -> text
        # path -> strict decode fails.
        doc_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 256 + b"SOP body"
        response = self._post("legacy.doc", doc_bytes, "application/msword")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "look like a plain text file")
        self.assertFalse(SOPChecklist.objects.filter(name="Upload legacy.doc").exists())

    def test_docx_upload_is_audited_as_a_draft(self):
        user = get_user_model().objects.create_user(username="doc-analyst")
        self.client.force_login(user)
        self._post(
            "audited.docx",
            _fixture("sample_checklist.docx"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        from apps.audit.models import AuditLog

        created = SOPChecklist.objects.get(name="Upload audited.docx")
        self.assertTrue(
            AuditLog.objects.filter(
                action="sop_draft_created", target_id=str(created.id)
            ).exists()
        )
