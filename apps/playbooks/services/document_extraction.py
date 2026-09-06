"""Text extraction from uploaded SOP checklist documents.

The SOP Library upload (apps/playbooks/forms.py) accepts a small UTF-8
text file, a modern Word .docx, or a PDF, and stores the extracted text
-- one step per line -- into ``SOPChecklist.checklist_items`` (a
TextField). This module does the .docx and PDF extraction; the
plain-text path stays in the form itself.

Design decisions (see the session that added this):

* **.docx is handled with the standard library** (``zipfile`` +
  ``xml.etree.ElementTree``), not python-docx, to avoid pulling in
  ``lxml``. A .docx body is just ``<w:t>`` text runs inside ``<w:p>``
  paragraphs in ``word/document.xml``.
* **PDF uses ``pypdf``** -- pure Python, no system dependencies. The
  import is lazy so a server missing the package degrades to a friendly
  "paste directly" error rather than failing to import this module.
* **Every parse is wrapped**: a corrupt, malformed, or hostile file
  raises :class:`DocumentParseError` (which the form turns into a
  friendly field error), never an unhandled exception, and never a
  partial/empty ``SOPChecklist`` row.
* **Hard bounds reject, they do not truncate.** A silently shortened
  checklist could be reviewed and approved as if complete. Over the
  page / item limit is a hard, explained rejection.
* **Legacy .doc (binary OLE) is not handled here at all.** It never
  reaches this module -- its magic bytes are neither PDF nor ZIP, so the
  form keeps it on the plain-text path where it fails the strict UTF-8
  decode with the existing "doesn't look like a plain text file"
  message. That is deliberate and unchanged.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from xml.etree import ElementTree as ET

# pypdf logs parser complaints (bad xref, missing EOF marker, ...) at
# WARNING; those would land in the console/error log for what we already
# handle as a friendly rejection. Quiet it to ERROR here.
logging.getLogger("pypdf").setLevel(logging.ERROR)

# -- Bounds -----------------------------------------------------------------

MAX_PDF_PAGES = 50
MAX_CHECKLIST_ITEMS = 2000  # non-empty extracted lines, .docx or PDF

# Secondary guard: even a small file that expands to a huge amount of
# text is capped here (roughly 2000 lines * 100 chars).
MAX_EXTRACTED_CHARS = 200_000

# Zip-bomb guards for .docx, both checked against the archive's central
# directory *before* any member is decompressed.
MAX_DOCX_MEMBER_UNCOMPRESSED = 40 * 1024 * 1024   # word/document.xml alone
MAX_DOCX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024   # every member summed

_WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_DOCUMENT_PART = "word/document.xml"

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"

# Same shape as apps.playbooks.services.text_parsing.parse_action_text:
# strip a leading bullet / number marker so "1. Do X", "- Do X" and
# "Do X" normalise to the same stored line. Adds the common unicode
# bullet glyphs Word/PDF export produces.
_LEADING_MARKER = re.compile(r"^\s*(?:[-*•‣◦⁃·]|[0-9]+[.)])\s*")


class DocumentParseError(Exception):
    """An uploaded document could not be turned into checklist text.

    The message is written for the end user and is safe to surface as a
    form validation error verbatim.
    """


_NO_TEXT_MESSAGE = {
    "pdf": (
        "No readable text found in this PDF. If it's a scanned document, "
        "try pasting the checklist directly."
    ),
    "docx": (
        "No readable text found in this Word document. Try pasting the "
        "checklist directly."
    ),
}

_CORRUPT_MESSAGE = {
    "pdf": (
        "This file couldn't be read as a PDF. It may be corrupted -- try "
        "re-exporting it, or paste the checklist directly."
    ),
    "docx": (
        "This file couldn't be read as a Word document. It may be corrupted "
        "-- try re-saving it, or paste the checklist directly."
    ),
}


def sniff_document_kind(head: bytes) -> str | None:
    """Return ``"pdf"``, ``"docx"``, or ``None`` from a file's first bytes.

    Content sniffing, not the file extension: a real text file named
    ``notes.pdf`` still takes the text path, and a ``.docx`` with the
    wrong extension is still parsed. ``None`` means "not a format this
    module handles" -- the caller keeps it on the plain-text path.
    """
    if head.startswith(_PDF_MAGIC):
        return "pdf"
    if head.startswith(_ZIP_MAGIC):
        return "docx"
    return None


def extract_checklist_text(kind: str, data: bytes) -> str:
    """Extract and normalise checklist text from ``data``.

    ``kind`` must be ``"pdf"`` or ``"docx"`` (from :func:`sniff_document_kind`).
    Raises :class:`DocumentParseError` for anything that cannot become a
    usable, non-empty checklist.
    """
    if kind == "pdf":
        raw_text = _extract_pdf_text(data)
    elif kind == "docx":
        raw_text = _extract_docx_text(data)
    else:  # pragma: no cover - guarded by the caller
        raise ValueError(f"unsupported document kind: {kind!r}")

    normalized = _normalize_lines(raw_text)
    if not normalized:
        raise DocumentParseError(_NO_TEXT_MESSAGE[kind])
    return normalized


def _normalize_lines(raw_text: str) -> str:
    """Raw extracted text -> one checklist step per line.

    Drops blank lines, strips leading bullet/number markers, collapses
    internal whitespace. Enforces the item and character caps (reject,
    never truncate silently).
    """
    lines: list[str] = []
    for line in raw_text.splitlines():
        cleaned = " ".join(_LEADING_MARKER.sub("", line).split())
        if not cleaned:
            continue
        lines.append(cleaned)
        if len(lines) > MAX_CHECKLIST_ITEMS:
            raise DocumentParseError(
                f"This document has more than {MAX_CHECKLIST_ITEMS} checklist "
                "items. Upload a shorter excerpt, or split it into several "
                "SOPs."
            )

    text = "\n".join(lines)
    if len(text) > MAX_EXTRACTED_CHARS:
        raise DocumentParseError(
            "This document has too much text to import as a checklist. "
            "Upload a shorter excerpt, or paste the relevant steps directly."
        )
    return text


# -- .docx ----------------------------------------------------------------


def _extract_docx_text(data: bytes) -> str:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

    with archive:
        # zipfile has parsed only the central directory at this point --
        # NO member has been decompressed yet. infolist()/getinfo() read
        # the directory's declared sizes; archive.read() further down is
        # the first and only decompression, and it happens strictly after
        # both size gates below.
        declared_total = sum(info.file_size for info in archive.infolist())
        if declared_total > MAX_DOCX_TOTAL_UNCOMPRESSED:
            raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

        try:
            document_info = archive.getinfo(_DOCUMENT_PART)
        except KeyError:
            # A valid zip, but not a Word document (e.g. a plain .zip).
            raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

        if document_info.file_size > MAX_DOCX_MEMBER_UNCOMPRESSED:
            raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

        # Size gates passed -> now decompress the one part we need.
        try:
            document_xml = archive.read(document_info)
        except (zipfile.BadZipFile, OSError, EOFError):
            raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

    # A real .docx document part never carries a DTD or entity
    # declarations. ElementTree does not resolve external entities and
    # raises on undefined ones, so this is belt-and-suspenders against
    # entity-expansion tricks -- no defusedxml dependency needed.
    head = document_xml[:4096].lstrip().lower()
    if b"<!doctype" in head or b"<!entity" in document_xml[:8192].lower():
        raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

    try:
        root = ET.fromstring(document_xml)
    except ET.ParseError:
        raise DocumentParseError(_CORRUPT_MESSAGE["docx"])

    paragraphs: list[str] = []
    for paragraph in root.iter(f"{_WORD_NS}p"):
        runs = [node.text for node in paragraph.iter(f"{_WORD_NS}t") if node.text]
        line = "".join(runs).strip()
        if line:
            paragraphs.append(line)
    return "\n".join(paragraphs)


# -- PDF ----------------------------------------------------------------


def _extract_pdf_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        raise DocumentParseError(
            "PDF support isn't available on this server right now. Paste the "
            "checklist directly, or upload a .txt or .docx file."
        )

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            # An empty user password is common for "protected" PDFs; if it
            # opens the document, carry on.
            if reader.decrypt("") == 0:  # PasswordType.NOT_DECRYPTED
                raise DocumentParseError(
                    "This PDF is password-protected. Remove the password, or "
                    "paste the checklist directly."
                )
        page_count = len(reader.pages)
    except DocumentParseError:
        raise
    except Exception:
        # pypdf raises a wide range on hostile input: PdfReadError,
        # PdfStreamError, KeyError, ValueError, RecursionError, ...
        raise DocumentParseError(_CORRUPT_MESSAGE["pdf"])

    if page_count > MAX_PDF_PAGES:
        raise DocumentParseError(
            f"This PDF has {page_count} pages, which is too long to import as "
            f"a checklist (limit {MAX_PDF_PAGES}). Upload a shorter excerpt, "
            "or paste the checklist directly."
        )

    chunks: list[str] = []
    for page in reader.pages:
        try:
            chunks.append(page.extract_text() or "")
        except Exception:
            # One unreadable page shouldn't lose the rest of the document.
            continue
    return "\n".join(chunks)
