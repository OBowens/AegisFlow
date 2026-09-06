from django import forms

from .services.document_extraction import (
    DocumentParseError,
    extract_checklist_text,
    sniff_document_kind,
)


class SOPChecklistForm(forms.Form):
    # An uploaded checklist is read into SOPChecklist.checklist_items (a
    # TextField), so uploads are validated here, before the database is
    # touched. Three formats are accepted:
    #   * plain UTF-8 text (.txt/.md) -- decoded strictly, NUL bytes
    #     rejected (Postgres text columns can't store them);
    #   * modern Word .docx and PDF -- text extracted via
    #     services/document_extraction.py.
    # Legacy .doc (binary OLE) is NOT supported: its magic bytes are
    # neither PDF nor ZIP, so it falls to the text path and fails the
    # strict decode with NOT_TEXT_FILE_ERROR -- unchanged behaviour.
    MAX_TEXT_FILE_SIZE = 2 * 1024 * 1024  # 2 MB -- plain-text path
    MAX_DOCUMENT_FILE_SIZE = 10 * 1024 * 1024  # 10 MB -- .docx / PDF path

    NOT_TEXT_FILE_ERROR = (
        "This doesn't look like a plain text file. Please upload a .txt, .md, "
        ".docx or PDF file, or paste the checklist directly."
    )

    name = forms.CharField(
        label="SOP name",
        max_length=255,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    incident_type = forms.CharField(
        label="Incident type",
        max_length=100,
        help_text=(
            "Must match an incident's type exactly to auto-attach (e.g. "
            "“failed_login”, “service_stopped”, “sensor_down”). "
            "A close-but-not-exact value can still match by keyword."
        ),
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    version = forms.CharField(
        label="Version",
        max_length=50,
        initial="1.0",
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    checklist_text = forms.CharField(
        label="Checklist items (pasted text)",
        required=False,
        help_text="One step per line. Leading -, *, or numbering is stripped automatically.",
        widget=forms.Textarea(attrs={"class": "upload-notes", "rows": 8}),
    )
    checklist_file = forms.FileField(
        label="...or upload a checklist file",
        required=False,
        help_text=(
            "Plain text (.txt, .md), Word (.docx), or PDF — one step per line, "
            "max 10 MB. Legacy .doc files aren't supported; save as .docx or "
            "paste the checklist directly."
        ),
        widget=forms.ClearableFileInput(attrs={"accept": ".txt,.md,.docx,.pdf"}),
    )

    def clean_checklist_file(self):
        checklist_file = self.cleaned_data.get("checklist_file")
        if not checklist_file:
            return checklist_file

        # Hard ceiling checked from the upload's own size before any read,
        # so an oversized file never gets pulled into memory.
        if checklist_file.size > self.MAX_DOCUMENT_FILE_SIZE:
            raise forms.ValidationError(
                "That file is too large. Upload a checklist under 10 MB, or "
                "paste the checklist directly."
            )

        data = checklist_file.read()
        kind = sniff_document_kind(data[:8])

        if kind is None:
            self._decoded_checklist_file = self._clean_text_upload(data)
        else:
            self._decoded_checklist_file = self._clean_document_upload(kind, data)

        return checklist_file

    def _clean_text_upload(self, data: bytes) -> str:
        if len(data) > self.MAX_TEXT_FILE_SIZE:
            raise forms.ValidationError(
                "That text file is too large. Upload a plain text checklist "
                "under 2 MB, or paste the checklist directly."
            )

        # Strict decode: no errors="ignore" fallback that would silently
        # turn binary bytes into a lossy string. A real text file decodes
        # cleanly.
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            raise forms.ValidationError(self.NOT_TEXT_FILE_ERROR)

        # UTF-8 will happily decode a NUL byte (U+0000); Postgres text
        # columns reject it. Catch it here rather than at INSERT time.
        if "\x00" in decoded:
            raise forms.ValidationError(self.NOT_TEXT_FILE_ERROR)

        return decoded

    def _clean_document_upload(self, kind: str, data: bytes) -> str:
        try:
            return extract_checklist_text(kind, data)
        except DocumentParseError as exc:
            raise forms.ValidationError(str(exc))

    def clean(self):
        cleaned_data = super().clean()
        checklist_text = (cleaned_data.get("checklist_text") or "").strip()
        checklist_file = cleaned_data.get("checklist_file")

        if checklist_file:
            content = getattr(self, "_decoded_checklist_file", "").strip()
            if not content:
                raise forms.ValidationError("The uploaded checklist file appears to be empty.")
            cleaned_data["checklist_items"] = content
        elif checklist_text:
            cleaned_data["checklist_items"] = checklist_text
        elif "checklist_file" not in self.errors:
            # A file that failed its own validation already has a clear,
            # field-level error -- don't also raise this misleading one.
            raise forms.ValidationError(
                "Provide checklist items either as pasted text or an uploaded file."
            )

        return cleaned_data
