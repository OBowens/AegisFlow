from django import forms


class SOPChecklistForm(forms.Form):
    # An uploaded checklist is read straight into SOPChecklist.checklist_items
    # (a TextField), so this form only accepts a small UTF-8 text file. Binary
    # documents (.doc/.docx/.pdf) are NOT parsed -- they are rejected here,
    # before the database is touched, rather than being best-effort decoded
    # into a string that slips past validation and then 500s on insert
    # (Postgres text columns cannot store NUL bytes).
    MAX_CHECKLIST_FILE_SIZE = 2 * 1024 * 1024  # 2 MB

    NOT_TEXT_FILE_ERROR = (
        "This doesn't look like a plain text file. Please upload a .txt or "
        ".md file, or paste the checklist directly."
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
            "Plain text file (.txt or .md), one step per line, max 2 MB. "
            "Used instead of pasted text if both are given."
        ),
        widget=forms.ClearableFileInput(attrs={"accept": ".txt,.md"}),
    )

    def clean_checklist_file(self):
        checklist_file = self.cleaned_data.get("checklist_file")
        if not checklist_file:
            return checklist_file

        if checklist_file.size > self.MAX_CHECKLIST_FILE_SIZE:
            raise forms.ValidationError(
                "That file is too large. Upload a plain text checklist under "
                "2 MB, or paste the checklist directly."
            )

        # Strict decode: no errors="ignore" fallback that would silently turn
        # binary bytes into a lossy string. A real text file decodes cleanly.
        try:
            decoded = checklist_file.read().decode("utf-8")
        except UnicodeDecodeError:
            raise forms.ValidationError(self.NOT_TEXT_FILE_ERROR)

        # UTF-8 will happily decode a NUL byte (U+0000); Postgres text columns
        # reject it. Catch it here rather than at INSERT time.
        if "\x00" in decoded:
            raise forms.ValidationError(self.NOT_TEXT_FILE_ERROR)

        self._decoded_checklist_file = decoded
        return checklist_file

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
