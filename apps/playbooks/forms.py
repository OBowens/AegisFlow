from django import forms


class SOPChecklistForm(forms.Form):
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
        help_text="Plain text file, one step per line. Used instead of pasted text if both are given.",
        widget=forms.ClearableFileInput(attrs={"accept": ".txt,.md"}),
    )

    def clean(self):
        cleaned_data = super().clean()
        checklist_text = (cleaned_data.get("checklist_text") or "").strip()
        checklist_file = cleaned_data.get("checklist_file")

        if checklist_file:
            content = checklist_file.read().decode("utf-8", errors="ignore").strip()
            if not content:
                raise forms.ValidationError("The uploaded checklist file appears to be empty.")
            cleaned_data["checklist_items"] = content
        elif checklist_text:
            cleaned_data["checklist_items"] = checklist_text
        else:
            raise forms.ValidationError(
                "Provide checklist items either as pasted text or an uploaded file."
            )

        return cleaned_data
