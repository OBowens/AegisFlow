from pathlib import Path

from django import forms

from .models import UploadedLogFile


class UploadLogFileForm(forms.Form):
    allowed_extensions = {".txt", ".log", ".json", ".csv"}
    max_file_size = 5 * 1024 * 1024

    log_file = forms.FileField(
        label="Log or report file",
        help_text="Accepted file types: .txt, .log, .json, .csv (max 5 MB).",
        widget=forms.ClearableFileInput(
            attrs={"accept": ".txt,.log,.json,.csv"}
        ),
    )
    source_type = forms.ChoiceField(
        label="Source type",
        choices=UploadedLogFile.SourceType.choices,
    )
    notes = forms.CharField(
        label="Notes",
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "Add any context about this sample upload.",
            }
        ),
    )

    def clean_log_file(self):
        uploaded_file = self.cleaned_data["log_file"]
        suffix = Path(uploaded_file.name).suffix.lower()

        if suffix not in self.allowed_extensions:
            raise forms.ValidationError(
                "Unsupported file type. Please upload a .txt, .log, .json, or .csv file."
            )

        if uploaded_file.size > self.max_file_size:
            raise forms.ValidationError(
                "File is too large. Please upload a file smaller than 5 MB."
            )

        return uploaded_file
