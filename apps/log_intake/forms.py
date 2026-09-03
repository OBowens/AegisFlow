from pathlib import Path

from django import forms

from .models import UploadedLogFile


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    """A FileField whose widget accepts multiple files, cleaning each one."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            return [single_file_clean(item, initial) for item in data]
        return single_file_clean(data, initial)


class UploadLogFileForm(forms.Form):
    allowed_extensions = {".txt", ".log", ".json", ".jsonl", ".csv"}
    max_file_size = 5 * 1024 * 1024

    log_file = MultipleFileField(
        label="Log or report files",
        help_text="Accepted file types: .txt, .log, .json, .jsonl, .csv (max 5 MB each). Select multiple files to upload them together.",
        widget=MultipleFileInput(
            attrs={"accept": ".txt,.log,.json,.jsonl,.csv"}
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
                "placeholder": "Add any context about these logs (e.g., time range, system, event)...",
            }
        ),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["log_file"].widget.attrs.update(
            {
                "class": "upload-native-input",
                "data-file-input": "true",
            }
        )
        self.fields["source_type"].widget.attrs.update(
            {
                "class": "upload-select",
                "data-source-type-select": "true",
            }
        )
        self.fields["notes"].widget.attrs.update(
            {
                "class": "upload-notes",
                "maxlength": "500",
                "data-notes-field": "true",
            }
        )

    def clean_log_file(self):
        uploaded_files = self.cleaned_data.get("log_file") or []
        if not isinstance(uploaded_files, list):
            uploaded_files = [uploaded_files]

        if not uploaded_files:
            raise forms.ValidationError("Please select at least one file to upload.")

        for uploaded_file in uploaded_files:
            suffix = Path(uploaded_file.name).suffix.lower()

            if suffix not in self.allowed_extensions:
                raise forms.ValidationError(
                    f'"{uploaded_file.name}" is an unsupported file type. '
                    "Please upload .txt, .log, .json, .jsonl, or .csv files."
                )

            if uploaded_file.size > self.max_file_size:
                raise forms.ValidationError(
                    f'"{uploaded_file.name}" is too large. Please upload files smaller than 5 MB each.'
                )

        return uploaded_files
