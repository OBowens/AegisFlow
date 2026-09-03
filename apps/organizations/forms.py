from django import forms

from .models import CriticalSystem


class OrganizationProfileForm(forms.Form):
    name = forms.CharField(
        label="Organization name",
        max_length=255,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    organization_type = forms.CharField(
        label="Organization type",
        max_length=100,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    country = forms.CharField(
        label="Country",
        max_length=100,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    sector = forms.CharField(
        label="Sector",
        max_length=100,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    risk_profile = forms.CharField(
        label="Risk profile",
        max_length=100,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )


class CriticalSystemForm(forms.Form):
    system_name = forms.CharField(
        label="System name",
        max_length=255,
        help_text="Must match an alert's affected system exactly to auto-match (case-insensitive).",
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    system_type = forms.CharField(
        label="System type",
        max_length=100,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    criticality = forms.ChoiceField(
        label="Criticality",
        choices=CriticalSystem.Criticality.choices,
        initial=CriticalSystem.Criticality.MEDIUM,
        widget=forms.Select(attrs={"class": "upload-select"}),
    )
    owner_name = forms.CharField(
        label="Owner",
        max_length=255,
        widget=forms.TextInput(attrs={"class": "upload-select"}),
    )
    recovery_priority = forms.ChoiceField(
        label="Recovery priority",
        choices=CriticalSystem.RecoveryPriority.choices,
        initial=CriticalSystem.RecoveryPriority.MEDIUM,
        widget=forms.Select(attrs={"class": "upload-select"}),
    )
    backup_required = forms.BooleanField(
        label="Backup required",
        required=False,
    )
