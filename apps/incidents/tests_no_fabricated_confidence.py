"""Regression coverage: the Work Queue's incident cards used to show an
"AI confidence" percentage computed purely from a severity->percentage
lookup table (critical=95%, high=82%, everything else=71%), completely
independent of evidence_count or the real (always-unpopulated)
IncidentGroup.confidence field. That fabricated number is removed --
this proves no incident card, at any severity and with any amount of
evidence, ever renders a confidence percentage again, whether or not
IncidentGroup.confidence is set.
"""

from django.test import TestCase
from config.testcase import AuthedTestCase
from django.urls import reverse

from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization


class NoFabricatedConfidenceTestCase(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization",
            organization_type="Demo",
            country="St. Vincent and the Grenadines",
            sector="Technology",
            risk_profile="medium",
        )

    def _create_incident(self, **overrides):
        defaults = {
            "organization": self.organization,
            "title": "Test incident",
            "incident_type": "database",
            "severity": IncidentGroup.Severity.HIGH,
            "affected_systems": "DB01",
        }
        defaults.update(overrides)
        return IncidentGroup.objects.create(**defaults)

    def test_no_severity_ever_renders_a_confidence_percentage(self):
        # One incident per severity level -- the old bug's lookup table
        # covered exactly these four buckets (critical, high, everything
        # else split into medium/low).
        for severity in (
            IncidentGroup.Severity.CRITICAL,
            IncidentGroup.Severity.HIGH,
            IncidentGroup.Severity.MEDIUM,
            IncidentGroup.Severity.LOW,
        ):
            self._create_incident(title=f"{severity} incident", severity=severity)

        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertNotIn("AI confidence", content)
        self.assertNotIn("af-confidence", content)
        # The exact fabricated values the old lookup table produced.
        self.assertNotIn("95%", content)
        self.assertNotIn("82%", content)
        self.assertNotIn("71%", content)

    def test_zero_evidence_high_severity_incident_shows_no_confidence_figure(self):
        # The exact "T"/"A" contamination-data shape that surfaced the
        # bug: 0 evidence, high severity -- previously rendered "82%"
        # regardless of having nothing to back it.
        self._create_incident(title="T", affected_systems="A", severity=IncidentGroup.Severity.HIGH)

        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        content = response.content.decode()
        self.assertIn("0 sources", content)
        self.assertNotIn("82%", content)
        self.assertNotIn("AI confidence", content)

    def test_a_real_confidence_value_shows_a_qualitative_label_not_a_raw_percentage(self):
        # A set IncidentGroup.confidence now genuinely displays -- as the
        # qualitative HIGH/MEDIUM/LOW pill (see _confidence_label), the
        # same style as playbooks/index.html's confidence pill, never as
        # a raw percentage (which is exactly the false-precision shape
        # the original fabricated-confidence bug had).
        self._create_incident(title="Scored incident", confidence=0.9)

        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        content = response.content.decode()
        self.assertIn("AI confidence", content)
        self.assertIn("playbook-confidence-pill--high", content)
        self.assertIn("HIGH", content)
        self.assertNotIn("90%", content)
        self.assertNotIn("83%", content)

    def test_incident_with_no_confidence_value_shows_no_ai_confidence_row_at_all(self):
        self._create_incident(title="Unscored incident", confidence=None)

        response = self.client.get(f"{reverse('incidents:index')}?tab=queue")

        self.assertNotContains(response, "AI confidence")
