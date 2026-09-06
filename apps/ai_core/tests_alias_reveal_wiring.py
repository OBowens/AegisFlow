"""Part 6: the click-to-reveal control wired into the base layouts.

The reveal endpoint (apps/ai_core/views.py) and its audit guarantees are
covered by tests_reveal_view.py; the alias markup by tests_alias_display.py
/ tests_alias_prose.py. This file covers the seam between them:

- both base layouts (layouts/app_base.html AND layouts/base.html) include
  the reveal partial exactly once, so every aliased page can reveal --
  including reports/detail.html, which extends the plain layout and was
  aliased-but-non-functional before this part;
- a data-alias-pk rendered into a real page actually resolves through the
  reveal endpoint to the real value.
"""

from __future__ import annotations

import re

from django.test import TestCase
from django.urls import reverse

from apps.ai_core.models import AliasMapping
from apps.incidents.models import IncidentGroup
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport
from config.testcase import AuthedTestCase

_PARTIAL_FORM = 'class="af-alias-reveal"'
_PARTIAL_SCRIPT = "js/alias-reveal.js"


def _make_org():
    return Organization.objects.create(
        name="Coral Bay Credit Union", organization_type="Business"
    )


class AppBaseLayoutWiringTests(AuthedTestCase):
    """incidents/investigation_overview.html -> layouts/app_base.html."""

    def setUp(self):
        self.org = _make_org()
        self.incident = IncidentGroup.objects.create(
            organization=self.org,
            title="High severity log activity on DB01",
            incident_type="log_activity",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
        )

    def test_reveal_partial_is_included_exactly_once(self):
        html = self.client.get(
            reverse("incidents:detail", args=[self.incident.id])
        ).content.decode()

        self.assertEqual(html.count(_PARTIAL_FORM), 1)
        self.assertEqual(html.count(_PARTIAL_SCRIPT), 1)
        self.assertIn("csrfmiddlewaretoken", html)

    def test_the_page_carries_a_revealable_alias(self):
        html = self.client.get(
            reverse("incidents:detail", args=[self.incident.id])
        ).content.decode()

        host = AliasMapping.objects.get(
            organization=self.org, identifier_type="HOST", real_value="DB01"
        )
        self.assertIn(f'data-alias-pk="{host.pk}"', html)
        self.assertIn(
            f'<span class="af-alias__value">{host.display_alias}</span>', html
        )


class PlainBaseLayoutWiringTests(AuthedTestCase):
    """reports/detail.html -> layouts/base.html (the layout that had no
    page-scripts / extra-head seam and so no working reveal before Part 6)."""

    def setUp(self):
        self.org = _make_org()
        self.incident = IncidentGroup.objects.create(
            organization=self.org,
            title="Suspicious activity on DB01",
            incident_type="log_activity",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
        )
        self.report = GeneratedReport.objects.create(
            organization=self.org,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Executive summary",
            summary="Attacker reached DB01 from 203.0.113.9.",
            body="Full narrative: 203.0.113.9 authenticated to DB01 overnight.",
        )

    def test_reveal_partial_is_included_exactly_once(self):
        html = self.client.get(
            reverse("reports:detail", args=[self.report.id])
        ).content.decode()

        self.assertEqual(html.count(_PARTIAL_FORM), 1)
        self.assertEqual(html.count(_PARTIAL_SCRIPT), 1)
        self.assertIn("csrfmiddlewaretoken", html)

    def test_extra_head_and_page_scripts_blocks_exist_on_the_plain_layout(self):
        from django.template.loader import get_template

        source = get_template("layouts/base.html").template.source
        self.assertIn("{% block extra_head %}", source)
        self.assertIn("{% block page_scripts %}", source)

    def test_report_body_aliases_are_revealable(self):
        html = self.client.get(
            reverse("reports:detail", args=[self.report.id])
        ).content.decode()

        ip = AliasMapping.objects.get(organization=self.org, identifier_type="IP")
        self.assertIn(f'data-alias-pk="{ip.pk}"', html)
        self.assertNotIn("203.0.113.9", html)


class RenderedAliasResolvesThroughTheEndpointTests(AuthedTestCase):
    """The pk in the DOM is the pk the endpoint accepts -- end to end."""

    def setUp(self):
        self.org = _make_org()
        self.incident = IncidentGroup.objects.create(
            organization=self.org,
            title="Suspicious activity on DB01",
            incident_type="log_activity",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
        )
        self.report = GeneratedReport.objects.create(
            organization=self.org,
            incident=self.incident,
            report_type=GeneratedReport.ReportType.EXECUTIVE,
            title="Executive summary",
            summary="",
            body="Narrative: 198.51.100.23 authenticated to DB01 overnight.",
        )

    def test_scrape_a_pk_from_the_page_and_reveal_it(self):
        page = self.client.get(
            reverse("reports:detail", args=[self.report.id])
        ).content.decode()

        pks = re.findall(r'data-alias-pk="(\d+)"', page)
        self.assertTrue(pks, "expected at least one aliased value on the page")

        ip = AliasMapping.objects.get(organization=self.org, identifier_type="IP")
        self.assertIn(str(ip.pk), pks)

        response = self.client.post(reverse("ai_core:reveal_alias", args=[int(ip.pk)]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["real_value"], "198.51.100.23")
