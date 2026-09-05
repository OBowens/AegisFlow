"""apps/ai_core/templatetags/alias_display.py + the display-time helpers in
apps/ai_core/services/alias_engine.py (Part 4: structured-field alias display).

Proves:
- a structured value renders as its stable AliasMapping label, minted once;
- a missing-value placeholder ("Unknown system", "Unassigned", the
  "AegisFlow AI" system actor) is short-circuited -- rendered as-is, and
  never minted into an AliasMapping row;
- warm_display_aliases is the one seam that mints, and the tag then reads.
"""

from django.template import Context, Template
from django.test import RequestFactory, TestCase

from apps.ai_core.models import AliasMapping
from apps.ai_core.services.alias_engine import (
    get_request_alias_store,
    is_non_identity_sentinel,
    warm_display_aliases,
)
from apps.organizations.models import Organization


def _render(value, identifier_type, organization, request=None):
    return Template(
        '{% load alias_display %}{% alias_field value itype org %}'
    ).render(
        Context({"value": value, "itype": identifier_type, "org": organization, "request": request})
    )


class AliasFieldTagTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Coral Bay Credit Union", organization_type="Business"
        )

    def test_structured_value_renders_as_a_stable_minted_alias(self):
        first = _render("PAYROLL-DB-01", "HOST", self.org)
        second = _render("PAYROLL-DB-01", "HOST", self.org)

        self.assertIn("[HOST_001]", first)
        self.assertNotIn("PAYROLL-DB-01", first)
        self.assertEqual(first, second)
        self.assertEqual(
            AliasMapping.objects.filter(
                organization=self.org, identifier_type="HOST", real_value="PAYROLL-DB-01"
            ).count(),
            1,
        )

    def test_ipv4_in_a_host_slot_is_classified_and_aliased_as_an_ip(self):
        rendered = _render("10.44.7.21", "HOST", self.org)
        self.assertIn("[IP_001]", rendered)
        self.assertFalse(
            AliasMapping.objects.filter(organization=self.org, identifier_type="HOST").exists()
        )

    def test_missing_value_sentinels_are_rendered_plainly_and_never_minted(self):
        for sentinel in ("Unknown system", "unassigned", "You", "AegisFlow AI"):
            rendered = _render(sentinel, "HOST", self.org)
            self.assertEqual(rendered.strip(), sentinel)
            self.assertNotIn("af-alias", rendered)
            self.assertTrue(is_non_identity_sentinel(sentinel))
        self.assertEqual(AliasMapping.objects.count(), 0)

    def test_blank_and_missing_organization_render_empty(self):
        self.assertEqual(_render("", "HOST", self.org).strip(), "")
        self.assertEqual(_render("WEB-01", "HOST", None).strip(), "")
        self.assertEqual(AliasMapping.objects.count(), 0)

    def test_warm_seam_mints_and_the_tag_then_reads_without_new_rows(self):
        request = RequestFactory().get("/")
        store = get_request_alias_store(request, self.org)
        warm_display_aliases(
            store,
            [("WEB-01", "HOST"), ("10.0.0.9", "IP"), ("Unknown system", "HOST")],
        )
        # The sentinel was skipped; the two real identifiers were minted.
        self.assertEqual(AliasMapping.objects.count(), 2)

        with self.assertNumQueries(0):
            rendered = _render("WEB-01", "HOST", self.org, request=request)
        self.assertIn("[HOST_001]", rendered)
        self.assertEqual(AliasMapping.objects.count(), 2)
