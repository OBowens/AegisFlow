"""apps.ai_core.services.alias_engine.sanitize_prose_for_display +
the {% alias_prose %} tag (Part 5: free-text / prose display sanitization).

Proves:
- a block of prose has EVERY distinct real identifier in it replaced with
  its stable [TYPE_00n] alias, and only those spans;
- ordinary non-identifier text (security vocabulary, versions, prose) is
  left untouched;
- the AliasMapping-backed dictionary augmentation catches identifiers the
  bare regexes would miss (a lowercase hostname, a bare service account);
- HTML in the source text is escaped;
- fail-closed: any exception anywhere in the pipeline replaces the block
  with PROSE_SANITIZE_FAILED_MARKER -- never the raw text, never a
  half-substituted result -- and logs a warning that carries no identifier.
"""

from unittest.mock import patch

from django.template import Context, Template
from django.test import RequestFactory, SimpleTestCase, TestCase

from apps.ai_core.models import AliasMapping
from apps.ai_core.services import alias_engine
from apps.ai_core.services.alias_engine import (
    PROSE_SANITIZE_FAILED_MARKER,
    PersistentAliasStore,
    sanitize_prose_for_display,
)
from apps.organizations.models import CriticalSystem, Organization


def _render_tag(value, organization, request=None):
    return Template(
        "{% load alias_display %}{% alias_prose value org %}"
    ).render(Context({"value": value, "org": organization, "request": request}))


class ProseSanitizerTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Coral Bay Credit Union", organization_type="Business"
        )
        # Seeds collect_org_identifiers' dictionary passes.
        CriticalSystem.objects.create(
            organization=self.org,
            system_name="PAYROLL-DB-01",
            system_type="server",
            criticality="high",
            owner_name="Dana Whitfield",
            recovery_priority="tier_1",
        )
        # Pre-existing aliases -- the display-only dictionary augmentation.
        AliasMapping.objects.create(
            organization=self.org,
            identifier_type="HOST",
            normalized_value="oldbox",
            real_value="oldbox",
            sequence=41,
        )
        AliasMapping.objects.create(
            organization=self.org,
            identifier_type="USER",
            normalized_value="svc-backup",
            real_value="svc-backup",
            sequence=7,
        )
        self.request = RequestFactory().get("/")

    def sanitize(self, text):
        return sanitize_prose_for_display(text, self.org, request=self.request)

    def test_multiple_distinct_identifiers_in_one_block_each_get_their_own_alias(self):
        text = (
            "The attacker at 203.0.113.9 authenticated to PAYROLL-DB-01 and then "
            "pivoted to WEB-02, mailing admin@partner.example from mailhost.corp. "
            "The lateral move also touched the retired host oldbox using the "
            "svc-backup service account."
        )
        rendered = str(self.sanitize(text))

        for real in (
            "203.0.113.9",
            "PAYROLL-DB-01",
            "WEB-02",
            "admin@partner.example",
            "mailhost.corp",
            "oldbox",
            "svc-backup",
        ):
            self.assertNotIn(real, rendered)

        for alias_type in ("IP", "HOST", "EMAIL", "USER"):
            self.assertIn(f"[{alias_type}_", rendered)
        # Three distinct hosts (PAYROLL-DB-01, WEB-02 from the regex +
        # oldbox from the augmented dict) -> three distinct host aliases.
        import re as _re

        host_aliases = set(_re.findall(r"\[HOST_\d+\]", rendered))
        self.assertEqual(len(host_aliases), 3)

    def test_same_identifier_twice_in_a_block_maps_to_one_stable_alias(self):
        rendered = str(
            self.sanitize("203.0.113.9 opened the door; later 203.0.113.9 came back.")
        )
        self.assertEqual(rendered.count("[IP_001]"), 2)
        self.assertNotIn("203.0.113.9", rendered)
        self.assertEqual(
            AliasMapping.objects.filter(organization=self.org, identifier_type="IP").count(),
            1,
        )

    def test_non_identifier_text_is_left_untouched(self):
        text = (
            "Failed password policy review: enforce SHA256 hashing and TLS 1.3 "
            "on all endpoints. No single account was implicated; escalate to tier 2 "
            "if the pattern repeats over 24/7 monitoring."
        )
        self.assertEqual(str(self.sanitize(text)), text)

    def test_augmented_dictionary_catches_a_lowercase_host_the_regex_misses(self):
        # The bare-host regex is uppercase-led only; "oldbox" is caught only
        # because it is already an AliasMapping row for this org.
        rendered = str(self.sanitize("Historic activity on oldbox was reviewed."))
        self.assertIn("[HOST_041]", rendered)
        self.assertNotIn("oldbox", rendered)

    def test_html_in_the_source_text_is_escaped(self):
        rendered = str(self.sanitize("<script>alert(1)</script> from 203.0.113.9"))
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn("[IP_001]", rendered)

    def test_newlines_become_br(self):
        rendered = str(self.sanitize("line one\nline two 203.0.113.9"))
        self.assertIn("line one<br>line two", rendered)

    def test_empty_and_none_render_empty(self):
        self.assertEqual(sanitize_prose_for_display("", self.org, request=self.request), "")
        self.assertEqual(sanitize_prose_for_display(None, self.org, request=self.request), "")

    def test_alias_prose_tag_matches_the_function(self):
        text = "Contact host WEB-02 about 203.0.113.9."
        self.assertEqual(
            _render_tag(text, self.org, self.request),
            str(self.sanitize(text)),
        )

    # --- fail-closed suite (7) ------------------------------------------

    def test_failsafe_run_passes_exception_hides_the_block(self):
        with patch.object(
            alias_engine, "run_passes", side_effect=RuntimeError("synthetic pipeline failure")
        ):
            rendered = str(self.sanitize("Sensitive activity on PAYROLL-DB-01 from 203.0.113.9"))
        self.assertEqual(rendered, PROSE_SANITIZE_FAILED_MARKER)
        self.assertNotIn("PAYROLL-DB-01", rendered)
        self.assertNotIn("203.0.113.9", rendered)

    def test_failsafe_dictionary_builder_exception_hides_the_block(self):
        with patch.object(
            alias_engine,
            "collect_org_identifiers",
            side_effect=RuntimeError("synthetic DB failure"),
        ):
            rendered = str(self.sanitize("Activity on PAYROLL-DB-01 from 203.0.113.9"))
        self.assertEqual(rendered, PROSE_SANITIZE_FAILED_MARKER)
        self.assertNotIn("PAYROLL-DB-01", rendered)

    def test_failsafe_get_or_create_exhaustion_hides_the_block_and_does_not_log_the_value(self):
        raw_error = (
            "Could not get-or-create an AliasMapping for HOST='SECRET-HOST-9' "
            "after repeated retries."
        )
        with self.assertLogs("apps.ai_core.services.alias_engine", level="WARNING") as logs:
            with patch.object(
                PersistentAliasStore, "_get_or_create", side_effect=RuntimeError(raw_error)
            ):
                rendered = str(self.sanitize("New host SECRET-HOST-9 appeared at 198.51.100.7"))
        self.assertEqual(rendered, PROSE_SANITIZE_FAILED_MARKER)
        self.assertNotIn("SECRET-HOST-9", rendered)
        self.assertNotIn("198.51.100.7", rendered)
        joined_logs = "\n".join(logs.output)
        self.assertNotIn("SECRET-HOST-9", joined_logs)
        self.assertNotIn("198.51.100.7", joined_logs)
        self.assertIn("RuntimeError", joined_logs)

    def test_failsafe_marker_text_is_exactly_as_specified(self):
        with patch.object(alias_engine, "run_passes", side_effect=RuntimeError("x")):
            self.assertEqual(
                str(self.sanitize("anything with 203.0.113.9")),
                "[hidden -- identifier check failed; reload to try again]",
            )

    def test_success_with_no_identifiers_renders_verbatim_not_the_marker(self):
        text = "Everything looks fine; no indicators of compromise were found."
        rendered = str(self.sanitize(text))
        self.assertEqual(rendered, text)
        self.assertNotEqual(rendered, PROSE_SANITIZE_FAILED_MARKER)

    def test_failsafe_logs_a_warning_with_no_identifier_material(self):
        with self.assertLogs("apps.ai_core.services.alias_engine", level="WARNING") as logs:
            with patch.object(alias_engine, "run_passes", side_effect=ValueError("boom")):
                self.sanitize("host PAYROLL-DB-01, ip 203.0.113.9, user root")
        joined = "\n".join(logs.output)
        self.assertNotIn("PAYROLL-DB-01", joined)
        self.assertNotIn("203.0.113.9", joined)
        self.assertIn("ValueError", joined)
        self.assertIn("block hidden", joined)

    def test_failsafe_is_per_block_other_blocks_still_sanitize(self):
        good = str(self.sanitize("Clean block mentioning WEB-02"))
        self.assertIn("[HOST_", good)
        with patch.object(alias_engine, "run_passes", side_effect=RuntimeError("x")):
            bad = str(self.sanitize("Broken block mentioning PAYROLL-DB-01"))
        self.assertEqual(bad, PROSE_SANITIZE_FAILED_MARKER)
        # After the patch is gone, a later block sanitizes normally again.
        recovered = str(self.sanitize("Recovered block mentioning 203.0.113.9"))
        self.assertIn("[IP_", recovered)


class ProseSanitizerNoOrgTests(SimpleTestCase):
    def test_no_organization_fails_closed(self):
        # No org -> no dictionary, nothing to alias against -> fail closed
        # rather than render prose that might carry an identifier.
        self.assertEqual(
            sanitize_prose_for_display("host WEB-01 from 203.0.113.9", None),
            PROSE_SANITIZE_FAILED_MARKER,
        )

    def test_no_organization_still_renders_empty_for_empty_text(self):
        self.assertEqual(sanitize_prose_for_display("", None), "")
