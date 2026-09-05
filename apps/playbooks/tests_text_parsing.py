"""apps.playbooks.services.text_parsing.checklist_item_key

The stable identity for a parsed SOP-checklist line that ChecklistItemState
rows key on. It's a SHA-256 digest of the fully normalized line text:
opaque and fixed-width (so it stays out of the rendered hidden form field
and the stored row), and derived from the *whole* line rather than the
first 300 characters the key used to be truncated to.
"""

from django.test import SimpleTestCase

from apps.playbooks.services.text_parsing import checklist_item_key


class ChecklistItemKeyTestCase(SimpleTestCase):
    def test_key_is_a_sha256_hex_digest_not_the_line_text(self):
        key = checklist_item_key("Lock the account and reset its credentials")
        self.assertRegex(key, r"^[0-9a-f]{64}$")
        self.assertNotIn("lock", key)
        self.assertNotIn("credential", key)

    def test_same_normalized_text_yields_the_same_key(self):
        # Whitespace, trailing period and case are all normalized away
        # before hashing, so these three are one checklist item.
        self.assertEqual(
            checklist_item_key("  Verify   incident details.  "),
            checklist_item_key("Verify incident details"),
        )
        self.assertEqual(
            checklist_item_key("VERIFY INCIDENT DETAILS"),
            checklist_item_key("Verify incident details"),
        )

    def test_different_lines_get_different_keys(self):
        self.assertNotEqual(
            checklist_item_key("Collect and preserve relevant logs"),
            checklist_item_key("Lock the account and reset its credentials"),
        )

    def test_lines_differing_only_past_300_chars_get_distinct_keys(self):
        # The old key was the normalized/lowercased text truncated to
        # [:300], so two long lines sharing a 300-char prefix collapsed
        # onto one ChecklistItemState. Hashing the full line keeps them
        # independent.
        shared_prefix = "review the exposed credential exposure and " * 8  # ~344 chars
        line_a = shared_prefix + "then isolate the mail relay"
        line_b = shared_prefix + "then isolate the VPN concentrator"

        self.assertGreater(len(shared_prefix), 300)
        self.assertNotEqual(checklist_item_key(line_a), checklist_item_key(line_b))

    def test_blank_text_is_stable(self):
        self.assertEqual(checklist_item_key(""), checklist_item_key("   "))
        self.assertRegex(checklist_item_key(""), r"^[0-9a-f]{64}$")
