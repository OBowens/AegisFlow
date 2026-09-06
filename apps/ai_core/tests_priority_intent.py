"""Coverage for the App Assistant's prioritization shortcut
(apps/ai_core/services/priority_intent.py): the phrase matcher that
recognises "what should I fix first" questions with no AI call, and the
answer builder that fills them from the most recent PriorityBriefing --
or says plainly that no current one exists and points at the button that
generates one.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.ai_core.services.priority_intent import (
    PRIORITY_BRIEFING_FRESH_DAYS,
    build_priority_shortcut_answer,
    looks_like_prioritization_question,
)
from apps.core.models import PriorityBriefing
from apps.organizations.models import Organization


class PrioritizationIntentMatchTestCase(TestCase):
    def test_matches_broad_what_should_i_fix_first_phrasings(self):
        for question in [
            "What should I fix first?",
            "what should i do next",
            "What should I focus on first on this page?",
            "what should I work on first",
            "Where do I start?",
            "what's most urgent right now",
            "Can you help me prioritize my incidents?",
            "what are my top priorities",
            "What needs my attention most?",
            "what should I prioritise",
            "what's next?",
        ]:
            self.assertTrue(looks_like_prioritization_question(question), question)

    def test_does_not_match_unrelated_how_to_questions(self):
        for question in [
            "how do I upload a log file",
            "what does the Verify stage mean?",
            "what is an evidence tier",
            "how do I close an incident",
            "what should I name my SOP checklist",
            "what should I do about this alert",  # incident-specific -> must still deflect
            "where is the audit history",
            "",
        ]:
            self.assertFalse(looks_like_prioritization_question(question), question)


class PriorityShortcutAnswerTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )

    def _make_briefing(self, *, text, age_days):
        briefing = PriorityBriefing.objects.create(
            organization=self.organization,
            briefing_text=text,
            model_used="claude-sonnet-5",
        )
        PriorityBriefing.objects.filter(pk=briefing.pk).update(
            generated_at=timezone.now() - timedelta(days=age_days)
        )
        briefing.refresh_from_db()
        return briefing

    def test_fresh_briefing_is_embedded_verbatim_with_a_home_pointer(self):
        self._make_briefing(
            text="1. WEB01 - reset credentials (High).\n2. DB02 - apply the patch.",
            age_days=1,
        )

        answer = build_priority_shortcut_answer(self.organization)

        self.assertIn("1. WEB01 - reset credentials (High).", answer)
        self.assertIn("2. DB02 - apply the patch.", answer)
        self.assertIn("Home page", answer)
        self.assertIn("Refresh priorities", answer)

    def test_no_briefing_says_so_and_points_at_the_explain_button(self):
        answer = build_priority_shortcut_answer(self.organization)

        self.assertIn("No priority briefing has been generated", answer)
        self.assertIn("Explain priorities", answer)
        self.assertNotIn("Refresh priorities", answer)

    def test_stale_briefing_is_treated_as_none_but_dated(self):
        self._make_briefing(
            text="Ranked list from three weeks ago.",
            age_days=PRIORITY_BRIEFING_FRESH_DAYS + 21,
        )

        answer = build_priority_shortcut_answer(self.organization)

        self.assertNotIn("Ranked list from three weeks ago.", answer)
        self.assertIn("out of date", answer)
        self.assertIn("Refresh priorities", answer)

    def test_latest_briefing_wins_over_older_rows(self):
        self._make_briefing(text="OLDER briefing body", age_days=3)
        self._make_briefing(text="NEWEST briefing body", age_days=0)

        answer = build_priority_shortcut_answer(self.organization)

        self.assertIn("NEWEST briefing body", answer)
        self.assertNotIn("OLDER briefing body", answer)

    def test_briefing_for_another_org_is_not_used(self):
        other = Organization.objects.create(name="Other Org", organization_type="Demo")
        PriorityBriefing.objects.create(
            organization=other, briefing_text="Other org ranking", model_used="x"
        )

        answer = build_priority_shortcut_answer(self.organization)

        self.assertNotIn("Other org ranking", answer)
        self.assertIn("No priority briefing has been generated", answer)
