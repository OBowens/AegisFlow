"""Coverage for the shared readiness score formula
(apps.resilience.services.scoring.compute_readiness_score), which replaced
two independent, identically-duplicated flat-penalty formulas in
apps/core/views.py and apps/resilience/views.py.

The old formula, `max(0, 100 - critical*8 - high*5 - medium*3)`, floored
permanently at 0 once volume alone pushed the subtraction past 100 (around
13 critical findings) regardless of the overall mix. The new formula
normalizes against the total finding count instead, so it reflects the
*composition* of findings, not how many of them there happen to be.
"""

from django.test import TestCase

import apps.core.views as core_views
import apps.resilience.views as resilience_views
from apps.resilience.services.scoring import compute_readiness_score


class ReadinessScoreFormulaTestCase(TestCase):
    def test_no_findings_is_a_perfect_score(self):
        self.assertEqual(
            compute_readiness_score(critical_count=0, high_count=0, medium_count=0), 100
        )

    def test_all_critical_findings_floors_at_zero(self):
        self.assertEqual(
            compute_readiness_score(critical_count=5, high_count=0, medium_count=0), 0
        )

    def test_score_never_goes_negative_or_above_100(self):
        score = compute_readiness_score(critical_count=1000, high_count=1000, medium_count=1000)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_past_thirteen_critical_findings_no_longer_permanently_floors(self):
        # Under the old formula, 13 critical findings alone (13 * 8 = 104)
        # already floored the score at 0, and it stayed 0 forever after --
        # regardless of how many additional high/medium findings existed
        # or what the overall mix looked like.
        old_formula_score_at_13 = max(0, 100 - (13 * 8))
        self.assertEqual(old_formula_score_at_13, 0)

        # The new formula still scores 20 critical-only findings at 0 (the
        # composition genuinely is 100% critical)...
        all_critical = compute_readiness_score(critical_count=20, high_count=0, medium_count=0)
        self.assertEqual(all_critical, 0)

        # ...but the same 20 critical findings alongside a healthy amount of
        # lower-severity findings score meaningfully above 0, since the
        # *composition* is no longer entirely critical. The old formula
        # could never recover from 0 once critical volume alone crossed the
        # ~13 threshold, no matter how many medium findings were added.
        mixed = compute_readiness_score(critical_count=20, high_count=10, medium_count=100)
        self.assertGreater(mixed, 0)

    def test_real_data_case_31_critical_7_high_10_medium(self):
        # 31 critical alone would have permanently floored the old formula
        # at 0 (31 * 8 = 248, far past 100). The new formula reflects that
        # critical findings dominate the mix (31 of 48 findings, ~65%)
        # without collapsing to a meaningless flat 0.
        score = compute_readiness_score(critical_count=31, high_count=7, medium_count=10)
        self.assertEqual(score, 18)

    def test_a_mostly_medium_mix_scores_much_higher_than_a_mostly_critical_mix(self):
        mostly_medium = compute_readiness_score(critical_count=1, high_count=1, medium_count=20)
        mostly_critical = compute_readiness_score(critical_count=20, high_count=1, medium_count=1)
        self.assertGreater(mostly_medium, mostly_critical)

    def test_core_and_resilience_views_call_the_same_shared_function(self):
        self.assertIs(core_views.compute_readiness_score, compute_readiness_score)
        self.assertIs(resilience_views.compute_readiness_score, compute_readiness_score)
