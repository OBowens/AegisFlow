"""Coverage for apps.incidents.views._confidence_label -- the
qualitative HIGH/MEDIUM/LOW bucketing used for the incident card's "AI
confidence" display (real value only, never a placeholder).
"""

from django.test import TestCase

from apps.incidents.views import _confidence_label


class ConfidenceLabelTestCase(TestCase):
    def test_none_returns_none(self):
        self.assertIsNone(_confidence_label(None))

    def test_high_threshold_and_above(self):
        self.assertEqual(_confidence_label(0.85), {"key": "high", "label": "HIGH"})
        self.assertEqual(_confidence_label(1.0), {"key": "high", "label": "HIGH"})

    def test_just_below_high_threshold_is_medium(self):
        self.assertEqual(_confidence_label(0.84), {"key": "medium", "label": "MEDIUM"})

    def test_medium_threshold_and_above(self):
        self.assertEqual(_confidence_label(0.6), {"key": "medium", "label": "MEDIUM"})
        self.assertEqual(_confidence_label(0.7), {"key": "medium", "label": "MEDIUM"})

    def test_just_below_medium_threshold_is_low(self):
        self.assertEqual(_confidence_label(0.59), {"key": "low", "label": "LOW"})

    def test_zero_is_low(self):
        self.assertEqual(_confidence_label(0.0), {"key": "low", "label": "LOW"})
