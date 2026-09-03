import unittest

from aegis_agent.backoff import compute_delay


class ComputeDelayTests(unittest.TestCase):
    def test_requires_at_least_one_failure(self):
        with self.assertRaises(ValueError):
            compute_delay(0, base=5, cap=300)

    def test_no_jitter_is_pure_exponential(self):
        delays = [compute_delay(n, base=5, cap=1000, jitter=0.0) for n in range(1, 6)]
        self.assertEqual(delays, [5, 10, 20, 40, 80])

    def test_capped(self):
        self.assertEqual(compute_delay(20, base=5, cap=300, jitter=0.0), 300)

    def test_jitter_stays_within_band(self):
        for rng_value in (0.0, 0.5, 1.0):
            delay = compute_delay(3, base=5, cap=1000, jitter=0.25, rng=lambda: rng_value)
            self.assertGreaterEqual(delay, 20 * 0.75 - 1e-9)
            self.assertLessEqual(delay, 20 * 1.25 + 1e-9)

    def test_never_negative(self):
        self.assertGreaterEqual(compute_delay(1, base=0.001, cap=1, jitter=1.0, rng=lambda: 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
