"""Retry timing helpers.

Kept separate so the arithmetic is unit-testable without a runner, a
clock, or real sleeping.
"""

from __future__ import annotations

import random


def compute_delay(
    failures: int,
    *,
    base: float,
    cap: float,
    jitter: float = 0.25,
    rng=random.random,
) -> float:
    """Exponential backoff with symmetric jitter.

    ``failures`` is 1 for the first retry. The un-jittered delay is
    ``base * 2**(failures-1)`` clamped to ``cap``; the result is that
    value +/- ``jitter`` fraction.
    """
    if failures < 1:
        raise ValueError("failures must be >= 1")
    raw = min(cap, base * (2 ** (failures - 1)))
    spread = raw * jitter
    return max(0.0, raw - spread + rng() * 2 * spread)
