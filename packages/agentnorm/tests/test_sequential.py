"""Anytime valid rate monitoring.

The central tests are exact, not simulated: the alarm decision depends only on the count
of positives at each time, so the probability of ever crossing the boundary within a
horizon can be computed by dynamic programming over that count. That turns "stays below
alpha" into an equality to check rather than a noisy estimate.
"""
from __future__ import annotations

import math
import random

import pytest

from agentnorm.sequential import RateAlarm, RateConfidenceSequence
from agentnorm.stats import binom_sf


def crossing_probability(boundary: list[int], p: float) -> float:
    """P(S_t >= boundary[t] for some t) for a Bernoulli(p) stream; boundary[0] unused."""
    dist = {0: 1.0}
    crossed = 0.0
    for t in range(1, len(boundary)):
        nxt: dict[int, float] = {}
        for s, w in dist.items():
            nxt[s] = nxt.get(s, 0.0) + w * (1 - p)
            nxt[s + 1] = nxt.get(s + 1, 0.0) + w * p
        for s in [s for s in nxt if s >= boundary[t]]:
            crossed += nxt.pop(s)
        dist = nxt
    return crossed


def naive_boundary(p0: float, alpha: float, horizon: int) -> list[int]:
    """Smallest count at which a fixed n exact binomial test rejects, for every n."""
    out, k = [0], 0
    for t in range(1, horizon + 1):
        while k <= t and binom_sf(k, t, p0) > alpha:
            k += 1
        out.append(k)
    return out


# --- the alarm ------------------------------------------------------------------------

def test_alarm_false_alarm_probability_is_at_most_alpha_exactly():
    p0, alpha, horizon = 0.05, 0.05, 1500
    alarm = RateAlarm(p0, alpha)
    boundary = [0] + [alarm.threshold(t) for t in range(1, horizon + 1)]
    assert crossing_probability(boundary, p0) <= alpha


def test_alarm_is_valid_for_every_rate_below_the_baseline():
    """The null is composite: any rate at or below the baseline must be safe."""
    alarm = RateAlarm(0.05, 0.05)
    boundary = [0] + [alarm.threshold(t) for t in range(1, 800)]
    for p in (0.01, 0.03, 0.049):
        assert crossing_probability(boundary, p) <= crossing_probability(boundary, 0.05) + 1e-12


def test_naive_peeking_is_not_valid():
    """The failure the alarm exists to fix, measured exactly on the same horizon."""
    p0, alpha, horizon = 0.05, 0.05, 1500
    naive = crossing_probability(naive_boundary(p0, alpha, horizon), p0)
    assert naive > 3 * alpha


def test_threshold_agrees_with_streaming_updates():
    rng = random.Random(7)
    alarm = RateAlarm(0.02, 0.05)
    first = None
    s = 0
    for t in range(1, 3000):
        x = rng.random() < 0.06
        s += x
        alarm.update(x)
        if first is None and s >= alarm.threshold(t):
            first = t
    assert alarm.alarmed_at == first is not None


def test_thresholds_in_one_pass_match_one_at_a_time():
    alarm = RateAlarm(0.03, 0.01)
    fast = alarm.thresholds(600)
    assert fast == [alarm.threshold(t) for t in range(601)]
    assert all(b >= a for a, b in zip(fast, fast[1:], strict=False)), "boundary never decreases"
    with pytest.raises(ValueError):
        alarm.thresholds(-1)


def test_alarm_detects_a_real_shift():
    rng = random.Random(3)
    alarm = RateAlarm(0.02, 0.01)
    for _ in range(300):
        alarm.update(rng.random() < 0.02)
    changed_at = alarm.n
    for _ in range(3000):
        if alarm.update(rng.random() < 0.10):
            break
    assert alarm.alarmed and alarm.alarmed_at - changed_at < 400
    assert alarm.e_value >= 100


def test_alarm_is_sticky_and_e_value_falls_on_clean_data():
    alarm = RateAlarm(0.1, 0.05)
    alarm.extend([1] * 10)
    assert alarm.alarmed
    at = alarm.alarmed_at
    alarm.extend([0] * 500)
    assert alarm.alarmed and alarm.alarmed_at == at
    assert alarm.e_value < 1.0


def test_alarm_rejects_bad_input():
    with pytest.raises(ValueError):
        RateAlarm(0.0)
    with pytest.raises(ValueError):
        RateAlarm(0.1, alpha=1.0)
    with pytest.raises(ValueError):
        RateAlarm(0.1).update(2)
    with pytest.raises(ValueError):
        RateAlarm(0.1).threshold(-1)


# --- the confidence sequence ----------------------------------------------------------

def test_confidence_sequence_covers_the_truth_uniformly_over_time():
    alpha, p, streams, steps = 0.1, 0.1, 300, 400
    rng = random.Random(11)
    misses = 0
    for _ in range(streams):
        cs = RateConfidenceSequence(alpha)
        for _ in range(steps):
            cs.successes += rng.random() < p
            cs.n += 1
            if not cs.contains(p):
                misses += 1
                break
    # Binomial(300, <=0.1): exceeding 0.1 + 3 sd would be a real failure, not noise.
    assert misses / streams <= alpha + 3 * math.sqrt(alpha * (1 - alpha) / streams)


def test_interval_matches_its_definition_on_a_grid():
    cs = RateConfidenceSequence(0.05)
    cs.extend([1] * 14 + [0] * 186)
    lo, hi = cs.interval()
    grid = [i / 20000 for i in range(1, 20000)]
    inside = [p for p in grid if cs.contains(p)]
    assert lo == pytest.approx(inside[0], abs=1e-4)
    assert hi == pytest.approx(inside[-1], abs=1e-4)
    assert lo < cs.mean < hi


def test_interval_edges_and_narrowing():
    cs = RateConfidenceSequence(0.05)
    assert cs.interval() == (0.0, 1.0)
    lo, hi = cs.extend([0] * 50)
    assert lo == 0.0 and hi < 0.2
    w1 = hi - lo
    lo, hi = cs.extend([0] * 950)
    assert hi - lo < w1
    all_ones = RateConfidenceSequence(0.05)
    assert all_ones.extend([True] * 30)[1] == 1.0


def test_confidence_sequence_is_wider_than_a_fixed_n_interval():
    """The price of looking whenever you like: at any single n it is wider."""
    from agentnorm.stats import clopper_pearson
    cs = RateConfidenceSequence(0.05)
    cs.extend([1] * 20 + [0] * 380)
    lo, hi = cs.interval()
    flo, fhi = clopper_pearson(20, 400)
    assert lo < flo and hi > fhi
