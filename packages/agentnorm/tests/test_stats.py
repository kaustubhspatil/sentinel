"""Exact binomial statistics. Reference values were produced by scipy, which is not a
dependency; they are pinned here so the tests run on the standard library alone."""
from __future__ import annotations

import math

import pytest

from agentnorm.stats import (
    Proportion,
    betainc,
    betaincinv,
    binom_sf,
    clopper_pearson,
    log_betainc,
)


def test_betainc_closed_form():
    # I_x(2, 3) = sum_{j=2..4} C(4, j) x^j (1 - x)^(4 - j); at 0.5 that is 11/16.
    assert betainc(2, 3, 0.5) == pytest.approx(11 / 16, abs=1e-13)


def test_betainc_symmetry():
    for a, b, x in [(0.5, 3.0, 0.2), (40, 7, 0.83), (1200, 30, 0.97)]:
        assert betainc(a, b, x) == pytest.approx(1 - betainc(b, a, 1 - x), abs=1e-12)


def test_betaincinv_inverts():
    for a, b, q in [(2, 9, 0.025), (31, 270, 0.975), (1, 1, 0.3)]:
        assert betainc(a, b, betaincinv(a, b, q)) == pytest.approx(q, abs=1e-10)


def test_binom_sf_matches_direct_sum():
    for k, n, p in [(1, 1, 0.02), (5, 100, 0.02), (3, 7, 0.4), (0, 10, 0.1), (11, 10, 0.1)]:
        direct = sum(math.comb(n, j) * p**j * (1 - p) ** (n - j) for j in range(max(k, 0), n + 1))
        assert binom_sf(k, n, p) == pytest.approx(direct, rel=1e-10, abs=1e-15)


def test_far_tail_is_accurate_in_log_space():
    """Alarms are decided in the tails, where 1 - I would cancel to zero."""
    n, p, k = 1000, 0.01, 60
    log_terms = [math.lgamma(n + 1) - math.lgamma(j + 1) - math.lgamma(n - j + 1)
                 + j * math.log(p) + (n - j) * math.log1p(-p) for j in range(k, n + 1)]
    top = max(log_terms)
    direct = top + math.log(sum(math.exp(t - top) for t in log_terms))
    assert log_betainc(k, n - k + 1, p) == pytest.approx(direct, rel=1e-9)
    assert direct < -60   # far beyond where 1 - (1 - tail) survives in doubles


def test_clopper_pearson_closed_forms_at_the_edges():
    n = 37
    lo, hi = clopper_pearson(0, n)
    assert lo == 0.0 and hi == pytest.approx(1 - 0.025 ** (1 / n), abs=1e-12)
    lo, hi = clopper_pearson(n, n)
    assert hi == 1.0 and lo == pytest.approx(0.025 ** (1 / n), abs=1e-12)


@pytest.mark.parametrize(("k", "n", "ref"), [
    (5, 10, (0.187086, 0.812914)),
    (3, 300, (0.002067, 0.028945)),
    (97, 100, (0.914824, 0.993770)),
    (0, 1200, (0.0, 0.003069)),
])
def test_clopper_pearson_matches_scipy(k, n, ref):
    lo, hi = clopper_pearson(k, n)
    assert lo == pytest.approx(ref[0], abs=1e-6)
    assert hi == pytest.approx(ref[1], abs=1e-6)


def test_clopper_pearson_rejects_nonsense():
    with pytest.raises(ValueError):
        clopper_pearson(5, 4)
    with pytest.raises(ValueError):
        clopper_pearson(1, 4, confidence=1.0)
    assert clopper_pearson(0, 0) == (0.0, 1.0)


def test_proportion_reports_interval_not_just_rate():
    p = Proportion(0, 300)
    assert p.rate == 0.0
    assert p.interval[1] > 0.01, "0 of 300 is consistent with a 1% rate"
    assert str(p).startswith("0.000 [0.000, 0.01")
    assert p.to_dict()["n"] == 300
    assert str(Proportion(0, 0)) == "n/a"
