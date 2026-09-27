"""Exact binomial statistics in the standard library.

Three upgrades need the same small toolkit: detection power needs exact intervals for a
true positive rate measured on a few hundred planted runs, the rate alarm needs tail
probabilities of a beta distribution, and the naive comparison it is measured against
needs a binomial tail. All of them reduce to the regularised incomplete beta function,
so that is implemented once, here, with a continued fraction evaluated in log space.

Why exact intervals rather than a normal approximation: the rates that matter here sit
near 0 (false positive rates at a 1% budget) or near 1 (a detector that almost always
fires), exactly where the normal approximation is worst. A Wald interval around 0 of 300
is the single point 0, which claims certainty nobody has. Clopper Pearson is
conservative, and conservative is the right direction for a claim about a monitor.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

_MAXIT = 20_000
_EPS = 1e-15
_TINY = 1e-300


def log_beta(a: float, b: float) -> float:
    """log B(a, b)."""
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (modified Lentz)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > _TINY else _TINY)
    h = d
    for m in range(1, _MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + aa / c
        c = c if abs(c) > _TINY else _TINY
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + aa / c
        c = c if abs(c) > _TINY else _TINY
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            return h
    raise ArithmeticError(f"incomplete beta did not converge for a={a}, b={b}, x={x}")


def _log1m_exp(v: float) -> float:
    """log(1 - exp(v)) for v <= 0, accurate at both ends."""
    if v >= 0.0:
        return -math.inf
    if v > -math.log(2.0):
        return math.log(-math.expm1(v))
    return math.log1p(-math.exp(v))


def log_betainc(a: float, b: float, x: float, *, upper: bool = False) -> float:
    """log of the regularised incomplete beta I_x(a, b), or of 1 - I_x(a, b) if `upper`.

    Whichever tail is small is computed directly rather than as one minus the other, so
    the result stays accurate far into the tails, which is where alarms are decided.
    """
    if a <= 0 or b <= 0:
        raise ValueError("a and b must be positive")
    if x <= 0.0:
        return 0.0 if upper else -math.inf
    if x >= 1.0:
        return -math.inf if upper else 0.0
    front = a * math.log(x) + b * math.log1p(-x) - log_beta(a, b)
    if x < (a + 1.0) / (a + b + 2.0):
        lower = min(0.0, front + math.log(_betacf(a, b, x)) - math.log(a))
        return _log1m_exp(lower) if upper else lower
    top = min(0.0, front + math.log(_betacf(b, a, 1.0 - x)) - math.log(b))
    return top if upper else _log1m_exp(top)


def betainc(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta I_x(a, b), the CDF of Beta(a, b) at x."""
    return math.exp(log_betainc(a, b, x))


def betaincinv(a: float, b: float, q: float) -> float:
    """The x with I_x(a, b) = q, by bisection. Slow but monotone and never wrong."""
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be in [0, 1]")
    if q == 0.0:
        return 0.0
    if q == 1.0:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if betainc(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-15:
            break
    return 0.5 * (lo + hi)


def binom_sf(k: int, n: int, p: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""
    if k <= 0:
        return 1.0
    if k > n:
        return 0.0
    return math.exp(log_betainc(k, n - k + 1, p))


def clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Exact two sided binomial confidence interval for k successes in n trials."""
    if n < 0 or not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k}, n={n}")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if n == 0:
        return 0.0, 1.0
    alpha = 1.0 - confidence
    lo = 0.0 if k == 0 else betaincinv(k, n - k + 1, alpha / 2)
    hi = 1.0 if k == n else betaincinv(k + 1, n - k, 1 - alpha / 2)
    return lo, hi


@dataclass(frozen=True)
class Proportion:
    """A count out of a total, with its exact interval attached."""

    hits: int
    n: int
    confidence: float = 0.95

    @property
    def rate(self) -> float:
        return self.hits / self.n if self.n else math.nan

    @property
    def interval(self) -> tuple[float, float]:
        return clopper_pearson(self.hits, self.n, self.confidence)

    def to_dict(self) -> dict[str, float | int]:
        lo, hi = self.interval
        return {"hits": self.hits, "n": self.n, "rate": round(self.rate, 4),
                "lo": round(lo, 4), "hi": round(hi, 4)}

    def __str__(self) -> str:
        if not self.n:
            return "n/a"
        lo, hi = self.interval
        return f"{self.rate:.3f} [{lo:.3f}, {hi:.3f}]"


__all__ = [
    "Proportion", "betainc", "betaincinv", "binom_sf", "clopper_pearson", "log_beta",
    "log_betainc",
]
