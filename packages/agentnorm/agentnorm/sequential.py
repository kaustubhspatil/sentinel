"""Anytime valid alarms on a monitored rate.

An operator does not look at a rate once. They look after every run: the share of runs
the monitor flagged this week, the wrong answer rate from the labels that trickle in. A
fixed sample test re run after every observation is not a test at level alpha. Each look
spends another chance of a false alarm, and over a long enough stream a stationary,
perfectly healthy rate crosses a fixed threshold with probability approaching one. The
experiment in `tools/exp_anytime_alarms.py` measures how far above alpha that goes.

The fix is a statistic whose guarantee holds uniformly over time. Both classes here are
built on a nonnegative supermartingale and Ville's inequality: if M_t is a nonnegative
supermartingale with M_0 = 1, then P(M_t >= 1/alpha for some t) <= alpha. So an alarm
raised the first time M_t reaches 1/alpha is a false alarm with probability at most
alpha, however often it is checked and however long the stream runs. This is the method
of mixtures (Robbins 1970; Howard, Ramdas, McAuliffe and Sekhon 2021), with a conjugate
beta mixture so every quantity is closed form and each update costs O(1).

`RateConfidenceSequence` gives a two sided interval for the rate that is valid at every
time simultaneously. `RateAlarm` tests the one sided question operators actually ask,
"is the rate above its baseline?", and is the sharper tool for that job.

What the guarantee needs: observations are 0 or 1 and, under the null, each one has
conditional mean at most the baseline given everything before it. Independence is not
required. What it does not give: fast detection after a long healthy stretch. Controlling
the chance of *ever* raising a false alarm means healthy history counts as evidence for
the null, so detection delay grows slowly with how long the stream has been clean. The
experiment measures that cost rather than hiding it.
"""
from __future__ import annotations

import math

from agentnorm.stats import log_beta, log_betainc


def _as_bit(x: object) -> int:
    if isinstance(x, bool):
        return int(x)
    if x in (0, 1):
        return int(x)  # type: ignore[call-overload]
    raise ValueError(f"observations must be 0/1 or bool, got {x!r}")


def _check_alpha(alpha: float) -> None:
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")


class RateConfidenceSequence:
    """Two sided confidence sequence for a Bernoulli rate (beta binomial mixture).

    For each candidate rate p, M_t(p) is the beta binomial marginal likelihood of the
    data divided by its likelihood under p. It is a martingale with mean one when p is the
    true rate, so the set of p with M_t(p) < 1/alpha covers the truth at every t at once
    with probability at least 1 - alpha. The set is an interval because the binomial log
    likelihood is concave in p, and it always contains the running mean.

    The prior only moves where the interval is tightest; coverage holds for any prior.
    Beta(1, 1) is neutral. If the rate is expected to be near 1%, Beta(1, 99) tightens the
    interval there at the cost of width elsewhere.

        cs = RateConfidenceSequence(alpha=0.05)
        for verdict in verdicts:
            cs.update(verdict.flagged)
            lo, hi = cs.interval()
    """

    def __init__(self, alpha: float = 0.05, prior: tuple[float, float] = (1.0, 1.0)) -> None:
        _check_alpha(alpha)
        a, b = prior
        if a <= 0 or b <= 0:
            raise ValueError("prior parameters must be positive")
        self.alpha = alpha
        self.a, self.b = float(a), float(b)
        self.n = 0
        self.successes = 0

    @property
    def failures(self) -> int:
        return self.n - self.successes

    @property
    def mean(self) -> float:
        return self.successes / self.n if self.n else math.nan

    def update(self, x: object) -> tuple[float, float]:
        self.successes += _as_bit(x)
        self.n += 1
        return self.interval()

    def extend(self, xs: object) -> tuple[float, float]:
        for x in xs:  # type: ignore[attr-defined]
            self.successes += _as_bit(x)
            self.n += 1
        return self.interval()

    def _log_marginal(self) -> float:
        return log_beta(self.a + self.successes, self.b + self.failures) - log_beta(self.a, self.b)

    def log_e_value(self, p: float) -> float:
        """log M_t(p): evidence against the rate being exactly p."""
        if not 0.0 <= p <= 1.0:
            raise ValueError("p must be in [0, 1]")
        s, f = self.successes, self.failures
        if (p == 0.0 and s) or (p == 1.0 and f):
            return math.inf
        loglik = (s * math.log(p) if s else 0.0) + (f * math.log1p(-p) if f else 0.0)
        return self._log_marginal() - loglik

    def contains(self, p: float) -> bool:
        return self.log_e_value(p) < math.log(1.0 / self.alpha)

    def interval(self) -> tuple[float, float]:
        """The current interval. Intersecting it with earlier ones is also valid."""
        if self.n == 0:
            return 0.0, 1.0
        s, f = self.successes, self.failures
        cut = self._log_marginal() - math.log(1.0 / self.alpha)

        def loglik(p: float) -> float:
            return (s * math.log(p) if s else 0.0) + (f * math.log1p(-p) if f else 0.0)

        p_hat = s / self.n
        lo = 0.0 if s == 0 else _bisect(loglik, cut, 0.0, p_hat, increasing=True)
        hi = 1.0 if f == 0 else _bisect(loglik, cut, p_hat, 1.0, increasing=False)
        return lo, hi


def _bisect(g, cut: float, lo: float, hi: float, *, increasing: bool) -> float:
    """Boundary of {p : g(p) > cut} on a side of the maximum where g is monotone."""
    for _ in range(100):
        mid = 0.5 * (lo + hi)
        inside = g(mid) > cut if 0.0 < mid < 1.0 else False
        if inside == increasing:
            hi = mid
        else:
            lo = mid
        if hi - lo < 1e-13:
            break
    return 0.5 * (lo + hi)


class RateAlarm:
    """Sequential test of H0: rate <= baseline, safe to check after every observation.

    The e value is a mixture over alternatives q > baseline of the likelihood ratio of q
    against the baseline, weighted by a beta prior truncated to (baseline, 1]. For every
    rate at or below the baseline each component is a supermartingale, so the mixture is
    one too, and the alarm (e value >= 1/alpha) is false with probability at most alpha
    over the whole stream.

    The default prior, Beta(1, (1 - baseline) / baseline) truncated above the baseline,
    puts its mass on shifts of the order of the baseline itself (a rate doubling), which
    is the size of change worth waking someone for. A different prior changes which shifts
    are found fastest, never the false alarm guarantee.

        alarm = RateAlarm(baseline=0.01, alpha=0.01)     # the monitor's budget
        for verdict in verdicts:
            if alarm.update(verdict.flagged):
                page(f"flag rate above 1% (e value {alarm.e_value:.0f})")

    The alarm is sticky. Restarting it after an alarm is a new test and spends a new alpha.
    """

    def __init__(
        self,
        baseline: float,
        alpha: float = 0.05,
        prior: tuple[float, float] | None = None,
    ) -> None:
        _check_alpha(alpha)
        if not 0.0 < baseline < 1.0:
            raise ValueError("baseline must be in (0, 1)")
        a, b = prior if prior is not None else (1.0, max(1.0, (1.0 - baseline) / baseline))
        if a <= 0 or b <= 0:
            raise ValueError("prior parameters must be positive")
        self.baseline = baseline
        self.alpha = alpha
        self.a, self.b = float(a), float(b)
        self._log_norm = log_beta(self.a, self.b) + log_betainc(self.a, self.b, baseline,
                                                                upper=True)
        self._log_p0 = math.log(baseline)
        self._log_q0 = math.log1p(-baseline)
        self._log_threshold = math.log(1.0 / alpha)
        self.n = 0
        self.successes = 0
        self.alarmed_at: int | None = None
        self._log_e = 0.0

    @property
    def alarmed(self) -> bool:
        return self.alarmed_at is not None

    @property
    def log_e_value(self) -> float:
        return self._log_e

    @property
    def e_value(self) -> float:
        return math.exp(self._log_e) if self._log_e < 700 else math.inf

    def _log_e_at(self, successes: int, n: int) -> float:
        f = n - successes
        a, b = self.a + successes, self.b + f
        log_mix = log_beta(a, b) + log_betainc(a, b, self.baseline, upper=True)
        return log_mix - self._log_norm - successes * self._log_p0 - f * self._log_q0

    def update(self, x: object) -> bool:
        """Record one observation. Returns True once the alarm has been raised."""
        self.successes += _as_bit(x)
        self.n += 1
        self._log_e = self._log_e_at(self.successes, self.n)
        if self.alarmed_at is None and self._log_e >= self._log_threshold:
            self.alarmed_at = self.n
        return self.alarmed

    def extend(self, xs: object) -> bool:
        for x in xs:  # type: ignore[attr-defined]
            self.update(x)
        return self.alarmed

    def threshold(self, n: int | None = None) -> int:
        """The smallest count of positives among `n` observations that raises the alarm.

        Useful on a dashboard ("17 flags in the next 400 runs would alarm") and for
        simulation, since the decision depends only on (n, count). Returns n + 1 if no
        count can alarm yet.
        """
        n = self.n if n is None else n
        if n < 0:
            raise ValueError("n must be non negative")
        # The e value increases with the count, and is at most 1 at the baseline mean,
        # so the search can start there.
        k = max(0, int(math.floor(self.baseline * n)))
        while k <= n and self._log_e_at(k, n) < self._log_threshold:
            k += 1
        return k

    def thresholds(self, horizon: int) -> list[int]:
        """`threshold(t)` for t = 0 .. horizon, in one pass.

        One more negative observation multiplies every mixture component by
        (1 - q) / (1 - baseline) < 1, so a count that alarms at t + 1 also alarms at t and
        the boundary never decreases. The search resumes where the last one stopped.
        """
        if horizon < 0:
            raise ValueError("horizon must be non negative")
        out = [self.threshold(0)]
        k = out[0]
        for t in range(1, horizon + 1):
            k = max(k, int(math.floor(self.baseline * t)))
            while k <= t and self._log_e_at(k, t) < self._log_threshold:
                k += 1
            out.append(k)
        return out


__all__ = ["RateAlarm", "RateConfidenceSequence"]
