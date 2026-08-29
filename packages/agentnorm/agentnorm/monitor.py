"""The public API: fit a baseline, score a run, get an actionable verdict.

Thresholds are chosen by **false-positive budget**, not by maximising a statistic. An
operator can act on "this fires once per two hundred clean runs"; nobody can act on "this
maximises F1". The budget is stated for the *suite*, then divided across detectors,
because five detectors each firing on 1% of runs union to roughly 5% — a suite advertised
at 1% that delivers 5% gets muted within a week, and a muted detector detects nothing.

Calibration needs enough runs to estimate the quantile it is asked for. A 0.2% quantile
cannot be estimated from 120 samples - the threshold lands on the sample maximum and does
not generalise. `fit` says so rather than returning a number that looks fine.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from agentnorm.detectors import DetectorSuite
from agentnorm.trace import Run

DEFAULT_BUDGET = 0.01


@dataclass(frozen=True)
class Alert:
    detector: str
    score: float
    threshold: float

    @property
    def ratio(self) -> float:
        return self.score / self.threshold if self.threshold else float("inf")

    def __str__(self) -> str:
        return f"{self.detector}={self.score:.2f} (threshold {self.threshold:.2f})"


@dataclass
class Verdict:
    run_id: str
    alerts: list[Alert] = field(default_factory=list)
    cold_start: bool = False
    uncalibrated: list[str] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return bool(self.alerts)

    def explain(self) -> str:
        """One line an operator can act on, naming the invariant that broke."""
        if not self.alerts:
            base = "no anomaly"
        else:
            base = "; ".join(str(a) for a in sorted(self.alerts, key=lambda a: -a.ratio))
        notes = []
        if self.cold_start:
            notes.append("cold start: no history for this agent version")
        if self.uncalibrated:
            notes.append(f"uncalibrated: {', '.join(self.uncalibrated)}")
        return base + (f" [{'; '.join(notes)}]" if notes else "")


class CalibrationWarning(UserWarning):
    pass


@dataclass
class Monitor:
    suite: DetectorSuite
    thresholds: dict[str, float]
    budget: float = DEFAULT_BUDGET
    calibration_runs: int = 0
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def fit(
        cls,
        runs: list[Run],
        *,
        budget: float = DEFAULT_BUDGET,
        calibration_fraction: float = 0.25,
        prior_strength: float = 8.0,
    ) -> Monitor:
        """Fit on benign runs and calibrate thresholds on a held-out slice.

        The calibration slice is held out deliberately: thresholds taken from the same
        runs the detectors were fitted on are optimistic, and the false-positive rate an
        operator experiences is the one measured on data the threshold has not seen.
        """
        if not runs:
            raise ValueError("no runs to fit on")

        cut = max(1, int(len(runs) * (1 - calibration_fraction)))
        fit_runs, calib_runs = runs[:cut], runs[cut:] or runs[-1:]

        suite = DetectorSuite.fit(fit_runs, prior_strength=prior_strength)
        per_detector = budget / len(DetectorSuite.NAMES)

        warnings: list[str] = []
        needed = int(math.ceil(1 / per_detector))
        if len(calib_runs) < needed:
            warnings.append(
                f"calibration set has {len(calib_runs)} runs but a {per_detector:.4f} "
                f"quantile needs at least {needed}; thresholds fall back to the observed "
                f"maximum and the true false-positive rate will exceed the budget"
            )

        scores: dict[str, list[float]] = {n: [] for n in DetectorSuite.NAMES}
        for r in calib_runs:
            for name, s in suite.score(r).items():
                if not s.suppressed:
                    scores[name].append(s.value)

        thresholds = {
            name: _quantile(vals, 1 - per_detector) if vals else math.inf
            for name, vals in scores.items()
        }
        return cls(suite=suite, thresholds=thresholds, budget=budget,
                   calibration_runs=len(calib_runs), warnings=warnings)

    def score(self, run: Run) -> Verdict:
        scores = self.suite.score(run)
        alerts = [
            Alert(name, s.value, self.thresholds[name])
            for name, s in scores.items()
            if not s.suppressed and s.value > self.thresholds[name]
        ]
        return Verdict(
            run_id=run.run_id,
            alerts=alerts,
            cold_start=self.suite.is_cold_start(run),
            uncalibrated=[n for n, s in scores.items() if s.suppressed or not s.calibrated],
            scores={n: s.value for n, s in scores.items()},
        )


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return math.inf
    s = sorted(values)
    return s[min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))]
