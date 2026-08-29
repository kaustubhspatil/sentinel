"""Evaluate the detectors against labelled traces.

Reports per-detector and per-scenario precision and recall at a threshold chosen on a
held-out split, never on the test set. Also reports what each detector *misses*, because
a detector suite is judged by its blind spots and an aggregate F1 hides them completely.

Thresholds are set from the benign distribution at a fixed false-positive budget rather
than by maximising F1. An operator can act on "this fires once per hundred clean runs";
they cannot act on "this maximises a statistic".
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

from agentnorm.detectors import DetectorSuite
from agentnorm.trace import Run

from sentinel.store.agentnorm_store import ClickHouseStore

FPR_BUDGET = 0.01  # target false-positive rate for the SUITE, not per detector

# Four independent detectors each firing on 1% of benign runs gives a union near 4%, not
# 1%. The first run of this measured 5.8% against a "1%" budget for exactly that reason.
# Splitting the budget across detectors (a Bonferroni-style correction) makes the number
# the operator actually experiences match the number that was promised.
N_DETECTORS = 5
PER_DETECTOR_BUDGET = FPR_BUDGET / N_DETECTORS


@dataclass
class DetectorResult:
    name: str
    threshold: float
    tp: int
    fp: int
    fn: int
    by_scenario: dict[str, tuple[int, int]]  # scenario -> (caught, total)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0


def load_runs() -> list[Run]:
    """Labelled evaluation runs only; real traffic is excluded."""
    store = ClickHouseStore()
    return store.read(where="is_anomalous >= 0")


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[idx]


def evaluate(seed: int = 11, prior_strength: float | None = None) -> dict[str, Any]:
    runs = load_runs()
    benign = [r for r in runs if r.is_anomalous == 0]
    anomalous = [r for r in runs if r.is_anomalous == 1]
    if not benign or not anomalous:
        raise RuntimeError("no labelled traces - run: python -m sentinel.detect.scenarios")

    # Split benign into fit / calibrate / test. Thresholds come from calibrate; the
    # false-positive rate is measured on test, which the threshold has never seen.
    rng = random.Random(seed)
    rng.shuffle(benign)
    n = len(benign)
    fit_set = benign[: int(0.6 * n)]
    calib_set = benign[int(0.6 * n) : int(0.8 * n)]
    test_benign = benign[int(0.8 * n) :]

    kwargs = {} if prior_strength is None else {"prior_strength": prior_strength}
    suite = DetectorSuite.fit(fit_set, **kwargs)

    calib_scores = {k: [] for k in DetectorSuite.NAMES}
    for r in calib_set:
        for k, s in suite.score(r).items():
            if not s.suppressed:
                calib_scores[k].append(s.value)
    thresholds = {k: _quantile(v, 1 - PER_DETECTOR_BUDGET) for k, v in calib_scores.items()}

    results: dict[str, DetectorResult] = {}
    for name in DetectorSuite.NAMES:
        thr = thresholds[name]
        fp = sum(1 for r in test_benign if suite.score(r)[name].value > thr)
        tp = fn = 0
        by_scenario: dict[str, list[int]] = {}
        for r in anomalous:
            hit = suite.score(r)[name].value > thr
            tp, fn = (tp + 1, fn) if hit else (tp, fn + 1)
            slot = by_scenario.setdefault(r.label, [0, 0])
            slot[0] += int(hit)
            slot[1] += 1
        results[name] = DetectorResult(
            name, thr, tp, fp, fn, {k: (v[0], v[1]) for k, v in by_scenario.items()}
        )

    # Union: any detector firing. Reported separately because the suite's value is
    # coverage across failure modes, not any single detector's score.
    union_fp = sum(
        1 for r in test_benign if any(suite.score(r)[k].value > thresholds[k] for k in thresholds)
    )
    union_tp = 0
    union_by_scenario: dict[str, list[int]] = {}
    for r in anomalous:
        hit = any(suite.score(r)[k].value > thresholds[k] for k in thresholds)
        union_tp += int(hit)
        slot = union_by_scenario.setdefault(r.label, [0, 0])
        slot[0] += int(hit)
        slot[1] += 1

    return {
        "counts": {
            "benign_total": len(benign),
            "fit": len(fit_set),
            "calibrate": len(calib_set),
            "test_benign": len(test_benign),
            "anomalous": len(anomalous),
        },
        "fpr_budget_suite": FPR_BUDGET,
        "fpr_budget_per_detector": round(PER_DETECTOR_BUDGET, 4),
        "prior_strength": prior_strength,
        "detectors": {
            name: {
                "threshold": round(r.threshold, 3),
                "precision": round(r.precision, 3),
                "recall": round(r.recall, 3),
                "false_positives": r.fp,
                "by_scenario": {k: f"{v[0]}/{v[1]}" for k, v in sorted(r.by_scenario.items())},
            }
            for name, r in results.items()
        },
        "union": {
            "recall": round(union_tp / len(anomalous), 3),
            "false_positives": union_fp,
            "fpr": round(union_fp / max(len(test_benign), 1), 4),
            "by_scenario": {k: f"{v[0]}/{v[1]}" for k, v in sorted(union_by_scenario.items())},
        },
    }


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
