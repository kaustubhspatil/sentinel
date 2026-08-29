"""Measuring a detector suite against labelled runs, and how much its settings matter.

Two things live here.

`evaluate` scores a fitted suite against labelled data: recall per attack family, and the
false-positive rate on held-out benign runs. Thresholds are calibrated on a slice the test
set never sees, because a false-positive rate measured on the data that set the threshold
is not a false-positive rate.

`sensitivity` sweeps the settings that were chosen by judgement rather than derived -
`prior_strength`, the false-positive budget, the calibration split - and reports how much
the answer moves. That is the difference between a result and a coincidence. A detector
whose recall collapses when a hand-picked constant changes by a factor of two has not been
validated, it has been tuned, and nobody should deploy it.

Reporting per-family recall rather than an aggregate is deliberate throughout. An
aggregate F1 hides a total blind spot behind a respectable number - which is how the
scope detector once scored well while catching 1 escalation in 25.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from agentnorm.detectors import DetectorSuite
from agentnorm.monitor import Monitor
from agentnorm.trace import Run


@dataclass
class Metrics:
    prior_strength: float
    budget: float
    calibration_fraction: float
    fit_runs: int
    test_benign_runs: int
    anomalous_runs: int
    false_positives: int
    detected: int
    by_family: dict[str, str] = field(default_factory=dict)
    by_detector_fp: dict[str, int] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        return self.detected / self.anomalous_runs if self.anomalous_runs else 0.0

    @property
    def fpr(self) -> float:
        return self.false_positives / self.test_benign_runs if self.test_benign_runs else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "prior_strength": self.prior_strength,
            "budget": self.budget,
            "calibration_fraction": self.calibration_fraction,
            "recall": round(self.recall, 3),
            "fpr": round(self.fpr, 4),
            "false_positives": self.false_positives,
            "test_benign_runs": self.test_benign_runs,
            "by_family": self.by_family,
        }


def evaluate(
    benign: list[Run],
    anomalous: list[Run],
    *,
    prior_strength: float = 8.0,
    budget: float = 0.01,
    calibration_fraction: float = 0.25,
    test_fraction: float = 0.2,
    seed: int = 11,
) -> Metrics:
    """Fit on benign runs, calibrate on a held-out slice, score on a slice neither saw."""
    if not benign or not anomalous:
        raise ValueError("need both benign and anomalous runs")

    pool = benign[:]
    random.Random(seed).shuffle(pool)
    cut = int(len(pool) * (1 - test_fraction))
    fit_pool, test_benign = pool[:cut], pool[cut:]

    monitor = Monitor.fit(
        fit_pool,
        budget=budget,
        calibration_fraction=calibration_fraction,
        prior_strength=prior_strength,
    )

    false_positives = sum(1 for r in test_benign if monitor.score(r).flagged)
    by_detector_fp = {
        name: sum(
            1
            for r in test_benign
            for a in monitor.score(r).alerts
            if a.detector == name
        )
        for name in DetectorSuite.NAMES
    }

    families: dict[str, list[int]] = {}
    detected = 0
    for run in anomalous:
        hit = monitor.score(run).flagged
        detected += int(hit)
        slot = families.setdefault(run.label or "unlabelled", [0, 0])
        slot[0] += int(hit)
        slot[1] += 1

    return Metrics(
        prior_strength=prior_strength,
        budget=budget,
        calibration_fraction=calibration_fraction,
        fit_runs=len(fit_pool),
        test_benign_runs=len(test_benign),
        anomalous_runs=len(anomalous),
        false_positives=false_positives,
        detected=detected,
        by_family={k: f"{v[0]}/{v[1]}" for k, v in sorted(families.items())},
        by_detector_fp=by_detector_fp,
    )


def sensitivity(
    benign: list[Run],
    anomalous: list[Run],
    *,
    prior_strengths: tuple[float, ...] = (1.0, 4.0, 8.0, 16.0, 64.0),
    budgets: tuple[float, ...] = (0.005, 0.01, 0.05),
    calibration_fractions: tuple[float, ...] = (0.15, 0.25, 0.4),
    seeds: tuple[int, ...] = (11, 23, 37),
) -> dict[str, Any]:
    """Vary one setting at a time around the defaults and report the spread.

    One at a time rather than a full grid: the question is whether any single judgement
    call is load-bearing, and a grid answers a different, more expensive question while
    making the individual effects harder to read.

    Multiple seeds because the split is random, and a range that is mostly split noise
    should not be read as sensitivity to the parameter.
    """
    base = {"prior_strength": 8.0, "budget": 0.01, "calibration_fraction": 0.25}
    out: dict[str, Any] = {"baseline": {}, "sweeps": {}}

    def run_at(**overrides: float) -> list[Metrics]:
        settings = {**base, **overrides}
        return [evaluate(benign, anomalous, seed=s, **settings) for s in seeds]

    def summarise(runs: list[Metrics]) -> dict[str, Any]:
        recalls = [m.recall for m in runs]
        fprs = [m.fpr for m in runs]
        return {
            "recall_mean": round(sum(recalls) / len(recalls), 3),
            "recall_range": [round(min(recalls), 3), round(max(recalls), 3)],
            "fpr_mean": round(sum(fprs) / len(fprs), 4),
            "fpr_range": [round(min(fprs), 4), round(max(fprs), 4)],
            "by_family": runs[0].by_family,
        }

    out["baseline"] = summarise(run_at())
    out["sweeps"]["prior_strength"] = {
        str(v): summarise(run_at(prior_strength=v)) for v in prior_strengths
    }
    out["sweeps"]["budget"] = {
        str(v): summarise(run_at(budget=v)) for v in budgets
    }
    out["sweeps"]["calibration_fraction"] = {
        str(v): summarise(run_at(calibration_fraction=v)) for v in calibration_fractions
    }

    # A parameter is load-bearing if moving it across the swept range moves recall by
    # more than split noise. The baseline's own seed-to-seed spread is that noise floor.
    noise = out["baseline"]["recall_range"][1] - out["baseline"]["recall_range"][0]
    verdict: dict[str, Any] = {"seed_noise_in_recall": round(noise, 3)}
    for param, results in out["sweeps"].items():
        means = [r["recall_mean"] for r in results.values()]
        spread = max(means) - min(means)
        verdict[param] = {
            "recall_spread": round(spread, 3),
            "load_bearing": bool(spread > max(noise, 0.02)),
        }
    out["verdict"] = verdict
    return out


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"baseline: recall {report['baseline']['recall_mean']} "
        f"{report['baseline']['recall_range']}  "
        f"fpr {report['baseline']['fpr_mean']} {report['baseline']['fpr_range']}",
        f"  by family: {report['baseline']['by_family']}",
        "",
    ]
    for param, results in report["sweeps"].items():
        v = report["verdict"][param]
        flag = "LOAD-BEARING" if v["load_bearing"] else "not load-bearing"
        lines.append(f"{param}  (recall spread {v['recall_spread']}) -> {flag}")
        for value, r in results.items():
            lines.append(
                f"    {value:>6}  recall {r['recall_mean']:.3f} {r['recall_range']}"
                f"   fpr {r['fpr_mean']:.4f} {r['fpr_range']}"
            )
        lines.append("")
    lines.append(f"seed noise in recall: {report['verdict']['seed_noise_in_recall']}")
    return "\n".join(lines)


__all__ = ["Metrics", "evaluate", "format_report", "sensitivity"]
