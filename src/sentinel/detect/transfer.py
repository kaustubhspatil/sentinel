"""Does a detector fitted on generated behaviour work on real behaviour?

This is the question the detection results were silent on. Everything reported so far was
fitted and scored on traces this project generated, which measures internal consistency
and nothing else. The eval and adversarial suites have since produced real `graph_agent`
runs against the live estate, so the transfer question is now answerable.

Three configurations, deliberately:

  synthetic -> real   fit on generated benign, score real runs. The honest test of whether
                      generated training data is worth anything.
  real -> real        fit and score on real runs (split), the achievable ceiling at this
                      data volume.
  real -> synthetic   fit on real, score generated anomalies. Tests whether a detector
                      trained on genuine behaviour still catches the attack families.

Every alert on real traffic is a false positive by assumption, because the real runs are
known-benign: they are this project's own evaluation and adversarial runs, and the one
genuine misbehaviour among them (the cross-tenant disclosure) was fixed before these
traces were collected. That assumption is stated rather than hidden, and it is the main
threat to these numbers.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import Any

from sentinel.detect.detectors import DetectorSuite, Run, assemble
from sentinel.store.clickhouse import client

COLUMNS = """run_id, step, agent, agent_version, tenant, tool, result_rows,
             zone, resource, scenario, is_anomalous"""


def _load(where: str) -> list[Run]:
    rows = client().query(
        f"SELECT {COLUMNS} FROM agent_tool_calls WHERE {where}"
    ).named_results()
    return assemble(list(rows))


def load_real() -> list[Run]:
    return _load("is_anomalous = -1")


def load_synthetic_benign() -> list[Run]:
    return _load("is_anomalous = 0")


def load_synthetic_anomalous() -> list[Run]:
    return _load("is_anomalous = 1")


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return s[min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))]


@dataclass
class TransferReport:
    config: str
    fit_runs: int
    scored_runs: int
    alerts: dict[str, int]
    alert_rate: dict[str, float]
    any_alert: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config,
            "fit_runs": self.fit_runs,
            "scored_runs": self.scored_runs,
            "alerts_by_detector": self.alerts,
            "alert_rate_by_detector": self.alert_rate,
            "runs_with_any_alert": self.any_alert,
            "any_alert_rate": round(self.any_alert / max(self.scored_runs, 1), 3),
        }


def _thresholds(suite: DetectorSuite, calib: list[Run], budget: float) -> dict[str, float]:
    scores = {k: [] for k in DetectorSuite.NAMES}
    for r in calib:
        for k, v in suite.score(r).items():
            scores[k].append(v)
    return {k: _quantile(v, 1 - budget) for k, v in scores.items()}


def evaluate_transfer(budget: float = 0.002, seed: int = 5) -> dict[str, Any]:
    real = load_real()
    syn_benign = load_synthetic_benign()
    syn_anom = load_synthetic_anomalous()
    if not real:
        raise RuntimeError("no real traces - run the eval suite first")

    out: dict[str, Any] = {"counts": {
        "real_runs": len(real),
        "synthetic_benign_runs": len(syn_benign),
        "synthetic_anomalous_runs": len(syn_anom),
    }}
    reports: list[TransferReport] = []

    # 1. synthetic -> real
    rng = random.Random(seed)
    shuffled = syn_benign[:]
    rng.shuffle(shuffled)
    cut = int(0.8 * len(shuffled))
    suite = DetectorSuite.fit(shuffled[:cut])
    thr = _thresholds(suite, shuffled[cut:], budget)
    alerts = {k: sum(1 for r in real if suite.score(r)[k] > thr[k]) for k in thr}
    any_alert = sum(1 for r in real if any(suite.score(r)[k] > thr[k] for k in thr))
    reports.append(TransferReport(
        "synthetic_fit -> real_score", cut, len(real), alerts,
        {k: round(v / len(real), 3) for k, v in alerts.items()}, any_alert))

    # 2. real -> real, split in half
    if len(real) >= 8:
        r2 = real[:]
        random.Random(seed + 1).shuffle(r2)
        half = len(r2) // 2
        s2 = DetectorSuite.fit(r2[:half])
        # With this few runs a 0.2% quantile is not estimable, so the threshold is the
        # observed maximum on the fit half. Stated because it makes the alert rate a
        # lower bound rather than a measurement.
        t2 = _thresholds(s2, r2[:half], budget)
        a2 = {k: sum(1 for r in r2[half:] if s2.score(r)[k] > t2[k]) for k in t2}
        any2 = sum(1 for r in r2[half:] if any(s2.score(r)[k] > t2[k] for k in t2))
        reports.append(TransferReport(
            "real_fit -> real_score", half, len(r2) - half, a2,
            {k: round(v / max(len(r2) - half, 1), 3) for k, v in a2.items()}, any2))

    # 3. real -> synthetic anomalies
    if syn_anom:
        s3 = DetectorSuite.fit(real)
        t3 = _thresholds(s3, real, budget)
        a3 = {k: sum(1 for r in syn_anom if s3.score(r)[k] > t3[k]) for k in t3}
        any3 = sum(1 for r in syn_anom if any(s3.score(r)[k] > t3[k] for k in t3))
        reports.append(TransferReport(
            "real_fit -> synthetic_anomaly_score", len(real), len(syn_anom), a3,
            {k: round(v / len(syn_anom), 3) for k, v in a3.items()}, any3))

    out["configurations"] = [r.to_dict() for r in reports]
    return out


if __name__ == "__main__":
    rep = evaluate_transfer()
    print(json.dumps(rep["counts"], indent=2))
    for c in rep["configurations"]:
        print(f"\n--- {c['config']}  (fit={c['fit_runs']} scored={c['scored_runs']})")
        for k, v in c["alert_rate_by_detector"].items():
            print(f"    {k:12s} alerts={c['alerts_by_detector'][k]:4d}  rate={v}")
        print(f"    ANY          {c['runs_with_any_alert']}  rate={c['any_alert_rate']}")
