"""Experiment: can the calibrated monitor fire, and on what?

Benign traffic is **synthetic** (`synthetic_population`), modelled on the reference
deployment's generator: three agents with different run shapes, three tenants whose scopes
are opaque ids, heavy tailed result sizes, occasional failed calls. Real traces live in
the deployment's ClickHouse, not in this repository, so the table below is a statement
about this population and these injectors, not about any production system.

For each false positive budget the monitor is fitted and calibrated on one slice, and on
a disjoint held out slice every injector plants one anomaly into every run. Reported per
detector and per anomaly: true positive rate with an exact 95% interval, next to the false
positive rate observed on the same runs before planting.

Two extra views:
  * a magnitude sweep, because "detects oversized results" means nothing without "how
    oversized";
  * cold start: the same injectors on runs from an agent version the monitor has never
    seen, where sequence and rate are suppressed by design.

Run from the package root, with agentnorm importable (`pip install -e .`, or
PYTHONPATH=.):

    python tools/exp_detection_power.py [--out tools/results/detection_power.json]

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from agentnorm import Monitor, Run
from agentnorm.power import (
    ANY,
    Burst,
    ExtraCalls,
    ForeignScope,
    InjectionContext,
    OversizedResult,
    UnseenTool,
    detection_power,
)
from agentnorm.trace import ToolCall

TENANT_SCOPES = {
    "acme": ["vpc-0a11", "vpc-0a12"],
    "globex": ["vpc-1b21", "vpc-1b22"],
    "initech": ["vpc-2c31", "vpc-2c32"],
}
SCALE = {"list_schema": 30, "find_entities": 12, "vulnerability_exposure": 40,
         "sla_status": 3, "traverse": 25, "attack_context": 8, "blast_radius": 15,
         "patch_plan": 5, "summarise": 1}


def _rows(rng: random.Random, tool: str) -> int:
    return max(1, int(rng.lognormvariate(0, 0.9) * SCALE[tool]))


def _path(agent: str, rng: random.Random) -> list[str]:
    if agent == "triage":
        path = [rng.choice(["list_schema", "find_entities"])]
        path += rng.choices(["vulnerability_exposure", "sla_status", "traverse"],
                            k=rng.randint(1, 3))
        if rng.random() < 0.4:
            path.append("attack_context")
        return path
    if agent == "reporting":
        path = ["find_entities"]
        path += rng.choices(["vulnerability_exposure", "sla_status", "traverse"],
                            weights=[3, 2, 1], k=rng.randint(4, 10))
        return [*path, "blast_radius", "summarise"]
    path = ["find_entities", "traverse", "blast_radius"]      # remediation
    path += ["patch_plan"] * rng.randint(1, 2)
    if rng.random() < 0.3:
        path.insert(2, "attack_context")
    return path


def synthetic_run(rng: random.Random, agent: str, version: str) -> Run:
    tenant = rng.choice(list(TENANT_SCOPES))
    run = Run(agent=agent, version=version, principal=tenant, label="synthetic_benign",
              is_anomalous=0)
    for step, tool in enumerate(_path(agent, rng), start=1):
        ok = rng.random() > 0.02
        run.calls.append(ToolCall(
            tool=tool, step=step, args={"tenant": tenant}, ok=ok,
            error="" if ok else "TransientGraphError: connection reset",
            result_size=_rows(rng, tool) if ok else 0,
            scope=rng.choice(TENANT_SCOPES[tenant]),
        ))
    return run


AGENTS = [("triage", "v1"), ("reporting", "v2"), ("remediation", "v1")]


def synthetic_population(n: int, seed: int) -> list[Run]:
    rng = random.Random(seed)
    return [synthetic_run(rng, *rng.choice(AGENTS)) for _ in range(n)]


MAIN = [ExtraCalls(3), UnseenTool(), ForeignScope(), OversizedResult(100.0), Burst(10)]
SWEEP = [ExtraCalls(1), ExtraCalls(3), ExtraCalls(10),
         OversizedResult(3.0), OversizedResult(10.0), OversizedResult(30.0),
         OversizedResult(100.0), OversizedResult(1000.0),
         Burst(3), Burst(5), Burst(10), Burst(20), UnseenTool(), ForeignScope()]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--out", default=str(Path(__file__).parent / "results" / "detection_power.json"))
    args = ap.parse_args()
    t0 = time.perf_counter()

    pool = synthetic_population(args.runs, args.seed)
    cut = int(len(pool) * 0.7)
    fit_runs, test_runs = pool[:cut], pool[cut:]
    ctx = InjectionContext.from_runs(fit_runs)
    cold = [synthetic_run(random.Random(args.seed + i), "triage", "v9") for i in range(1000)]

    result: dict = {"synthetic": "synthetic_population", "runs": args.runs, "seed": args.seed,
                    "fit_and_calibration_runs": len(fit_runs), "held_out_runs": len(test_runs),
                    "by_budget": {}, "sweep": {}, "cold_start": {}}

    for budget in (0.005, 0.01, 0.05, 0.1, 0.2):
        monitor = Monitor.fit(fit_runs, budget=budget)
        report = detection_power(monitor, test_runs, SWEEP, context=ctx, seed=args.seed)
        result["by_budget"][str(budget)] = {"warnings": monitor.warnings,
                                            "calibration_runs": monitor.calibration_runs,
                                            **report.to_dict()}
        if budget == 0.01:
            main_report = detection_power(monitor, test_runs, MAIN, context=ctx, seed=args.seed)
            print(main_report.format())
            print()
            cold_report = detection_power(monitor, cold, MAIN, context=ctx, seed=args.seed)
            result["cold_start"] = cold_report.to_dict()
            print("cold start: agent version triage@v9, never seen in fit")
            print(cold_report.format())
            print()

    # The sweep as an operating table: suite level TPR per injector across budgets.
    names = [inj.name for inj in SWEEP]
    budgets = list(result["by_budget"])
    print("suite level (any detector) true positive rate by budget, held out, 95% exact CI")
    print(f"{'':<24}" + "".join(f"{b:>22}" for b in budgets))
    fpr_row = [result["by_budget"][b]["fpr"][ANY] for b in budgets]
    print(f"{'benign (FPR)':<24}" + "".join(
        f"{r['rate']:>8.3f} [{r['lo']:.3f},{r['hi']:.3f}]" for r in fpr_row))
    for name in names:
        cells = [result["by_budget"][b]["tpr"][name][ANY] for b in budgets]
        result["sweep"][name] = {b: c for b, c in zip(budgets, cells, strict=True)}
        print(f"{name:<24}" + "".join(
            f"{c['rate']:>8.3f} [{c['lo']:.3f},{c['hi']:.3f}]" for c in cells))

    result["seconds"] = round(time.perf_counter() - t0, 1)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"\n{result['seconds']} s; written to {args.out}")


if __name__ == "__main__":
    main()
