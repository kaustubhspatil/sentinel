"""Experiment: peeking at a rate after every run, naive tests against anytime valid ones.

Question. An operator checks the share of flagged runs after every run and alarms when it
looks too high. With a fixed sample test re run at every look, how often does a perfectly
stationary benign stream raise a false alarm? With `RateAlarm` and with the lower bound of
`RateConfidenceSequence`? And once the rate really does shift, how long does each take?

Method. Every rule here decides from (t, S_t) alone, where S_t is the running count of
positives, so each rule is a boundary b(t): alarm the first time S_t >= b(t). Boundaries
are computed with agentnorm itself (standard library). Streams are simulated with numpy,
and the same false alarm probabilities are also computed exactly by dynamic programming
over S_t, so the simulation is checked against an exact answer.

Synthetic by construction: streams are i.i.d. Bernoulli draws, labelled as such.

Run from the package root, with agentnorm importable (`pip install -e .`, or
PYTHONPATH=.):

    python tools/exp_anytime_alarms.py [--streams 20000] [--out tools/results/anytime_alarms.json]

Needs numpy (experiment only; agentnorm itself does not).
"""
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

import numpy as np

from agentnorm.sequential import RateAlarm, RateConfidenceSequence
from agentnorm.stats import binom_sf, clopper_pearson

Z_95 = 1.6448536269514722   # one sided 5% normal quantile
NEVER = np.iinfo(np.int32).max


def naive_exact_boundary(p0: float, alpha: float, horizon: int, min_n: int = 1) -> np.ndarray:
    """Exact one sided binomial test at level alpha, re run at every t >= min_n."""
    b = np.full(horizon + 1, NEVER, dtype=np.int64)
    k = 0
    for t in range(1, horizon + 1):
        while k <= t and binom_sf(k, t, p0) > alpha:
            k += 1
        if t >= min_n:
            b[t] = k
    return b


def naive_z_boundary(p0: float, horizon: int, min_n: int = 30) -> np.ndarray:
    """Normal approximation z test at 5%, re run at every t >= min_n (a dashboard rule)."""
    b = np.full(horizon + 1, NEVER, dtype=np.int64)
    t = np.arange(min_n, horizon + 1)
    b[min_n:] = np.floor(p0 * t + Z_95 * np.sqrt(p0 * (1 - p0) * t)).astype(np.int64) + 1
    return b


def single_look_boundary(p0: float, alpha: float, horizon: int) -> np.ndarray:
    b = np.full(horizon + 1, NEVER, dtype=np.int64)
    k = 0
    while binom_sf(k, horizon, p0) > alpha:
        k += 1
    b[horizon] = k
    return b


def alarm_boundary(p0: float, alpha: float, horizon: int) -> np.ndarray:
    return np.asarray(RateAlarm(p0, alpha).thresholds(horizon), dtype=np.int64)


def cs_boundary(p0: float, alpha: float, horizon: int, prior: tuple[float, float]) -> np.ndarray:
    """Alarm when the two sided confidence sequence lies entirely above p0."""
    b = np.zeros(horizon + 1, dtype=np.int64)
    b[0] = NEVER
    cs = RateConfidenceSequence(alpha, prior)
    for t in range(1, horizon + 1):
        k = int(math.floor(p0 * t)) + 1
        cs.n = t
        while k <= t:
            cs.successes = k
            if not cs.contains(p0):
                break
            k += 1
        b[t] = k
    return b


def exact_crossing(boundary: np.ndarray, rates: np.ndarray) -> np.ndarray:
    """P(first crossing at t) for t = 0..horizon, stream rate rates[t] at step t.

    The top bin holds every count at or above the cap, which is above every finite
    boundary, so mass there is never lost and crosses at the next finite boundary.
    """
    horizon = len(boundary) - 1
    finite = boundary[1:][boundary[1:] < NEVER]
    cap = int(min(finite.max(), horizon)) + 2
    dist = np.zeros(cap + 1)
    dist[0] = 1.0
    first = np.zeros(horizon + 1)
    for t in range(1, horizon + 1):
        p = rates[t]
        new = dist * (1 - p)
        new[1:] += dist[:-1] * p
        new[-1] += dist[-1] * p
        bt = int(min(boundary[t], cap + 1))
        first[t] = new[bt:].sum()
        new[bt:] = 0.0
        dist = new
    return first


def simulate_first_crossing(boundaries: dict[str, np.ndarray], rates: np.ndarray,
                            streams: int, rng: np.random.Generator,
                            chunk: int = 1000) -> dict[str, np.ndarray]:
    """First crossing time per stream and rule (horizon + 1 means never).

    Every rule sees the same simulated streams, so differences between rules are not
    simulation noise.
    """
    horizon = len(rates) - 1
    out = {name: np.empty(streams, dtype=np.int64) for name in boundaries}
    for start in range(0, streams, chunk):
        m = min(chunk, streams - start)
        s = np.cumsum(rng.random((m, horizon)) < rates[1:], axis=1, dtype=np.int32)
        for name, b in boundaries.items():
            hit = s >= b[1:]
            first = hit.argmax(axis=1) + 1
            out[name][start:start + m] = np.where(hit.any(axis=1), first, horizon + 1)
    return out


def ci(k: int, n: int) -> list[float]:
    lo, hi = clopper_pearson(int(k), int(n))
    return [round(lo, 4), round(hi, 4)]


def false_alarm_study(p0: float, alpha: float, horizon: int, streams: int,
                      rng: np.random.Generator) -> dict:
    prior = (1.0, max(1.0, (1 - p0) / p0))
    rules = {
        "naive exact test, every run": naive_exact_boundary(p0, alpha, horizon, 1),
        "naive exact test, every run after 100": naive_exact_boundary(p0, alpha, horizon, 100),
        "naive z test, every run after 30": naive_z_boundary(p0, horizon, 30),
        "single look at the horizon": single_look_boundary(p0, alpha, horizon),
        "confidence sequence lower bound": cs_boundary(p0, alpha, horizon, prior),
        "RateAlarm": alarm_boundary(p0, alpha, horizon),
    }
    rates = np.full(horizon + 1, p0)
    checkpoints = [h for h in (100, 500, 1000, 2000, 5000, 10000) if h <= horizon]
    out = {}
    firsts = simulate_first_crossing(rules, rates, streams, rng)
    for name, b in rules.items():
        first = firsts[name]
        exact_first = np.cumsum(exact_crossing(b, rates))
        row = {}
        for h in checkpoints:
            k = int((first <= h).sum())
            row[str(h)] = {"simulated": round(k / streams, 4), "ci95": ci(k, streams),
                           "exact": round(float(exact_first[h]), 4)}
        out[name] = row
    return out


def shift_study(p0: float, alpha: float, change_at: int, ratio: float, after: int,
                streams: int, rng: np.random.Generator) -> dict:
    horizon = change_at + after
    prior = (1.0, max(1.0, (1 - p0) / p0))
    p1 = min(0.999, p0 * ratio)
    rates = np.full(horizon + 1, p0)
    rates[change_at + 1:] = p1
    rules = {
        "naive exact test, every run after 100": naive_exact_boundary(p0, alpha, horizon, 100),
        "confidence sequence lower bound": cs_boundary(p0, alpha, horizon, prior),
        "RateAlarm": alarm_boundary(p0, alpha, horizon),
    }
    out = {}
    firsts = simulate_first_crossing(rules, rates, streams, rng)
    for name in rules:
        first = firsts[name]
        before = int((first <= change_at).sum())
        live = first[first > change_at]
        found = live[live <= horizon] - change_at
        row = {
            "false_alarm_before_change": round(before / streams, 4),
            "detected_within": after,
            "detected": round(len(found) / max(len(live), 1), 4),
            "detected_ci95": ci(len(found), max(len(live), 1)),
        }
        if len(found):
            q = np.percentile(found, [25, 50, 75])
            row["delay_quartiles"] = [int(v) for v in q]
        out[name] = row
    return {"p0": p0, "p1": p1, "change_at": change_at, **{"rules": out}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--streams", type=int, default=20000)
    ap.add_argument("--shift-streams", type=int, default=5000)
    ap.add_argument("--horizon", type=int, default=10000)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--out", default=str(Path(__file__).parent / "results" / "anytime_alarms.json"))
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    t0 = time.perf_counter()

    result: dict = {"alpha": args.alpha, "streams": args.streams, "horizon": args.horizon,
                    "synthetic": "i.i.d. Bernoulli streams", "false_alarm": {}, "shift": []}
    for p0 in (0.01, 0.05):
        fa = false_alarm_study(p0, args.alpha, args.horizon, args.streams, rng)
        result["false_alarm"][str(p0)] = fa
        print(f"\nfalse alarm probability, stationary rate p0={p0}, alpha={args.alpha}, "
              f"{args.streams} streams (simulated [95% CI] / exact)")
        for name, row in fa.items():
            cells = "  ".join(f"t<={h}: {v['simulated']:.3f} {v['ci95']} / {v['exact']:.3f}"
                              for h, v in row.items() if h in ("1000", str(args.horizon)))
            print(f"  {name:<40} {cells}")

    for p0 in (0.01, 0.05):
        for change_at in (100, 1000, 5000):
            for ratio in (1.5, 2.0, 3.0, 5.0):
                r = shift_study(p0, args.alpha, change_at, ratio, 10000, args.shift_streams, rng)
                result["shift"].append(r)
                print(f"\nshift p0={p0} -> p1={r['p1']:.3f} at t={change_at}")
                for name, row in r["rules"].items():
                    print(f"  {name:<40} false alarm before change {row['false_alarm_before_change']:.3f}"
                          f"  detected {row['detected']:.3f} {row['detected_ci95']}"
                          f"  delay quartiles {row.get('delay_quartiles')}")

    result["seconds"] = round(time.perf_counter() - t0, 1)
    result["backend"] = f"numpy {np.__version__} (CPU)"
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"\n{result['seconds']} s; written to {args.out}")


if __name__ == "__main__":
    main()
