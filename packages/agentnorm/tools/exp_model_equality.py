"""Experiment: how many canary prompts does it take to notice a model swap?

Data. Real outputs recorded by the Plimsoll evaluation harness (a separate repository):
several models answering the same questions through the same retrieval pipeline, at
temperature 0. Each `answers-*.rows.jsonl` holds one row per question (`qid`,
`model_answer`); the matching `.json` holds the corpus digest and retriever. No API is
called here; the outputs are read from disk. Only statistics are written out, never
answer text.

Canary output. The model's own text (`model_answer`). An empty text is the model
choosing to abstain; prompts where either side abstained are dropped, symmetrically, so
the paired null stays exact.

Comparisons.
  Different models, same corpus digest and same retriever (the clean case).
  Different models where the retriever also differs (flagged as confounded).
  Same model, different retrieval pipeline. Not a null for "the outputs are equal", since
    the prompts the model sees differ, but the right check of what the test reacts to.
  Exact null by construction: one model's outputs, prompts split at random into two
    disjoint halves and paired at random. Exchangeable by design, so this checks the
    implementation's calibration, not the realism of the null.
  Same model across corpus versions is *not* used: the qids in the two versions are
    different questions (principal and reason agree on 10 of 150), so there is no pairing.

For each comparison and number of canary prompts n, R random subsets of the shared prompt
pool are tested. The subsets come from one finite pool (about 100 prompts), so they
overlap, increasingly so as n grows; the Clopper Pearson interval on the rejection rate
describes resampling noise for this pool, not uncertainty over other canary sets.

Run from the package root, with agentnorm importable (`pip install -e .`, or
PYTHONPATH=.):

    python tools/exp_model_equality.py --reports <plimsoll>/reports [--reps 500]

Standard library only (multiprocessing for speed).
"""
from __future__ import annotations

import argparse
import json
import random
import time
from multiprocessing import Pool
from pathlib import Path

from agentnorm.equality import model_equality_test, pair_outputs
from agentnorm.stats import clopper_pearson

RUNS = {
    "sonnet-4-6/dense+rerank": "claude-sonnet-4-6-dense-rerank",
    "nova-pro/dense+rerank": "nova-pro-v1-dense-rerank",
    "nova-lite/dense": "nova-lite-v1-dense",
    "haiku-4-5/dense+rerank": "claude-haiku-4-5-20251001-v1-dense-rerank",
    "haiku-4-5/dense+rerank+decompose": "claude-haiku-4-5-20251001-v1-dense-rerank-decompose",
    "haiku-4-5/dense+llmrerank+decompose": "claude-haiku-4-5-20251001-v1-dense-llmrerank-decompose",
    "nova-lite/dense+rerank": "nova-lite-v1-dense-rerank",
}

COMPARISONS = [
    ("different model", "sonnet-4-6/dense+rerank", "nova-pro/dense+rerank"),
    ("different model", "haiku-4-5/dense+rerank", "nova-lite/dense+rerank"),
    ("different model, retriever also differs", "nova-lite/dense", "nova-pro/dense+rerank"),
    ("same model, pipeline differs", "haiku-4-5/dense+rerank", "haiku-4-5/dense+rerank+decompose"),
    ("same model, pipeline differs", "haiku-4-5/dense+rerank", "haiku-4-5/dense+llmrerank+decompose"),
]
NULL_SPLIT_RUNS = ["sonnet-4-6/dense+rerank", "nova-pro/dense+rerank", "haiku-4-5/dense+rerank",
                   "nova-lite/dense+rerank"]
SIZES = (5, 10, 20, 50)


def load(reports: Path, stem: str) -> tuple[dict[str, str], dict]:
    meta = json.loads((reports / f"answers-{stem}.json").read_text(encoding="utf-8"))["meta"]
    rows = {}
    with (reports / f"answers-{stem}.rows.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            rows[r["qid"]] = r["model_answer"] or ""
    return rows, meta


def _task(args: tuple) -> tuple[str, str, int, float]:
    key, design, n, a, b, seed, permutations = args
    r = model_equality_test(a, b, paired=(design == "paired"), permutations=permutations,
                            seed=seed)
    return key, design, n, r.p_value


def rate(k: int, n: int) -> dict:
    lo, hi = clopper_pearson(k, n)
    return {"rejected": k, "n": n, "rate": round(k / n, 4), "ci95": [round(lo, 4), round(hi, 4)]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", required=True, type=Path)
    ap.add_argument("--reps", type=int, default=500)
    ap.add_argument("--permutations", type=int, default=999)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--out", default=str(Path(__file__).parent / "results" / "model_equality.json"))
    args = ap.parse_args()
    t0 = time.perf_counter()

    data = {name: load(args.reports, stem) for name, stem in RUNS.items()}
    rng = random.Random(args.seed)
    tasks: list[tuple] = []
    info: dict[str, dict] = {}
    full: dict[str, dict] = {}

    for kind, a_name, b_name in COMPARISONS:
        (ra, ma), (rb, mb) = data[a_name], data[b_name]
        if ma["corpus_digest"] != mb["corpus_digest"]:
            raise SystemExit(f"{a_name} and {b_name} are on different corpora; no pairing")
        ids, oa, ob = pair_outputs(ra, rb)
        key = f"{a_name} vs {b_name}"
        info[key] = {"kind": kind, "corpus_digest": ma["corpus_digest"][:12],
                     "retrievers": [ma["retriever"], mb["retriever"]],
                     "pool": len(ids), "identical_outputs": sum(x == y for x, y in zip(oa, ob, strict=True))}
        for design in ("paired", "unpaired"):
            r = model_equality_test(oa, ob, paired=design == "paired",
                                    permutations=args.permutations, seed=args.seed)
            full.setdefault(key, {})[design] = {"n": len(ids), "p_value": round(r.p_value, 4),
                                                "statistic": round(r.statistic, 5)}
        for n in SIZES:
            for _ in range(args.reps):
                idx = rng.sample(range(len(ids)), n)
                sub_a, sub_b = [oa[i] for i in idx], [ob[i] for i in idx]
                seed = rng.randrange(2**31)
                for design in ("paired", "unpaired"):
                    tasks.append((key, design, n, sub_a, sub_b, seed, args.permutations))

    for name in NULL_SPLIT_RUNS:
        rows, meta = data[name]
        pool = sorted(q for q, text in rows.items() if text)
        key = f"{name}, random disjoint halves"
        info[key] = {"kind": "exact null by construction", "corpus_digest": meta["corpus_digest"][:12],
                     "retrievers": [meta["retriever"]], "pool": len(pool)}
        for n in SIZES:
            if 2 * n > len(pool):
                continue
            for _ in range(args.reps):
                chosen = rng.sample(pool, 2 * n)   # random order, so halves pair at random
                sub_a = [rows[q] for q in chosen[:n]]
                sub_b = [rows[q] for q in chosen[n:]]
                seed = rng.randrange(2**31)
                for design in ("paired", "unpaired"):
                    tasks.append((key, design, n, sub_a, sub_b, seed, args.permutations))

    counts: dict[tuple[str, str, int], list[int]] = {}
    with Pool(args.workers) as pool:
        for key, design, n, p in pool.imap_unordered(_task, tasks, chunksize=8):
            slot = counts.setdefault((key, design, n), [0, 0])
            slot[0] += p <= args.alpha
            slot[1] += 1

    result: dict = {"alpha": args.alpha, "reps": args.reps, "permutations": args.permutations,
                    "comparisons": {}}
    for key, meta in info.items():
        entry = {**meta, "full_pool": full.get(key), "rejection_rate": {}}
        for design in ("paired", "unpaired"):
            entry["rejection_rate"][design] = {
                str(n): rate(*counts[(key, design, n)]) for n in SIZES if (key, design, n) in counts
            }
        result["comparisons"][key] = entry

    print(f"rejection rate at alpha={args.alpha} over {args.reps} random canary subsets "
          f"[95% exact CI]; full pool p value last")
    for key, entry in result["comparisons"].items():
        print(f"\n{key}  ({entry['kind']}; pool {entry['pool']}"
              + (f", {entry['identical_outputs']} identical" if "identical_outputs" in entry else "")
              + ")")
        for design in ("paired", "unpaired"):
            cells = "  ".join(f"n={n}: {v['rate']:.3f} {v['ci95']}"
                              for n, v in entry["rejection_rate"][design].items())
            fp = entry["full_pool"][design]["p_value"] if entry["full_pool"] else None
            print(f"  {design:<9} {cells}" + (f"  full pool p={fp}" if fp is not None else ""))

    result["seconds"] = round(time.perf_counter() - t0, 1)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=1), encoding="utf-8")
    print(f"\n{result['seconds']} s with {args.workers} worker processes; written to {args.out}")


if __name__ == "__main__":
    main()
