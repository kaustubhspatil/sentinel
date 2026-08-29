"""Retrieval ablation: which strategy actually earns its infrastructure?

Reports hit@k, recall@k and MRR for each strategy over the benchmark in `corpus.py`,
broken down by query source. The breakdown is the point. An aggregate number averages two
different tasks - recovering a technique from a defensive write-up, and recovering a CVE
from a remediation instruction - and hides that a strategy can be excellent at one and
worthless at the other.

Graph-only retrieval is expected to score near zero here, and that is the honest result
rather than a bug: these queries name no entity, so there is nothing to traverse from.
Reporting it is what justifies the hybrid, and would equally have shown the hybrid to be
pointless had dense retrieval dominated on its own.
"""
from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from typing import Any

from sentinel.rag.corpus import Query, load_benchmark, load_documents
from sentinel.rag.retrieval import BM25, DenseRetriever, GraphRetriever, HybridRetriever, Retriever

K_VALUES = (1, 5, 10)


@dataclass
class StrategyResult:
    name: str
    queries: int
    hit_at: dict[int, float] = field(default_factory=dict)
    recall_at: dict[int, float] = field(default_factory=dict)
    mrr: float = 0.0
    empty_results: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.name,
            "queries": self.queries,
            "hit@1": round(self.hit_at.get(1, 0.0), 3),
            "hit@5": round(self.hit_at.get(5, 0.0), 3),
            "hit@10": round(self.hit_at.get(10, 0.0), 3),
            "recall@10": round(self.recall_at.get(10, 0.0), 3),
            "mrr": round(self.mrr, 3),
            "returned_nothing": self.empty_results,
        }


def score_strategy(retriever: Retriever, queries: list[Query], max_k: int = 10) -> StrategyResult:
    hits: dict[int, list[float]] = {k: [] for k in K_VALUES}
    recalls: dict[int, list[float]] = {k: [] for k in K_VALUES}
    rr: list[float] = []
    empty = 0

    for q in queries:
        results = retriever.retrieve(q.text, k=max_k)
        if not results:
            empty += 1
        ranked = [h.doc_id for h in results]
        for k in K_VALUES:
            top = set(ranked[:k])
            hits[k].append(1.0 if top & q.gold_doc_ids else 0.0)
            recalls[k].append(len(top & q.gold_doc_ids) / len(q.gold_doc_ids))
        first = next((i for i, d in enumerate(ranked, 1) if d in q.gold_doc_ids), None)
        rr.append(1.0 / first if first else 0.0)

    return StrategyResult(
        name=retriever.name,
        queries=len(queries),
        hit_at={k: statistics.mean(v) if v else 0.0 for k, v in hits.items()},
        recall_at={k: statistics.mean(v) if v else 0.0 for k, v in recalls.items()},
        mrr=statistics.mean(rr) if rr else 0.0,
        empty_results=empty,
    )


def run(limit_per_source: int = 150, use_dense: bool = True) -> dict[str, Any]:
    docs = load_documents()
    queries = load_benchmark()

    # Cap per source so one family does not dominate the aggregate purely by count.
    by_source: dict[str, list[Query]] = {}
    for q in queries:
        by_source.setdefault(q.source, []).append(q)
    sampled: list[Query] = []
    for qs in by_source.values():
        sampled.extend(qs[:limit_per_source])

    doc_ids = {d.doc_id for d in docs}
    # A query whose gold answer is not in the corpus is unanswerable and would depress
    # every strategy equally while measuring nothing.
    sampled = [
        Query(q.query_id, q.text, q.gold_doc_ids & doc_ids, q.source)
        for q in sampled
    ]
    sampled = [q for q in sampled if q.gold_doc_ids]

    retrievers: list[Retriever] = [BM25(docs), GraphRetriever()]
    if use_dense:
        from sentinel.rag.embed import VectorStore

        store = VectorStore()
        # Embed every benchmark query up front, in as few requests as possible.
        store.warm([q.text for q in sampled])
        dense = DenseRetriever(store)
        retrievers.append(dense)
        retrievers.append(HybridRetriever([dense, retrievers[0]]))
    else:
        retrievers.append(HybridRetriever([retrievers[0], retrievers[1]]))

    report: dict[str, Any] = {
        "documents": len(docs),
        "queries": len(sampled),
        "by_source": {s: len([q for q in sampled if q.source == s]) for s in by_source},
        "overall": [],
        "per_source": {},
    }

    for r in retrievers:
        report["overall"].append(score_strategy(r, sampled).to_dict())

    for source in by_source:
        subset = [q for q in sampled if q.source == source]
        if not subset:
            continue
        report["per_source"][source] = [
            score_strategy(r, subset).to_dict() for r in retrievers
        ]
    return report


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"corpus {report['documents']:,} documents, {report['queries']:,} queries "
        f"{report['by_source']}",
        "",
        f"{'strategy':10s} {'hit@1':>7s} {'hit@5':>7s} {'hit@10':>7s} {'recall@10':>10s} "
        f"{'MRR':>7s} {'empty':>6s}",
    ]
    for row in report["overall"]:
        lines.append(
            f"{row['strategy']:10s} {row['hit@1']:7.3f} {row['hit@5']:7.3f} "
            f"{row['hit@10']:7.3f} {row['recall@10']:10.3f} {row['mrr']:7.3f} "
            f"{row['returned_nothing']:6d}"
        )
    for source, rows in report["per_source"].items():
        lines += ["", f"  {source}"]
        for row in rows:
            lines.append(
                f"    {row['strategy']:10s} hit@5 {row['hit@5']:.3f}  "
                f"MRR {row['mrr']:.3f}  empty {row['returned_nothing']}"
            )
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    use_dense = "--no-dense" not in sys.argv
    rep = run(use_dense=use_dense)
    print(format_report(rep))
    from pathlib import Path

    Path("evals").mkdir(exist_ok=True)
    Path("evals/retrieval_ablation.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
