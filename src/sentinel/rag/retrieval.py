"""Four retrieval strategies, built to be compared rather than to win.

  bm25    lexical, no model, no infrastructure
  dense   Azure text-embedding-3-small vectors in pgvector
  graph   traverse the knowledge graph from entities named in the query
  hybrid  dense candidates fused with graph expansion

**BM25 is here as a baseline, not as a straw man.** Dense retrieval is routinely reported
against no lexical baseline at all, which makes any result unfalsifiable: on domain text
full of exact identifiers - `T1078.004`, `CVE-2021-34473`, package names - a good lexical
matcher is frequently hard to beat, and a hybrid that cannot beat it is not worth its
infrastructure. Reporting BM25 is what makes the dense number mean something.

Fusion uses Reciprocal Rank Fusion rather than score addition. Cosine similarities and
graph hop distances are not on the same scale and normalising them requires a constant
nobody can justify; RRF only needs the ranks, which is the honest amount of information
these two methods actually share.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Protocol

from sentinel.graph.client import session
from sentinel.rag.corpus import Document

TOKEN = re.compile(r"[a-z0-9][a-z0-9._-]*")
# Identifiers are the highest-signal tokens in this domain, so they are matched whole
# rather than split on punctuation.
ID_PATTERN = re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|T\d{4}(?:\.\d{3})?|M\d{4})\b", re.I)


def tokenize(text: str) -> list[str]:
    return TOKEN.findall(text.lower())


@dataclass(frozen=True)
class Hit:
    doc_id: str
    score: float
    rank: int


class Retriever(Protocol):
    name: str

    def retrieve(self, query: str, k: int = 10) -> list[Hit]: ...


class BM25:
    """Okapi BM25. Pure Python, no dependencies, no index server."""

    name = "bm25"

    def __init__(self, docs: list[Document], k1: float = 1.5, b: float = 0.75) -> None:
        self.k1, self.b = k1, b
        self.doc_ids = [d.doc_id for d in docs]
        self.tokens = [tokenize(d.content) for d in docs]
        self.lengths = [len(t) for t in self.tokens]
        self.avg_len = sum(self.lengths) / max(len(self.lengths), 1)
        self.tf: list[Counter[str]] = [Counter(t) for t in self.tokens]

        df: Counter[str] = Counter()
        for t in self.tokens:
            df.update(set(t))
        n = len(docs)
        self.idf = {
            term: math.log(1 + (n - freq + 0.5) / (freq + 0.5)) for term, freq in df.items()
        }
        self.postings: dict[str, list[int]] = defaultdict(list)
        for i, counts in enumerate(self.tf):
            for term in counts:
                self.postings[term].append(i)

    def retrieve(self, query: str, k: int = 10) -> list[Hit]:
        q_terms = tokenize(query)
        scores: dict[int, float] = defaultdict(float)
        for term in q_terms:
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i in self.postings[term]:
                freq = self.tf[i][term]
                denom = freq + self.k1 * (
                    1 - self.b + self.b * self.lengths[i] / self.avg_len
                )
                scores[i] += idf * freq * (self.k1 + 1) / denom
        ordered = sorted(scores.items(), key=lambda kv: -kv[1])[:k]
        return [Hit(self.doc_ids[i], s, r + 1) for r, (i, s) in enumerate(ordered)]


class DenseRetriever:
    """Cosine similarity over stored embeddings."""

    name = "dense"

    def __init__(self, store) -> None:  # noqa: ANN001 - avoids importing pgvector here
        self.store = store

    def retrieve(self, query: str, k: int = 10) -> list[Hit]:
        rows = self.store.search(query, k=k)
        return [Hit(doc_id, score, r + 1) for r, (doc_id, score) in enumerate(rows)]


class GraphRetriever:
    """Entities named in the query, expanded one hop through the graph.

    Deliberately narrow. Graph traversal is precise when the query names an entity and
    useless when it does not, and the ablation should show that rather than hide it behind
    a fallback to text search.
    """

    name = "graph"

    def retrieve(self, query: str, k: int = 10) -> list[Hit]:
        ids = {m.group(0).upper() for m in ID_PATTERN.finditer(query)}
        if not ids:
            return []
        with session() as s:
            rows = list(s.run(
                """
                UNWIND $ids AS wanted
                MATCH (n)
                WHERE (n:Technique AND toUpper(n.attack_id) = wanted)
                   OR (n:Vulnerability AND toUpper(n.cve_id) = wanted)
                   OR (n:Mitigation AND toUpper(n.attack_id) = wanted)
                OPTIONAL MATCH (n)-[r]-(m)
                WHERE m:Technique OR m:Vulnerability
                RETURN coalesce(n.attack_id, n.cve_id) AS seed,
                       collect(DISTINCT coalesce(m.attack_id, m.cve_id))[0..25] AS related
                """,
                ids=sorted(ids),
            ))
        out: list[Hit] = []
        seen: set[str] = set()
        for row in rows:
            for doc_id in [row["seed"], *(row["related"] or [])]:
                if doc_id and doc_id not in seen:
                    seen.add(doc_id)
                    out.append(Hit(doc_id, 1.0 / (len(out) + 1), len(out) + 1))
        return out[:k]


class HybridRetriever:
    """Reciprocal Rank Fusion over two or more retrievers."""

    name = "hybrid"

    def __init__(self, retrievers: list[Retriever], rrf_k: int = 60) -> None:
        self.retrievers = retrievers
        # 60 is the constant from the original RRF paper. Named rather than inlined
        # because it is a choice, and the ablation reports sensitivity to it.
        self.rrf_k = rrf_k

    def retrieve(self, query: str, k: int = 10) -> list[Hit]:
        fused: dict[str, float] = defaultdict(float)
        for retriever in self.retrievers:
            for hit in retriever.retrieve(query, k=max(k, 20)):
                fused[hit.doc_id] += 1.0 / (self.rrf_k + hit.rank)
        ordered = sorted(fused.items(), key=lambda kv: -kv[1])[:k]
        return [Hit(doc_id, score, r + 1) for r, (doc_id, score) in enumerate(ordered)]
