"""The text corpus, and a retrieval benchmark with ground truth we did not invent.

The graph already holds a large amount of prose that nothing has used so far: 697 ATT&CK
technique descriptions, their detection guidance, 44 mitigation write-ups, and 1,685 KEV
vulnerability descriptions with CISA's required-action text. This turns that into a
retrieval corpus.

**The benchmark is the important part.** The usual way to build one is to generate a
question from a document and then check whether retrieval finds that document, which
mostly measures lexical overlap with text the query was copied from - and flatters
whichever method matches strings.

MITRE and CISA have already done the work of writing *separate* documents that are
genuinely related:

  mitigation text  ->  the technique it mitigates      (1,448 MITIGATES edges)
  required action  ->  the vulnerability it remediates (CISA, per KEV entry)

Both sides are human-authored, independently, by domain experts, and the relation between
them is asserted by the same experts rather than by me. So a query built from one side has
a gold answer on the other that no amount of string matching guarantees. That is a real
retrieval task, and the queries were never written with retrieval in mind.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.graph.client import session


@dataclass(frozen=True)
class Document:
    """One retrievable unit."""

    doc_id: str
    kind: str          # 'technique' | 'vulnerability' | 'mitigation'
    title: str
    text: str
    tactics: tuple[str, ...] = ()

    @property
    def content(self) -> str:
        return f"{self.title}\n\n{self.text}".strip()


@dataclass
class Query:
    """A benchmark query with expert-asserted ground truth."""

    query_id: str
    text: str
    gold_doc_ids: set[str] = field(default_factory=set)
    source: str = ""   # which relation supplied the ground truth


def load_documents() -> list[Document]:
    docs: list[Document] = []
    with session() as s:
        for r in s.run(
            """
            MATCH (t:Technique)
            OPTIONAL MATCH (t)-[:ACHIEVES]->(ta:Tactic)
            RETURN t.attack_id AS id, t.name AS name,
                   coalesce(t.description, '') AS description,
                   coalesce(t.detection, '') AS detection,
                   collect(DISTINCT ta.name) AS tactics
            """
        ):
            body = "\n\n".join(x for x in (r["description"], r["detection"]) if x)
            docs.append(Document(r["id"], "technique", r["name"], body,
                                 tuple(t for t in r["tactics"] if t)))

        for r in s.run(
            """
            MATCH (v:Vulnerability) WHERE v.kev = true
            RETURN v.cve_id AS id, coalesce(v.name, v.cve_id) AS name,
                   coalesce(v.description, '') AS description,
                   coalesce(v.vendor, '') AS vendor, coalesce(v.product, '') AS product
            """
        ):
            body = " ".join(x for x in (r["vendor"], r["product"], r["description"]) if x)
            docs.append(Document(r["id"], "vulnerability", r["name"], body))

    return [d for d in docs if d.text.strip()]


_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MARKUP = re.compile(r"<[^>]+>")


def _clean(text: str) -> str:
    """ATT&CK prose carries inline citations and markup that leak nothing but noise."""
    text = _CITATION.sub("", text)
    text = _MARKUP.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def load_benchmark(min_query_chars: int = 80) -> list[Query]:
    """Build queries whose ground truth comes from MITRE and CISA, not from us."""
    queries: list[Query] = []
    with session() as s:
        # A mitigation describes a defence; the technique it defends against is the gold
        # answer. One mitigation often covers several techniques, so gold is a set.
        for r in s.run(
            """
            MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique)
            WHERE m.description IS NOT NULL AND size(m.description) > 100
            RETURN m.attack_id AS mid, m.name AS mname, m.description AS mdesc,
                   collect(DISTINCT t.attack_id) AS techniques
            """
        ):
            text = _clean(r["mdesc"])
            if len(text) < min_query_chars:
                continue
            queries.append(Query(
                query_id=f"mitigation:{r['mid']}",
                text=f"{r['mname']}. {text}"[:1200],
                gold_doc_ids=set(r["techniques"]),
                source="ATT&CK MITIGATES",
            ))

        # CISA writes a required action per KEV entry, separately from the vulnerability
        # description. Recovering the CVE from the remediation instruction is a genuine
        # retrieval task and the pairing is CISA's, not ours.
        for r in s.run(
            """
            MATCH (v:Vulnerability)
            WHERE v.kev = true AND v.required_action IS NOT NULL
              AND size(v.required_action) > 60
            RETURN v.cve_id AS cve, v.required_action AS action, v.product AS product
            LIMIT 400
            """
        ):
            action = _clean(r["action"])
            if len(action) < min_query_chars:
                continue
            queries.append(Query(
                query_id=f"kev:{r['cve']}",
                text=f"{r['product']}: {action}"[:1200],
                gold_doc_ids={r["cve"]},
                source="CISA KEV required action",
            ))

    return queries


if __name__ == "__main__":
    docs = load_documents()
    qs = load_benchmark()
    by_kind: dict[str, int] = {}
    for d in docs:
        by_kind[d.kind] = by_kind.get(d.kind, 0) + 1
    by_source: dict[str, int] = {}
    for q in qs:
        by_source[q.source] = by_source.get(q.source, 0) + 1
    print(f"documents: {len(docs):,}  {by_kind}")
    print(f"queries  : {len(qs):,}  {by_source}")
    print(f"mean gold docs per query: "
          f"{sum(len(q.gold_doc_ids) for q in qs) / max(len(qs), 1):.2f}")
