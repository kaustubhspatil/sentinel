# Retrieval ablation

Four strategies over the estate corpus, measured against a benchmark whose ground truth
was written by MITRE and CISA rather than by this project.

## The benchmark

The usual way to build a retrieval benchmark is to generate a question from a document and
check that retrieval finds that document. That mostly measures lexical overlap with text
the query was copied from, and flatters whichever method matches strings.

MITRE and CISA have already written *separate* documents that are genuinely related, and
asserted the relation themselves:

| query | gold answer | relation asserted by |
|---|---|---|
| a mitigation write-up | the technique it mitigates | MITRE ATT&CK `MITIGATES` edges |
| a CISA required-action | the CVE it remediates | CISA KEV catalogue |

Both sides are human-authored, independently, by domain experts, and neither was written
with retrieval in mind. **2,382 documents, 193 queries, mean 4.05 gold documents per
query.**

## Results

```
strategy     hit@1   hit@5  hit@10  recall@10     MRR  empty
bm25         0.218   0.373   0.456      0.288   0.289      0
graph        0.000   0.000   0.000      0.000   0.000    193
dense        0.264   0.482   0.565      0.433   0.350      0
hybrid       0.264   0.487   0.591      0.438   0.356      0
```

Read only that table and the conclusion is "dense beats lexical by 11 points, hybrid is
marginally best." Both halves of that are misleading.

## The reversal

| | ATT&CK mitigation → technique | CISA action → CVE |
|---|---|---|
| bm25 | **0.698** | 0.280 |
| dense | 0.651 | 0.433 |
| hybrid | 0.628 | **0.447** |

**BM25 wins outright on one task and loses badly on the other.** The aggregate hides a
reversal, and anyone deploying dense retrieval on the strength of the overall number would
be shipping a regression for half their traffic.

The reason is in who wrote the text. Mitigation write-ups and technique descriptions are
both authored by MITRE, in MITRE's vocabulary, so the words genuinely overlap and a lexical
matcher is hard to beat. CISA's required-action text is operational prose — *"apply
mitigations per vendor instructions"* — sharing almost no vocabulary with a CVE
description, so lexical matching has nothing to grip and embeddings earn their cost.

**The hybrid is also not free.** Fusing a strong arm with a weaker one *degrades* the
mitigation task, from 0.698 to 0.628. Reciprocal Rank Fusion has no way to know that one
retriever is authoritative for a given query, so it dilutes the good ranking with the
worse one. Hybrid retrieval is routinely presented as strictly better than its parts. Here
it is better on aggregate and worse where one method dominates.

## Graph-only retrieves nothing

Zero on all 193 queries, and this is the honest result rather than a bug: these queries
name no entity, so there is nothing to traverse from. Graph traversal is precise when a
query names a `CVE-…` or `T1078.004` and useless when it does not.

That number is worth reporting rather than quietly dropping the arm. It is what justifies
the hybrid at all, and it would equally have exposed the hybrid as pointless had dense
retrieval dominated on its own.

## What this changes

Routing by query type is the defensible design here, not a single global strategy: use
lexical retrieval when the query and corpus share an authorship vocabulary, dense when
they do not, and graph only when the query names an entity. That conclusion is only
visible because the benchmark was split by source; a single aggregate would have
recommended dense everywhere.

## Reproducing

```bash
python -m sentinel.rag.embed        # index the corpus (idempotent, content-hash cached)
python -m sentinel.rag.ablation     # all four strategies
python -m sentinel.rag.ablation --no-dense
```

An operational note worth recording: the Azure embedding deployment rejected roughly nine
requests in ten with a transient `404 DeploymentNotFound` for hours after Azure reported it
`Succeeded`, and the regional `Standard` SKU never served at all - only `GlobalStandard`
did. Indexing 2,382 documents crawled at 13 docs/min until requests were packed by token
budget rather than a fixed count, which cut the number of requests roughly fivefold and
finished the job in one pass. The same fix applied to the 193 query embeddings, which had
been 193 independent chances to fail. When a dependency is unreliable, the thing to reduce
is the number of times you depend on it, not the retry logic around each attempt.
