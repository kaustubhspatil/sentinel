# Sentinel

**An agentic IT-operations platform — and the validation layer that decides when its agents
are allowed to act alone.**

Sentinel manages a small, real fleet of Linux hosts across three clouds. It models that
estate as an ontology-backed knowledge graph, exposes the graph to LLM agents through MCP
tools so they can plan and act over it, and then treats those agents the way a regulated
institution treats any production model: as something that must be back-tested, calibrated
and monitored before it is trusted.

Most agent projects stop at "the agent works." This one starts there.

---

## Status

Early. The estate and the ingestion path are live; the reasoning and validation layers are
being built in the open. **No result appears in this README until it has been measured** —
the Results section stays empty rather than aspirational.

| Component | State |
|---|---|
| Public threat-intel ingestion (KEV / EPSS / ATT&CK) | working |
| Ontology and design rationale | drafted |
| Backbone host (Neo4j, ClickHouse, Redpanda, Temporal, Postgres) | running |
| Reference-data load into graph and columnar store | working |
| Fleet nodes (multi-cloud, node_exporter + osquery + Alloy) | running |
| Estate + inventory load | working |
| Version-aware CVE matching (CPE) | **not started - see caveat below** |
| MCP tool server | not started |
| Anomaly detection | not started |
| Evaluation harness | not started |

Currently loaded, from live feeds:

| Store | Contents |
|---|---|
| Neo4j | 1,685 KEV vulnerabilities · 697 ATT&CK techniques · 44 mitigations · 15 tactics · 3 hosts · 1,293 package installs · 692 packages · 2 tenants |
| ClickHouse | 365,950 EPSS scores/day (4.6 MiB/day compressed) |

### Caveat on CVE matching

The graph currently joins packages to CVEs on a hand-written product-name map, which
answers *"is a package called openssl installed"* - **not** *"is the installed version
vulnerable"*. On a patched Ubuntu 24.04 host those are very different questions, and the
current exposure counts are therefore dominated by false positives.

This is stated rather than hidden because the number is meaningless without it. Every such
edge carries `match_method` and `confidence` so it can be filtered or re-derived, and
version-aware matching against NVD CPE data is the next piece of work. Until then, no
exposure figure from this graph should be treated as a finding.

The split is the architecture working as designed: the graph holds the ~1.7k CVEs an
operator reasons about, while the third of a million daily exploit-probability scores stay
in the columnar store where a time series belongs.

## Why the data is real

Synthetic data makes every anomaly detector look good. This project avoids that as far as it
can: the estate is genuinely operated, and the threat intelligence describes the actual world.

| Layer | Source | Real? |
|---|---|---|
| Endpoint telemetry | `node_exporter` + `osquery` on a live multi-cloud fleet | yes — machines actually running |
| Vulnerability exposure | CISA KEV + FIRST EPSS (daily) + NVD, matched to installed packages by CPE | yes |
| Adversary model | MITRE ATT&CK Enterprise (STIX 2.1) | yes |
| Ticketing | GitHub Issues API + webhooks | yes |
| Incidents | Whatever actually breaks, plus a labelled red-team suite | both, labelled |
| Anomaly ground truth | Loghub labelled log datasets + injected scenarios | yes |

Anything generated is prefixed `synthetic_` and is never mixed into an evaluation set
without being labelled as such.

## Architecture

```
  fleet hosts ──▶ event stream ──▶ columnar store        (volume: metrics, logs, tool calls)
       │                              │
       └──────────▶ entity resolution ┴──▶ knowledge graph   (meaning: estate + agent behaviour)
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        ▼                                           ▼
                  MCP tool server ──▶ agents                 detection layer
                        │              │                    (baselines, sequence
                        │              ▼                     surprisal, scope
                        │        durable workflows            escalation)
                        │              │
                        └──────────────┴──▶ evaluation harness ──▶ CI gate
```

Two design commitments drive everything else:

**The graph holds meaning; the columnar store holds volume.** Time series never enter the
graph — they would destroy traversal latency and buy nothing. The graph's job is to answer
questions a query language cannot form.

**Agent behaviour is modelled in the same graph as the estate it manages.** That is what
turns "did this run touch a resource outside its normal scope?" into a traversal rather than
a log-scraping heuristic.

See [`ontology/ontology.md`](ontology/ontology.md) for the modelling rationale, including the
alternatives that were rejected and what each decision costs.

## Results

_Empty by design until measured._ This section will carry: retrieval ablation
(vector / graph / hybrid), multi-hop answer accuracy against a naive-RAG baseline, detector
precision–recall on labelled anomalies, LLM-judge calibration (Cohen's κ against human
labels), and a latency–cost curve across model tiers.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"
python -m sentinel.ingest.feeds
```

`sentinel.ingest.feeds` needs no credentials — it pulls the public CISA KEV catalogue,
today's EPSS scores and the MITRE ATT&CK STIX bundle. Everything else requires the setup in
[`docs/SETUP.md`](docs/SETUP.md).

## Repository layout

```
src/sentinel/
  config.py        settings; secrets load from outside the repo
  ingest/          public threat-intel and lifecycle feeds
  ontology/        schema definitions and validation
  graph/           knowledge-graph load and traversal
  agents/          MCP tool server and agent workflows
  detect/          behavioural baselines and anomaly detection
  eval/            evaluation harness and benchmarks
  api/             service layer
ontology/          OWL/SHACL sources and the design rationale
docs/              setup, operations, incident log
```

## Licence

MIT — see [LICENSE](LICENSE).
