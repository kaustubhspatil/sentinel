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
| Version-aware CVE matching (Ubuntu USN) | working |
| MCP tool server (7 tools) | working |
| Durable remediation workflow (Temporal) | working |
| Anomaly detection | not started |
| Evaluation harness | not started |

Currently loaded, from live feeds:

| Store | Contents |
|---|---|
| Neo4j | 1,685 KEV vulnerabilities · 697 ATT&CK techniques · 44 mitigations · 15 tactics · 3 hosts · 1,293 package installs · 692 packages · 2 tenants |
| ClickHouse | 365,950 EPSS scores/day (4.6 MiB/day compressed) |

### On CVE matching

Package-to-CVE matching is version-aware, using Ubuntu Security Notices as the source of
fix versions and a Debian version comparison implemented directly and unit-tested against
dpkg's own cases. An edge means *the installed version predates the version that fixed
this CVE on this release* - not merely that a package with a matching name exists.

Every edge records the USN, the installed version and the fixing version, so any claim
traces back to evidence.

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

### Version-aware matching vs. a name heuristic

The first thing measured, because it decides whether every downstream exposure number
means anything. Both methods ran over the same 1,293 package installs on the same three
hosts.

| | Product-name heuristic | Version-aware (USN) |
|---|---|---|
| Exposure edges | 28 | 237 |
| Distinct CVEs | 14 | 44 |
| **KEV-listed CVEs present** | **28 claimed** | **0 actual** |
| Evidence per edge | package name resembles a KEV product | USN id + installed version + fixing version |
| Unparseable versions | n/a | 0 of 1,293 |

The heuristic was wrong in both directions. It **invented** every one of its known-exploited
findings — all 28 were packages whose *name* matched a KEV product while the installed
version was patched — and it simultaneously **missed** 33 genuinely outdated packages
carrying real CVEs, because they were not on the hand-written hint list.

A tidy false-positive rate would have been the comfortable result. Reporting that the
impressive-looking number was entirely artefact is the useful one.

### Current exposure

| Tenant | Host | Vulnerable installs | Distinct CVEs | KEV |
|---|---|---|---|---|
| Globex Financial | `sentinel-fleet-az-01` (Azure) | 27 | 44 | 0 |
| Acme Manufacturing | `sentinel-fleet-gcp-01` (GCP) | 5 | 11 | 0 |

The asymmetry is real and not a modelling artefact: the Azure marketplace image was built
against an older package set than the GCP one, so an identically-configured host carries
five times the exposure depending only on where it was provisioned. That is exactly the
kind of finding an estate-wide graph surfaces and a per-host check does not.

_Still to be measured:_ retrieval ablation (vector / graph / hybrid), multi-hop answer
accuracy against a naive-RAG baseline, detector precision–recall on labelled anomalies,
LLM-judge calibration (Cohen's κ against human labels), and a latency–cost curve across
model tiers.

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"
python -m sentinel.ingest.feeds
```

`sentinel.ingest.feeds` needs no credentials — it pulls the public CISA KEV catalogue,
today's EPSS scores and the MITRE ATT&CK STIX bundle. Everything else requires the setup in
[`docs/SETUP.md`](docs/SETUP.md).

## The tool surface

Seven MCP tools: schema discovery, entity lookup, single-hop traversal, and four
purposeful aggregates. There is deliberately **no `run_cypher` tool** — handing a model a
query language costs you hallucinated labels, advisory-only tenant isolation, and
traversals that can walk the entire graph.

`blast_radius("openssl")` against the live estate:

```
host                    tenant   version               vulnerable  zone
sentinel-fleet-az-01    globex   3.0.13-0ubuntu3.12    True        Azure canadacentral VNet
sentinel-fleet-gcp-01   acme     3.0.13-0ubuntu3.15    False       GCP us-central1 default VPC
```

Same package, two tenants, three patch releases apart — one exposed, one not. Answering
that requires the estate, the inventory, the security notices and the version comparison
to all line up.

Guardrails return the valid options rather than an empty result, so a wrong guess corrects
itself instead of reading as "no exposure found":

```json
{"error": "unknown kind 'Server'", "valid_kinds": ["Contract", "Customer", "Host", ...]}
```

## Durability

The backbone runs on preemptible capacity, so the process executing a remediation can
vanish without warning. Verified rather than assumed — `SIGKILL` the worker while a
workflow waits for approval:

```
stage: awaiting_approval
31125 Killed    python -m sentinel.agents.worker
status with no worker running: RUNNING
stage after restart:           awaiting_approval   → approved → completed
```

The workflow survives the total loss of its process and resumes at the same step, without
redoing the diagnosis or duplicating the ticket. Full transcript and the reasoning behind
the activity/workflow split in [`docs/durability.md`](docs/durability.md).

Autonomy is threshold-gated and the thresholds are explicit: any known-exploited CVE, or
more than five proposed actions, requires human approval. Run against `acme` (5 actions,
no KEV) the same workflow completes autonomously; against `globex` (10 actions) it waits.

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
