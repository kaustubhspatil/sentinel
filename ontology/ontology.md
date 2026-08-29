# Sentinel ontology — design rationale

This document records *why* the schema looks the way it does. Each decision below is stated
with the alternative that was rejected and the cost the choice carries, because in a domain
model the reasoning outlives the diagram.

## 1. Scope

The estate of a Managed Service Provider: who is served, on what commercial terms, with
which machines, running which software, exposed to which vulnerabilities, and what happened
when something broke - plus the actors, human and machine, that act on all of it.

## 2. Core classes

```
Customer ──has──▶ Contract ──covers──▶ Site ──contains──▶ Host ──in──▶ NetworkZone
                     │                                     │
                     └──defines──▶ SLA                      ├──runs──▶ PackageInstall ──of──▶ Package
                                                            │                                    │
Incident ──affects──▶ Host                                  │                          affected_by
   │                                                        │                                    ▼
   ├──classified_as──▶ RootCause                            └──emits──▶ Observation      Vulnerability (CVE)
   ├──breaches?──▶ SLA                                                                           │
   └──handled_by──▶ AgentRun                                                            exploited_by
                                                                                                 ▼
Actor ─┬─▶ Human  (Technician)      ──performs──▶ Action ──targets──▶ Resource ──in──▶ NetworkZone
       └─▶ Agent  (versioned)            ▲   └─▶ ToolCall (subclass)
                                         │
              AgentRun | Session ──during┘
```

## 3. Modelling decisions, and what was rejected

**`Incident` is a class, not an edge property.**
Rejected: `Host —had_incident{ts, severity}→ RootCause`. An incident is participated in by
many hosts, several technicians, one or more agent runs and a ticket; it accumulates
evidence over time and needs its own identity to be cited by the RAG layer. Anything a
retrieval answer must cite needs to be a node.

**`SLA` attaches to `Contract`, not to `Customer` or `Host`.**
A customer can hold several contracts on different terms, and the same physical host can be
covered by different terms over time. Attaching to `Customer` cannot express that; attaching
to `Host` duplicates the terms across every host and makes contract amendment a fan-out
write. `Contract` is the natural key of commercial truth.

**`PackageInstall` is reified between `Host` and `Package`.**
Rejected: `Host —installed{version}→ Package`. The install carries version, install date,
patch window and detection source, and the vulnerability match is a property *of the
install*, not of the package abstractly. This is also the join that makes CVE exposure a
graph traversal instead of a batch job.

**`Observation` is deliberately thin in the graph.**
Metrics live in ClickHouse; the graph holds only aggregate/summary nodes and pointers.
Putting millions of time-series points into a property graph destroys traversal performance
and buys nothing - the graph's job is *meaning*, the columnar store's job is *volume*.

**`Site` and `NetworkZone` are separate classes.**
Rejected: a single `Site` doing both jobs. `Site` is physical/organisational - it drives SLA
terms, dispatch and invoicing. `NetworkZone` is the security/routing boundary (VPC, subnet,
VLAN, region) - it drives blast radius, lateral movement and scope escalation. Conflating
them breaks both directions: two hosts in one site but different VPCs are *not* adjacent, so
blast-radius answers silently lie; and one VPC spanning two customer locations breaks SLA
attribution. Cost is one class and one edge, and it is what makes "the agent touched a
Resource in a NetworkZone this role has never entered" expressible as a traversal.

**`Actor` splits into `Human` and `Agent`; `AgentRun` is NOT an Actor.**
Rejected: a superclass over `Technician` and `AgentRun`. That is a category error - a
technician is a persistent *identity*, an agent run is an execution *episode*. The correct
pairing is `Human` ↔ `Agent` (identity) and `Session` ↔ `AgentRun` (episode). Both produce
`Action` records (`ToolCall` is a subclass), each carrying `performed_by → Actor` and
`during → AgentRun | Session`. Accountability therefore attaches to the Actor and causality
to the Action, so "who did this" is uniform without blurring human and machine responsibility.

The human/machine distinction is a **statistical** requirement, not just taxonomy: their
behavioural distributions are nothing alike, so pooling them would poison the group priors of
the hierarchical anomaly model. `Agent` is **versioned** (prompt + model + tool grant) for the
same reason - a version bump is a change-point in the behavioural time series, and the
detector must reset its priors on deployment rather than alerting on it.

**`RootCause` is a shared node over a controlled vocabulary - classified, not resolved.**
Rejected (a) per-incident free text: it makes the flagship query ("which customers share a
root cause with Tuesday's outage") unanswerable. Rejected (b) free-text entity resolution:
unbounded work with no ground truth, and indefensible under "how do you know the clusters are
right?". Instead the vocabulary is seeded from ATT&CK techniques (security causes) plus a
small curated ops taxonomy - resource exhaustion, config drift, certificate expiry,
dependency failure, capacity, human error. Narrative text stays on `Incident.narrative`; the
edge is a classification, which is *measurable*: hand-labelled incidents give per-class
precision/recall and a confusion matrix.

An explicit `unclassified` bucket retains the narrative, and the **unclassified rate is a
monitored metric**. That bucket is periodically clustered to *propose* new vocabulary terms,
adopted only with human approval - a closed vocabulary at runtime with human-in-the-loop
schema evolution.

## 4. OWL/SHACL vs. labelled property graph

Authored formally, served pragmatically:

- **OWL** for the class hierarchy, domain/range and disjointness. It documents intent, is
  tool-visualisable (WebVOWL), and aligns cleanly with ATT&CK's STIX vocabulary.
- **SHACL** for the constraints we actually enforce at ingestion: cardinality, required
  properties, value ranges. SHACL validates; OWL infers - conflating the two is the usual
  mistake.
- **Labelled property graph (Neo4j)** at runtime, because multi-hop traversal latency is a
  hard requirement for the agent loop and Cypher is far easier to constrain safely than
  generated SPARQL.

**What this trades away, honestly:** no reasoner-derived inference at query time. Any
subsumption we want must be materialised at ingest. That is an acceptable cost here because
the estate's semantics are shallow and the latency budget is not - but it is a real loss and
should be stated as one.

## 5. Multi-tenancy

Every node carries `tenant_id`, enforced at the query layer, never at the application layer.
Cross-tenant traversal is possible only through explicitly shared reference data
(`Vulnerability`, `Technique`, `Package`, `RootCause`), which are global by design.

## 6. Known costs accepted

Recording these openly, because a design document that lists only benefits is marketing.

- The `RootCause` vocabulary needs a few hundred hand-labelled incidents before the
  classifier means anything. That labelling is unglamorous and sits on the critical path.
- `NetworkZone` is close to 1:1 with cloud account at the current fleet size. It earns its
  keep only once the blast-radius query exists; if that query never materialises, the class
  should be collapsed back into `Site`.
- Materialising subsumption at ingest (see §4) means schema changes require a backfill rather
  than taking effect at query time.
