# warden

**Behavioural monitoring for AI agents.** Evaluation grades what an agent *said*, offline.
This watches how it *behaves*, at runtime, and tells you when a run does not look like the
ones before it.

Zero dependencies. No database, no framework, no context propagation.

```python
from warden import RunRecorder, Monitor

rec = RunRecorder(agent="triage", version="v3", principal="acme")

with rec.tool_call("search_tickets", {"q": q}, scope="acme") as call:
    rows = search(q)
    call.result_size = len(rows)

monitor = Monitor.fit(history)            # past benign runs
verdict = monitor.score(rec.finish())

if verdict.flagged:
    print(verdict.explain())
    # volume=7.31 (threshold 3.02) [cold start: no history for this agent version]
```

## Why this exists

Agents are unvalidated models running in production. We have good tooling for grading
their outputs before release and almost none for answering the question that matters after
release: **did this run behave like the others?**

That question is closer to fraud detection than to evaluation. It is about the shape of an
episode — which tools, in what order, touching whose data, returning how much — not about
whether an answer was good.

Five detectors, each owning one failure mode, deliberately not fused into a single score.
A fused score says something is wrong without saying what, and "what" decides whether you
page someone, revoke a credential, or ignore it.

| Detector | Catches |
|---|---|
| `volume` | an agent returning far more data than usual — exfiltration-shaped |
| `sequence` | a path no planner would take, where every individual call is legitimate |
| `scope` | a run entitled to one principal touching another's resources |
| `novel_tool` | reaching a tool this agent has never used |
| `rate` | an order-of-magnitude change in calls per run |

## The hard part: cold start

Agent versions change weekly. A detector meeting an entity it has never seen is not an
edge case — it is the **normal operating condition**, and it is where naive monitoring
falls apart.

Measured on a live deployment: a suite fitted on one population and scored against a real
agent it had not seen alerted on **100% of known-benign runs**. Every tool looked novel,
because the *agent* was novel. The detector was reporting "I have not met you" on every
run, forever.

The per-detector breakdown is the useful part:

| Detector | Alert rate on benign runs from an unseen agent | After |
|---|---|---|
| volume (hierarchical) | **0.000** | 0.000 |
| sequence | 0.000 | 0.000 |
| scope | 0.000 | 0.000 |
| novel_tool | **1.000** | 0.000 |
| rate | **0.536** | suppressed |
| **any** | **1.000** | **0.000** |

The hierarchical model transferred untouched; the set-membership ones had no cold-start
behaviour at all. Detection was unchanged after the fix — union recall stayed at 1.000
across five attack families.

So every detector in warden answers "what do I do about an entity I have not observed?"
explicitly:

- **pool** where the quantity is comparable across agents (`volume`, `sequence`,
  `novel_tool`) — shrink toward the population rather than treating the newcomer as alien
- **assert** where no history is needed (`scope`) — entitlement is checked, not learned
- **suppress** where pooling would be wrong (`rate`) — run length is not comparable between
  a triage agent making three calls and a reporting agent making forty, so warden reports
  *not yet calibrated* instead of guessing

## Thresholds you can act on

Thresholds come from a **false-positive budget**, not from maximising a statistic. An
operator can act on "this fires once per two hundred clean runs". Nobody can act on "this
maximises F1".

The budget is stated for the suite and divided across detectors, because five detectors
each firing on 1% of runs union to about 5% — a suite advertised at 1% that delivers 5%
gets muted within a week, and a muted detector detects nothing.

warden also refuses to pretend about calibration. Asked for a 0.2% quantile from 40 runs,
it fits, and warns:

```
calibration set has 40 runs but a 0.0020 quantile needs at least 500;
thresholds fall back to the observed maximum and the true false-positive
rate will exceed the budget
```

## Design choices worth knowing

**The unit is a run, not a span.** Scope escalation, abnormal paths and volume anomalies
are properties of a whole episode.

**`version` is a change-point, not a label.** Changing a prompt, model or tool grant
changes the behavioural distribution. Baselines key on `agent@version`, so a deployment
resets the baseline instead of triggering an alert storm.

**Human and agent traces are never pooled.** Their tool-use distributions are nothing
alike, and pooling would poison the priors. `actor_kind` exists for this.

**Failed calls are recorded, then re-raised.** A trace that omits failures hides exactly
the behaviour worth detecting — an agent probing for a tool it lacks, or retrying a
refused action.

**Attribute names follow OpenTelemetry's GenAI semantic conventions** where they exist, so
traces can be exported rather than trapped.

## Status

Early, and honest about it. The detectors are validated against five labelled attack
families and against real agent traffic from one deployment. What is not yet true:

- the attack families are generated, so recall against them is a ceiling rather than a
  performance claim — a genuinely novel attack will not look like any of the five
- real-traffic validation is one deployment and tens of runs, not thousands
- there is no persistence layer; bring your own store

## Reference deployment

warden was extracted from [Sentinel](../../README.md), an agentic IT-operations platform
running on a live multi-cloud estate. Sentinel is where these numbers come from, and where
warden found a real cross-tenant disclosure in Sentinel's own agent — a run scoped to one
tenant returning another tenant's host and package data, because `tenant` was a parameter
the model could set freely. A boundary the caller can rewrite is not a boundary.

## Licence

MIT.
