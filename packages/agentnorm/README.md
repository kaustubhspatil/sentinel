# agentnorm

**Behavioural monitoring for AI agents.** Evaluation grades what an agent *said*, offline.
This watches how it *behaves*, at runtime, and tells you when a run does not look like the
ones before it.

Zero dependencies. No database, no framework, no context propagation.

```python
from agentnorm import RunRecorder, Monitor

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

## Instrumenting an agent you already have

Hand over the tool callables you already use; get back callables with the same signatures
that record as a side effect. No restructuring, no context propagation.

```python
from agentnorm import JsonlStore, Monitor, Session

store = JsonlStore("history.jsonl")

session = Session(agent="triage", version="v3", principal="acme",
                  scope_of=lambda tool, args, result: args.get("tenant"))
tools = session.wrap({"search_tickets": search_tickets, "export_all": export_all})

# ... run the agent using `tools` exactly as before ...

store.append(session.finish())
verdict = Monitor.fit(store.read()).score(session.finish())
```

`scope_of` is what makes cross-tenant detection possible at all - without it agentnorm can
see that a call happened but not whose data it touched. Returning `None` means "unknown",
which is treated as in-scope, because a false accusation of cross-tenant access is worse
than a miss.

### What that gets you

From [`examples/quickstart.py`](examples/quickstart.py), fitted on 300 normal runs:

```
normal run           -> no anomaly

exfiltration attempt -> scope=1.00 (threshold 0.00); novel_tool=1.00 (threshold 0.00);
                        sequence=3.61 (threshold 0.00); volume=7.98 (threshold 2.17)

new agent version    -> no anomaly [cold start: no history for this agent version;
                                    uncalibrated: sequence, novel_tool, rate]
```

Four detectors fire on the exfiltration attempt and each names the invariant that broke -
wrong tenant, unfamiliar tool, unusual path, far too much data. That is the difference
between "something is wrong" and a page an engineer can act on at 3am.

The third line is the one most monitoring gets wrong: a version bump is a **change-point**,
not an anomaly. agentnorm reports that it has no history rather than alerting, and names
which detectors are consequently unavailable.

It also refuses to pretend about calibration:

```
warning: calibration set has 75 runs but a 0.0020 quantile needs at least 500;
thresholds fall back to the observed maximum and the true false-positive rate
will exceed the budget
```

## Framework adapters

For frameworks that report tool calls through callbacks rather than direct invocation:

```python
from agentnorm import Session
from agentnorm.adapters.langchain import agentnorm_callback

session = Session(agent="researcher", version="v2", principal="acme")
graph.invoke(state, config={"callbacks": [agentnorm_callback(session)]})

verdict = monitor.score(session.finish())
```

Works with LangChain and LangGraph. **agentnorm still does not depend on either** - the base
class is imported lazily and the handler works as a plain object without it, because
LangChain duck-types handlers in the paths that matter. That is deliberate: a monitoring
library that drags in an agent framework is unusable by anyone running a different one,
and comparing agents across frameworks on equal footing is half the point.

The adapter is tested with LangChain deliberately *not* installed - the callback contract
is replayed instead - so the zero-dependency guarantee stays testable in CI.

Two behaviours worth knowing, because callback streams are messier than they look:

- **Concurrent tools are matched by the framework's `run_id`.** LangGraph runs tools in
  parallel, so starts and ends interleave and pairing them by order is wrong.
- **A call the framework never ends is recorded as failed, not discarded.** An agent
  killed mid-tool leaves an open call, and a run that ends inside a tool is itself a
  signal. Conversely an end with no start - the handler attached mid-run - is dropped,
  because a call with no beginning has no duration and no arguments, and inventing them
  would corrupt the baseline it feeds.

## Persistence

`Monitor.fit` needs history, so a monitor that cannot remember is useless in practice.
`JsonlStore` is the smallest thing that solves it: append-only JSON Lines, standard
library only. Append-only is deliberate - behavioural history is evidence, and a store
that can be rewritten in place is worth much less during an investigation. A truncated
final line from an interrupted write costs one run, not the file.

`Store` is a protocol, so ClickHouse or Postgres is a drop-in. The reference deployment
uses ClickHouse.

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

So every detector in agentnorm answers "what do I do about an entity I have not observed?"
explicitly:

- **pool** where the quantity is comparable across agents (`volume`, `sequence`,
  `novel_tool`) — shrink toward the population rather than treating the newcomer as alien
- **assert** where no history is needed (`scope`) — entitlement is checked, not learned
- **suppress** where pooling would be wrong (`rate`) — run length is not comparable between
  a triage agent making three calls and a reporting agent making forty, so agentnorm reports
  *not yet calibrated* instead of guessing

## Thresholds you can act on

Thresholds come from a **false-positive budget**, not from maximising a statistic. An
operator can act on "this fires once per two hundred clean runs". Nobody can act on "this
maximises F1".

The budget is stated for the suite and divided across detectors, because five detectors
each firing on 1% of runs union to about 5% — a suite advertised at 1% that delivers 5%
gets muted within a week, and a muted detector detects nothing.

agentnorm also refuses to pretend about calibration. Asked for a 0.2% quantile from 40 runs,
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

## Measuring your own detectors

`agentnorm.evaluation` scores a suite against your labelled runs and sweeps the settings that
were chosen by judgement rather than derived:

```python
from agentnorm.evaluation import sensitivity, format_report

print(format_report(sensitivity(benign_runs, labelled_attacks)))
```

Run against the reference deployment's 4,000 benign and 200 labelled anomalous runs, recall
was **1.000 at every setting** — across a 64-fold range of prior strength, a 10-fold range
of false-positive budget, and three calibration splits. No hand-picked constant is
load-bearing, and the false-positive rate tracks the budget while staying below it, so the
per-detector budget division is conservative rather than optimistic.

That result cuts both ways, and the second half matters more. Recall that cannot be moved
by any setting also means the generated attacks sit nowhere near the decision boundary: the
test is easy, which is evidence for the ceiling caveat below rather than against it.

## Status

Early, and honest about it. The detectors are validated against five labelled attack
families and against real agent traffic from one deployment. What is not yet true:

- the attack families are generated, so recall against them is a ceiling rather than a
  performance claim — a genuinely novel attack will not look like any of the five
- real-traffic validation is one deployment and tens of runs, not thousands
- there is no persistence layer; bring your own store

## Reference deployment

agentnorm was extracted from [Sentinel](../../README.md), an agentic IT-operations platform
running on a live multi-cloud estate. Sentinel is where these numbers come from, and where
agentnorm found a real cross-tenant disclosure in Sentinel's own agent — a run scoped to one
tenant returning another tenant's host and package data, because `tenant` was a parameter
the model could set freely. A boundary the caller can rewrite is not a boundary.

## Licence

MIT.
