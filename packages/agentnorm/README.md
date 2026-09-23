# agentnorm

[![PyPI](https://img.shields.io/pypi/v/agentnorm)](https://pypi.org/project/agentnorm/)
[![Python](https://img.shields.io/pypi/pyversions/agentnorm)](https://pypi.org/project/agentnorm/)
[![License](https://img.shields.io/pypi/l/agentnorm)](LICENSE)

Runtime behavioural monitoring for AI agents. It learns what a normal run looks like for
each agent (which tools, in what order, touching whose data, returning how much) and flags
runs that don't fit.

- Zero dependencies (checked in CI)
- No database, framework or context propagation required
- Handles new agents and new versions without an alert storm

```bash
pip install agentnorm
```

## Quick start

```python
from agentnorm import RunRecorder, Monitor

rec = RunRecorder(agent="triage", version="v3", principal="acme")

with rec.tool_call("search_tickets", {"q": q}, scope="acme") as call:
    rows = search(q)
    call.result_size = len(rows)

monitor = Monitor.fit(history)            # past normal runs
verdict = monitor.score(rec.finish())

if verdict.flagged:
    print(verdict.explain())
    # volume=7.31 (threshold 3.02) [cold start: no history for this agent version]
```

### Wrapping tools you already have

`Session.wrap` returns callables with the same signatures that record as a side effect:

```python
from agentnorm import JsonlStore, Monitor, Session

store = JsonlStore("history.jsonl")

session = Session(agent="triage", version="v3", principal="acme",
                  scope_of=lambda tool, args, result: args.get("tenant"))
tools = session.wrap({"search_tickets": search_tickets, "export_all": export_all})

# run the agent with `tools` as usual

store.append(session.finish())
verdict = Monitor.fit(store.read()).score(session.finish())
```

`scope_of` tells agentnorm whose data a call touched. Without it cross-tenant checks can't
run. Returning `None` means unknown and is treated as in scope.

### LangChain / LangGraph

```python
from agentnorm import Session
from agentnorm.adapters.langchain import agentnorm_callback

session = Session(agent="researcher", version="v2", principal="acme")
graph.invoke(state, config={"callbacks": [agentnorm_callback(session)]})

verdict = monitor.score(session.finish())
```

agentnorm doesn't depend on LangChain. The base class is imported lazily and the adapter
tests run without LangChain installed. Parallel tool calls are matched by `run_id`, a call
that never ends is recorded as failed, and an end without a start is dropped.

## Example output

From [`examples/quickstart.py`](examples/quickstart.py), fitted on 300 normal runs:

```
normal run           -> no anomaly

exfiltration attempt -> scope=1.00 (threshold 0.00); novel_tool=1.00 (threshold 0.00);
                        sequence=3.61 (threshold 0.00); volume=7.98 (threshold 2.17)

new agent version    -> no anomaly [cold start: no history for this agent version;
                                    uncalibrated: sequence, novel_tool, rate]
```

Each detector reports separately, so you know *what* broke (wrong tenant, unfamiliar tool,
odd path, too much data) instead of getting one opaque score.

## Detectors

| Detector | Catches |
|---|---|
| `volume` | far more data returned than usual |
| `sequence` | an unusual order of calls, even if each call is fine |
| `scope` | a run touching another principal's resources |
| `novel_tool` | a tool this agent has never used |
| `rate` | a big change in calls per run |

## Cold start

Agent versions change all the time, so meeting an unseen agent is the normal case. In the
reference deployment, a suite fitted on one population alerted on **100%** of benign runs
from a new agent. Most of that came from `novel_tool` (every tool looked new because the
agent was new) and `rate`.

| Detector | Alert rate on benign runs, unseen agent | After fix |
|---|---|---|
| volume | 0.000 | 0.000 |
| sequence | 0.000 | 0.000 |
| scope | 0.000 | 0.000 |
| novel_tool | 1.000 | 0.000 |
| rate | 0.536 | suppressed |
| **any** | **1.000** | **0.000** |

Recall stayed at 1.000 across five attack types. Each detector now handles unknown agents
in one of three ways:

- **pool** toward the population (`volume`, `sequence`, `novel_tool`)
- **assert** without history (`scope`)
- **suppress** and report "not calibrated yet" (`rate`)

## Thresholds

Thresholds come from a false-positive budget ("fires about once per 200 clean runs"), set
for the whole suite and split across detectors. Five detectors at 1% each would add up to
about 5% overall.

If there isn't enough data for the budget, agentnorm still fits but warns:

```
calibration set has 40 runs but a 0.0020 quantile needs at least 500;
thresholds fall back to the observed maximum and the true false-positive
rate will exceed the budget
```

## Design notes

- The unit is a whole run, not a single span.
- Baselines are keyed on `agent@version`, so a new version starts a new baseline.
- Human and agent traces are never pooled (`actor_kind`).
- Failed tool calls are recorded, then re-raised.
- Attribute names follow the OpenTelemetry GenAI conventions.
- `JsonlStore` is append-only JSON Lines. `Store` is a protocol, so you can plug in
  ClickHouse, Postgres, etc.

## Evaluating your own setup

```python
from agentnorm.evaluation import sensitivity, format_report

print(format_report(sensitivity(benign_runs, labelled_attacks)))
```

On the reference deployment (4,000 benign runs, 200 labelled anomalies) recall was 1.000
at every setting tried: a 64x range of prior strength, a 10x range of FP budget and three
calibration splits. The false-positive rate stayed under budget. That also means the
generated attacks are easy, so treat recall as an upper bound.

## Alternatives

| | What it is | Use it instead if |
|---|---|---|
| [AgentOps](https://github.com/AgentOps-AI/agentops) | agent monitoring SDK with cost tracking and wide framework support | you want broad integrations and a hosted product |
| [Agentomaly](https://github.com/sushaan-k/agentomaly) | behavioural anomaly detection on OpenTelemetry with alerting built in | you already run OTel and want Slack/PagerDuty wiring |
| AgentLens | MCP-native observability with a hash-chained audit log | you want a platform and MCP is your main surface |
| TRACE | hardware-attested trust records | you need third-party verification and can run in a TEE |

agentnorm is smaller than these. What it does differently: explicit cold-start handling
per detector, and zero dependencies. What it doesn't have: a hosted backend, dashboards or
alert routing.

## Status and limits

Early release.

- The attack families used for testing are generated, so recall is a ceiling.
- Real-traffic validation is one deployment and tens of runs.

## Where it came from

agentnorm was pulled out of [Sentinel](https://github.com/kaustubhspatil/sentinel), an
agentic IT-ops platform running on a small multi-cloud fleet. The numbers above come from
there. It also caught a real bug in Sentinel's own agent: a run scoped to one tenant
returned another tenant's hosts, because `tenant` was a tool parameter the model could set.

## License

MIT
