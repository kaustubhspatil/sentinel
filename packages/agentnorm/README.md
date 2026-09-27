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

## Three checks on the monitor itself

A monitor is a model too, and three questions about it are usually answered by assertion.
Can it fire at the budget it was calibrated to? Can the rate it reports be watched
continuously without the watching itself causing false alarms? Is the model it watches
still the one that was validated? Each has a function here, standard library only, and a
reproducible experiment under [`tools/`](tools/) whose output is committed in
[`tools/results/`](tools/results/).

### Can it fire? Detection power at the calibrated budget

A false positive budget says how often a monitor fires on clean runs. A threshold of
infinity meets every budget, so the other half of the result is the true positive rate at
that calibration. `detection_power` plants one anomaly into each held out benign run and
counts what fires, per detector and per anomaly type, with exact (Clopper Pearson)
intervals for the true positive rate and for the false positive rate on the same runs
before planting.

```python
from agentnorm import detection_power, measure_power
from agentnorm.power import Burst, OversizedResult

monitor, report = measure_power(benign_runs, budget=0.01)   # fit, calibrate, hold out
print(report.format())
print(report.blind_spots(target=0.8))    # injectors shown to stay below 80%

report = detection_power(monitor, held_out, [OversizedResult(10), Burst(3)])
```

Measured on 2,400 held out runs from a **synthetic** population (three agents, three
tenants with opaque scopes, heavy tailed result sizes; 8,000 runs;
`tools/exp_detection_power.py`), at a 1% budget, 95% exact intervals:

| planted anomaly | any detector | by detector |
|---|---|---|
| none (false positive rate) | 0.007 [0.004, 0.012] | |
| 3 extra copies of normal calls | 0.987 [0.982, 0.991] | sequence 0.936, rate 0.758 |
| a tool never seen | 1.000 [0.998, 1.000] | novel_tool 1.000, sequence 1.000 |
| a scope owned by another tenant | 1.000 [0.998, 1.000] | scope 1.000 |
| one result 100 times its size | 0.693 [0.674, 0.711] | volume 0.690 |
| the same call 10 times in a row | 1.000 [0.998, 1.000] | rate 1.000, sequence 0.706 |

The magnitude sweep is where the honest numbers are. One result 10 times its usual size is
caught 4.8% [4.0, 5.8] of the time at a 1% budget, and still only 30.7% [28.8, 32.6] at a
20% budget. Thirty times: 26.1% and 67.1%. Result sizes are heavy tailed, so the volume
threshold sits 4.5 standard deviations out and anything short of a hundredfold jump in a
single call mostly passes. Under cold start (an agent version never seen) sequence and rate
are suppressed by design, and bursts and extra calls are caught in 0 of 1,000 runs
[0, 0.004]: the price of not alerting on every deployment.

The population is synthetic and the anomalies are the ones someone thought of, so this is
an upper bound against an adversary who adapts, not an estimate.

### Watching a rate without inflating false alarms

An operator checks the share of flagged runs after every run. A fixed sample test re run at
every look is not a test at level alpha: each look is another chance, and a healthy,
stationary stream eventually crosses. `RateAlarm` tests "is the rate above its baseline?"
with a mixture martingale (Robbins; Howard et al. 2021), so the probability of *ever*
raising a false alarm is at most alpha however often it is checked. `RateConfidenceSequence`
is the matching two sided interval, valid at every time at once.

```python
from agentnorm import RateAlarm, RateConfidenceSequence

alarm = RateAlarm(baseline=0.01, alpha=0.05)     # null: flag rate at most 1%
cs = RateConfidenceSequence(alpha=0.05)
for run in stream:
    flagged = monitor.score(run).flagged          # or a wrong answer label
    cs.update(flagged)
    if alarm.update(flagged):
        page(f"flag rate above 1%: e value {alarm.e_value:.0f}, rate in {cs.interval()}")

alarm.threshold(400)     # flags among the first 400 runs that would raise the alarm
```

Probability of any false alarm within 10,000 runs of a stationary 1% stream, alpha 0.05,
20,000 simulated streams per row (95% exact interval), and the same probability computed
exactly by dynamic programming (`tools/exp_anytime_alarms.py`):

| rule | simulated | exact |
|---|---|---|
| exact binomial test after every run | 0.349 [0.342, 0.356] | 0.344 |
| the same, starting after 100 runs | 0.298 [0.292, 0.304] | 0.295 |
| normal approximation z test after 30 runs | 0.442 [0.435, 0.449] | 0.436 |
| one test, once, at run 10,000 | 0.043 [0.040, 0.046] | 0.042 |
| confidence sequence lower bound above 1% | 0.011 [0.010, 0.013] | 0.011 |
| `RateAlarm` | 0.031 [0.028, 0.033] | 0.031 |

At a 5% base rate the rows are 0.402, 0.343, 0.454, 0.048, 0.013 and 0.035. The cost is
detection delay, and it grows with how long the stream was clean before the change,
because clean history is evidence too. For a rate doubling from 1% to 2%, median runs from
the change to the alarm were 879, 1,460 and 2,724 when the change came at run 100, 1,000
and 5,000 (the naive test, which is not valid: 350, 781 and 1,553). `RateAlarm` was faster
than the confidence sequence in every shift tested, as a one sided test should be.

### Did the model behind the API change?

A hosted model can change without its name changing, and under a model risk framework such
as OSFI E-23 a model change is a revalidation trigger. Following Gao, Liang and Guestrin
(ICLR 2025, model equality testing), keep a fixed set of canary prompts, record the outputs
once, collect them again later and run a two sample test. `model_equality_test` is a kernel
(MMD) permutation test on style features of the output text (character trigrams and
length). The default paired design swaps the two outputs *within* each prompt, which is
exact under "same model" for any number of prompts.

```python
from agentnorm import model_equality_test
from agentnorm.equality import pair_outputs

ids, before, after = pair_outputs(reference_outputs, todays_outputs)   # {prompt_id: text}
result = model_equality_test(before, after)
if result.rejected(0.01):
    open_revalidation_ticket(str(result))
```

Measured on real outputs recorded by the Plimsoll harness (same questions, same corpus,
temperature 0; no API calls here; `tools/exp_model_equality.py`). Rejection rate at 0.05
over 500 random canary subsets of a pool of about 100 prompts, paired design, 95% exact
interval:

| comparison | 5 prompts | 10 | 20 | 50 |
|---|---|---|---|---|
| Sonnet 4.6 vs Nova Pro, same retriever | 0 | 0.994 [0.983, 0.999] | 1.000 | 1.000 |
| Haiku 4.5 vs Nova Lite, same retriever | 0 | 0.466 [0.422, 0.511] | 0.960 [0.939, 0.975] | 1.000 |
| Nova Lite vs Nova Pro (retriever differs too) | 0 | 0.244 [0.207, 0.284] | 0.590 [0.546, 0.634] | 1.000 |
| Haiku 4.5, two retrieval pipelines | 0 | 0.006 | 0.020 | 0.014 |
| one model, random disjoint halves (exact null) | 0 | 0.034 to 0.060 | 0.036 to 0.050 | 0.040 to 0.046 |

Five prompts reject nothing, and that is arithmetic rather than bad luck: with one output
per prompt the paired test has 2^(n-1) relabellings, so its smallest p value at n = 5 is
1/16. `EqualityResult.min_p_value` says so. The unpaired design can reject at 5 (0.450 for
Sonnet against Nova Pro) but is weaker from 10 prompts on. On the full pool every
different model pair gave p = 0.001, the smallest attainable with 999 permutations.

What the null is, and is not. There are no repeated samples of one model on the same
prompts, so "same model, same prompts" cannot be tested directly; at temperature 0 it
would mostly give identical text. The random halves row is exact by construction and
checks calibration, not realism. The two pipeline rows are the realistic check: same model,
same questions, different retrieved context, and the test almost never fires (full pool p
of 0.29 and 0.55), so the style features track the model rather than the content. The
flip side: a pipeline change of that kind would go unnoticed. And a rejection says the
outputs changed, not why; hold the rest of the pipeline fixed when collecting canaries.

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
