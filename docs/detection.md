# Behavioural anomaly detection on agent traces

Agents are unvalidated models running in production. This is the back-testing regime for
them: five detectors over agent tool-call traces, fitted on benign behaviour and scored
against labelled misbehaviour.

## Results

4,000 benign runs (60% fit / 20% calibrate / 20% test) and 200 anomalous runs across five
scenarios. Thresholds are set on the calibration split and never touch the test split.

| Detector | Threshold | Precision | Recall | FP on 800 benign |
|---|---|---|---|---|
| volume | 3.270 | 0.976 | 0.200 | 1 |
| sequence | 1.562 | 0.952 | 0.600 | 6 |
| scope | 0.000 | 1.000 | 0.200 | 0 |
| novel_tool | 0.000 | 1.000 | 0.200 | 0 |
| rate | 2.722 | 1.000 | 0.200 | 0 |
| **union (any fires)** | — | — | **1.000** | **7 (0.88%)** |

Coverage by scenario, union: `scope_escalation 40/40 · output_volume 40/40 ·
abnormal_sequence 40/40 · unexpected_tool 40/40 · burst_rate 40/40`.

Individual recall near 0.2 is the expected result, not a weakness: each detector targets
one of five failure families, so catching one family completely *is* 0.2 recall overall.
The suite is the unit of analysis; the per-detector table exists to show which detector
owns which failure, so an alert can say what broke rather than only that something did.

## What these numbers do not mean

**Union recall of 1.000 is a ceiling, not a performance claim.** The anomalies are
generated, and generated anomalies are separable by construction — I wrote both the
attack and the detector. The honest reading is "no scenario is invisible to the suite",
which is a useful negative result (a blind spot would have shown up here) and nothing
more. Real misbehaviour is subtler, and the first genuinely novel incident will not look
like any of these five.

**The benign data is synthetic too.** It varies deliberately — three agents, two tenants,
variable run lengths, occasional errors, heavy-tailed result sizes — because uniform
benign traffic flatters every detector. That mitigation is a judgement, not a proof.

The next real step is replacing generated benign traffic with the fleet's actual agent
runs, at which point the false-positive rate becomes a measurement rather than an estimate.

## Two corrections made during this work

Both are more informative than the final numbers.

### The scope detector was asking the wrong question

The first version asked *"has this agent ever touched this zone before?"* and caught
**1 of 25** cross-tenant escalations.

The reason is the interesting part. Agents legitimately serve several tenants, so once an
agent has worked for both `acme` and `globex`, every zone is familiar and nothing is
novel. Familiarity was the wrong invariant.

The right invariant is scope consistency *within a run*: a run declared for tenant T must
not touch tenant U's zones, regardless of what that agent has done for U elsewhere. That
is an assertion rather than a statistic, so it is now checked as one — and it catches
**40 of 40**.

A detector that looks statistically sophisticated can still be measuring the wrong thing,
and only per-scenario reporting exposes that. An aggregate F1 would have shown a
respectable number and hidden a total blind spot.

### The false-positive budget was not what it claimed

Five detectors each firing on 1% of benign runs produce a union near 5%, not 1%. The
first measurement was **5.8% against a "1%" budget**. Splitting the budget across
detectors (Bonferroni-style, 0.2% each) makes the number an operator experiences match
the number promised.

Then a second problem surfaced: with only 120 calibration runs, a 0.2% quantile is not
estimable — the threshold lands on the sample maximum and does not generalise, giving
3.3% on the test split. Raising the benign corpus to 4,000 runs (800 calibrating) brought
the measured suite FPR to **0.88%**, inside budget.

Choosing thresholds by false-positive budget rather than by maximising F1 is deliberate:
an operator can act on "this fires once per hundred clean runs". Nobody can act on "this
maximises a statistic".

## Design notes

**Hierarchical volume baseline.** Per `(agent, tool)`, parameters are shrunk toward the
population mean by a Normal–Normal conjugate update, weighted by how much evidence each
pair has. Independent per-pair statistics fail exactly where it matters — on a pair with
three observations, where the variance is meaningless and everything looks extreme. A pair
with 500 observations trusts itself; a pair with 3 mostly inherits the population. This is
what stops a new agent version or a rarely-used tool from alarming on day one. Log space,
because result sizes are heavy-tailed.

**`agent_version` is a change-point, not a label.** Changing a prompt, model or tool grant
changes the behavioural distribution. A detector that pools across versions alarms on
every deployment; keying on version lets it reset priors instead.

**Human and agent traces are never pooled.** Their tool-use distributions are nothing
alike, and pooling would poison the group priors. `actor_kind` is a first-class column for
this reason.

**Detectors stay separate.** A fused score tells an operator something is wrong without
saying what, and "what" is the entire value at 3am.
