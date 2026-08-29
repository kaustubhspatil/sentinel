# Evaluation harness

Seven tasks over the live estate, scored on trajectories rather than answers alone. An
agent that reaches the right conclusion in two calls and one that takes six are not equally
good, and an agent that reaches the *wrong* conclusion fluently is worse than one that
fails loudly.

## Baseline: azure/model-router, small tier

```
passed 4/7 scored (57%), 0 errored
  mean fact recall     0.786
  tasks w/ fabrication 1
  mean tool recall     0.714
  malformed calls      0
  premature answers    0
  median latency       13,048 ms
  total tokens         51,958
```

| Task | Result | Detail |
|---|---|---|
| tenant_exposure_comparison | **FAIL** | fabricated `32` |
| sla_window_acme | PASS | |
| openssl_blast_radius | **FAIL** | fact recall 0.33 |
| kev_presence | PASS | correctly answered "none" |
| worst_package | PASS | cited USN-8678-1 |
| attack_context_lookup | PASS | |
| unanswerable_by_design | **FAIL** | fact recall 0.50 |

Zero malformed calls and zero premature answers: the model follows the JSON protocol
reliably. Its failures are reasoning failures, not formatting ones, which is the more
interesting result.

## The failure worth naming

`tenant_exposure_comparison` fails **reproducibly**, and it is the failure this harness was
built to catch:

> "Globex has more outdated packages: 32 compared with Acme's 5. Globex's Regulated SLA
> specifies a 24-hour patch window."

Fluent, confident, correctly structured, right about the tenant and right about the SLA —
and **32 is invented**. Ground truth is 27. The number is `27 + 5`: the agent summed both
tenants and attributed the total to one of them.

Nothing about the answer signals this. There is no hedging, no malformed output, no error.
An LLM-judge scoring "is this a good answer" would very likely pass it. It is caught only
because the task declares `must_not_contain: ["32"]` and the ground truth is checked by
exact match against the graph.

That is the argument for checking verifiable facts exactly rather than judging them: **a
judge that can be wrong should never be the only check on a number that can be verified.**

## Design decisions

**Infrastructure errors are excluded from the pass rate.** An earlier run scored 4/7 with
two failures caused by Azure exhausting a 10K TPM quota and falling through to unreachable
providers. Reported naively that is a 57% capability score, when it measured a rate limit.
Errored tasks are now classified separately, and the current run has zero.

**Tool usage is scored as recall, not exact match.** An agent that reaches the right answer
by a different route has taken a different path, not failed. `sla_window_acme` passes with
five calls where two would do — inefficient, not wrong, and the efficiency shows up
separately.

**One task is unanswerable by design.** Contract value is deliberately absent from the
ontology; the correct behaviour is to say so. A suite made only of answerable questions
rewards confident guessing, which is exactly the behaviour that produced `32`.

**Malformed-call rate is a model property, not a harness detail.** Tool calls use a JSON
protocol rather than native function calling, so that providers can be compared on equal
footing — native tool calling differs in shape across vendors, and a comparison built on it
measures three adapters as much as three models. The cost is that malformed output is
possible; the benefit is that it becomes measurable. Here it is zero.

## Two bugs found by the harness itself

**The agent refused without trying.** The first run answered *"unable to determine ... the
query did not return results"* having called nothing. Prompting alone did not fix it; the
runner now rejects an answer produced with no tool call and counts it as a premature
answer. A single worked example in the prompt was what actually changed the behaviour —
describing the protocol was not enough, showing one turn of it was.

**Falling back on a transient error hid the real one.** Azure returned intermittent 404s
while a capacity change propagated across a GlobalStandard deployment. The router moved
straight to the next provider and reported *Gemini's* 429 — pointing diagnosis at entirely
the wrong provider. The Azure client now retries the same deployment on transient statuses
before any fallback, which took infrastructure errors from 6/7 to 0/7.

## Not yet done

- **LLM judge with human calibration.** The judge is only worth having if its agreement
  with human labels is measured (Cohen's κ), and that needs a few hundred hand-labelled
  answers. Those labels must be produced by hand — a judge calibrated against
  machine-generated labels is circular and measures nothing.
- **Adversarial suite**: prompt injection through tool output, and attempts to induce
  cross-tenant reads.
- **Model-tier comparison**: needs a second reachable provider (see `llm-providers.md`).
- **CI gate**: fail a pull request when pass rate or fact recall regresses.
