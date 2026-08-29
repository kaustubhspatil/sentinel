# Cold Start Is the Normal Case: Behavioural Monitoring for Ephemeral Agent Identities

*Kaustubh Patil · August 2026 · Technical report / preprint*

---

## Abstract

Behavioural anomaly detection is being applied to AI agents, but the standard approach
inherits an assumption from user and entity behaviour analytics that agents structurally
violate: that an entity persists long enough to accumulate a behavioural baseline.
Industry practice assumes a 60–90 day learning period, while production agents are created
continuously, versioned weekly, and frequently ephemeral. We show that a detector suite
without explicit cold-start handling alerted on **100% of known-benign runs** from an agent
version it had not observed, and that the failure is not uniform across detectors: a
hierarchical Bayesian volume baseline transferred at a **0% false-positive rate** without
modification, while set-membership and per-entity detectors failed completely. We propose a
three-way discrimination — **pool, assert, suppress** — determined by whether a quantity is
comparable across agents, and show it restores a 0% false-positive rate on unseen agents
with detection recall unchanged (1.000 across five attack families, suite false-positive
rate 0.13%). We further argue that behavioural monitoring for agents should be *out of
band* rather than in the request path, since in-path defenses must trade utility for
security and are therefore forced into the leniency that adaptive attackers exploit; we
measure zero utility cost for out-of-band monitoring on AgentDojo. Finally, we report a
negative result: all six static AgentDojo attack families achieved 0% success against a
2026 frontier model, so detection could not be measured on that benchmark.

**Artefacts:** https://github.com/kaustubhspatil/agentnorm ·
https://github.com/kaustubhspatil/sentinel

---

## 1. Introduction

Two literatures are converging on agent security from opposite directions and have not yet
met.

The **prompt-injection** literature builds in-path defenses — capability systems,
information-flow control, reference monitors, task-alignment shields. These are
enforcement mechanisms: they sit between the agent and its tools and decide whether an
action proceeds.

The **identity and behaviour analytics** literature treats agents as non-human identities
and applies the machinery built for service accounts: learn what normal looks like, alert
on deviation. This is detection, and it is where enterprise budget is moving — agents
outnumber human identities by roughly 45:1 in large organisations, and only a small
minority of organisations report full visibility into their service accounts.

This report makes three contributions, one of them negative:

1. A characterisation and measurement of the **cold-start failure** in agent behavioural
   monitoring, with a per-detector breakdown showing the failure is not uniform (§3).
2. A **pool / assert / suppress** discrimination for deciding what may be shared across
   agent identities, with measurements for each choice (§4).
3. An argument and measurement for **out-of-band** rather than in-path monitoring, and a
   negative result on the measurability of detection against a saturated benchmark (§5, §6).

## 2. Setting

An agent *run* is one episode: a single agent, a single task, an ordered sequence of tool
calls. The unit of analysis is the run rather than the individual call, because the
behaviours worth detecting — scope escalation, an abnormal decision path, an
exfiltration-shaped volume anomaly — are properties of the episode.

Each run carries an identity `agent@version`. Versioning is not cosmetic: a change of
prompt, model, or tool grant changes the behavioural distribution, so a version bump is a
**change-point in the series**, not an anomaly to report.

We evaluate five detectors:

| detector | signal |
|---|---|
| volume | result size per `(agent@version, tool)`, hierarchical Normal–Normal, log space |
| sequence | bigram surprisal over the tool sequence |
| scope | calls touching a scope owned by a different principal |
| novel_tool | tools the identity has not used |
| rate | calls per run against the identity's own distribution |

Thresholds are set by **false-positive budget**, divided across detectors, and calibrated
on a held-out slice. An operator can act on "this fires once per two hundred clean runs";
nobody can act on "this maximises F1".

## 3. The cold-start failure

**Setup.** Fit the suite on one population of benign runs; score benign runs from an agent
identity absent from the fit set. Every alert is a false positive by construction.

**Result.**

| detector | alert rate on benign runs, unseen identity |
|---|---|
| volume (hierarchical) | **0.000** |
| sequence | 0.000 (pooled) |
| scope | 0.000 |
| novel_tool | **1.000** |
| rate | **0.536** |
| **any detector** | **1.000** |

The suite alerted on every run. The per-detector split is the finding: the hierarchical
model transferred untouched, because shrinking toward a population prior is precisely what
lets it score a group it has barely observed. The set-membership detector failed totally —
every tool looked novel because the *identity* was novel, so the detector reported "I have
not met you" on every run, indefinitely.

This matters because the condition is not exceptional. Agent platforms report on the order
of a million agents created; agent versions change weekly; many architectures instantiate
agents per task. **An unseen identity is the normal operating condition of an agent
monitor, and a 60–90 day baselining assumption never becomes satisfied.**

## 4. Pool, assert, suppress

The fix is not "pool everything." Whether sharing across identities is valid depends on
whether the *quantity* is comparable across identities.

**Pool** where it is. A row is a row: result sizes are commensurable across agents, so a
`(identity, tool)` pair with three observations should be shrunk toward the population
rather than trusted alone. Tool vocabulary is likewise shared — a tool unknown to the whole
population is meaningfully novel; a tool merely unknown to a new identity is not.

**Assert** where no history is needed. Scope entitlement is a property of the run, not a
statistic to be learned. An earlier version of our scope detector asked whether the agent
had *seen* a scope before and caught 1 escalation in 25 — agents legitimately serve many
principals, so familiarity is the wrong invariant. Scope consistency *within a run* needs
no history and caught 40 of 40.

**Suppress** where pooling is invalid. Run length is not comparable: a triage agent making
three calls and a reporting agent making forty are both normal, so the population mean
describes neither. Scoring an unseen identity against it fired on **54%** of benign runs.
Transition structure is the same — a triage agent's path is not evidence about a reporting
agent's, and pooling it alerted on **100%**. For these the correct output is *not yet
calibrated*, reported as such, not a guess.

**Result after the discrimination:** false-positive rate on unseen identities **0.000**;
detection recall unchanged at **1.000** across five attack families; suite false-positive
rate **0.13%** (1 of 800 held-out benign runs).

**On novelty.** Hierarchical profiling and population priors for cold start are known —
there are patents, and Kubernetes-style profile inheritance gives a new pod its
Deployment's profile with no learning window. What we did not find in prior work is the
*discrimination*: existing approaches inherit a profile wholesale. The contribution here is
the finding that inheritance is valid for some quantities and actively harmful for others,
with the measurements that separate them.

## 5. Out of band, not in path

Every published prompt-injection defense sits in the request path. That placement forces a
binary decision — allow or block — and blocking costs task completion. The literature says
so explicitly: a detection-first design "can inherently sacrifice task completion, because
once suspicious divergence is detected the safest response is to stop or refuse," and
strict task-alignment enforcement "can suppress benign preparatory or diagnostic tool calls
… which degrades utility in long-horizon tasks."

An in-path defense must therefore be lenient enough not to break real work. **That leniency
is the gap adaptive attackers exploit** — a cheap black-box loop that rewrites the injection
raises attack success above static levels against nearly all evaluated defenses, and
stacking more filters does not close it.

Out-of-band detection escapes the trade because it never decides. Its false-positive cost
is an analyst's attention, not a failed task, so it can afford strictness that an in-path
defense cannot. We measured the utility claim directly on AgentDojo's workspace suite:
**15/15 benign tasks solved with the monitor attached, 0 false positives** — passive
observation is definitionally free, and no in-path defense can make the same claim.

There is also a structural asymmetry worth stating, which we could not measure (§6). Text
is the attacker's *delivery mechanism*; the action is the attacker's *goal*. Rewriting a
payload is cheap; abandoning the action means abandoning the objective. This predicts that
action-level detection degrades less under adaptive attack than text-level filtering. We
regard this as a hypothesis, not a result.

## 6. Negative result: the benchmark is saturated

We attempted to measure detection against AgentDojo (97 tasks, 629 security test cases).
All six static attack families — `important_instructions`, `tool_knowledge`, `injecagent`,
`system_message`, `ignore_previous`, `direct` — achieved **0% attack success** against a
2026 frontier model, while the same agent solved 15/15 benign tasks. We verified the
injections were correctly placed rather than assuming a harness fault.

We then built a black-box adaptive attacker in the AutoDojo style, iteratively refining
injections against observed agent behaviour. Within a 3–5 iteration budget it also achieved
0%. Notably, the attacker model initially *refused* to generate injections under a plain
red-team framing; only an explicit benchmark framing produced adversarial text.

**With no successful attacks there is nothing to detect**, so §5's asymmetry hypothesis
remains unmeasured on this benchmark. Testing it requires a weaker target model, a much
larger attacker budget, or longer-horizon tasks where the malicious action blends into
normal tool patterns — each of which invites the criticism that the result was engineered.

We report this because it is a dated, reproducible data point that **static injection
benchmarks are saturated against current frontier models**, which is precisely what the
adaptive-attack literature warns about, and because omitting it would misrepresent what our
detection numbers rest on.

## 7. Evidence as a by-product

A monitor that observes which agent touched which resource, under whose authority, already
holds what the EU AI Act's Article 12 requires of high-risk systems from August 2026:
automatic, tamper-evident event logging, retained six months, reconstructable afterwards.
Detection and evidence come from the same observation; most monitoring discards the latter.

We implement records following the IETF `draft-sharif-agent-audit-trail` format, hash-chained
with SHA-256 over the RFC 8785 canonical form of the preceding record. The draft's
`recording_component` field is defined for an entity writing records independently of the
agent, so out-of-band recording is anticipated by the specification.

Two implementation notes matter for evidence integrity. Floats are **rejected** rather than
approximated, because RFC 8785 mandates a specific float serialisation and an approximation
would yield hashes that verify locally and fail against another implementation — the worst
failure mode for evidence. And hash chaining establishes **integrity, not immutability**: an
adversary who can rewrite the whole log can recompute the whole chain. Detecting that
requires anchoring the head hash outside the writer's control.

## 8. Limitations

- Attack traces are generated. Recall of 1.000 is a **ceiling, not a performance claim**; a
  sensitivity sweep found recall unmoved across a 64-fold range of prior strength and a
  10-fold range of budget, which indicates the attacks sit far from the decision boundary —
  the test is easy.
- Real-traffic validation is one deployment and tens of runs.
- The asymmetry hypothesis of §5 is unmeasured.
- The cold-start technique is not novel; the discrimination and its measurements are the
  contribution.

## 9. Related work

In-path defenses: CaMeL, RTBAS, Progent, FIDES, Task Shield, DRIFT, AgentArmor. Adaptive
attacks: AutoDojo; *The Attacker Moves Second*; *Adaptive Attacks Break Defenses Against
Indirect Prompt Injection*. Trace-based detection: TraceAegis; content-aware attack
detection in tool-call traffic. Benchmarks: AgentDojo. Identity and behaviour analytics for
non-human identities: CSA's non-human identity governance work; vendor treatments of agent
behaviour analytics.

## 10. Conclusion

The framing that agent behavioural monitoring is UEBA with new telemetry is wrong in one
specific, consequential way: UEBA assumes entities persist, and agents do not. Cold start
is not an edge case to be handled eventually — it is the operating condition. Handling it
requires deciding, per quantity, whether sharing across identities is valid at all, and our
measurements show the answer differs sharply between quantities that look similar.

Separately, we argue the field has built only enforcement, and that detection deserves to
be a distinct artefact with a distinct cost function — the same split that produced EDR
alongside prevention at the endpoint.

---

### Reproducing

```bash
git clone https://github.com/kaustubhspatil/agentnorm && cd agentnorm
pip install -e ".[dev]" && pytest -q && python examples/quickstart.py
```

Detection, sensitivity and transfer measurements: `sentinel/src/sentinel/detect/`.
AgentDojo integration and adaptive attacker: `sentinel/src/sentinel/bench/`.
