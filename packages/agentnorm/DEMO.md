# Demonstrating agentnorm

Three demos, in ascending order of setup cost. **The first needs nothing but Python** and is
the one to use in a live conversation — it cannot fail on someone else's wifi.

---

## 1. Detection and evidence, 30 seconds, no infrastructure

```bash
pip install agentnorm
```

The example script lives in the repository, not the wheel, so either clone it:

```bash
git clone https://github.com/kaustubhspatil/agentnorm && cd agentnorm
python examples/quickstart.py
```

...or paste this, which is the same demo in twelve lines:

```python
import random
from agentnorm import Monitor, RunRecorder

def run(agent="triage", version="v1", principal="acme", tools=("search",), size=None):
    rng = random.Random()
    r = RunRecorder(agent, version=version, principal=principal)
    for t in tools:
        with r.tool_call(t, {"q": "x"}, scope=principal) as c:
            c.result_size = size or max(1, int(rng.lognormvariate(0, .6) * 12))
    return r.finish()

monitor = Monitor.fit([run() for _ in range(300)])

print("normal      ->", monitor.score(run()).explain())
print("exfiltration->", monitor.score(
    run(tools=("search", "export_all"), principal="globex", size=90_000)).explain())
print("new version ->", monitor.score(run(version="v2")).explain())
```

```
normal run           -> no anomaly

exfiltration attempt -> scope=1.00 (threshold 0.00); novel_tool=1.00 (threshold 0.00);
                        sequence=3.61 (threshold 0.00); volume=7.98 (threshold 2.17)

new agent version    -> no anomaly [cold start: no history for this agent version;
                                    uncalibrated: sequence, novel_tool, rate]
```

**What to say while it runs:**

Four detectors fire on one attack and each names a *different* broken invariant — wrong
tenant, unfamiliar tool, abnormal path, far too much data. That is the difference between
"something is wrong" and a page an engineer can act on at 3am.

The third line is the one most monitoring gets wrong. A version bump is a **change-point**,
not an anomaly. The industry's stated blocker for agent behaviour analytics is that
baselines need 60–90 days of history while agents are ephemeral and versioned weekly.
agentnorm answers that explicitly rather than alerting on every deployment.

---

## 2. The audit trail — the compliance demo

```python
from agentnorm import AuditLog, Monitor, RunRecorder

def run(agent="triage", principal="acme", size=5, tools=("search", "summarise")):
    r = RunRecorder(agent, version="v3", principal=principal)
    for t in tools:
        with r.tool_call(t, {"q": "x"}, scope=principal) as c:
            c.result_size = size
    return r.finish()

log = AuditLog("audit.jsonl")
history = [run(size=5 + i % 4) for i in range(200)]
for h in history[:5]:
    log.write_run(h)

monitor = Monitor.fit(history)
suspicious = run(size=90_000, tools=("search", "export_all"), principal="globex")
log.write_run(suspicious)

print("verdict:", monitor.score(suspicious).explain())
print("audit  :", log.verify())
print("head   :", log.chain_head())
```

```
verdict: novel_tool=1.00; sequence=2.37; volume=62.19 (threshold 1.39)
audit  : chain intact: 24 records verified
head   : 385a29307b3757cd34c09c1dab16efdf...
```

Then **tamper with it in front of them** — this is the moment that lands:

```python
import json
lines = open("audit.jsonl").read().splitlines()
rec = json.loads(lines[3]); rec["action_detail"]["resource"] = "someone-elses-data"
lines[3] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
open("audit.jsonl", "w").write("\n".join(lines) + "\n")

print(AuditLog("audit.jsonl").verify())
# chain BROKEN at record 4: prev_hash mismatch
```

**What to say:**

Detection and evidence come from the same observation. The EU AI Act's Article 12
obligations took effect in August 2026: automatic, tamper-evident logging for high-risk
systems, six-month retention, penalties to 3% of global turnover. What regulators want to
answer is *which agent accessed what data, under whose authority, and can you reconstruct
it later* — which is exactly what a behavioural monitor already sees, and was previously
throwing away.

Records follow the IETF `draft-sharif-agent-audit-trail` format. The draft has a
`recording_component` field for an entity writing records independently of the agent, so
out-of-band recording is anticipated by the standard rather than bolted onto it.

**Be honest about the limit, unprompted.** Hash chaining proves integrity, not
immutability: anyone who can rewrite the whole file can recompute the whole chain.
Detecting that needs the head hash anchored where the writer cannot reach — a WORM bucket
or a transparency log. `chain_head()` exists for that, and anchoring it is the
deployment's job. Saying this before you are asked is worth more than the feature.

---

## 3. LangGraph integration — the adoption demo

```python
from agentnorm import Session
from agentnorm.adapters.langchain import agentnorm_callback

session = Session(agent="researcher", version="v2", principal="acme",
                  scope_of=lambda tool, args, result: args.get("tenant"))

graph.invoke(state, config={"callbacks": [agentnorm_callback(session)]})

verdict = monitor.score(session.finish())
```

**agentnorm does not depend on LangChain** — the base class is imported lazily and the
handler works as a plain object without it. CI enforces this: a job walks the AST and
fails the build if any third-party import appears at module scope. Lazy imports inside
functions are allowed and *reported*, so the optional-dependency set stays visible.

---

## Questions you will get

**"How is this different from LangSmith / Braintrust / Arize?"**
> They grade outputs, mostly offline. This watches run *shape* at runtime — which tools,
> in what order, touching whose data, returning how much. Closer to fraud detection than
> to evaluation. I would run both.

**"Why not just block the bad action?"**
> Every published defense — CaMeL, RTBAS, Progent, Task Shield — sits in the request path,
> so it must decide allow-or-block, which forces a security/utility trade-off and forces
> leniency. Leniency is the gap an adaptive attacker walks through. Out-of-band detection
> has a different cost function: a false positive costs an analyst's attention, not a
> failed task. So it can afford to be strict, and it cannot reduce task success at all.
> It is the EDR-versus-antivirus split, and this field has so far built only the antivirus.

**"What's your detection rate?"**
> On generated attacks, 1.000 — and I do not think that means much, because I wrote both
> the attacks and the detectors. The sensitivity sweep shows recall is unmoved across a
> 64-fold range of prior strength, which tells you the test is easy rather than that the
> detector is good. Against AgentDojo's 629 third-party security cases the honest answer
> is that all six static attack families scored 0% on a current frontier model, so there
> were no successful attacks to detect. That is a real, dated finding about static
> benchmarks, not a detection number.

**"Is the cold-start solution novel?"**
> The technique is not — hierarchical profiling and population priors for cold start are
> known, with patents and Kubernetes-style profile inheritance. What appears unclaimed is
> the discrimination: *which quantities may be pooled and which must not*. Result size and
> tool vocabulary pool cleanly at 0% false positives; run length and transition structure
> cannot, at 54% and 100% if you try. That measured taxonomy is the contribution.

---

## What to lead with

If you have one minute, run demo 1 and tell the cold-start story. If you have five, add
demo 2 and tamper with the log in front of them.

The strongest single sentence:

> *A suite fitted on one population alerted on 100% of known-benign runs from an agent it
> had not seen. The hierarchical model transferred at 0%; the set-membership detectors had
> no cold-start behaviour at all. Fixing that took the suite to 0% with detection unchanged
> — and in a world where agent versions ship weekly, cold start is the normal operating
> condition, not an edge case.*
