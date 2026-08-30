# What to do next

Ordered by value per unit of effort, with the honest reason for each.

## Do these first — they cost little and matter most

**1. ~~Publish to PyPI~~ — done.** Live at https://pypi.org/project/agentnorm/, verified
installing into a clean environment with zero dependencies. What remains: rotate the token
used for the upload and reissue one scoped to the `agentnorm` project, a scope that only
exists now the project does.

**2. Anchor the audit chain.** Hash chaining proves integrity, not immutability. A twenty-line
addition — write `chain_head()` and a timestamp to an append-only destination the writer
cannot rewrite (an S3 bucket with object lock, or a countersigning endpoint) — converts
"tamper-evident" from a qualified claim into an unqualified one. This is the single highest
credibility-per-line change available.

**3. Get one other person's traces.** Every number here comes from generated data or one
deployment. One external deployment reporting its false-positive rate is worth more than
any feature on this list.

## The research that is set up but unfinished

**4. Measure the asymmetry hypothesis.** The claim that action-level detection degrades less
than text-level filtering under adaptive attack is unmeasured, because all attacks scored 0%
on a current model. The harness exists (`sentinel/bench/`). It needs a target where attacks
land: an older model, a much larger attacker budget, or longer-horizon tasks. Be ready for
the criticism that a weak target was chosen to make the result appear — pre-empt it by
reporting the target's static-attack success rate alongside.

**5. Retire the generated attack corpus.** Recall of 1.000 that no hyperparameter can move
means the attacks are too easy. Either source harder ones or stop quoting recall and quote
false-positive rate and coverage instead.

## Product direction, if it goes that way

**6. Delegation-chain reconstruction.** The audit format supports `delegation` records; nothing
yet emits them from a real multi-agent framework. The unmet need is stated plainly in the
identity literature — *"the action is traceable to a system but not to a decision"* — and
reconstructing "who authorised this" across four agents and two protocols is the part no
existing layer covers. This is the most product-shaped gap remaining.

**7. An export path into what enterprises already run.** Alerts belong in a SIEM, and audit
records belong wherever compliance evidence lives. Aligning the trace schema with
OpenTelemetry's GenAI semantic conventions (already partially mapped in `trace.py`) makes
agentnorm a producer for infrastructure teams already have, rather than another console.

**8. Discovery.** Only a small minority of organisations can enumerate their service accounts;
agent sprawl is worse. "Which agents exist and what do they touch" is a smaller, more
tractable product than detection, and it is the thing a buyer asks for first — you cannot
monitor what you cannot list.

## Now done, listed so nobody re-does them

- OpenAPI → MCP connector generation — the last JD bullet. 1,222 GitHub operations to 40
  capability tools, with risk, resource and scope derived from the spec so a generated
  connector arrives already instrumented. See `docs/connectors.md`.
- Competitive due diligence — Agentomaly, AgentOps, AgentLens and TRACE occupy this
  category; all four are named in the README with when to pick them instead.

## Deliberately not worth doing

More framework adapters, more detectors, more eval tasks, a hosted dashboard. None of these
address the binding constraint, which is external validation rather than surface area.

## The strategic read

The library is a few hundred lines of statistics; its moat is judgement, and judgement is
copyable once documented. The durable asset would be **data** — behavioural baselines across
many deployments — and that is a chicken-and-egg problem a solo project rarely escapes.

The highest-certainty return on this work is the role it qualifies you for. The company path
is a long shot even executed well. They are not exclusive: publish, take the job, let six
months of adoption decide. If a compliance or risk owner — not an engineer — asks for the
audit trail, that is the signal worth acting on.
