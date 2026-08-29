# Durability: what happens when the worker dies

The backbone runs on preemptible capacity, so the process executing a remediation can
vanish at any moment with no warning and no graceful shutdown. This is the test that the
design actually survives that, rather than merely claiming to.

## The claim

A remediation workflow that is waiting for human approval must survive the total loss of
the process running it — and resume at the same step, not restart from the beginning and
not re-execute the side effects it already performed.

## The test

Run against `globex`, whose exposure produces 10 proposed actions and therefore trips the
approval gate.

```
--- 1. start; reaches the approval gate ---
   stage: awaiting_approval

--- 2. SIGKILL the worker ---
   31125 Killed    python -m sentinel.agents.worker
   worker is dead

--- 3. query state with NO worker running ---
   status: RUNNING

--- 4. restart worker, then approve ---
   stage after restart: awaiting_approval
   COMPLETED: {'outcome': 'still_exposed',
               'ticket': 'INC-globex-20260829022518',
               'approver': 'kaustubh-after-restart',
               'findings': 10,
               'required_approval': True}
```

Step 3 is the interesting one. With **no worker process in existence**, the workflow is
still `RUNNING` and still answers queries about its stage, because its state lives in
Temporal's event history rather than in a process's memory. Step 4 shows it resuming at
`awaiting_approval` — the diagnosis and the ticket were not redone, and the ticket was not
duplicated.

`SIGKILL` rather than `SIGTERM` is deliberate: a graceful shutdown proves only that
cleanup handlers run, which is not what a preemption gives you.

## Why the code is shaped the way it is

**Every side effect is in an activity; only control flow is in the workflow.** Workflow
code is *replayed* from history on recovery, so it must be deterministic. An LLM call is
the least deterministic thing in the system — put one in workflow code and recovery
silently produces a different plan than the one already half-executed, which is worse than
crashing.

**The approval gate is a signal, not a poll.** A workflow awaiting approval consumes no
resources, survives worker redeployment, and can wait days. The same gate implemented as
a sleep loop dies with the process; implemented as a queue plus a database table, it is a
worse re-implementation of what Temporal already provides.

**Writes retry less than reads.** Reads are idempotent, so they retry up to five times.
Writes retry three times with a longer interval, because retrying a failed write is how a
remediation opens forty tickets instead of one.

## What is deliberately not proven here

The upgrades themselves are not executed. The gate, the audit trail and the verification
loop needed to work first — an agent that can mutate production before its guardrails are
measured is the thing this project argues against. Consequently `verify` correctly reports
`still_exposed`, because nothing was patched. A green result at this stage would mean the
verification step was lying.

## Threshold behaviour, observed

The same workflow run against `acme` completed **without a gate**: 5 proposed actions and
no known-exploited CVE puts it inside the autonomous limit. Same code, different tenant,
different autonomy — which is the intended behaviour and worth checking rather than
assuming.
