"""Durable remediation workflow: diagnose → plan → gate → act → verify → close.

Everything in this module must be deterministic on replay. No I/O, no clock reads, no
randomness, no model calls - those all live in activities. What remains here is the
control flow, which is exactly what should survive a crash unchanged.

The human gate is a Temporal *signal*, not a poll. A workflow awaiting approval consumes
no resources and can wait days; the worker can be redeployed underneath it and the wait
survives, because the pending state lives in the event history rather than in a process.
That property is the reason this runs on Temporal at all: an approval gate implemented
with a sleep loop is a liability, and one implemented with a queue and a database table
is a re-implementation of this.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from sentinel.agents.activities import (
        close_ticket,
        diagnose,
        open_ticket,
        plan_remediation,
        verify,
    )

# Reads are cheap and idempotent, so retry them freely. Anything that writes gets a
# tighter policy: retrying a failed write is how you end up with duplicate tickets.
READ_RETRY = RetryPolicy(maximum_attempts=5, initial_interval=timedelta(seconds=1))
WRITE_RETRY = RetryPolicy(maximum_attempts=3, initial_interval=timedelta(seconds=2))


@dataclass
class RemediationInput:
    tenant: str
    limit: int = 10
    # How long to hold the workflow open waiting for a human. Expiry is a decision
    # ("nobody approved this") rather than a failure, and is recorded as such.
    approval_timeout_hours: int = 24


@workflow.defn
class RemediationWorkflow:
    def __init__(self) -> None:
        self._approved: bool | None = None
        self._approver: str = ""
        self._stage: str = "starting"

    # --- signals and queries -------------------------------------------------

    @workflow.signal
    async def approve(self, approver: str) -> None:
        self._approved = True
        self._approver = approver

    @workflow.signal
    async def reject(self, approver: str) -> None:
        self._approved = False
        self._approver = approver

    @workflow.query
    def stage(self) -> str:
        """Lets an operator see where a long-running remediation is without touching it."""
        return self._stage

    # --- the workflow --------------------------------------------------------

    @workflow.run
    async def run(self, params: RemediationInput) -> dict[str, Any]:
        self._stage = "diagnosing"
        findings = await workflow.execute_activity(
            diagnose,
            args=[params.tenant, params.limit],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=READ_RETRY,
        )
        if not findings:
            self._stage = "clean"
            return {"tenant": params.tenant, "outcome": "no_findings", "findings": 0}

        self._stage = "planning"
        plan = await workflow.execute_activity(
            plan_remediation,
            args=[findings, params.tenant],
            start_to_close_timeout=timedelta(seconds=120),
            retry_policy=READ_RETRY,
        )

        self._stage = "opening_ticket"
        ticket = await workflow.execute_activity(
            open_ticket,
            args=[params.tenant, plan, findings],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=WRITE_RETRY,
        )

        if plan["requires_approval"]:
            self._stage = "awaiting_approval"
            try:
                await workflow.wait_condition(
                    lambda: self._approved is not None,
                    timeout=timedelta(hours=params.approval_timeout_hours),
                )
            except TimeoutError:
                self._stage = "approval_expired"
                await workflow.execute_activity(
                    close_ticket,
                    args=[ticket["ticket_id"], "expired",
                          f"No approval within {params.approval_timeout_hours}h; no action taken."],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=WRITE_RETRY,
                )
                return {"tenant": params.tenant, "outcome": "approval_expired",
                        "ticket": ticket["ticket_id"], "findings": len(findings)}

            if not self._approved:
                self._stage = "rejected"
                await workflow.execute_activity(
                    close_ticket,
                    args=[ticket["ticket_id"], "rejected",
                          f"Rejected by {self._approver}; no action taken."],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=WRITE_RETRY,
                )
                return {"tenant": params.tenant, "outcome": "rejected",
                        "ticket": ticket["ticket_id"], "approver": self._approver}

        # Execution of the upgrade itself is intentionally not wired up yet. The
        # approval gate, the audit trail and the verification loop are what needed
        # proving first; an agent that can mutate production before its guardrails are
        # measured is the thing this project argues against.
        self._stage = "verifying"
        verification = await workflow.execute_activity(
            verify,
            args=[params.tenant, plan["packages"]],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=READ_RETRY,
        )

        self._stage = "closing"
        outcome = "verified_clean" if verification["still_exposed_packages"] == 0 else "still_exposed"
        await workflow.execute_activity(
            close_ticket,
            args=[
                ticket["ticket_id"],
                outcome,
                f"approved_by={self._approver or 'auto'} "
                f"still_exposed={verification['still_exposed_packages']} "
                f"open_cves={verification['open_cves']}",
            ],
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=WRITE_RETRY,
        )

        self._stage = "done"
        return {
            "tenant": params.tenant,
            "outcome": outcome,
            "ticket": ticket["ticket_id"],
            "findings": len(findings),
            "actions_proposed": len(plan["actions"]),
            "required_approval": plan["requires_approval"],
            "approver": self._approver or None,
            "verification": verification,
        }
