"""Temporal worker.

Run with:  python -m sentinel.agents.worker

Killing this process mid-workflow is a supported operation, not an outage: the workflow's
state lives in Temporal's event history, so a restarted worker resumes from the last
completed activity rather than starting over. That is worth demonstrating deliberately -
see docs/durability.md.
"""
from __future__ import annotations

import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from sentinel.agents.activities import (
    close_ticket,
    diagnose,
    open_ticket,
    plan_remediation,
    verify,
)
from sentinel.agents.workflows import RemediationWorkflow
from sentinel.config import settings

TASK_QUEUE = "sentinel-remediation"


async def main() -> None:
    client = await Client.connect(settings.temporal_address, namespace=settings.temporal_namespace)
    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[RemediationWorkflow],
        activities=[diagnose, plan_remediation, open_ticket, verify, close_ticket],
    )
    print(f"worker listening on {TASK_QUEUE} at {settings.temporal_address}")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
