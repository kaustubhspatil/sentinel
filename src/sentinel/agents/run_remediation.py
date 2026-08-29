"""Start a remediation workflow and report the outcome.

Usage:
    python -m sentinel.agents.run_remediation <tenant> [--approve NAME | --reject NAME]
"""
from __future__ import annotations

import asyncio
import sys

from temporalio.client import Client

from sentinel.agents.worker import TASK_QUEUE
from sentinel.agents.workflows import RemediationInput, RemediationWorkflow
from sentinel.config import settings


async def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    tenant = sys.argv[1]
    approve = "--approve" in sys.argv
    reject = "--reject" in sys.argv
    who = sys.argv[sys.argv.index("--approve" if approve else "--reject") + 1] if (approve or reject) else ""

    client = await Client.connect(settings.temporal_address, namespace=settings.temporal_namespace)
    handle = await client.start_workflow(
        RemediationWorkflow.run,
        RemediationInput(tenant=tenant),
        id=f"remediate-{tenant}-{asyncio.get_event_loop().time():.0f}",
        task_queue=TASK_QUEUE,
    )
    print(f"started {handle.id}")

    # Give the workflow a moment to reach the gate before signalling, so the signal
    # lands on a workflow that is actually waiting rather than racing the start.
    await asyncio.sleep(3)
    print(f"stage: {await handle.query(RemediationWorkflow.stage)}")

    if approve:
        await handle.signal(RemediationWorkflow.approve, who)
        print(f"approved by {who}")
    elif reject:
        await handle.signal(RemediationWorkflow.reject, who)
        print(f"rejected by {who}")

    result = await handle.result()
    print("result:", result)


if __name__ == "__main__":
    asyncio.run(main())
