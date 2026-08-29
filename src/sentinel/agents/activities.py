"""Temporal activities: every step that touches the outside world.

The split between activities and workflow code is the whole point of running this on a
durable execution engine, and it is not stylistic. Workflow code is *replayed* from an
event history after a crash, so it must be deterministic - the same inputs must produce
the same decisions, every time. An LLM call is the least deterministic thing in the
system. So every model call, graph read and API write lives here, in an activity, whose
result is recorded in history and replayed from the record rather than re-executed.

Put a model call in workflow code and recovery silently produces a different plan than
the one that was half-executed. That is the failure mode this file exists to prevent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from temporalio import activity

from sentinel.graph.client import session


@dataclass
class Finding:
    """One diagnosed exposure, with the evidence that supports it."""

    host: str
    tenant: str
    package: str
    installed_version: str
    fixed_version: str
    usn: str
    cve_ids: list[str]
    max_epss: float
    includes_kev: bool

    @property
    def severity(self) -> str:
        if self.includes_kev:
            return "critical"
        if self.max_epss >= 0.1:
            return "high"
        return "moderate"


@dataclass
class Plan:
    """A remediation plan. Actions are proposed here, never executed here."""

    summary: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    requires_approval: bool = True
    rationale: str = ""


@activity.defn
async def diagnose(tenant: str, limit: int = 10) -> list[dict[str, Any]]:
    """Read current exposure for a tenant straight from the graph.

    Deliberately not an LLM call. The facts are in the graph and are exact; asking a
    model to restate them would only introduce a chance of getting them wrong.
    """
    with session() as s:
        rows = [
            dict(r)
            for r in s.run(
                """
                MATCH (h:Host {tenant_id: $tenant})-[:RUNS]->(i:PackageInstall)
                      -[r:AFFECTED_BY]->(v:Vulnerability)
                MATCH (i)-[:OF]->(p:Package)
                RETURN h.hostname AS host, h.tenant_id AS tenant, p.name AS package,
                       r.installed_version AS installed_version,
                       r.fixed_version AS fixed_version, r.usn AS usn,
                       collect(DISTINCT v.cve_id) AS cve_ids,
                       max(coalesce(v.epss, 0.0)) AS max_epss,
                       any(x IN collect(v.kev) WHERE x) AS includes_kev
                ORDER BY includes_kev DESC, max_epss DESC, size(cve_ids) DESC
                LIMIT $limit
                """,
                tenant=tenant,
                limit=limit,
            )
        ]
    return rows


@activity.defn
async def plan_remediation(findings: list[dict[str, Any]], tenant: str) -> dict[str, Any]:
    """Turn findings into a proposed plan.

    Rule-based for now, and honest about it: an LLM here would add narrative but no
    decision quality, because the mapping from "package X is behind" to "upgrade
    package X" is deterministic. The LLM earns its place at the ambiguous steps -
    triage of novel incidents and root-cause narrative - not here.
    """
    critical = [f for f in findings if f.get("includes_kev")]
    high = [f for f in findings if not f.get("includes_kev") and f.get("max_epss", 0) >= 0.1]
    packages = sorted({f["package"] for f in findings})

    actions = [
        {
            "kind": "package_upgrade",
            "host": f["host"],
            "package": f["package"],
            "from_version": f["installed_version"],
            "to_version": f["fixed_version"],
            "usn": f["usn"],
            "cve_count": len(f.get("cve_ids", [])),
        }
        for f in findings
    ]

    # Anything touching a known-exploited CVE, or more than a handful of packages at
    # once, stays behind a human gate. The threshold is explicit and auditable rather
    # than left to a model's judgement.
    requires_approval = bool(critical) or len(actions) > 5

    return {
        "summary": (
            f"{len(findings)} outdated package(s) on tenant {tenant}: "
            f"{len(critical)} known-exploited, {len(high)} high exploit-probability"
        ),
        "actions": actions,
        "requires_approval": requires_approval,
        "rationale": (
            "Approval required: known-exploited CVE present."
            if critical
            else f"Approval required: {len(actions)} actions exceeds the autonomous limit of 5."
            if requires_approval
            else "Within autonomous limits: no KEV involvement and few actions."
        ),
        "packages": packages,
    }


@activity.defn
async def open_ticket(tenant: str, plan: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Record the plan as a ticket.

    Writes to the graph rather than to GitHub while the workflow is still being proven.
    Creating real issues is an outward-facing side effect and is gated separately - a
    retry storm that opens forty tickets is precisely the failure durable execution is
    supposed to prevent, not cause.
    """
    ticket_id = f"INC-{tenant}-{datetime.now(UTC):%Y%m%d%H%M%S}"
    with session() as s:
        s.run(
            """
            MERGE (i:Incident {id: $id})
            SET i.tenant_id = $tenant, i.summary = $summary, i.status = 'open',
                i.created_at = datetime(), i.requires_approval = $requires_approval,
                i.plan = $plan_json, i.action_count = $action_count
            WITH i
            UNWIND $hosts AS hostname
            MATCH (h:Host {hostname: hostname})
            MERGE (i)-[:AFFECTS]->(h)
            """,
            id=ticket_id,
            tenant=tenant,
            summary=plan["summary"],
            requires_approval=plan["requires_approval"],
            plan_json=json.dumps(plan)[:8000],
            action_count=len(plan["actions"]),
            hosts=sorted({f["host"] for f in findings}),
        )
    return {"ticket_id": ticket_id, "status": "open"}


@activity.defn
async def verify(tenant: str, packages: list[str]) -> dict[str, Any]:
    """Re-read the graph to confirm whether the named packages are still exposed.

    Verification reads the same source of truth as diagnosis rather than trusting the
    action's own report of success. An action that claims success and changed nothing
    is the interesting failure, and only an independent read catches it.
    """
    with session() as s:
        rec = s.run(
            """
            MATCH (h:Host {tenant_id: $tenant})-[:RUNS]->(i:PackageInstall)
                  -[:AFFECTED_BY]->(v:Vulnerability)
            MATCH (i)-[:OF]->(p:Package)
            WHERE p.name IN $packages
            RETURN count(DISTINCT p) AS still_exposed, count(DISTINCT v) AS open_cves
            """,
            tenant=tenant,
            packages=packages,
        ).single()
    return {
        "still_exposed_packages": rec["still_exposed"] if rec else 0,
        "open_cves": rec["open_cves"] if rec else 0,
        "verified_at": datetime.now(UTC).isoformat(),
    }


@activity.defn
async def close_ticket(ticket_id: str, outcome: str, detail: str) -> dict[str, Any]:
    with session() as s:
        s.run(
            """
            MATCH (i:Incident {id: $id})
            SET i.status = $outcome, i.closed_at = datetime(), i.outcome_detail = $detail
            """,
            id=ticket_id,
            outcome=outcome,
            detail=detail[:2000],
        )
    return {"ticket_id": ticket_id, "status": outcome}
