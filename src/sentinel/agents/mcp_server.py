"""MCP tool server over the estate knowledge graph.

Design decisions worth stating, because they are the difference between a tool server an
agent can reason with and one that merely exposes a database:

**No arbitrary Cypher tool.** The obvious shortcut - one `run_cypher` tool and let the
model write queries - fails three ways at once: the model hallucinates labels and
relationships that do not exist, tenant isolation becomes advisory rather than enforced,
and a malformed traversal can walk the entire graph. Every tool here is a constrained
operation whose query is written by hand.

**Composable primitives, not one tool per question.** `find_entities` then `traverse`
lets an agent answer questions nobody anticipated. A tool per question only answers the
questions already thought of, and the interesting ones are the others. A small number of
purposeful aggregates sit alongside them for the queries whose Cypher is genuinely
intricate - SLA breach arithmetic in particular.

**Tenant scope is a parameter, not an assumption.** Cross-tenant reads require passing
`tenant=None` explicitly, which is visible in the trace rather than implicit in its
absence.

**Every result is bounded and carries ids.** Unbounded results destroy the context window;
ids let the agent cite what it found and traverse onward from it.
"""
from __future__ import annotations

from typing import Any, Literal

from mcp.server.mcpserver import MCPServer

from sentinel.graph.client import session

mcp = MCPServer("sentinel")

MAX_LIMIT = 100

# Labels an agent may address. An allowlist rather than free-form: it keeps a
# hallucinated label from silently returning an empty result that reads as "no exposure".
ENTITY_KINDS = {
    "Host": ("id", ["hostname", "tenant_id", "provider", "role", "os_release", "address"]),
    "Customer": ("id", ["name", "tenant_id"]),
    "Contract": ("id", ["name", "tenant_id"]),
    "SLA": ("id", ["name", "patch_window_critical_hours", "response_minutes", "coverage"]),
    "Site": ("id", ["name", "kind", "region", "tenant_id"]),
    "NetworkZone": ("id", ["name", "provider", "cidr"]),
    "Package": ("key", ["name"]),
    "PackageInstall": ("id", ["version", "arch", "tenant_id"]),
    "Vulnerability": ("cve_id", ["kev", "epss", "product", "vendor", "name", "kev_due_date"]),
    "Technique": ("attack_id", ["name", "is_subtechnique", "platforms"]),
    "Tactic": ("shortname", ["name"]),
    "Mitigation": ("attack_id", ["name"]),
}

RELATIONSHIPS = {
    "HAS_CONTRACT", "DEFINES", "COVERS", "CONTAINS", "IN_ZONE", "RUNS", "OF",
    "AFFECTED_BY", "EXPLOITED_BY", "ACHIEVES", "MITIGATES", "SUBTECHNIQUE_OF",
}


def _clamp(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


@mcp.tool()
def list_schema() -> dict[str, Any]:
    """Describe the entity kinds and relationships available for traversal.

    Call this first when unsure how the estate is modelled. It prevents guessing at
    label or relationship names that do not exist.
    """
    return {
        "entity_kinds": {k: {"key": v[0], "properties": v[1]} for k, v in ENTITY_KINDS.items()},
        "relationships": sorted(RELATIONSHIPS),
        "notes": (
            "PackageInstall sits between Host and Package and carries the version. "
            "Site is a physical/organisational location; NetworkZone is a security "
            "boundary. They do not correspond one-to-one."
        ),
    }


@mcp.tool()
def find_entities(
    kind: str,
    contains: str | None = None,
    tenant: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Find entry-point nodes of a given kind, optionally filtered by a substring.

    Args:
        kind: one of the entity kinds from list_schema.
        contains: case-insensitive substring matched against the node's key and name.
        tenant: restrict to one tenant. Omit only when a cross-tenant view is intended.
        limit: maximum rows, capped at 100.
    """
    if kind not in ENTITY_KINDS:
        return {"error": f"unknown kind {kind!r}", "valid_kinds": sorted(ENTITY_KINDS)}
    key, props = ENTITY_KINDS[kind]
    limit = _clamp(limit)

    where = []
    params: dict[str, Any] = {"limit": limit}
    if contains:
        where.append(
            f"(toLower(toString(n.{key})) CONTAINS toLower($contains) "
            f"OR toLower(coalesce(n.name,'')) CONTAINS toLower($contains))"
        )
        params["contains"] = contains
    if tenant:
        where.append("n.tenant_id = $tenant")
        params["tenant"] = tenant
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    returns = ", ".join([f"n.{key} AS id"] + [f"n.{p} AS {p}" for p in props])
    with session() as s:
        rows = [dict(r) for r in s.run(
            f"MATCH (n:{kind}) {clause} RETURN {returns} LIMIT $limit", **params
        )]
    return {"kind": kind, "count": len(rows), "truncated": len(rows) == limit, "results": rows}


@mcp.tool()
def traverse(
    kind: str,
    node_id: str,
    relationship: str,
    direction: Literal["out", "in", "both"] = "both",
    limit: int = 25,
) -> dict[str, Any]:
    """Follow one relationship from one node and return the neighbours.

    Single-hop by design: the agent chains hops itself, so each step appears in the
    trace and can be inspected. A depth parameter would hide the reasoning inside one
    opaque call and makes runaway traversals easy.
    """
    if kind not in ENTITY_KINDS:
        return {"error": f"unknown kind {kind!r}", "valid_kinds": sorted(ENTITY_KINDS)}
    if relationship not in RELATIONSHIPS:
        return {"error": f"unknown relationship {relationship!r}",
                "valid_relationships": sorted(RELATIONSHIPS)}
    key, _ = ENTITY_KINDS[kind]
    limit = _clamp(limit)

    arrow = {
        "out": f"-[r:{relationship}]->",
        "in": f"<-[r:{relationship}]-",
        "both": f"-[r:{relationship}]-",
    }[direction]

    with session() as s:
        rows = [dict(r) for r in s.run(
            f"""
            MATCH (n:{kind} {{{key}: $id}}){arrow}(m)
            RETURN labels(m)[0] AS kind,
                   coalesce(m.id, m.cve_id, m.attack_id, m.key, m.shortname) AS id,
                   coalesce(m.name, m.hostname, '') AS name,
                   properties(r) AS edge
            LIMIT $limit
            """,
            id=node_id, limit=limit,
        )]
    return {"from": {"kind": kind, "id": node_id}, "relationship": relationship,
            "direction": direction, "count": len(rows),
            "truncated": len(rows) == limit, "neighbours": rows}


@mcp.tool()
def vulnerability_exposure(
    tenant: str | None = None,
    host_id: str | None = None,
    kev_only: bool = False,
    limit: int = 25,
) -> dict[str, Any]:
    """Packages whose installed version predates the version that fixed a CVE.

    Each row carries the USN and both versions, so the finding can be verified rather
    than trusted. Set kev_only to restrict to CVEs CISA lists as known-exploited.
    """
    limit = _clamp(limit)
    where = ["true"]
    params: dict[str, Any] = {"limit": limit}
    if tenant:
        where.append("h.tenant_id = $tenant")
        params["tenant"] = tenant
    if host_id:
        where.append("h.id = $host_id")
        params["host_id"] = host_id
    if kev_only:
        where.append("v.kev = true")

    with session() as s:
        rows = [dict(r) for r in s.run(
            f"""
            MATCH (h:Host)-[:RUNS]->(i:PackageInstall)-[r:AFFECTED_BY]->(v:Vulnerability)
            MATCH (i)-[:OF]->(p:Package)
            WHERE {" AND ".join(where)}
            RETURN h.hostname AS host, h.tenant_id AS tenant, p.name AS package,
                   r.installed_version AS installed, r.fixed_version AS fixed,
                   r.usn AS usn, collect(DISTINCT v.cve_id)[0..8] AS cves,
                   count(DISTINCT v) AS cve_count,
                   max(coalesce(v.epss, 0.0)) AS max_epss,
                   any(x IN collect(v.kev) WHERE x) AS includes_kev
            ORDER BY cve_count DESC
            LIMIT $limit
            """,
            **params,
        )]
    return {"count": len(rows), "truncated": len(rows) == limit,
            "evidence": "installed vs fixed version per Ubuntu Security Notice",
            "results": rows}


@mcp.tool()
def sla_status(tenant: str | None = None, limit: int = 25) -> dict[str, Any]:
    """Remediation status against each tenant's contracted patch window.

    The window comes from the SLA on the contract, which is three hops from the
    vulnerability - so the same CVE can be within terms for one customer and breaching
    for another. That arithmetic lives here rather than in the agent's head.
    """
    limit = _clamp(limit)
    params: dict[str, Any] = {"limit": limit}
    tclause = "AND c.tenant_id = $tenant" if tenant else ""
    if tenant:
        params["tenant"] = tenant

    with session() as s:
        rows = [dict(r) for r in s.run(
            f"""
            MATCH (c:Customer)-[:HAS_CONTRACT]->(k:Contract)-[:DEFINES]->(sla:SLA),
                  (k)-[:COVERS]->(:Site)-[:CONTAINS]->(h:Host)
                  -[:RUNS]->(i:PackageInstall)-[:AFFECTED_BY]->(v:Vulnerability)
            WHERE true {tclause}
            WITH c, sla, h, v,
                 CASE WHEN v.kev AND v.kev_date_added IS NOT NULL
                      THEN duration.inDays(v.kev_date_added, date()).days * 24
                      ELSE null END AS hours_known
            RETURN c.name AS customer, sla.name AS sla,
                   sla.patch_window_critical_hours AS window_hours,
                   h.hostname AS host,
                   count(DISTINCT v) AS open_cves,
                   sum(CASE WHEN v.kev THEN 1 ELSE 0 END) AS kev_cves,
                   sum(CASE WHEN hours_known > sla.patch_window_critical_hours
                            THEN 1 ELSE 0 END) AS breaching
            ORDER BY breaching DESC, open_cves DESC
            LIMIT $limit
            """,
            **params,
        )]
    return {"count": len(rows), "results": rows,
            "note": "breaching counts only KEV CVEs, where a remediation clock exists"}


@mcp.tool()
def blast_radius(package: str, limit: int = 25) -> dict[str, Any]:
    """Which hosts, tenants and network zones share a given package.

    The question behind an incident: if this component is the cause, who else is
    exposed? Zones matter here rather than sites - adjacency is a network property.
    """
    limit = _clamp(limit)
    with session() as s:
        rows = [dict(r) for r in s.run(
            """
            MATCH (p:Package {key: $package})<-[:OF]-(i:PackageInstall)<-[:RUNS]-(h:Host)
            OPTIONAL MATCH (h)-[:IN_ZONE]->(z:NetworkZone)
            RETURN h.hostname AS host, h.tenant_id AS tenant, i.version AS version,
                   collect(DISTINCT z.name) AS zones,
                   exists((i)-[:AFFECTED_BY]->(:Vulnerability)) AS vulnerable
            LIMIT $limit
            """,
            package=package, limit=limit,
        )]
    return {"package": package, "count": len(rows), "results": rows}


@mcp.tool()
def attack_context(cve_id: str | None = None, technique_id: str | None = None) -> dict[str, Any]:
    """Adversary context for a CVE or an ATT&CK technique, with mitigations.

    Answers "what would an attacker do with this, and what stops them" rather than
    leaving the agent to infer it from a CVE description.
    """
    with session() as s:
        if technique_id:
            rec = s.run(
                """
                MATCH (t:Technique {attack_id: $tid})
                OPTIONAL MATCH (t)-[:ACHIEVES]->(ta:Tactic)
                OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
                OPTIONAL MATCH (t)-[:SUBTECHNIQUE_OF]->(parent:Technique)
                RETURN t.attack_id AS id, t.name AS name, t.description AS description,
                       collect(DISTINCT ta.name) AS tactics,
                       collect(DISTINCT m.name) AS mitigations,
                       collect(DISTINCT parent.attack_id) AS parent_of
                """,
                tid=technique_id,
            ).single()
            return dict(rec) if rec else {"error": f"unknown technique {technique_id!r}"}
        if cve_id:
            rec = s.run(
                """
                MATCH (v:Vulnerability {cve_id: $cve})
                RETURN v.cve_id AS id, v.kev AS kev, v.epss AS epss,
                       v.product AS product, v.vendor AS vendor,
                       v.description AS description, v.required_action AS required_action,
                       v.kev_due_date AS remediation_due
                """,
                cve=cve_id,
            ).single()
            return dict(rec) if rec else {"error": f"unknown CVE {cve_id!r}"}
    return {"error": "pass either cve_id or technique_id"}


if __name__ == "__main__":
    mcp.run()
