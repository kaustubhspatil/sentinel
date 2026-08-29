"""Graph constraints and indexes.

Constraints are the runtime half of the ontology: SHACL documents intent, but Neo4j is
what actually refuses bad data at 3am. Every class with a natural key gets a uniqueness
constraint, which doubles as the index the loaders' MERGE statements depend on - without
it, every MERGE degrades to a full label scan.

Idempotent: safe to run on every deploy.
"""
from __future__ import annotations

from sentinel.graph.client import session

CONSTRAINTS = [
    # --- global reference data (shared across tenants by design) ---
    "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE",
    "CREATE CONSTRAINT technique_id IF NOT EXISTS FOR (t:Technique) REQUIRE t.attack_id IS UNIQUE",
    "CREATE CONSTRAINT tactic_id IF NOT EXISTS FOR (t:Tactic) REQUIRE t.shortname IS UNIQUE",
    "CREATE CONSTRAINT mitigation_id IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.attack_id IS UNIQUE",
    "CREATE CONSTRAINT package_key IF NOT EXISTS FOR (p:Package) REQUIRE p.key IS UNIQUE",
    "CREATE CONSTRAINT rootcause_key IF NOT EXISTS FOR (r:RootCause) REQUIRE r.key IS UNIQUE",
    # --- estate ---
    "CREATE CONSTRAINT customer_id IF NOT EXISTS FOR (c:Customer) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT contract_id IF NOT EXISTS FOR (c:Contract) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT site_id IF NOT EXISTS FOR (s:Site) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT zone_id IF NOT EXISTS FOR (z:NetworkZone) REQUIRE z.id IS UNIQUE",
    "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
    "CREATE CONSTRAINT install_id IF NOT EXISTS FOR (i:PackageInstall) REQUIRE i.id IS UNIQUE",
    "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.id IS UNIQUE",
    # --- actors and their actions (the half that makes agents observable) ---
    "CREATE CONSTRAINT actor_id IF NOT EXISTS FOR (a:Actor) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT agentrun_id IF NOT EXISTS FOR (r:AgentRun) REQUIRE r.id IS UNIQUE",
    "CREATE CONSTRAINT action_id IF NOT EXISTS FOR (a:Action) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE",
]

INDEXES = [
    # tenant_id is on the hot path of every estate query: isolation is enforced in the
    # query layer, so it must be cheap to filter on.
    "CREATE INDEX host_tenant IF NOT EXISTS FOR (h:Host) ON (h.tenant_id)",
    "CREATE INDEX incident_tenant IF NOT EXISTS FOR (i:Incident) ON (i.tenant_id)",
    "CREATE INDEX agentrun_tenant IF NOT EXISTS FOR (r:AgentRun) ON (r.tenant_id)",
    "CREATE INDEX agentrun_started IF NOT EXISTS FOR (r:AgentRun) ON (r.started_at)",
    "CREATE INDEX action_kind IF NOT EXISTS FOR (a:Action) ON (a.kind)",
    "CREATE INDEX vuln_kev IF NOT EXISTS FOR (v:Vulnerability) ON (v.kev)",
    "CREATE INDEX vuln_epss IF NOT EXISTS FOR (v:Vulnerability) ON (v.epss)",
]


def apply() -> tuple[int, int]:
    with session() as s:
        for stmt in CONSTRAINTS:
            s.run(stmt)
        for stmt in INDEXES:
            s.run(stmt)
    return len(CONSTRAINTS), len(INDEXES)


if __name__ == "__main__":
    c, i = apply()
    print(f"applied {c} constraints, {i} indexes")
