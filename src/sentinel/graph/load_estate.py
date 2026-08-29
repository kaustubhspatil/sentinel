"""Load the declared estate: customers, contracts, SLAs, sites, zones and hosts.

These facts are not discoverable from a machine. No agent can tell you who is billed for
a host or which SLA covers it, so they are declared in deploy/estate.yaml and merged into
the graph alongside the inventory that *is* discovered.

Everything here is tenant-scoped except NetworkZone, which is shared infrastructure -
two tenants can legitimately sit in the same provider region while remaining isolated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sentinel.graph.client import session

DEFAULT_ESTATE = Path(__file__).resolve().parents[3] / "deploy" / "estate.yaml"


@dataclass
class EstateStats:
    customers: int = 0
    contracts: int = 0
    slas: int = 0
    sites: int = 0
    zones: int = 0
    hosts: int = 0
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        base = (
            f"customers={self.customers} contracts={self.contracts} slas={self.slas} "
            f"sites={self.sites} zones={self.zones} hosts={self.hosts}"
        )
        return base if not self.errors else base + f" errors={len(self.errors)}"


def load(path: Path | None = None) -> EstateStats:
    doc = yaml.safe_load((path or DEFAULT_ESTATE).read_text(encoding="utf-8"))
    stats = EstateStats()

    zones = doc.get("zones", [])
    customers = doc.get("customers", [])
    hosts = doc.get("hosts", [])

    known_zones = {z["id"] for z in zones}
    known_sites: set[str] = set()

    with session() as s:
        s.run(
            """
            UNWIND $rows AS row
            MERGE (z:NetworkZone {id: row.id})
            SET z.name = row.name, z.provider = row.provider, z.cidr = row.cidr
            """,
            rows=zones,
        )
        stats.zones = len(zones)

        for cust in customers:
            s.run(
                "MERGE (c:Customer {id: $id}) SET c.name = $name, c.tenant_id = $id",
                id=cust["id"],
                name=cust.get("name"),
            )
            stats.customers += 1

            for contract in cust.get("contracts", []):
                sla = contract.get("sla") or {}
                s.run(
                    """
                    MATCH (c:Customer {id: $cust})
                    MERGE (k:Contract {id: $id})
                    SET k.name = $name, k.tenant_id = $cust
                    MERGE (c)-[:HAS_CONTRACT]->(k)
                    WITH k
                    MERGE (s:SLA {id: $sla_id})
                    SET s.name = $sla_name,
                        s.patch_window_critical_hours = $crit,
                        s.patch_window_high_hours = $high,
                        s.response_minutes = $resp,
                        s.coverage = $coverage
                    MERGE (k)-[:DEFINES]->(s)
                    """,
                    cust=cust["id"],
                    id=contract["id"],
                    name=contract.get("name"),
                    sla_id=sla.get("id"),
                    sla_name=sla.get("name"),
                    crit=sla.get("patch_window_critical_hours"),
                    high=sla.get("patch_window_high_hours"),
                    resp=sla.get("response_minutes"),
                    coverage=sla.get("coverage"),
                )
                stats.contracts += 1
                if sla:
                    stats.slas += 1

                for site in contract.get("sites", []):
                    s.run(
                        """
                        MATCH (k:Contract {id: $contract})
                        MERGE (t:Site {id: $id})
                        SET t.name = $name, t.kind = $kind, t.region = $region,
                            t.tenant_id = $cust
                        MERGE (k)-[:COVERS]->(t)
                        """,
                        contract=contract["id"],
                        id=site["id"],
                        name=site.get("name"),
                        kind=site.get("kind"),
                        region=site.get("region"),
                        cust=cust["id"],
                    )
                    known_sites.add(site["id"])
                    stats.sites += 1

        for host in hosts:
            # Fail loudly on a dangling reference rather than silently creating an
            # orphan Site or Zone - a host in a zone that does not exist would make
            # every blast-radius answer quietly wrong.
            if host.get("site") not in known_sites:
                stats.errors.append(f"{host['id']}: unknown site {host.get('site')!r}")
                continue
            bad = [z for z in host.get("zones", []) if z not in known_zones]
            if bad:
                stats.errors.append(f"{host['id']}: unknown zone(s) {bad}")
                continue

            s.run(
                """
                MATCH (t:Site {id: $site})
                MERGE (h:Host {id: $id})
                SET h.hostname = $hostname, h.tenant_id = $tenant, h.address = $address,
                    h.role = $role, h.provider = $provider, h.instance_type = $instance_type,
                    h.os_release = $os_release
                MERGE (t)-[:CONTAINS]->(h)
                WITH h
                UNWIND $zones AS zid
                MATCH (z:NetworkZone {id: zid})
                MERGE (h)-[:IN_ZONE]->(z)
                """,
                id=host["id"],
                hostname=host.get("hostname"),
                tenant=host.get("tenant"),
                address=host.get("address"),
                role=host.get("role"),
                provider=host.get("provider"),
                instance_type=host.get("instance_type"),
                os_release=host.get("os_release"),
                site=host["site"],
                zones=host.get("zones", []),
            )
            stats.hosts += 1

    return stats


if __name__ == "__main__":
    st = load()
    print(st)
    for e in st.errors:
        print("  ERROR:", e)
