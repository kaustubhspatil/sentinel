"""Load discovered package inventory and join it to known-exploited vulnerabilities.

osquery emits deb_packages as a snapshot: the whole inventory, every run. This reads
those snapshots and creates the PackageInstall nodes that sit between a Host and a
Package - reified because the install, not the package, is what carries a version and
what a CVE actually affects.

On matching, honestly: this joins on vendor/product strings from the CISA KEV catalogue
against Debian package names, which is a coarse heuristic. Proper matching needs CPE
identifiers from NVD, and until that lands the match count here is a lower bound with
a real false-positive rate. It is reported as a measured number rather than presented
as authoritative, and `match_method` is recorded on every edge so the weak matches can
be re-derived once CPE matching exists.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.graph.client import session

BATCH = 1000

# Debian package names that map to a KEV vendor/product with reasonable confidence.
# Deliberately small and explicit: a fuzzy match over 600 package names against 1,685
# KEV entries produces mostly noise, and noise in a vulnerability graph is worse than
# a gap, because it gets acted on.
KEV_PRODUCT_HINTS: dict[str, tuple[str, str]] = {
    "openssl": ("OpenSSL", "OpenSSL"),
    "openssh-server": ("OpenBSD", "OpenSSH"),
    "sudo": ("Sudo", "Sudo"),
    "curl": ("Haxx", "curl"),
    "git": ("Git", "Git"),
    "python3": ("Python Software Foundation", "Python"),
    "bash": ("GNU", "Bash"),
    "glibc": ("GNU", "glibc"),
    "libc6": ("GNU", "glibc"),
    "polkitd": ("PolicyKit", "polkit"),
    "policykit-1": ("PolicyKit", "polkit"),
    "samba": ("Samba", "Samba"),
    "nginx": ("F5", "NGINX"),
    "apache2": ("Apache", "HTTP Server"),
}


@dataclass
class InventoryStats:
    hosts: int = 0
    installs: int = 0
    packages: int = 0
    candidate_matches: int = 0
    unmatched_hosts: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return (
            f"hosts={self.hosts} packages={self.packages:,} installs={self.installs:,} "
            f"candidate_cve_matches={self.candidate_matches}"
        )


def parse_snapshot(line: str) -> tuple[str, str, list[dict]] | None:
    """Return (host_identifier, query_name, rows) for a deb_packages snapshot line."""
    try:
        doc = json.loads(line)
    except json.JSONDecodeError:
        return None
    if doc.get("name") != "deb_packages":
        return None
    rows = doc.get("snapshot") or []
    return doc.get("hostIdentifier", ""), doc["name"], rows


def latest_snapshots(path: Path) -> dict[str, list[dict]]:
    """Last deb_packages snapshot per host in a snapshots log."""
    out: dict[str, list[dict]] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_snapshot(line)
        if parsed:
            host, _, rows = parsed
            out[host] = rows
    return out


def _host_key(host_identifier: str) -> str:
    """osquery reports the FQDN; the graph keys hosts on the short name."""
    return host_identifier.split(".")[0]


def load_host_inventory(host_id: str, rows: list[dict], stats: InventoryStats) -> None:
    installs = [
        {
            "install_id": f"{host_id}:{r['name']}:{r.get('version', '')}",
            "package_key": r["name"],
            "name": r["name"],
            "version": r.get("version"),
            "arch": r.get("arch"),
        }
        for r in rows
        if r.get("name")
    ]

    with session() as s:
        result = s.run("MATCH (h:Host {id: $id}) RETURN h.tenant_id AS t", id=host_id).single()
        if result is None:
            stats.unmatched_hosts.append(host_id)
            return
        tenant = result["t"]

        for i in range(0, len(installs), BATCH):
            s.run(
                """
                UNWIND $rows AS row
                MATCH (h:Host {id: $host})
                MERGE (p:Package {key: row.package_key})
                  ON CREATE SET p.name = row.name
                MERGE (i:PackageInstall {id: row.install_id})
                SET i.version = row.version, i.arch = row.arch, i.tenant_id = $tenant,
                    i.last_seen = datetime()
                MERGE (h)-[:RUNS]->(i)
                MERGE (i)-[:OF]->(p)
                """,
                rows=installs[i : i + BATCH],
                host=host_id,
                tenant=tenant,
            )

        # Candidate CVE exposure. Recorded with match_method so it can be re-derived
        # once CPE matching exists - and so a downstream consumer can filter on
        # confidence rather than trusting every edge equally.
        hints = [
            {"pkg": pkg, "vendor": vendor, "product": product}
            for pkg, (vendor, product) in KEV_PRODUCT_HINTS.items()
        ]
        rec = s.run(
            """
            UNWIND $hints AS hint
            MATCH (h:Host {id: $host})-[:RUNS]->(i:PackageInstall)-[:OF]->(p:Package)
            WHERE p.key = hint.pkg
            MATCH (v:Vulnerability)
            WHERE v.kev = true AND toLower(v.product) CONTAINS toLower(hint.product)
            MERGE (i)-[r:POTENTIALLY_AFFECTED_BY]->(v)
            SET r.match_method = 'product-name-hint', r.confidence = 'low',
                r.asserted_at = datetime()
            RETURN count(r) AS n
            """,
            hints=hints,
            host=host_id,
        ).single()
        stats.candidate_matches += rec["n"] if rec else 0

    stats.hosts += 1
    stats.installs += len(installs)
    stats.packages += len({i["package_key"] for i in installs})


def load_file(path: Path) -> InventoryStats:
    stats = InventoryStats()
    for host_identifier, rows in latest_snapshots(path).items():
        load_host_inventory(_host_key(host_identifier), rows, stats)
    return stats


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/snapshots.log")
    st = load_file(target)
    print(st)
    for h in st.unmatched_hosts:
        print(f"  WARNING: snapshot for unknown host {h!r} - not in estate.yaml")
