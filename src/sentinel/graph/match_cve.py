"""Version-aware CVE matching.

Replaces the product-name heuristic with the real question: does the installed version
of this package predate the version that fixed a given CVE on this release?

Answering that needs three things to line up - the package name, the release, and a
correct Debian version comparison - and getting any of them wrong produces a confident
wrong answer rather than an obvious failure. So:

  * matching is per-release, driven by the host's os_release
  * comparison uses sentinel.util.debver, which is unit-tested against dpkg's own cases
  * versions that will not parse are counted and reported, never silently skipped
  * edges record the USN and the fixing version, so any claim can be traced back

Low-confidence product-name edges from the earlier heuristic are removed for any host
this runs over, so the two schemes cannot coexist and be double-counted.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.config import settings
from sentinel.graph.client import session
from sentinel.util.debver import is_older

BATCH = 500


@dataclass
class MatchStats:
    hosts: int = 0
    installs_examined: int = 0
    vulnerable_installs: int = 0
    cve_edges: int = 0
    cves: set[str] = field(default_factory=set)
    unparseable_versions: int = 0
    heuristic_edges_removed: int = 0

    def __str__(self) -> str:
        return (
            f"hosts={self.hosts} installs={self.installs_examined:,} "
            f"vulnerable_installs={self.vulnerable_installs} "
            f"distinct_cves={len(self.cves)} edges={self.cve_edges} "
            f"unparseable_versions={self.unparseable_versions} "
            f"heuristic_edges_removed={self.heuristic_edges_removed}"
        )


def _usn_index(release: str) -> dict[str, list[tuple[str, str, list[str]]]]:
    """package name -> [(fixed_version, usn_id, cve_ids)]"""
    path = settings.raw_dir / f"usn_{release}.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} missing - run: python -m sentinel.ingest.usn"
        )
    index: dict[str, list[tuple[str, str, list[str]]]] = defaultdict(list)
    for notice in json.loads(path.read_text(encoding="utf-8")):
        cves = [c for c in notice.get("cves", []) if c.startswith("CVE-")]
        if not cves:
            continue
        for pkg in notice.get("packages", []):
            index[pkg["name"]].append((pkg["version"], notice["id"], cves))
    return index


def match_release(release: str = "noble") -> MatchStats:
    stats = MatchStats()
    index = _usn_index(release)

    with session() as s:
        hosts = [
            r["id"]
            for r in s.run(
                "MATCH (h:Host) WHERE coalesce(h.os_release, $rel) = $rel RETURN h.id AS id",
                rel=release,
            )
        ]

        for host_id in hosts:
            stats.hosts += 1
            installs = list(
                s.run(
                    """
                    MATCH (h:Host {id: $host})-[:RUNS]->(i:PackageInstall)-[:OF]->(p:Package)
                    RETURN i.id AS install_id, p.key AS name, i.version AS version
                    """,
                    host=host_id,
                )
            )
            stats.installs_examined += len(installs)

            edges: list[dict] = []
            for row in installs:
                name, version = row["name"], row["version"]
                if not version or name not in index:
                    continue
                hit = False
                for fixed_version, usn_id, cves in index[name]:
                    try:
                        older = is_older(version, fixed_version)
                    except ValueError:
                        stats.unparseable_versions += 1
                        continue
                    if not older:
                        continue
                    hit = True
                    for cve in cves:
                        edges.append(
                            {
                                "install_id": row["install_id"],
                                "cve_id": cve,
                                "usn": usn_id,
                                "fixed_version": fixed_version,
                                "installed_version": version,
                            }
                        )
                        stats.cves.add(cve)
                if hit:
                    stats.vulnerable_installs += 1

            # Drop the earlier low-confidence edges for this host before writing the
            # version-aware ones, so a stale heuristic claim cannot survive alongside
            # a real measurement.
            removed = s.run(
                """
                MATCH (:Host {id: $host})-[:RUNS]->(:PackageInstall)
                      -[r:POTENTIALLY_AFFECTED_BY]->(:Vulnerability)
                DELETE r RETURN count(r) AS n
                """,
                host=host_id,
            ).single()
            stats.heuristic_edges_removed += removed["n"] if removed else 0

            for i in range(0, len(edges), BATCH):
                s.run(
                    """
                    UNWIND $rows AS row
                    MATCH (i:PackageInstall {id: row.install_id})
                    MERGE (v:Vulnerability {cve_id: row.cve_id})
                      ON CREATE SET v.kev = false
                    MERGE (i)-[r:AFFECTED_BY]->(v)
                    SET r.usn = row.usn,
                        r.fixed_version = row.fixed_version,
                        r.installed_version = row.installed_version,
                        r.match_method = 'usn-version',
                        r.confidence = 'high',
                        r.asserted_at = datetime()
                    """,
                    rows=edges[i : i + BATCH],
                )
            stats.cve_edges += len(edges)

    return stats


if __name__ == "__main__":
    print(match_release())
