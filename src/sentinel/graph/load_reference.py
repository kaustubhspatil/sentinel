"""Load global reference data into the knowledge graph.

Scope is deliberate. The graph receives:
  - Vulnerability nodes for the CISA KEV catalogue (~1.7k), enriched with the current
    EPSS score, because those are the CVEs an operator actually reasons about
  - the MITRE ATT&CK technique/tactic/mitigation structure

The graph does NOT receive all ~366k EPSS rows. Those are a daily time series and belong
in ClickHouse (see sentinel.store.load_epss). Putting them here would add a third of a
million nodes that no traversal ever visits, inflate the page cache, and slow every
query that does matter.

Vulnerability nodes for non-KEV CVEs are created later, on demand, when a package
install is found to be affected by one.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from sentinel.config import settings
from sentinel.graph.client import session

BATCH = 500


@dataclass
class LoadStats:
    vulnerabilities: int = 0
    techniques: int = 0
    tactics: int = 0
    mitigations: int = 0
    mitigates_edges: int = 0
    subtechnique_edges: int = 0

    def __str__(self) -> str:
        return (
            f"vulnerabilities={self.vulnerabilities:,}  techniques={self.techniques:,}  "
            f"tactics={self.tactics}  mitigations={self.mitigations:,}  "
            f"mitigates={self.mitigates_edges:,}  subtechnique_of={self.subtechnique_edges:,}"
        )


def _latest(prefix: str) -> Path:
    files = sorted(settings.raw_dir.glob(f"{prefix}*.json"))
    if not files:
        raise FileNotFoundError(
            f"no {prefix}*.json in {settings.raw_dir} - run: python -m sentinel.ingest.feeds"
        )
    return files[-1]


def _epss_index() -> dict[str, tuple[float, float]]:
    """Current EPSS score per CVE, used only to enrich the KEV set."""
    rows = json.loads(_latest("epss_").read_text(encoding="utf-8"))
    return {r["cve"]: (float(r["epss"]), float(r["percentile"])) for r in rows}


def load_kev(stats: LoadStats) -> None:
    payload = json.loads(_latest("kev_").read_text(encoding="utf-8"))
    epss = _epss_index()
    as_of = date.today().isoformat()

    records = []
    for v in payload.get("vulnerabilities", []):
        score, pct = epss.get(v["cveID"], (None, None))
        records.append(
            {
                "cve_id": v["cveID"],
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),
                "required_action": v.get("requiredAction"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate") or None,
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                "cwes": v.get("cwes") or [],
                "epss": score,
                "epss_percentile": pct,
                "epss_as_of": as_of if score is not None else None,
            }
        )

    cypher = """
    UNWIND $rows AS row
    MERGE (v:Vulnerability {cve_id: row.cve_id})
    SET v.kev             = true,
        v.vendor          = row.vendor,
        v.product         = row.product,
        v.name            = row.name,
        v.description     = row.description,
        v.required_action = row.required_action,
        v.kev_date_added  = date(row.date_added),
        v.kev_due_date    = CASE WHEN row.due_date IS NULL THEN NULL ELSE date(row.due_date) END,
        v.ransomware      = row.ransomware,
        v.cwes            = row.cwes,
        v.epss            = row.epss,
        v.epss_percentile = row.epss_percentile,
        v.epss_as_of      = CASE WHEN row.epss_as_of IS NULL THEN NULL ELSE date(row.epss_as_of) END
    """
    with session() as s:
        for i in range(0, len(records), BATCH):
            s.run(cypher, rows=records[i : i + BATCH])
    stats.vulnerabilities = len(records)


def _attack_objects() -> list[dict]:
    bundle = json.loads(_latest("attack_enterprise").read_text(encoding="utf-8"))
    # Revoked and deprecated objects stay in the bundle for provenance; loading them
    # would let an agent reason from retired doctrine.
    return [
        o
        for o in bundle.get("objects", [])
        if not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_attack(stats: LoadStats) -> None:
    objects = _attack_objects()
    by_stix: dict[str, str] = {}
    techniques: list[dict] = []
    mitigations: list[dict] = []
    tactics: dict[str, str] = {}

    for o in objects:
        kind = o.get("type")
        if kind == "attack-pattern":
            aid = _attack_id(o)
            if not aid:
                continue
            by_stix[o["id"]] = aid
            phases = [
                p["phase_name"]
                for p in o.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            for ph in phases:
                tactics[ph] = ph.replace("-", " ").title()
            techniques.append(
                {
                    "attack_id": aid,
                    "name": o.get("name"),
                    "description": (o.get("description") or "")[:4000],
                    "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
                    "platforms": o.get("x_mitre_platforms") or [],
                    "detection": (o.get("x_mitre_detection") or "")[:4000],
                    "tactics": phases,
                }
            )
        elif kind == "course-of-action":
            aid = _attack_id(o)
            if not aid:
                continue
            by_stix[o["id"]] = aid
            mitigations.append(
                {
                    "attack_id": aid,
                    "name": o.get("name"),
                    "description": (o.get("description") or "")[:4000],
                }
            )

    mitigates: list[dict] = []
    subtech: list[dict] = []
    for o in objects:
        if o.get("type") != "relationship":
            continue
        src = by_stix.get(o.get("source_ref"))
        tgt = by_stix.get(o.get("target_ref"))
        if not src or not tgt:
            continue
        if o.get("relationship_type") == "mitigates":
            mitigates.append({"m": src, "t": tgt})
        elif o.get("relationship_type") == "subtechnique-of":
            subtech.append({"child": src, "parent": tgt})

    with session() as s:
        s.run(
            """
            UNWIND $rows AS row
            MERGE (t:Tactic {shortname: row.shortname}) SET t.name = row.name
            """,
            rows=[{"shortname": k, "name": v} for k, v in tactics.items()],
        )
        for i in range(0, len(techniques), BATCH):
            s.run(
                """
                UNWIND $rows AS row
                MERGE (t:Technique {attack_id: row.attack_id})
                SET t.name = row.name, t.description = row.description,
                    t.is_subtechnique = row.is_subtechnique,
                    t.platforms = row.platforms, t.detection = row.detection
                WITH t, row
                UNWIND row.tactics AS phase
                MATCH (ta:Tactic {shortname: phase})
                MERGE (t)-[:ACHIEVES]->(ta)
                """,
                rows=techniques[i : i + BATCH],
            )
        for i in range(0, len(mitigations), BATCH):
            s.run(
                """
                UNWIND $rows AS row
                MERGE (m:Mitigation {attack_id: row.attack_id})
                SET m.name = row.name, m.description = row.description
                """,
                rows=mitigations[i : i + BATCH],
            )
        for i in range(0, len(mitigates), BATCH):
            s.run(
                """
                UNWIND $rows AS row
                MATCH (m:Mitigation {attack_id: row.m}), (t:Technique {attack_id: row.t})
                MERGE (m)-[:MITIGATES]->(t)
                """,
                rows=mitigates[i : i + BATCH],
            )
        for i in range(0, len(subtech), BATCH):
            s.run(
                """
                UNWIND $rows AS row
                MATCH (c:Technique {attack_id: row.child}), (p:Technique {attack_id: row.parent})
                MERGE (c)-[:SUBTECHNIQUE_OF]->(p)
                """,
                rows=subtech[i : i + BATCH],
            )

    stats.techniques = len(techniques)
    stats.tactics = len(tactics)
    stats.mitigations = len(mitigations)
    stats.mitigates_edges = len(mitigates)
    stats.subtechnique_edges = len(subtech)


def main() -> LoadStats:
    stats = LoadStats()
    load_kev(stats)
    load_attack(stats)
    return stats


if __name__ == "__main__":
    print(main())
