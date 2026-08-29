"""Fetch public vulnerability feeds.

Sources (all free, no auth):
  KEV   - CISA Known Exploited Vulnerabilities catalogue
  EPSS  - FIRST Exploit Prediction Scoring System (daily; a genuine time series)
  ATT&CK- MITRE Enterprise ATT&CK in STIX 2.1

These are the real-world anchors of the ontology: every CVE, exploit-probability
score and adversary technique below describes the actual world, not a simulation.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import httpx

from sentinel.config import settings

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TIMEOUT = httpx.Timeout(60.0, connect=15.0)


@dataclass(frozen=True)
class FetchResult:
    name: str
    path: Path
    records: int


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, follow_redirects=True, headers={"User-Agent": "sentinel/0.1"})


def fetch_kev(out_dir: Path | None = None) -> FetchResult:
    out_dir = out_dir or settings.raw_dir
    with _client() as c:
        payload = c.get(KEV_URL).raise_for_status().json()
    path = out_dir / f"kev_{date.today():%Y%m%d}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return FetchResult("kev", path, len(payload.get("vulnerabilities", [])))


def fetch_epss(out_dir: Path | None = None) -> FetchResult:
    """Daily exploit-probability scores. Re-run daily to build the baseline series."""
    out_dir = out_dir or settings.raw_dir
    with _client() as c:
        blob = c.get(EPSS_URL).raise_for_status().content
    text = gzip.decompress(blob).decode("utf-8")
    # First line is a '#model_version' comment; the header follows.
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    rows = list(csv.DictReader(io.StringIO("\n".join(lines))))
    path = out_dir / f"epss_{date.today():%Y%m%d}.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return FetchResult("epss", path, len(rows))


def fetch_attack(out_dir: Path | None = None) -> FetchResult:
    """MITRE ATT&CK as STIX 2.1 - a professionally authored ontology to align ours against."""
    out_dir = out_dir or settings.raw_dir
    with _client() as c:
        payload = c.get(ATTACK_URL).raise_for_status().json()
    path = out_dir / "attack_enterprise.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return FetchResult("attack", path, len(payload.get("objects", [])))


def fetch_all() -> list[FetchResult]:
    return [fetch_kev(), fetch_epss(), fetch_attack()]


if __name__ == "__main__":
    for r in fetch_all():
        print(f"{r.name:8s} {r.records:>8,} records -> {r.path.name}")
