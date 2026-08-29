"""Load the daily EPSS series into ClickHouse.

EPSS publishes an exploit-probability score for every known CVE, every day. That is a
time series of ~366k rows per day, and it is the raw material for the exploitability
baselines later: what matters operationally is not that a CVE scores 0.4, but that it
scored 0.02 last week.

This is the concrete half of the "graph holds meaning, columnar store holds volume"
split. Nothing here enters Neo4j; only the KEV subset is enriched into the graph.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path

from sentinel.config import settings
from sentinel.store.clickhouse import apply_schema, client

DATE_IN_NAME = re.compile(r"(\d{8})")


def _as_of(path: Path) -> date:
    """Trust the filename's stamp, not today's date - a re-run must be idempotent."""
    m = DATE_IN_NAME.search(path.name)
    if not m:
        raise ValueError(f"cannot determine as_of date from {path.name}")
    return datetime.strptime(m.group(1), "%Y%m%d").date()


def load_file(path: Path) -> int:
    rows = json.loads(path.read_text(encoding="utf-8"))
    as_of = _as_of(path)
    data = [(as_of, r["cve"], float(r["epss"]), float(r["percentile"])) for r in rows]

    c = client()
    # ReplacingMergeTree ordered by (cve_id, as_of): re-running a day overwrites rather
    # than duplicating, so a retried Actions run cannot corrupt the series.
    c.insert(
        "epss_scores",
        data,
        column_names=["as_of", "cve_id", "epss", "percentile"],
    )
    return len(data)


def load_all() -> dict[str, int]:
    apply_schema()
    out: dict[str, int] = {}
    for path in sorted(settings.raw_dir.glob("epss_*.json")):
        out[path.name] = load_file(path)
    return out


if __name__ == "__main__":
    total = 0
    for name, n in load_all().items():
        print(f"{name}: {n:,} rows")
        total += n
    print(f"total {total:,}")
