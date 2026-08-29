"""ClickHouse connection and schema.

Everything time-ordered lives here rather than in the graph: EPSS history, host metrics,
and - later - agent tool-call traces. The graph answers "what does this mean"; this
answers "what happened, and how often".
"""
from __future__ import annotations

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from sentinel.config import settings

DDL = [
    """
    CREATE TABLE IF NOT EXISTS epss_scores (
        as_of       Date,
        cve_id      LowCardinality(String),
        epss        Float32,
        percentile  Float32
    ) ENGINE = ReplacingMergeTree
    ORDER BY (cve_id, as_of)
    """,
    # Daily snapshots of 366k CVEs accumulate fast, and the interesting signal is
    # movement, not the level. Partitioning by month keeps drops cheap if we ever
    # need to age data out.
    """
    CREATE TABLE IF NOT EXISTS kev_snapshot (
        as_of        Date,
        cve_id       LowCardinality(String),
        vendor       String,
        product      String,
        date_added   Date,
        due_date     Nullable(Date),
        ransomware   UInt8
    ) ENGINE = ReplacingMergeTree
    ORDER BY (cve_id, as_of)
    """,
]


def client() -> Client:
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password or "",
        database=settings.clickhouse_db,
    )


def apply_schema() -> int:
    c = client()
    for stmt in DDL:
        c.command(stmt)
    return len(DDL)


if __name__ == "__main__":
    print(f"applied {apply_schema()} ClickHouse tables")
