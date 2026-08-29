"""ClickHouse implementation of warden's `Store` protocol.

warden ships a JSONL store so it works with no infrastructure. This is the other end of
that spectrum: the same interface backed by a columnar store, which is what the reference
deployment actually uses.

Having both is the point of making `Store` a protocol. The library stays adoptable in five
lines, and a deployment that outgrows a file swaps the implementation without touching a
detector.

The table predates warden, so this adapter maps between the two vocabularies rather than
migrating the schema:

    agent_tool_calls          warden
    ------------------        ----------------
    tenant                    Run.principal
    zone                      ToolCall.scope
    result_rows               ToolCall.result_size
    agent + agent_version     Run.key

That mapping is deliberate rather than a rename. `tenant` and `zone` are Sentinel's
domain words; `principal` and `scope` are the general ones. A library that insisted on the
former would be unusable outside an MSP.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from warden.trace import Run, ToolCall

from sentinel.store.clickhouse import client

TABLE = "agent_tool_calls"

COLUMNS = [
    "ts", "run_id", "step", "agent", "agent_version", "actor_kind", "tenant", "tool",
    "args", "resource", "zone", "ok", "error", "duration_ms", "result_rows",
    "output_bytes", "scenario", "is_anomalous",
]

READ_COLUMNS = """ts, run_id, step, agent, agent_version, actor_kind, tenant, tool,
                  resource, zone, ok, error, duration_ms, result_rows, output_bytes,
                  scenario, is_anomalous"""


class ClickHouseStore:
    """Append-only run history in ClickHouse, satisfying `warden.Store`."""

    def append(self, run: Run) -> None:
        self.extend([run])

    def extend(self, runs: list[Run]) -> int:
        rows: list[tuple] = []
        for run in runs:
            for call in run.calls:
                rows.append((
                    call.started_at,
                    run.run_id,
                    call.step,
                    run.agent,
                    run.version,
                    run.actor_kind,
                    run.principal,
                    call.tool,
                    json.dumps(call.args, default=str)[:4000],
                    call.resource,
                    call.scope,
                    1 if call.ok else 0,
                    call.error[:500],
                    call.duration_ms,
                    call.result_size,
                    call.output_bytes,
                    run.label,
                    run.is_anomalous,
                ))
        if not rows:
            return 0
        client().insert(TABLE, rows, column_names=COLUMNS)
        return len(rows)

    def read(
        self,
        *,
        agent: str | None = None,
        limit: int | None = None,
        where: str = "true",
    ) -> list[Run]:
        clauses = [where]
        if agent:
            clauses.append(f"agent = '{agent}'")
        rows = client().query(
            f"SELECT {READ_COLUMNS} FROM {TABLE} WHERE {' AND '.join(clauses)}"
        ).named_results()

        runs = _assemble(list(rows))
        return runs[-limit:] if limit else runs

    def read_labelled(self, is_anomalous: int) -> list[Run]:
        return self.read(where=f"is_anomalous = {is_anomalous}")

    def read_unlabelled(self) -> list[Run]:
        """Real traffic: everything that is not evaluation data."""
        return self.read(where="is_anomalous = -1")


def _assemble(rows: list[dict[str, Any]]) -> list[Run]:
    """Group flat call rows back into runs, preserving call order."""
    by_run: dict[str, Run] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        grouped[r["run_id"]].append(r)

    for run_id, calls in grouped.items():
        calls.sort(key=lambda c: c["step"])
        head = calls[0]
        run = Run(
            agent=head["agent"],
            version=head["agent_version"] or "unversioned",
            principal=head["tenant"] or "",
            actor_kind=head["actor_kind"] or "agent",
            run_id=run_id,
            started_at=_as_datetime(head["ts"]),
            label=head.get("scenario") or "",
            is_anomalous=int(head.get("is_anomalous", -1)),
        )
        run.calls = [
            ToolCall(
                tool=c["tool"],
                step=int(c["step"]),
                ok=bool(c["ok"]),
                error=c.get("error") or "",
                duration_ms=int(c.get("duration_ms") or 0),
                result_size=int(c.get("result_rows") or 0),
                output_bytes=int(c.get("output_bytes") or 0),
                resource=c.get("resource") or "",
                scope=c.get("zone") or "",
                started_at=_as_datetime(c["ts"]),
            )
            for c in calls
        ]
        by_run[run_id] = run
    return list(by_run.values())


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.now(UTC)
