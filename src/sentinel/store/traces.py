"""Agent trace capture.

Every tool call an agent makes is recorded here: which agent version, which run, which
tool, with what arguments, against which tenant and resource, how long it took, how much
it returned. This table is the dataset the detection layer learns from, so its schema is
chosen for the questions the detectors will ask rather than for debugging convenience.

Three design points that matter later:

**agent_version is a first-class column.** Changing a prompt, model or tool grant changes
the behavioural distribution, so a version bump is a change-point in the series. A
detector that pools across versions will alarm on every deployment; one that keys on
version can reset its priors instead.

**actor_kind separates human from machine.** Their tool-use distributions are nothing
alike, and pooling them would poison the group priors of the hierarchical baseline.

**output_bytes and result_rows are recorded, not just latency.** Output volume is one of
the anomaly signals that matters most - an agent quietly returning ten thousand rows where
it usually returns twenty is exfiltration-shaped, and no latency metric shows it.
"""
from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from sentinel.store.clickhouse import client

TRACE_DDL = """
CREATE TABLE IF NOT EXISTS agent_tool_calls (
    ts              DateTime64(3),
    run_id          String,
    step            UInt16,
    agent           LowCardinality(String),
    agent_version   LowCardinality(String),
    actor_kind      LowCardinality(String),   -- 'agent' | 'human'
    tenant          LowCardinality(String),
    tool            LowCardinality(String),
    args            String,                    -- JSON, for post-hoc analysis
    resource        String,                    -- primary entity touched, if any
    zone            LowCardinality(String),
    ok              UInt8,
    error           String,
    duration_ms     UInt32,
    result_rows     UInt32,
    output_bytes    UInt32,
    -- Labelled only for generated evaluation data; empty for real traffic.
    scenario        LowCardinality(String),
    is_anomalous    Int8 DEFAULT -1            -- -1 unknown, 0 benign, 1 anomalous
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant, agent, tool, ts)
"""


@dataclass
class RunContext:
    """Identifies one agent run; steps within it are ordered."""

    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    agent: str = "remediation"
    agent_version: str = "v1"
    actor_kind: str = "agent"
    tenant: str = ""
    scenario: str = ""
    is_anomalous: int = -1
    _step: int = 0

    def next_step(self) -> int:
        self._step += 1
        return self._step


_BUFFER: list[tuple] = []
COLUMNS = [
    "ts", "run_id", "step", "agent", "agent_version", "actor_kind", "tenant", "tool",
    "args", "resource", "zone", "ok", "error", "duration_ms", "result_rows",
    "output_bytes", "scenario", "is_anomalous",
]


def apply_schema() -> None:
    client().command(TRACE_DDL)


def record(
    ctx: RunContext,
    tool: str,
    args: dict[str, Any],
    *,
    ok: bool,
    duration_ms: int,
    result_rows: int = 0,
    output_bytes: int = 0,
    resource: str = "",
    zone: str = "",
    error: str = "",
) -> None:
    _BUFFER.append(
        (
            datetime.now(timezone.utc),
            ctx.run_id,
            ctx.next_step(),
            ctx.agent,
            ctx.agent_version,
            ctx.actor_kind,
            ctx.tenant,
            tool,
            json.dumps(args, default=str)[:4000],
            resource,
            zone,
            1 if ok else 0,
            error[:500],
            duration_ms,
            result_rows,
            output_bytes,
            ctx.scenario,
            ctx.is_anomalous,
        )
    )


def flush() -> int:
    """Write buffered traces. Batched because per-call inserts would dominate latency."""
    if not _BUFFER:
        return 0
    n = len(_BUFFER)
    client().insert("agent_tool_calls", _BUFFER, column_names=COLUMNS)
    _BUFFER.clear()
    return n


@contextmanager
def traced(ctx: RunContext, tool: str, args: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Time and record one tool call.

    The caller sets `out["result_rows"]` and `out["resource"]`; failures are recorded
    with the exception message and re-raised, because a trace that omits failed calls
    would hide exactly the behaviour worth detecting.
    """
    started = time.perf_counter()
    out: dict[str, Any] = {"result_rows": 0, "output_bytes": 0, "resource": "", "zone": ""}
    try:
        yield out
    except Exception as exc:  # noqa: BLE001 - recorded then re-raised
        record(
            ctx, tool, args, ok=False,
            duration_ms=int((time.perf_counter() - started) * 1000),
            error=f"{type(exc).__name__}: {exc}",
            resource=str(out.get("resource", "")),
        )
        raise
    else:
        record(
            ctx, tool, args, ok=True,
            duration_ms=int((time.perf_counter() - started) * 1000),
            result_rows=int(out.get("result_rows", 0)),
            output_bytes=int(out.get("output_bytes", 0)),
            resource=str(out.get("resource", "")),
            zone=str(out.get("zone", "")),
        )


if __name__ == "__main__":
    apply_schema()
    print("agent_tool_calls table ready")
