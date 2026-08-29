"""Recording what an agent did.

The unit of analysis is a *run*: one agent, one task, an ordered sequence of tool calls.
Not a message, not a span - a run, because the behaviours worth detecting (scope
escalation, a path no planner would take, volume anomalies) are properties of the whole
episode rather than any single call.

Three fields carry most of the detection value, and they are deliberate:

`version` is a change-point, not a label. Changing a prompt, model or tool grant changes
the behavioural distribution. A baseline that pools across versions alarms on every
deployment; one that keys on version resets instead.

`principal` is the scope the run is entitled to - a tenant, a customer, a user. It is
recorded per run and compared against what each call actually touched, because a scope
the caller can rewrite is not a scope.

`result_size` matters as much as latency. An agent quietly returning ten thousand rows
where it usually returns twenty is exfiltration-shaped, and no latency metric shows it.

Attribute names follow OpenTelemetry's GenAI semantic conventions where they exist
(`gen_ai.agent.name`, `gen_ai.tool.name`), so traces can be exported rather than trapped.
"""
from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Mapping to OpenTelemetry GenAI semantic conventions. Kept in one place so an exporter
# can be written without touching the recorder.
OTEL_ATTRS = {
    "agent": "gen_ai.agent.name",
    "version": "gen_ai.agent.version",
    "tool": "gen_ai.tool.name",
    "run_id": "gen_ai.conversation.id",
}


@dataclass
class ToolCall:
    """One tool invocation within a run."""

    tool: str
    step: int
    args: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: str = ""
    duration_ms: int = 0
    result_size: int = 0
    output_bytes: int = 0
    # What this call actually touched. `scope` is the entitlement the resource belongs
    # to; comparing it against the run's principal is how escalation is detected.
    resource: str = ""
    scope: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # Monotonic start, used only to compute duration. Excluded from serialisation.
    _started: float | None = field(default=None, repr=False, compare=False)


@dataclass
class Run:
    """One agent episode."""

    agent: str
    version: str = "unversioned"
    principal: str = ""
    actor_kind: str = "agent"  # 'agent' | 'human' - never pooled together
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    calls: list[ToolCall] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    label: str = ""          # set only for evaluation data
    is_anomalous: int = -1   # -1 unknown, 0 benign, 1 anomalous

    @property
    def tools(self) -> list[str]:
        return [c.tool for c in self.calls]

    @property
    def sizes(self) -> list[int]:
        return [c.result_size for c in self.calls]

    @property
    def scopes(self) -> list[str]:
        return [c.scope for c in self.calls]

    @property
    def n_calls(self) -> int:
        return len(self.calls)

    @property
    def key(self) -> str:
        """Grouping key for baselines: an agent version is a distinct behavioural entity."""
        return f"{self.agent}@{self.version}"


class RunRecorder:
    """Records a run. Deliberately tiny and dependency-free.

    Instrumenting an agent should not require adopting a framework, a database, or a
    context-propagation library. If recording is harder than that, it does not get done,
    and a monitoring tool nobody instruments monitors nothing.

        rec = RunRecorder(agent="triage", version="v3", principal="acme")
        with rec.tool_call("search_docs", {"q": q}) as call:
            rows = search(q)
            call.result_size = len(rows)
        run = rec.finish()
    """

    def __init__(
        self,
        agent: str,
        *,
        version: str = "unversioned",
        principal: str = "",
        actor_kind: str = "agent",
    ) -> None:
        self.run = Run(agent=agent, version=version, principal=principal,
                       actor_kind=actor_kind)
        self._step = 0

    @property
    def run_id(self) -> str:
        """The id of the run being recorded.

        Exposed on the recorder as well as the run because callers routinely need it
        before the run is finished - to correlate a model call, a log line or a trace
        span with the run it belongs to.
        """
        return self.run.run_id

    def start_call(
        self, tool: str, args: dict[str, Any] | None = None, *, scope: str = ""
    ) -> ToolCall:
        """Begin a call without a `with` block.

        Callback-driven frameworks report start and end as separate events, often
        interleaved across concurrent tools, so a context manager cannot express them.
        `tool_call` is built on top of this pair.
        """
        self._step += 1
        call = ToolCall(tool=tool, step=self._step, args=dict(args or {}), scope=scope)
        call._started = time.perf_counter()
        return call

    def complete_call(
        self, call: ToolCall, *, ok: bool = True, error: str = "", result_size: int = 0
    ) -> ToolCall:
        """Finish a call started with `start_call` and attach it to the run."""
        started = getattr(call, "_started", None)
        call.duration_ms = int((time.perf_counter() - started) * 1000) if started else 0
        call.ok = ok
        call.error = error
        if result_size:
            call.result_size = result_size
        self.run.calls.append(call)
        return call

    @contextmanager
    def tool_call(
        self, tool: str, args: dict[str, Any] | None = None, *, scope: str = ""
    ) -> Iterator[ToolCall]:
        """Time and record one call. Failures are recorded, then re-raised.

        A trace that omits failed calls hides exactly the behaviour worth detecting: an
        agent probing for a tool it lacks, or retrying a refused action.
        """
        call = self.start_call(tool, args, scope=scope)
        try:
            yield call
        except Exception as exc:
            self.complete_call(call, ok=False, error=f"{type(exc).__name__}: {exc}")
            raise
        else:
            self.complete_call(call, ok=True, result_size=call.result_size)

    def finish(self) -> Run:
        return self.run
