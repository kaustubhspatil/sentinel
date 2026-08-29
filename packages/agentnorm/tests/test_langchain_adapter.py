"""Tests for the LangChain / LangGraph adapter.

LangChain is deliberately **not** installed for these tests. The callback contract is
simulated instead, which keeps agentnorm's zero-dependency guarantee testable in CI and
proves the handler works as a plain object rather than only as a framework subclass.
"""
from __future__ import annotations

import random
import uuid

from agentnorm import Monitor, RunRecorder, Session
from agentnorm.adapters.langchain import agentnorm_callback


def emit_tool(handler, name: str, *, inputs=None, output=None, error=None, run_id=None):
    """Replay the callback sequence LangChain produces for one tool invocation."""
    rid = run_id or uuid.uuid4()
    handler.on_tool_start({"name": name}, str(inputs or ""), run_id=rid, inputs=inputs or {})
    if error is not None:
        handler.on_tool_error(error, run_id=rid)
    else:
        handler.on_tool_end(output, run_id=rid)
    return rid


def test_records_a_simple_tool_sequence():
    rec = RunRecorder("researcher", version="v2", principal="acme")
    handler = agentnorm_callback(rec)
    emit_tool(handler, "web_search", inputs={"q": "x"}, output={"results": [1, 2, 3]})
    emit_tool(handler, "summarise", inputs={"text": "y"}, output="a summary")
    run = handler.finish()

    assert run.tools == ["web_search", "summarise"]
    assert run.sizes == [3, 1]
    assert all(c.ok for c in run.calls)


def test_works_without_langchain_installed():
    """The handler must not require the framework's base class to exist."""
    handler = agentnorm_callback(RunRecorder("a"))
    assert handler.raise_error is False
    emit_tool(handler, "t", output=[1])
    assert handler.finish().n_calls == 1


def test_interleaved_concurrent_tools_are_matched_by_run_id():
    """LangGraph runs tools in parallel; starts and ends arrive out of order."""
    rec = RunRecorder("planner", version="v1")
    handler = agentnorm_callback(rec)
    a, b = uuid.uuid4(), uuid.uuid4()

    handler.on_tool_start({"name": "slow"}, "", run_id=a, inputs={"n": 1})
    handler.on_tool_start({"name": "fast"}, "", run_id=b, inputs={"n": 2})
    handler.on_tool_end([1, 2], run_id=b)          # fast finishes first
    handler.on_tool_end([1, 2, 3, 4], run_id=a)

    run = handler.finish()
    by_tool = {c.tool: c.result_size for c in run.calls}
    assert by_tool == {"slow": 4, "fast": 2}


def test_tool_error_is_recorded_not_dropped():
    handler = agentnorm_callback(RunRecorder("a"))
    emit_tool(handler, "flaky", error=TimeoutError("upstream"))
    run = handler.finish()
    assert run.n_calls == 1
    assert run.calls[0].ok is False
    assert "TimeoutError" in run.calls[0].error


def test_unterminated_call_is_closed_as_failed():
    """An agent killed mid-tool: the open call is a signal, not something to discard."""
    handler = agentnorm_callback(RunRecorder("a"))
    handler.on_tool_start({"name": "hangs"}, "", run_id=uuid.uuid4(), inputs={})
    run = handler.finish()
    assert run.n_calls == 1
    assert run.calls[0].ok is False
    assert "unterminated" in run.calls[0].error


def test_end_without_start_is_ignored():
    """Attaching the handler mid-run must not invent a call with no duration or args."""
    handler = agentnorm_callback(RunRecorder("a"))
    handler.on_tool_end([1, 2], run_id=uuid.uuid4())
    assert handler.finish().n_calls == 0


def test_scope_of_enables_cross_principal_detection():
    handler = agentnorm_callback(
        RunRecorder("a", principal="acme"),
        scope_of=lambda tool, args, result: args.get("tenant"),
    )
    emit_tool(handler, "read", inputs={"tenant": "acme"}, output=[1])
    emit_tool(handler, "read", inputs={"tenant": "globex"}, output=[1])
    assert handler.finish().scopes == ["acme", "globex"]


def test_accepts_a_session_as_well_as_a_recorder():
    session = Session(agent="a", version="v1", principal="acme")
    handler = agentnorm_callback(session)
    emit_tool(handler, "t", output=[1, 2])
    assert session.finish().n_calls == 1


def test_missing_tool_name_does_not_break_recording():
    handler = agentnorm_callback(RunRecorder("a"))
    rid = uuid.uuid4()
    handler.on_tool_start(None, "raw input", run_id=rid)
    handler.on_tool_end([1], run_id=rid)
    run = handler.finish()
    assert run.tools == ["unknown_tool"]


def test_recorded_runs_feed_the_monitor():
    """End to end: callbacks in, verdict out.

    History varies deliberately. A perfectly uniform baseline has zero variance, which
    makes every deviation look extreme and would let this test pass for the wrong reason.
    """
    rng = random.Random(11)
    history = []
    for _ in range(200):
        h = agentnorm_callback(RunRecorder("researcher", version="v2", principal="acme"))
        emit_tool(h, "web_search",
                  output={"results": list(range(max(1, int(rng.lognormvariate(0, 0.6) * 8))))})
        emit_tool(h, "summarise", output="s")
        history.append(h.finish())

    monitor = Monitor.fit(history)

    normal = agentnorm_callback(RunRecorder("researcher", version="v2", principal="acme"))
    emit_tool(normal, "web_search", output={"results": list(range(8))})
    emit_tool(normal, "summarise", output="s")
    assert not monitor.score(normal.finish()).flagged, "a typical run must not alert"

    huge = agentnorm_callback(RunRecorder("researcher", version="v2", principal="acme"))
    emit_tool(huge, "web_search", output={"results": list(range(50_000))})
    emit_tool(huge, "summarise", output="s")
    verdict = monitor.score(huge.finish())
    assert verdict.flagged and any(a.detector == "volume" for a in verdict.alerts)
