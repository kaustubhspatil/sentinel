"""Tests for instrumentation and persistence.

These cover the adoption path rather than the maths: if wrapping existing tools changes
their behaviour, or if history cannot survive a restart, the detectors never get used at
all.
"""
from __future__ import annotations

import pytest

from agentnorm import JsonlStore, Monitor, Session, default_size_of


def search(q: str, tenant: str = "acme") -> dict:
    return {"count": 3, "results": [1, 2, 3], "tenant": tenant}


def failing_tool() -> None:
    raise RuntimeError("upstream down")


# --- wrapping must be transparent -------------------------------------------------

def test_wrapped_tool_returns_the_same_value():
    session = Session(agent="a")
    tools = session.wrap({"search": search})
    assert tools["search"]("hello") == search("hello")


def test_wrapping_preserves_kwargs_and_positional_args():
    session = Session(agent="a")
    tools = session.wrap({"search": search})
    assert tools["search"]("q", tenant="globex")["tenant"] == "globex"
    run = session.finish()
    assert run.calls[0].args["0"] == "q"
    assert run.calls[0].args["tenant"] == "globex"


def test_exception_propagates_and_is_recorded():
    session = Session(agent="a")
    tools = session.wrap({"boom": failing_tool})
    with pytest.raises(RuntimeError):
        tools["boom"]()
    run = session.finish()
    assert run.n_calls == 1
    assert run.calls[0].ok is False


def test_tool_metadata_survives_wrapping():
    session = Session(agent="a")
    wrapped = session.wrap_one("search", search)
    assert wrapped.__name__ == "search"


# --- size inference ---------------------------------------------------------------

@pytest.mark.parametrize(
    "result,expected",
    [
        ({"count": 42, "results": [1]}, 42),      # explicit count wins
        ({"results": [1, 2, 3]}, 3),
        ({"rows": [1, 2]}, 2),
        ([1, 2, 3, 4], 4),
        ("a string", 1),                          # not 8 - a string is one result
        (None, 0),
        (object(), 1),
    ],
)
def test_default_size_inference(result, expected):
    assert default_size_of("t", {}, result) == expected


def test_custom_size_of_is_used():
    session = Session(agent="a", size_of=lambda tool, args, res: 999)
    session.wrap({"search": search})["search"]("q")
    assert session.finish().calls[0].result_size == 999


# --- scope extraction -------------------------------------------------------------

def test_scope_of_enables_violation_detection():
    session = Session(
        agent="a", principal="acme",
        scope_of=lambda tool, args, res: args.get("tenant"),
    )
    tools = session.wrap({"search": search})
    tools["search"]("q", tenant="acme")
    tools["search"]("q", tenant="globex")     # cross-tenant
    run = session.finish()
    assert run.scopes == ["acme", "globex"]


def test_unknown_scope_is_not_treated_as_a_violation():
    """A false accusation of cross-tenant access is worse than a miss."""
    session = Session(agent="a", principal="acme",
                      scope_of=lambda tool, args, res: None)
    session.wrap({"search": search})["search"]("q")
    run = session.finish()
    assert run.calls[0].scope == ""


# --- persistence ------------------------------------------------------------------

def _run(agent="a", tenant="acme"):
    session = Session(agent=agent, version="v1", principal=tenant,
                      scope_of=lambda t, a, r: a.get("tenant"))
    session.wrap({"search": search})["search"]("q", tenant=tenant)
    return session.finish()


def test_roundtrip_preserves_run(tmp_path):
    store = JsonlStore(tmp_path / "runs.jsonl")
    original = _run()
    store.append(original)
    restored = store.read()[0]
    assert restored.run_id == original.run_id
    assert restored.tools == original.tools
    assert restored.scopes == original.scopes
    assert restored.key == original.key


def test_history_survives_and_feeds_the_monitor(tmp_path):
    store = JsonlStore(tmp_path / "runs.jsonl")
    store.extend(_run() for _ in range(60))
    monitor = Monitor.fit(JsonlStore(tmp_path / "runs.jsonl").read())
    assert not monitor.score(_run()).flagged


def test_truncated_final_line_costs_one_run_not_the_file(tmp_path):
    path = tmp_path / "runs.jsonl"
    store = JsonlStore(path)
    store.extend(_run() for _ in range(5))
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"agent": "a", "calls": [tru')      # interrupted write
    assert len(store.read()) == 5


def test_unserialisable_args_do_not_break_persistence(tmp_path):
    store = JsonlStore(tmp_path / "runs.jsonl")
    session = Session(agent="a")
    session.wrap({"search": lambda **kw: {"count": 1}})["search"](obj=object())
    store.append(session.finish())
    assert len(store.read()) == 1


def test_read_filters_by_agent(tmp_path):
    store = JsonlStore(tmp_path / "runs.jsonl")
    store.extend([_run(agent="a"), _run(agent="b"), _run(agent="a")])
    assert len(store.read(agent="a")) == 2
