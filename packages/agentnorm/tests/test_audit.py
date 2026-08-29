"""Tests for the tamper-evident audit trail.

The tampering tests are the ones that matter. An audit log whose integrity check passes
after a record is altered is worse than no audit log, because it launders the alteration.
"""
from __future__ import annotations

import json

import pytest

from agentnorm import RunRecorder
from agentnorm.audit import (
    AuditChain,
    AuditLog,
    canonical,
    digest,
    record_run,
)
from agentnorm.audit import (
    verify_chain as verify,
)


def make_run(agent="triage", principal="acme", n=3):
    rec = RunRecorder(agent, version="v1", principal=principal)
    for i in range(n):
        with rec.tool_call(f"tool_{i}", {"q": "x"}, scope=principal) as c:
            c.result_size = 5
    return rec.finish()


# --- canonicalisation --------------------------------------------------------------

def test_canonical_is_key_order_independent():
    a = {"b": 1, "a": {"d": 2, "c": 3}}
    b = {"a": {"c": 3, "d": 2}, "b": 1}
    assert canonical(a) == canonical(b)
    assert digest(a) == digest(b)


def test_floats_are_rejected_not_approximated():
    """Silent float handling would produce hashes that fail cross-implementation."""
    with pytest.raises(TypeError, match="float"):
        canonical({"latency": 1.5})


def test_canonical_preserves_unicode_without_escaping():
    assert "é" in canonical({"name": "café"})


# --- chain construction ------------------------------------------------------------

def test_records_chain_by_hash_and_parent():
    chain = AuditChain()
    records = record_run(chain, make_run())
    assert records[0]["prev_hash"] is None
    assert records[0]["parent_record_id"] is None
    for prev, cur in zip(records, records[1:], strict=False):
        assert cur["prev_hash"] == digest(prev)
        assert cur["parent_record_id"] == prev["record_id"]


def test_run_produces_lifecycle_bookends_and_one_record_per_call():
    records = record_run(AuditChain(), make_run(n=4))
    assert len(records) == 6  # started + 4 calls + finished
    assert records[0]["action_detail"]["event"] == "run_started"
    assert records[-1]["action_detail"]["event"] == "run_finished"
    assert sum(r["action_type"] == "tool_call" for r in records) == 4


def test_principal_is_on_every_record():
    """'Under whose authority' must survive without a session lookup."""
    records = record_run(AuditChain(), make_run(principal="globex"))
    assert all(r["principal"] == "globex" for r in records)


def test_failed_call_is_recorded_as_failure():
    rec = RunRecorder("a", version="v1", principal="acme")
    with pytest.raises(ValueError):  # noqa: PT012
        with rec.tool_call("boom"):
            raise ValueError("nope")
    records = record_run(AuditChain(), rec.finish())
    assert [r["outcome"] for r in records if r["action_type"] == "tool_call"] == ["failure"]


def test_invalid_vocabulary_is_rejected():
    chain = AuditChain()
    with pytest.raises(ValueError, match="action_type"):
        chain.append(agent_id="a", agent_version="v1", session_id="s",
                     action_type="not_a_type", action_detail={}, outcome="success")


# --- delegation --------------------------------------------------------------------

def test_delegation_records_the_chain_not_the_prompt():
    chain = AuditChain()
    rec = chain.delegate(
        agent_id="urn:agent:planner", agent_version="v1", session_id="s1",
        delegate_agent_id="urn:agent:worker", task_description="send the quarterly report",
        principal="acme",
    )
    detail = rec["action_detail"]
    assert rec["action_type"] == "delegation"
    assert detail["delegate_agent_id"] == "urn:agent:worker"
    assert len(detail["task_description_hash"]) == 64
    assert "send the quarterly report" not in json.dumps(rec)


# --- tamper evidence ---------------------------------------------------------------

def test_intact_chain_verifies():
    records = record_run(AuditChain(), make_run())
    assert verify(records).ok


def test_altering_a_record_is_detected_at_the_next_record():
    records = record_run(AuditChain(), make_run(n=4))
    records[2]["action_detail"]["result_size"] = 999_999
    result = verify(records)
    assert not result.ok
    assert result.first_broken_index == 3


def test_deleting_a_record_is_detected():
    records = record_run(AuditChain(), make_run(n=4))
    del records[2]
    result = verify(records)
    assert not result.ok
    assert result.first_broken_index == 2


def test_reordering_records_is_detected():
    records = record_run(AuditChain(), make_run(n=4))
    records[1], records[2] = records[2], records[1]
    assert not verify(records).ok


def test_appending_a_forged_record_is_detected():
    records = record_run(AuditChain(), make_run())
    forged = dict(records[-1])
    forged["record_id"] = "forged"
    forged["action_detail"] = {"event": "run_finished", "calls": 0}
    records.append(forged)
    assert not verify(records).ok


# --- on-disk log -------------------------------------------------------------------

def test_log_roundtrips_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.write_run(make_run())
    log.write_run(make_run(agent="reporting"))
    assert log.verify().ok
    assert len(list(log.read())) == 10


def test_reopening_continues_one_chain(tmp_path):
    """A restart must not silently start a second chain that verifies on its own."""
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path)
    first.write_run(make_run())
    head = first.chain_head()

    second = AuditLog(path)
    assert second.chain_head() == head
    second.write_run(make_run())
    assert AuditLog(path).verify().ok


def test_tampering_with_the_file_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.write_run(make_run(n=3))

    lines = path.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[2])
    doctored["action_detail"]["resource"] = "someone-elses-data"
    lines[2] = canonical(doctored)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert not AuditLog(path).verify().ok


def test_chain_head_is_exposed_for_external_anchoring(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.chain_head() is None
    log.write_run(make_run())
    assert len(log.chain_head()) == 64
