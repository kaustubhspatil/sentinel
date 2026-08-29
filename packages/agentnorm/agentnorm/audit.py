"""Tamper-evident audit trail for agent actions.

The EU AI Act's Article 12 obligations for high-risk systems take effect in August 2026:
automatic logging of events relevant to traceability, tamper-evident, retained six months
(twenty-four for biometric and law-enforcement systems), with penalties up to 3% of global
turnover. What regulators and security teams have converged on needing is the ability to
say *which agent accessed what data, under whose authority, and to reconstruct it later*.

Behavioural monitoring already sees every one of those facts. It was throwing away the
evidence.

Records follow the IETF Agent Audit Trail draft (`draft-sharif-agent-audit-trail`), which
matters for two reasons. Aligning with an emerging standard is a far better position than
inventing a log format nobody else reads. And the draft has a field, `recording_component`,
for exactly this situation - an entity that writes records *independently of the agent*,
for gateways and middleware logging on the agent's behalf. Out-of-band recording is
anticipated by the standard rather than bolted onto it.

**What tamper-evident does and does not mean here.** Each record carries the SHA-256 of its
predecessor's canonical form, so altering or removing any record breaks every hash after it
and the break is detectable. That is integrity, not immutability: someone who can rewrite
the whole file can recompute the whole chain. Detecting *that* requires anchoring the head
hash somewhere the writer does not control - a WORM bucket, a countersigning service, a
transparency log. `chain_head()` exists to be anchored; anchoring it is the deployment's
job, and this module does not pretend to do it.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentnorm.trace import Run, ToolCall

SPEC = "draft-sharif-agent-audit-trail-00"

# Action types from the draft's controlled vocabulary.
ACTION_TYPES = frozenset(
    {"tool_call", "tool_response", "decision", "delegation", "escalation", "error", "lifecycle"}
)
OUTCOMES = frozenset({"success", "failure", "timeout", "denied", "escalated"})


def canonical(record: dict[str, Any]) -> str:
    """JSON Canonicalization Scheme (RFC 8785), to the extent audit records need it.

    JCS exists so two parties hashing the same record agree on the bytes. Records here
    contain only strings, integers, booleans, nulls and nested objects and arrays of
    those - so sorted keys, no insignificant whitespace, and UTF-8 without ASCII escaping
    is exactly JCS for this domain.

    Floats are deliberately excluded rather than approximated: JCS mandates a specific
    shortest-round-trip float serialisation, and getting that subtly wrong would produce
    hashes that verify locally and fail against another implementation - the worst
    possible failure mode for evidence.
    """
    _reject_floats(record)
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _reject_floats(value: Any, path: str = "") -> None:
    if isinstance(value, float):
        raise TypeError(
            f"float at {path or 'root'}: audit records must not contain floats, because "
            "canonical float serialisation differs between implementations and would "
            "break cross-verification. Encode as a string or an integer."
        )
    if isinstance(value, dict):
        for k, v in value.items():
            _reject_floats(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _reject_floats(v, f"{path}[{i}]")


def digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()


@dataclass
class AuditChain:
    """Builds a hash-linked sequence of Agent Audit Trail records."""

    recording_component: str = f"agentnorm/{SPEC}"
    records: list[dict[str, Any]] = field(default_factory=list)
    _prev_hash: str | None = None
    _prev_id: str | None = None

    def append(
        self,
        *,
        agent_id: str,
        agent_version: str,
        session_id: str,
        action_type: str,
        action_detail: dict[str, Any],
        outcome: str,
        trust_level: str = "L2",
        record_phase: str = "post_execution",
        principal: str | None = None,
        human_override: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        if action_type not in ACTION_TYPES:
            raise ValueError(f"action_type {action_type!r} not in {sorted(ACTION_TYPES)}")
        if outcome not in OUTCOMES:
            raise ValueError(f"outcome {outcome!r} not in {sorted(OUTCOMES)}")

        ts = (timestamp or datetime.now(timezone.utc)).astimezone(timezone.utc)
        record: dict[str, Any] = {
            "record_id": str(uuid.uuid4()),
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "agent_id": agent_id,
            "agent_version": agent_version,
            "session_id": session_id,
            "action_type": action_type,
            "action_detail": action_detail,
            "outcome": outcome,
            "trust_level": trust_level,
            "record_phase": record_phase,
            "parent_record_id": self._prev_id,
            "prev_hash": self._prev_hash,
            "recording_component": self.recording_component,
        }
        # "under whose authority" - the regulator's question. Carried on every record
        # rather than inferred from a session lookup that may not survive retention.
        if principal:
            record["principal"] = principal
        if human_override:
            record["human_override"] = human_override

        self.records.append(record)
        self._prev_id = record["record_id"]
        self._prev_hash = digest(record)
        return record

    def chain_head(self) -> str | None:
        """Hash of the latest record. Anchor this externally to detect wholesale rewrites."""
        return self._prev_hash

    def delegate(
        self,
        *,
        agent_id: str,
        agent_version: str,
        session_id: str,
        delegate_agent_id: str,
        task_description: str,
        delegate_trust_level: str = "L2",
        constraints: list[str] | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        """Record an agent handing work to another agent.

        This is the record that makes a multi-agent chain reconstructable. Without it an
        action is traceable to a system but not to a decision: four agents across two
        protocols, none of which logged who asked whom to do what.

        The task is recorded as a hash rather than as text, so the chain proves what was
        delegated without the audit log becoming a copy of every prompt.
        """
        return self.append(
            agent_id=agent_id,
            agent_version=agent_version,
            session_id=session_id,
            action_type="delegation",
            action_detail={
                "delegate_agent_id": delegate_agent_id,
                "delegate_trust_level": delegate_trust_level,
                "task_description_hash": hashlib.sha256(
                    task_description.encode("utf-8")
                ).hexdigest(),
                "constraints": constraints or [],
            },
            outcome="success",
            principal=principal,
        )


def _call_detail(call: ToolCall) -> dict[str, Any]:
    return {
        "tool_name": call.tool,
        "step": call.step,
        "arguments": {k: _scalar(v) for k, v in call.args.items()},
        "resource": call.resource,
        "scope": call.scope,
        "duration_ms": call.duration_ms,
        "result_size": call.result_size,
    }


def _scalar(value: Any) -> Any:
    """Audit values are strings, ints, bools or null - floats break canonicalisation."""
    if isinstance(value, bool) or isinstance(value, int) or value is None:
        return value
    if isinstance(value, str):
        return value[:2000]
    return str(value)[:2000]


def record_run(chain: AuditChain, run: Run, *, trust_level: str = "L2") -> list[dict[str, Any]]:
    """Emit an audit record per tool call in a run, plus lifecycle bookends."""
    out = [
        chain.append(
            agent_id=f"urn:agent:{run.agent}",
            agent_version=run.version,
            session_id=run.run_id,
            action_type="lifecycle",
            action_detail={"event": "run_started", "actor_kind": run.actor_kind},
            outcome="success",
            trust_level=trust_level,
            record_phase="pre_execution",
            principal=run.principal or None,
            timestamp=run.started_at,
        )
    ]
    for call in run.calls:
        out.append(
            chain.append(
                agent_id=f"urn:agent:{run.agent}",
                agent_version=run.version,
                session_id=run.run_id,
                action_type="tool_call",
                action_detail=_call_detail(call),
                outcome="success" if call.ok else "failure",
                trust_level=trust_level,
                principal=run.principal or None,
                timestamp=call.started_at,
            )
        )
    out.append(
        chain.append(
            agent_id=f"urn:agent:{run.agent}",
            agent_version=run.version,
            session_id=run.run_id,
            action_type="lifecycle",
            action_detail={"event": "run_finished", "calls": run.n_calls},
            outcome="success",
            trust_level=trust_level,
            principal=run.principal or None,
        )
    )
    return out


@dataclass
class VerificationResult:
    ok: bool
    records: int
    first_broken_index: int | None = None
    reason: str = ""

    def __str__(self) -> str:
        if self.ok:
            return f"chain intact: {self.records} records verified"
        return f"chain BROKEN at record {self.first_broken_index}: {self.reason}"


def verify_chain(records: Iterable[dict[str, Any]]) -> VerificationResult:
    """Recompute the chain and report the first record that does not agree.

    Reporting *where* the chain breaks matters more than a boolean: the break points at
    the earliest record that was altered or removed, which is the first thing an
    investigator needs.
    """
    prev_hash: str | None = None
    prev_id: str | None = None
    count = 0

    for i, record in enumerate(records):
        count += 1
        if record.get("prev_hash") != prev_hash:
            return VerificationResult(
                False, count, i,
                f"prev_hash mismatch (expected {prev_hash!r}, found {record.get('prev_hash')!r})",
            )
        if record.get("parent_record_id") != prev_id:
            return VerificationResult(
                False, count, i, "parent_record_id does not match the preceding record"
            )
        try:
            prev_hash = digest(record)
        except TypeError as exc:
            return VerificationResult(False, count, i, str(exc))
        prev_id = record.get("record_id")

    return VerificationResult(True, count)


class AuditLog:
    """Append-only audit log on disk, one JSON record per line."""

    def __init__(self, path: str | Path, recording_component: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.chain = AuditChain(
            recording_component=recording_component or f"agentnorm/{SPEC}"
        )
        # Resume an existing chain so restarts do not silently start a second one, which
        # would verify cleanly on its own and hide the discontinuity.
        existing = list(self.read())
        if existing:
            self.chain.records = existing
            self.chain._prev_id = existing[-1].get("record_id")
            self.chain._prev_hash = digest(existing[-1])

    def write_run(self, run: Run, *, trust_level: str = "L2") -> int:
        records = record_run(self.chain, run, trust_level=trust_level)
        with self.path.open("a", encoding="utf-8") as fh:
            for record in records:
                fh.write(canonical(record) + "\n")
        return len(records)

    def read(self) -> Iterator[dict[str, Any]]:
        if not self.path.is_file():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify(self) -> VerificationResult:
        return verify_chain(self.read())

    def chain_head(self) -> str | None:
        return self.chain.chain_head()
