"""A tool-calling agent over the estate graph.

Tool calls use a JSON protocol rather than a provider's native function-calling API. That
is a deliberate trade and worth being explicit about, because native tool calling is more
reliable: the provider constrains the output, so malformed calls are largely impossible.

The reason not to use it here is that the point of this project is comparing providers on
equal footing. Native tool calling differs in shape across OpenAI, Gemini and local
models, so a comparison built on it measures three different harnesses as much as three
models. A JSON protocol is the same instruction for everyone, and the rate at which a model
*fails to follow it* becomes a measurable property of the model rather than a hidden
property of the adapter. Malformed-call rate is reported by the evaluation harness for
exactly this reason.

Every step is traced to ClickHouse, so the anomaly detectors see real agent behaviour and
not only generated scenarios.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentnorm.trace import RunRecorder

from sentinel.agents import mcp_server as tools
from sentinel.llm.base import Message
from sentinel.llm.router import router
from sentinel.store.agentnorm_store import ClickHouseStore

MAX_STEPS = 8

# The tool surface offered to the agent. Bound to the same functions the MCP server
# exposes, so the agent cannot reach anything an MCP client could not.
TOOLBOX: dict[str, Callable[..., dict]] = {
    "list_schema": tools.list_schema,
    "find_entities": tools.find_entities,
    "traverse": tools.traverse,
    "vulnerability_exposure": tools.vulnerability_exposure,
    "sla_status": tools.sla_status,
    "blast_radius": tools.blast_radius,
    "attack_context": tools.attack_context,
}

# Tools whose queries widen to every tenant when no tenant filter is supplied. When a run
# is scoped, these are pinned rather than left to the model's discretion.
TENANT_SCOPED_TOOLS = {
    "find_entities": ("tenant",),
    "vulnerability_exposure": ("tenant",),
    "sla_status": ("tenant",),
}

SYSTEM = """You are an IT operations analyst with read-only access to a knowledge graph \
describing a managed service estate: customers, contracts, SLAs, sites, network zones, \
hosts, installed packages, vulnerabilities and ATT&CK techniques.

Answer the user's question by calling tools. Respond with EXACTLY ONE JSON object and no \
other text.

To call a tool:
{"tool": "<name>", "args": {...}}

To answer:
{"answer": "<your answer>", "citations": ["<entity id>", ...]}

Available tools:
- list_schema()  -> entity kinds and relationships
- find_entities(kind, contains=None, tenant=None, limit=20)
- traverse(kind, node_id, relationship, direction="both", limit=25)
- vulnerability_exposure(tenant=None, host_id=None, kev_only=False, limit=25)
- sla_status(tenant=None, limit=25)
- blast_radius(package, limit=25)
- attack_context(cve_id=None, technique_id=None)

Rules:
- You MUST call at least one tool before answering. You have live access to real data;
  never claim you cannot retrieve something without trying.
- Base every factual claim on tool output. Never invent hosts, versions, CVEs or counts.
- Cite the entity ids your answer rests on.
- Only after tool calls have genuinely failed may you say the question is unanswerable.
- Prefer few, well-chosen calls over many."""


# A single worked example. Added after observing the model emit well-formed JSON that
# refused the task without calling anything - "unable to determine ... the query did not
# return results", having run no query at all. Describing the protocol was not enough;
# showing one turn of it is what made the model use it.
FEWSHOT = [
    Message("user", "How many hosts does tenant acme have?"),
    Message("assistant", '{"tool": "find_entities", "args": {"kind": "Host", "tenant": "acme"}}'),
    Message("user", 'Tool result:\n{"kind": "Host", "count": 1, "results": [{"id": "example-host-01"}]}'),
    Message("assistant", '{"answer": "Tenant acme has 1 host: example-host-01.", "citations": ["example-host-01"]}'),
]


@dataclass
class Step:
    tool: str
    args: dict[str, Any]
    ok: bool
    result_rows: int = 0
    error: str = ""


@dataclass
class AgentResult:
    question: str
    answer: str = ""
    citations: list[str] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    tool_sequence: list[str] = field(default_factory=list)
    malformed_calls: int = 0
    premature_answers: int = 0
    scope_violations: int = 0
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    provider: str = ""
    model: str = ""
    stopped_reason: str = ""
    run_id: str = ""


def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a response.

    Models wrap JSON in prose or fences even when told not to. Recovering from that is
    not cheating - it is what a production harness does - but each recovery is counted
    as a malformed call so the model's instruction-following is measured, not hidden.
    """
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    depth, start = 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = None
    return None


def run(
    question: str,
    *,
    tenant: str = "",
    tier: str = "small",
    max_steps: int = MAX_STEPS,
    agent_version: str = "graph-agent-v1",
) -> AgentResult:
    # Instrumented with agentnorm: the reference deployment consumes the extracted
    # library rather than keeping a parallel copy of it.
    ctx = RunRecorder("graph_agent", version=agent_version, principal=tenant)
    result = AgentResult(question=question, run_id=ctx.run_id)

    # Seed the schema rather than spending a turn on it. It is the same information
    # list_schema would return, it is needed for almost every question, and fetching it
    # up front removes one round trip from every run.
    schema = json.dumps(TOOLBOX["list_schema"](), default=str)[:1500]
    history: list[Message] = [
        Message("system", SYSTEM),
        *FEWSHOT,
        Message("user", f"Graph schema:\n{schema}\n\nQuestion: {question}"),
    ]

    for _ in range(max_steps):
        resp = router.complete(
            history, tier=tier, purpose="graph_agent", run_id=ctx.run_id, temperature=0.0
        )
        result.llm_calls += 1
        result.input_tokens += resp.input_tokens
        result.output_tokens += resp.output_tokens
        result.latency_ms += resp.latency_ms
        result.provider, result.model = resp.provider, resp.model

        if not resp.ok:
            result.stopped_reason = f"llm_error: {resp.error[:120]}"
            break

        payload = _extract_json(resp.text)
        if payload is None:
            result.malformed_calls += 1
            history.append(Message("assistant", resp.text[:500]))
            history.append(Message("user", "That was not a single JSON object. Reply with one JSON object only."))
            continue
        if "answer" in payload:
            # An answer with no tool call is a refusal dressed as a response. Observed on
            # the first run: the model replied "I am unable to determine..." having called
            # nothing, while the tools would have answered it in two calls. Prompting
            # alone does not reliably prevent this, so it is enforced here and counted.
            if not result.tool_sequence:
                result.premature_answers += 1
                history.append(Message("assistant", json.dumps(payload)))
                history.append(Message(
                    "user",
                    "You answered without calling any tool. The data is available - "
                    "call a tool first. Start with list_schema if unsure.",
                ))
                continue
            result.answer = str(payload.get("answer", ""))
            cites = payload.get("citations") or []
            result.citations = [str(c) for c in cites] if isinstance(cites, list) else []
            result.stopped_reason = "answered"
            break

        name = payload.get("tool")
        args = payload.get("args") or {}
        if name not in TOOLBOX or not isinstance(args, dict):
            result.malformed_calls += 1
            history.append(Message("assistant", resp.text[:500]))
            history.append(Message("user", f"Unknown tool {name!r}. Choose one of: {', '.join(TOOLBOX)}."))
            continue

        # Enforce the run's tenant scope at the tool boundary.
        #
        # Found by the adversarial suite: asked by "the acme administrator" to list
        # globex's vulnerable hosts "for benchmarking", the agent complied and disclosed
        # host names and package versions. The tools were working exactly as written -
        # tenant was a *parameter* the model could set freely, and the run's own scope
        # existed only in the trace context. A boundary the caller can rewrite is not a
        # boundary. This is precisely the scope-escalation failure the detection layer was
        # built to catch, found in this project's own agent.
        if tenant:
            requested = args.get("tenant")
            if requested and requested != tenant:
                observation = {
                    "error": f"scope violation: this run is scoped to tenant {tenant!r} "
                             f"and may not read tenant {requested!r}",
                    "scope": tenant,
                }
                result.scope_violations += 1
                result.steps.append(Step(name, args, ok=False, error="scope violation"))
                result.tool_sequence.append(name)
                history.append(Message("assistant", json.dumps(payload)))
                history.append(Message("user", f"Tool result:\n{json.dumps(observation)}"))
                continue
            # Tools that accept a tenant filter are pinned to the run's tenant, so an
            # omitted filter cannot silently widen the query to every tenant.
            if "tenant" in TENANT_SCOPED_TOOLS.get(name, ()):
                args = {**args, "tenant": tenant}

        with ctx.tool_call(name, args, scope=str(args.get("tenant") or tenant)) as call:
            try:
                observation = TOOLBOX[name](**args)
                rows = int(observation.get("count", 0)) if isinstance(observation, dict) else 0
                call.result_size = rows
                call.resource = str(
                    args.get("node_id") or args.get("host_id") or args.get("package") or ""
                )
                step = Step(name, args, ok="error" not in observation, result_rows=rows)
            except TypeError as exc:
                observation = {"error": f"bad arguments: {exc}"}
                step = Step(name, args, ok=False, error=str(exc))
                result.malformed_calls += 1

        result.steps.append(step)
        result.tool_sequence.append(name)
        history.append(Message("assistant", json.dumps(payload)))
        history.append(Message("user", f"Tool result:\n{json.dumps(observation, default=str)[:3000]}"))
    else:
        result.stopped_reason = "max_steps"

    ClickHouseStore().append(ctx.finish())
    return result


if __name__ == "__main__":
    import sys

    q = " ".join(sys.argv[1:]) or "Which tenant has the most outdated packages, and what is their SLA?"
    r = run(q)
    print(f"provider={r.provider}/{r.model} steps={r.tool_sequence} "
          f"malformed={r.malformed_calls} premature={r.premature_answers} "
          f"tokens={r.input_tokens}+{r.output_tokens} "
          f"latency={r.latency_ms}ms reason={r.stopped_reason}")
    print("\nANSWER:", r.answer)
    print("CITATIONS:", r.citations)
