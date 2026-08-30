"""Generate MCP tools from an OpenAPI specification.

Two things make this more than code generation.

**A spec has more operations than an agent can choose between.** GitHub's REST API is 1,222
operations. Exposing those as 1,222 MCP tools does not produce a capable agent; it produces
one that cannot reliably pick a tool, and a context window mostly full of tool definitions.
So the generator groups operations into a small number of capability-level tools and lets
the agent name the operation it wants as an argument. The tool count becomes a property of
the *domain* rather than of the endpoint count.

**A spec knows what each operation means, and generators throw that away.** The method, the
path, the presence of a path parameter and the declared response codes together say whether
an operation reads or writes, whether it is destructive, and which resource it touches.
That is precisely the metadata behavioural monitoring otherwise asks a human to supply by
hand - `scope_of`, and a sense of which calls are dangerous. Deriving it from the spec means
a generated connector arrives already instrumented: the monitor knows a `DELETE /repos/{o}/{r}`
is a destructive write against resource `repos` without anyone writing that down.

The connector and the monitor are usually built by different people at different times. They
do not have to be.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

WRITE_METHODS = {"post", "put", "patch", "delete"}
DESTRUCTIVE_METHODS = {"delete"}

# Path segments that mark an operation as touching authorisation or credentials, whatever
# its HTTP method. These are worth flagging separately: a POST that creates a token is not
# the same kind of write as a POST that creates a comment.
SENSITIVE = re.compile(
    r"/(tokens?|keys?|secrets?|credentials?|permissions?|admin|billing|payments?|"
    r"members?|collaborators?|teams?)(/|$)",
    re.I,
)
PARAM = re.compile(r"\{([^}]+)\}")

# Path parameters that name an owner rather than an item. This list is a judgement call and
# the generator treats it as one: the first version omitted "enterprise", which silently
# classified every /enterprises/{enterprise}/... write as unscoped. That is the failure mode
# worth designing against - a missing keyword does not error, it quietly under-reports what
# monitoring can see. The generator therefore reports the operations it could not scope so a
# human reviews the gap rather than inheriting it.
SCOPE_KEYWORDS = (
    "owner", "org", "account", "tenant", "workspace", "customer", "user", "repo",
    "project", "enterprise", "installation", "client_id", "team", "group", "namespace",
)


@dataclass(frozen=True)
class Operation:
    """One endpoint, with the semantics the spec already implies."""

    operation_id: str
    method: str
    path: str
    summary: str
    capability: str          # the tag - the domain grouping the API's own authors chose
    resource: str            # the first concrete path segment: repos, issues, users
    reads: bool
    writes: bool
    destructive: bool
    sensitive: bool
    scope_params: tuple[str, ...]   # path params that identify *whose* data this is

    @property
    def risk(self) -> str:
        if self.destructive or (self.writes and self.sensitive):
            return "high"
        if self.writes or self.sensitive:
            return "medium"
        return "low"


def _resource(path: str) -> str:
    for segment in path.strip("/").split("/"):
        if segment and not segment.startswith("{"):
            return segment
    return "root"


def _scope_params(path: str) -> tuple[str, ...]:
    """Path parameters that identify an owner rather than an item.

    `/repos/{owner}/{repo}/issues/{issue_number}` is scoped to `owner` and `repo`; the
    issue number identifies *which* item, not *whose*. Getting this distinction right is
    what lets the monitor tell a cross-tenant read from an ordinary one.
    """
    params = PARAM.findall(path)
    owners = [p for p in params if any(k in p.lower() for k in SCOPE_KEYWORDS)]
    return tuple(owners)


def parse(spec: dict[str, Any]) -> list[Operation]:
    ops: list[Operation] = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head"}:
                continue
            if not isinstance(op, dict):
                continue
            m = method.lower()
            tags = op.get("tags") or ["untagged"]
            ops.append(Operation(
                operation_id=op.get("operationId") or f"{m}_{path}",
                method=m,
                path=path,
                summary=(op.get("summary") or "").strip(),
                capability=tags[0],
                resource=_resource(path),
                reads=m in {"get", "head"},
                writes=m in WRITE_METHODS,
                destructive=m in DESTRUCTIVE_METHODS,
                sensitive=bool(SENSITIVE.search(path)),
                scope_params=_scope_params(path),
            ))
    return ops


@dataclass
class Capability:
    """A group of operations exposed to the agent as one tool."""

    name: str
    operations: list[Operation] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if any(o.risk == "high" for o in self.operations):
            return "high"
        if any(o.risk == "medium" for o in self.operations):
            return "medium"
        return "low"

    def describe(self, limit: int = 12) -> str:
        """The tool description the agent actually sees.

        It lists the most useful operations rather than all of them, because the point of
        grouping is to keep the description short enough to reason over. Read operations
        come first: an agent exploring an unfamiliar API should meet the safe ones first.
        """
        ordered = sorted(self.operations, key=lambda o: (o.writes, o.destructive, o.operation_id))
        shown = ordered[:limit]
        lines = [f"  {o.operation_id} ({o.method.upper()} {o.path}) - {o.summary or 'no summary'}"
                 for o in shown]
        more = len(self.operations) - len(shown)
        if more:
            lines.append(f"  ... and {more} more; call list_operations(capability='{self.name}')")
        return "\n".join(lines)


def group(ops: list[Operation], max_tools: int = 40) -> list[Capability]:
    """Group operations by the API's own tags, merging the long tail.

    Using the spec's tags rather than clustering the text is deliberate: the API's authors
    already grouped these for human readers, and that grouping is better than anything
    inferred from endpoint names. The long tail is merged so the tool count stays bounded
    no matter how many tags a spec declares.
    """
    by_tag: dict[str, list[Operation]] = {}
    for op in ops:
        by_tag.setdefault(op.capability, []).append(op)

    ranked = sorted(by_tag.items(), key=lambda kv: -len(kv[1]))
    caps = [Capability(name, sorted(o, key=lambda x: x.operation_id))
            for name, o in ranked[: max_tools - 1]]

    tail = [op for name, o in ranked[max_tools - 1:] for op in o]
    if tail:
        caps.append(Capability("other", sorted(tail, key=lambda x: x.operation_id)))
    return caps


@dataclass
class ConnectorReport:
    title: str
    operations: int
    capabilities: int
    reduction: str
    risk_counts: dict[str, int]
    scoped_operations: int
    unscoped_write_operations: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def analyse(spec: dict[str, Any], max_tools: int = 40) -> tuple[list[Capability], ConnectorReport]:
    ops = parse(spec)
    caps = group(ops, max_tools=max_tools)
    risk: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    for o in ops:
        risk[o.risk] += 1
    scoped = sum(1 for o in ops if o.scope_params)
    # A write with no owner in its path is the interesting case: nothing in the request
    # says whose data it touches, so scope has to come from the credential instead.
    unscoped_writes = sum(1 for o in ops if o.writes and not o.scope_params)
    return caps, ConnectorReport(
        title=(spec.get("info") or {}).get("title", "unknown"),
        operations=len(ops),
        capabilities=len(caps),
        reduction=f"{len(ops)} -> {len(caps)} ({len(ops) / max(len(caps), 1):.0f}x fewer tools)",
        risk_counts=risk,
        scoped_operations=scoped,
        unscoped_write_operations=unscoped_writes,
    )


# --- generated artefacts ---------------------------------------------------------

def tool_definitions(caps: list[Capability]) -> list[dict[str, Any]]:
    """MCP-shaped tool definitions, one per capability."""
    out = []
    for cap in caps:
        out.append({
            "name": f"{cap.name.replace('-', '_')}",
            "description": (
                f"{cap.name} operations ({len(cap.operations)} available, "
                f"highest risk: {cap.risk}). Pick one by operation_id:\n"
                + cap.describe()
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation_id": {
                        "type": "string",
                        "description": "The operation to invoke, from the list above.",
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Path, query and body parameters for that operation.",
                    },
                },
                "required": ["operation_id"],
            },
            "_risk": cap.risk,
        })
    return out


def monitoring_policy(ops: list[Operation]) -> dict[str, Any]:
    """The hooks agentnorm would otherwise ask a human to write.

    `scope_of` needs to know which argument identifies whose data a call touched;
    risk classification needs to know which operations are destructive. Both are
    derivable from the spec, so a generated connector can arrive instrumented.
    """
    return {
        "scope_parameters": sorted({p for o in ops for p in o.scope_params}),
        "destructive_operations": sorted(o.operation_id for o in ops if o.destructive),
        "sensitive_operations": sorted(o.operation_id for o in ops if o.sensitive)[:200],
        "risk_by_operation": {o.operation_id: o.risk for o in ops},
        "note": (
            "scope_parameters is the argument list agentnorm's scope_of should read: if a "
            "call carries one of these and its value differs from the run's principal, that "
            "is a cross-principal access. Derived from the spec, not written by hand."
        ),
    }


if __name__ == "__main__":
    import sys

    path = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw/github-openapi.json")
    spec = json.loads(path.read_text(encoding="utf-8"))
    caps, report = analyse(spec)
    print(json.dumps(report.to_dict(), indent=2))
    print("\ntop capabilities:")
    for cap in caps[:8]:
        print(f"  {cap.name:22s} {len(cap.operations):4d} ops   risk={cap.risk}")
    policy = monitoring_policy(parse(spec))
    print(f"\nderived scope parameters: {policy['scope_parameters'][:10]}")
    print(f"destructive operations   : {len(policy['destructive_operations'])}")
