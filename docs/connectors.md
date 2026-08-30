# OpenAPI → MCP connector generation

Generating agent tools from an API specification, and keeping the semantics the
specification already contains.

## The scale problem, stated as a number

GitHub's REST API is **1,222 operations**. Exposing those as 1,222 MCP tools does not
produce a capable agent — it produces one that cannot reliably choose a tool, with a context
window mostly full of tool definitions.

The generator groups operations into capability-level tools, using the API's own tags. The
tags are better than anything clustered from endpoint names, because the API's authors
already grouped these for human readers.

```
GitHub v3 REST API
  operations        1222
  capabilities        40
  reduction         1222 -> 40  (31x fewer tools)
```

The agent picks a capability, then names the operation as an argument. **Tool count becomes a
property of the domain rather than of the endpoint count**, so a 5,000-operation spec exposes
the same 40 tools.

## The part most generators throw away

A specification already says what each operation *means*. The HTTP method says whether it
reads or writes. `DELETE` says destructive. The path says which resource. Path parameters
say whose data.

That is precisely the metadata behavioural monitoring otherwise asks a human to write by
hand — `agentnorm` normally requires you to supply a `scope_of` hook and decide which calls
are dangerous. Both are derivable:

```
risk classification    531 low · 427 medium · 264 high
scoped operations      1065 of 1222
destructive operations 187
scope parameters       owner, org, repo, enterprise, account_id, installation, ...
```

A generated connector can therefore arrive **already instrumented**. The monitor knows that
`DELETE /repos/{owner}/{repo}` is a destructive write against resource `repos`, scoped to
`owner` and `repo`, without anyone writing that down. The connector and the monitor are
usually built by different people at different times; they do not have to be.

## The output worth acting on

The most useful number the generator produces is the one it *cannot* classify:

```
unscoped write operations: 54   (of which 22 destructive or sensitive)
```

These are writes where **nothing in the request says whose data is affected**:

```
POST   /credentials/revoke
DELETE /gists/{gist_id}
DELETE /installation/token
DELETE /notifications/threads/{thread_id}
PUT    /user/codespaces/secrets/{secret_name}
```

A gist id identifies *which* gist, not *whose*. For these operations, scope-based monitoring
is structurally blind — authority has to come from the credential instead, which means
credential isolation is doing work that request inspection cannot check.

**Knowing which 54 endpoints those are is the actionable output.** It converts "our
monitoring might have gaps" into a reviewable list.

## A heuristic that failed quietly, and what it changed

The first version of the scope-parameter list omitted `enterprise`. Nothing errored. Every
`/enterprises/{enterprise}/...` write was silently classified as unscoped, inflating the
blind-spot count from 54 to 86.

That is the failure mode worth designing against: **a missing keyword does not raise, it
under-reports what monitoring can see.** So the generator treats its own scope list as a
judgement call and reports the operations it could not scope, so a human reviews the gap
rather than inheriting it.

## Using it

```bash
python -m sentinel.connectors.openapi data/raw/github-openapi.json
```

```python
from sentinel.connectors.openapi import analyse, monitoring_policy, parse, tool_definitions

caps, report = analyse(spec)          # capability grouping + counts
tools = tool_definitions(caps)        # MCP tool definitions
policy = monitoring_policy(parse(spec))   # scope params, destructive set, risk per operation
```

`policy["scope_parameters"]` is the argument list `agentnorm`'s `scope_of` should read: if a
call carries one of these and its value differs from the run's principal, that is a
cross-principal access — derived from the spec, not written by hand.

## Limits

- Capability grouping uses the spec's tags. A spec with no tags falls back to one bucket per
  first path segment, which is worse.
- Risk classification is derived from method and path, not from reading the descriptions. A
  `POST /search` is scored as a write because the method says so.
- The generator emits definitions and policy, not an executing client. Wiring authentication,
  pagination and retries per API remains real work.
