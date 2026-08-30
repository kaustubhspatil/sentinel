"""Tests for OpenAPI to MCP connector generation.

The scope-derivation tests matter most. A missing keyword does not raise - it silently
classifies an operation as unscoped, which under-reports what monitoring can see. That
failure mode is the reason the generator reports its own gaps.
"""
from __future__ import annotations

import pytest

from sentinel.connectors.openapi import (
    analyse,
    group,
    monitoring_policy,
    parse,
    tool_definitions,
)


def spec(paths):
    return {"info": {"title": "test"}, "paths": paths}


def op(method="get", tags=("things",), summary="does a thing", op_id=None):
    return {method: {"operationId": op_id or f"{method}_thing", "tags": list(tags),
                     "summary": summary}}


# --- semantics derived from the spec ---------------------------------------------

@pytest.mark.parametrize("method,writes,destructive", [
    ("get", False, False), ("head", False, False),
    ("post", True, False), ("put", True, False), ("patch", True, False),
    ("delete", True, True),
])
def test_method_determines_read_write_destructive(method, writes, destructive):
    o = parse(spec({"/things": op(method)}))[0]
    assert o.writes is writes
    assert o.destructive is destructive
    assert o.reads is (not writes)


def test_risk_ranks_destructive_above_write_above_read():
    ops = parse(spec({
        "/things": op("get", op_id="read"),
        "/stuff": op("post", op_id="write"),
        "/items/{id}": op("delete", op_id="destroy"),
    }))
    risk = {o.operation_id: o.risk for o in ops}
    assert risk == {"read": "low", "write": "medium", "destroy": "high"}


def test_credential_paths_are_sensitive_regardless_of_method():
    o = parse(spec({"/user/tokens": op("get", op_id="list_tokens")}))[0]
    assert o.sensitive
    assert o.risk == "medium", "a read of credentials is not low risk"


def test_sensitive_write_is_high_risk():
    o = parse(spec({"/user/keys": op("post", op_id="add_key")}))[0]
    assert o.risk == "high"


# --- scope derivation -------------------------------------------------------------

def test_owner_parameters_are_scope_but_item_ids_are_not():
    o = parse(spec({"/repos/{owner}/{repo}/issues/{issue_number}": op()}))[0]
    assert set(o.scope_params) == {"owner", "repo"}
    assert "issue_number" not in o.scope_params, "an item id says which, not whose"


def test_enterprise_is_recognised_as_scope():
    """The regression: the first version omitted this and under-reported silently."""
    o = parse(spec({"/enterprises/{enterprise}/teams/{team_slug}": op("delete")}))[0]
    assert "enterprise" in o.scope_params


def test_genuinely_unscopable_paths_report_no_scope():
    o = parse(spec({"/gists/{gist_id}": op("delete")}))[0]
    assert o.scope_params == (), "nothing in this request says whose gist it is"


def test_resource_is_the_first_concrete_segment():
    assert parse(spec({"/repos/{owner}/{repo}": op()}))[0].resource == "repos"
    assert parse(spec({"/{version}/users": op()}))[0].resource == "users"


# --- grouping ---------------------------------------------------------------------

def test_grouping_bounds_the_tool_count():
    paths = {f"/r{i}": op("get", tags=(f"tag{i}",), op_id=f"o{i}") for i in range(200)}
    caps = group(parse(spec(paths)), max_tools=10)
    assert len(caps) <= 10
    assert sum(len(c.operations) for c in caps) == 200, "no operation may be dropped"


def test_long_tail_is_merged_not_discarded():
    paths = {f"/r{i}": op("get", tags=(f"tag{i}",), op_id=f"o{i}") for i in range(30)}
    caps = group(parse(spec(paths)), max_tools=5)
    assert caps[-1].name == "other"
    assert sum(len(c.operations) for c in caps) == 30


def test_capability_risk_is_the_worst_of_its_operations():
    paths = {"/a": op("get", op_id="a"), "/b/{id}": op("delete", op_id="b")}
    caps = group(parse(spec(paths)))
    assert caps[0].risk == "high"


def test_tool_description_names_operations_and_risk():
    caps = group(parse(spec({"/a": op("get", op_id="list_a")})))
    d = tool_definitions(caps)[0]
    assert "list_a" in d["description"]
    assert d["inputSchema"]["required"] == ["operation_id"]


# --- the monitoring policy the generator hands to agentnorm -----------------------

def test_policy_derives_scope_parameters_and_destructive_set():
    ops = parse(spec({
        "/repos/{owner}/{repo}": op("delete", op_id="delete_repo"),
        "/repos/{owner}/{repo}/issues": op("get", op_id="list_issues"),
    }))
    policy = monitoring_policy(ops)
    assert set(policy["scope_parameters"]) == {"owner", "repo"}
    assert policy["destructive_operations"] == ["delete_repo"]
    assert policy["risk_by_operation"]["list_issues"] == "low"


def test_report_counts_operations_monitoring_cannot_scope():
    _, report = analyse(spec({
        "/repos/{owner}/{repo}": op("delete", op_id="scoped_write"),
        "/gists/{gist_id}": op("delete", op_id="unscoped_write"),
    }))
    assert report.unscoped_write_operations == 1
    assert report.scoped_operations == 1
