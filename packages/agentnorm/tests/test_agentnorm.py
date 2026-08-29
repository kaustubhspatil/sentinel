"""Tests for agentnorm.

The cold-start tests are the important ones. They encode a failure measured on a real
deployment: a suite fitted on one population alerted on 100% of known-benign runs from an
agent it had not seen, purely because every tool looked novel. Without these tests that
regression is invisible — every other metric looked healthy while the detector was
useless.
"""
from __future__ import annotations

import math
import random

import pytest

from agentnorm import Monitor, Run, RunRecorder
from agentnorm.detectors import DetectorSuite


def make_run(agent="triage", version="v1", principal="acme", tools=None, sizes=None,
             scopes=None) -> Run:
    rec = RunRecorder(agent=agent, version=version, principal=principal)
    tools = tools or ["list", "search", "summarise"]
    sizes = sizes or [1, 20, 5]
    scopes = scopes or [principal] * len(tools)
    for tool, size, scope in zip(tools, sizes, scopes, strict=True):
        with rec.tool_call(tool, {"x": 1}, scope=scope) as call:
            call.result_size = size
    return rec.finish()


def benign_population(n=200, seed=3) -> list[Run]:
    rng = random.Random(seed)
    runs = []
    for _ in range(n):
        k = rng.randint(2, 4)
        tools = rng.choices(["list", "search", "summarise", "fetch"], k=k)
        sizes = [max(1, int(rng.lognormvariate(0, 0.8) * 15)) for _ in tools]
        runs.append(make_run(tools=tools, sizes=sizes))
    return runs


# --- recording -------------------------------------------------------------------

def test_recorder_captures_order_and_timing():
    rec = RunRecorder(agent="a", version="v1")
    with rec.tool_call("first") as c:
        c.result_size = 3
    with rec.tool_call("second") as c:
        c.result_size = 7
    run = rec.finish()
    assert run.tools == ["first", "second"]
    assert [c.step for c in run.calls] == [1, 2]
    assert all(c.duration_ms >= 0 for c in run.calls)


def test_failed_calls_are_recorded_then_reraised():
    rec = RunRecorder(agent="a")
    with pytest.raises(ValueError):  # noqa: PT012
        with rec.tool_call("boom"):
            raise ValueError("nope")
    run = rec.finish()
    assert run.n_calls == 1, "a failed call must still appear in the trace"
    assert run.calls[0].ok is False
    assert "ValueError" in run.calls[0].error


def test_run_key_separates_versions():
    assert make_run(version="v1").key != make_run(version="v2").key


# --- cold start ------------------------------------------------------------------

def test_unseen_agent_does_not_alert_on_every_tool():
    """The regression that made the suite useless: novel_tool firing on 100% of runs."""
    monitor = Monitor.fit(benign_population())
    stranger = make_run(agent="brand-new-agent", version="v9")
    verdict = monitor.score(stranger)
    assert verdict.cold_start is True
    assert not any(a.detector == "novel_tool" for a in verdict.alerts)


def test_rate_is_suppressed_not_guessed_for_unseen_agent():
    """Run length is not comparable across agents, so an unseen agent gets no rate score."""
    monitor = Monitor.fit(benign_population())
    verdict = monitor.score(make_run(agent="stranger", version="v1"))
    assert math.isnan(verdict.scores["rate"])
    assert "rate" in verdict.uncalibrated
    assert not any(a.detector == "rate" for a in verdict.alerts)


def test_genuinely_novel_tool_still_detected_for_known_agent():
    """Cold-start tolerance must not blunt detection for an agent we do know."""
    monitor = Monitor.fit(benign_population())
    run = make_run(tools=["list", "exfiltrate_everything"], sizes=[1, 5],
                   scopes=["acme", "acme"])
    verdict = monitor.score(run)
    assert verdict.scores["novel_tool"] >= 1.0


# --- detection -------------------------------------------------------------------

def test_scope_violation_needs_no_history():
    """An assertion, not a statistic: it must fire on the first run it ever sees."""
    suite = DetectorSuite.fit([])
    run = make_run(principal="acme", scopes=["acme", "globex", "acme"])
    assert suite.score(run)["scope"].value == 1.0


def test_scope_clean_when_all_calls_in_principal():
    suite = DetectorSuite.fit([])
    assert suite.score(make_run(principal="acme"))["scope"].value == 0.0


def test_volume_anomaly_detected():
    monitor = Monitor.fit(benign_population())
    huge = make_run(tools=["search"], sizes=[500_000], scopes=["acme"])
    assert any(a.detector == "volume" for a in monitor.score(huge).alerts)


def test_benign_run_is_not_flagged():
    population = benign_population()
    monitor = Monitor.fit(population)
    flagged = sum(1 for r in population[-40:] if monitor.score(r).flagged)
    assert flagged <= 4, f"{flagged}/40 benign runs flagged - false positive rate too high"


# --- calibration honesty ---------------------------------------------------------

def test_thin_calibration_set_warns_rather_than_lying():
    """A 0.2% quantile cannot be estimated from a handful of runs; say so."""
    monitor = Monitor.fit(benign_population(n=8))
    assert monitor.warnings, "expected a calibration warning for a tiny fit set"
    assert "quantile" in monitor.warnings[0]


def test_budget_is_split_across_detectors():
    """Five detectors at the suite budget each would union to five times the budget."""
    monitor = Monitor.fit(benign_population(), budget=0.05)
    assert monitor.budget == 0.05
    # thresholds exist for every detector that produced finite scores
    assert set(monitor.thresholds) == set(DetectorSuite.NAMES)


def test_verdict_explains_itself():
    monitor = Monitor.fit(benign_population())
    verdict = monitor.score(make_run(tools=["search"], sizes=[500_000], scopes=["acme"]))
    assert "volume" in verdict.explain()


def test_empty_fit_is_rejected():
    with pytest.raises(ValueError):
        Monitor.fit([])


# --- learned scope ownership -----------------------------------------------------

def opaque_run(principal: str, scopes: list[str]) -> Run:
    """Scopes are opaque ids (a VPC, a workspace) - never a copy of the principal name."""
    return make_run(principal=principal, tools=["list"] * len(scopes),
                    sizes=[5] * len(scopes), scopes=scopes)


def test_scope_ownership_is_learned_not_assumed():
    """The regression found by deploying against a real estate.

    Scopes were network-zone ids, so a direct principal==scope comparison marked every
    benign call a violation. The threshold calibrated away and the detector then caught
    none of 40 genuine escalations.
    """
    history = (
        [opaque_run("acme", ["vpc-1", "vpc-1"]) for _ in range(30)]
        + [opaque_run("globex", ["vpc-2", "vpc-2"]) for _ in range(30)]
    )
    suite = DetectorSuite.fit(history)

    assert suite.score(opaque_run("acme", ["vpc-1"]))["scope"].value == 0.0, \
        "an opaque scope owned by this principal is not a violation"
    assert suite.score(opaque_run("acme", ["vpc-2"]))["scope"].value == 1.0, \
        "reaching into another principal's scope is a violation"


def test_unknown_scope_falls_back_to_direct_comparison():
    suite = DetectorSuite.fit([opaque_run("acme", ["vpc-1"]) for _ in range(5)])
    assert suite.score(opaque_run("acme", ["never-seen"]))["scope"].value == 1.0


# --- sequence suppression --------------------------------------------------------

def test_sequence_is_suppressed_for_an_unseen_agent():
    """Transition structure is agent-specific; pooling it alerted on 100% of benign runs."""
    suite = DetectorSuite.fit(benign_population())
    score = suite.score(make_run(agent="stranger", version="v1"))["sequence"]
    assert score.suppressed
    assert score.calibrated is False


def test_sequence_still_scores_a_known_agent():
    suite = DetectorSuite.fit(benign_population())
    score = suite.score(make_run())["sequence"]
    assert not score.suppressed


def test_run_id_available_before_finish():
    """Callers need the id mid-run, to correlate model calls and log lines with it."""
    rec = RunRecorder("a", version="v1")
    assert rec.run_id
    with rec.tool_call("t") as c:
        c.result_size = 1
    assert rec.finish().run_id == rec.run_id
