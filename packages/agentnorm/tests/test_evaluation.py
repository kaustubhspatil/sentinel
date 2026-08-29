"""Tests for the evaluation and sensitivity tooling."""
from __future__ import annotations

import random

import pytest

from agentnorm import Run, RunRecorder
from agentnorm.evaluation import evaluate, sensitivity


def _run(agent="triage", version="v1", principal="acme", tools=None, sizes=None,
         scopes=None, label="", anomalous=-1) -> Run:
    rec = RunRecorder(agent=agent, version=version, principal=principal)
    tools = tools or ["list", "search"]
    sizes = sizes or [1, 12]
    scopes = scopes or [principal] * len(tools)
    for tool, size, scope in zip(tools, sizes, scopes, strict=True):
        with rec.tool_call(tool, {}, scope=scope) as call:
            call.result_size = size
    run = rec.finish()
    run.label, run.is_anomalous = label, anomalous
    return run


def benign(n=300, seed=5) -> list[Run]:
    rng = random.Random(seed)
    return [
        _run(sizes=[1, max(1, int(rng.lognormvariate(0, 0.7) * 12))],
             label="benign", anomalous=0)
        for _ in range(n)
    ]


def anomalies(n=30) -> list[Run]:
    out = []
    for _ in range(n):
        out.append(_run(sizes=[1, 90_000], label="volume", anomalous=1))
        out.append(_run(scopes=["acme", "globex"], label="scope", anomalous=1))
        out.append(_run(tools=["list", "exfiltrate"], label="novel_tool", anomalous=1))
    return out


def test_evaluate_reports_per_family_not_just_an_aggregate():
    m = evaluate(benign(), anomalies())
    assert set(m.by_family) == {"volume", "scope", "novel_tool"}
    assert 0.0 <= m.recall <= 1.0
    assert m.test_benign_runs > 0


def test_evaluate_holds_out_the_test_set():
    """The benign runs scored must not be the ones the threshold was set on."""
    m = evaluate(benign(n=200), anomalies(n=5))
    assert m.fit_runs + m.test_benign_runs == 200


def test_evaluate_rejects_missing_labels():
    with pytest.raises(ValueError):
        evaluate([], anomalies())


def test_sensitivity_sweeps_each_parameter():
    report = sensitivity(benign(n=200), anomalies(n=10),
                         prior_strengths=(1.0, 8.0, 64.0),
                         budgets=(0.01, 0.05),
                         calibration_fractions=(0.25,),
                         seeds=(11, 23))
    assert set(report["sweeps"]) == {"prior_strength", "budget", "calibration_fraction"}
    assert set(report["sweeps"]["prior_strength"]) == {"1.0", "8.0", "64.0"}
    for param in report["sweeps"]:
        assert "load_bearing" in report["verdict"][param]


def test_sensitivity_compares_against_seed_noise():
    """A spread smaller than seed-to-seed variation is not sensitivity to the parameter."""
    report = sensitivity(benign(n=200), anomalies(n=10),
                         prior_strengths=(8.0,), budgets=(0.01,),
                         calibration_fractions=(0.25,), seeds=(11, 23, 37))
    assert report["verdict"]["prior_strength"]["load_bearing"] is False
    assert report["verdict"]["seed_noise_in_recall"] >= 0.0
