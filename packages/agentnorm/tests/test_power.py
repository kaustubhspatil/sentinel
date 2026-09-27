"""Detection power: planting anomalies into held out benign runs."""
from __future__ import annotations

import random
from dataclasses import dataclass

import pytest

from agentnorm import Monitor, Run, RunRecorder
from agentnorm.power import (
    ANY,
    PLANTED_SCOPE,
    PLANTED_TOOL,
    Burst,
    ExtraCalls,
    ForeignScope,
    InjectionContext,
    OversizedResult,
    UnseenTool,
    default_injectors,
    detection_power,
    measure_power,
)

SCOPES = {"acme": "vpc-1", "globex": "vpc-2"}


def _run(principal="acme", tools=("list", "search", "summarise"), sizes=(3, 20, 5)) -> Run:
    rec = RunRecorder(agent="triage", version="v1", principal=principal)
    for tool, size in zip(tools, sizes, strict=True):
        with rec.tool_call(tool, {"q": 1}, scope=SCOPES.get(principal, principal)) as c:
            c.result_size = size
    return rec.finish()


def population(n=900, seed=4) -> list[Run]:
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        tools = rng.choices(["list", "search", "summarise", "fetch"], k=rng.randint(2, 5))
        sizes = [max(1, int(rng.lognormvariate(0, 0.8) * 15)) for _ in tools]
        out.append(_run(rng.choice(["acme", "globex"]), tools, sizes))
    return out


CTX = InjectionContext.from_runs(population(50))


# --- injectors change exactly one thing ---------------------------------------------

def test_injectors_do_not_mutate_the_original():
    run = _run()
    before = [(c.tool, c.result_size, c.scope) for c in run.calls]
    for inj in default_injectors():
        planted = inj(run, random.Random(0), CTX)
        assert planted is not None and planted is not run
        assert planted.run_id != run.run_id
        assert planted.is_anomalous == 1 and planted.label == inj.name
    assert [(c.tool, c.result_size, c.scope) for c in run.calls] == before


def test_extra_calls_only_adds_copies_of_existing_calls():
    run = _run()
    planted = ExtraCalls(4)(run, random.Random(1), CTX)
    assert planted.n_calls == run.n_calls + 4
    assert set(planted.tools) <= set(run.tools)
    assert [c.step for c in planted.calls] == list(range(1, planted.n_calls + 1))


def test_unseen_tool_adds_one_call_to_a_tool_nobody_uses():
    planted = UnseenTool()(_run(), random.Random(1), CTX)
    assert planted.tools.count(PLANTED_TOOL) == 1
    assert PLANTED_TOOL not in CTX.tools
    # everything else about the call is normal, including its scope
    assert all(c.scope == "vpc-1" for c in planted.calls)


def test_unseen_tool_refuses_when_the_tool_is_not_unseen():
    ctx = InjectionContext(tools={PLANTED_TOOL})
    assert UnseenTool()(_run(), random.Random(0), ctx) is None


def test_foreign_scope_uses_another_principals_real_scope():
    run = _run("acme")
    planted = ForeignScope()(run, random.Random(2), CTX)
    changed = [c for c, o in zip(planted.calls, run.calls, strict=True) if c.scope != o.scope]
    assert len(changed) == 1 and changed[0].scope == "vpc-2"


def test_foreign_scope_falls_back_when_there_is_one_tenant():
    ctx = InjectionContext.from_runs([_run("acme")])
    planted = ForeignScope()(_run("acme"), random.Random(0), ctx)
    assert PLANTED_SCOPE in planted.scopes


def test_oversized_result_multiplies_one_size():
    run = _run(sizes=(3, 20, 5))
    planted = OversizedResult(1000)(run, random.Random(3), CTX)
    ratios = sorted(p.result_size / o.result_size for p, o in zip(planted.calls, run.calls, strict=True))
    assert ratios == [1.0, 1.0, 1000.0]


def test_burst_repeats_one_call_consecutively():
    run = _run()
    planted = Burst(6)(run, random.Random(5), CTX)
    assert planted.n_calls == run.n_calls + 6
    tools = planted.tools
    longest = max(sum(1 for _ in g) for _, g in __import__("itertools").groupby(tools))
    assert longest >= 7


def test_injectors_skip_empty_runs():
    empty = RunRecorder(agent="triage", version="v1", principal="acme").finish()
    for inj in default_injectors():
        assert inj(empty, random.Random(0), CTX) is None


# --- the report ---------------------------------------------------------------------

def test_power_report_has_every_detector_and_injector_with_intervals():
    monitor, report = measure_power(population(), budget=0.05, seed=1)
    assert report.n_runs == 270
    assert set(report.tpr) == {inj.name for inj in default_injectors()}
    for row in report.tpr.values():
        assert set(row) == {*report.detectors, ANY}
        for p in row.values():
            lo, hi = p.interval
            assert 0.0 <= lo <= p.rate <= hi <= 1.0
    assert report.per_detector_budget == pytest.approx(0.01)
    assert report.budget == monitor.budget


def test_gross_anomalies_are_found_by_the_detector_that_owns_them():
    _, report = measure_power(population(), budget=0.05, seed=1)
    assert report.tpr["foreign_scope"]["scope"].rate == 1.0
    assert report.tpr["unseen_tool"]["novel_tool"].rate == 1.0
    assert report.tpr["oversized_result(x100)"]["volume"].rate > 0.95
    # and not by a detector that has no business firing on them
    assert report.tpr["foreign_scope"]["novel_tool"].rate == 0.0


def test_false_positive_column_is_measured_on_the_held_out_runs():
    """Measured, not asserted: one split with 158 calibration runs can land well above the
    budget (this one does), which is exactly why the column carries an interval."""
    _, report = measure_power(population(), budget=0.05, seed=1)
    assert all(p.n == report.n_runs for p in report.fpr.values())
    per_detector = [report.fpr[d].hits for d in report.detectors]
    assert max(per_detector) <= report.fpr[ANY].hits <= sum(per_detector)


@dataclass(frozen=True)
class _Nothing:
    """Plants nothing. Its true positive rate is the false positive rate."""

    name: str = "nothing"

    def __call__(self, run, rng, ctx):
        from agentnorm.power import _clone
        return _clone(run, self.name)


def test_blind_spot_is_reported_when_an_injector_is_invisible():
    runs = population()
    monitor = Monitor.fit(runs[:600], budget=0.05)
    report = detection_power(monitor, runs[600:], [_Nothing(), ForeignScope()])
    assert report.blind_spots(0.8) == ["nothing"]
    assert report.tpr["nothing"][ANY].rate == pytest.approx(report.fpr[ANY].rate)


def test_skipped_runs_are_counted_not_hidden():
    runs = population(300)
    empty = RunRecorder(agent="triage", version="v1", principal="acme").finish()
    monitor = Monitor.fit(runs[:200], budget=0.05)
    report = detection_power(monitor, [*runs[200:], empty], [Burst(5)])
    assert report.skipped["burst(k=5)"] == 1
    assert report.tpr["burst(k=5)"][ANY].n == report.n_runs - 1
    assert "skipped" in report.format()


def test_format_is_a_table():
    _, report = measure_power(population(), budget=0.05, seed=1)
    text = report.format()
    assert "benign (FPR)" in text and "foreign_scope" in text and "any" in text
    assert report.to_dict()["tpr"]["foreign_scope"]["scope"]["rate"] == 1.0


def test_bad_arguments_are_rejected():
    monitor = Monitor.fit(population(100))
    with pytest.raises(ValueError):
        detection_power(monitor, [])
    with pytest.raises(ValueError):
        detection_power(monitor, population(10), [Burst(3), Burst(3)])
    with pytest.raises(ValueError):
        measure_power(population(10), test_fraction=1.0)
