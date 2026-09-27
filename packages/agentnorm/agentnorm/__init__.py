"""agentnorm - behavioural monitoring for AI agents.

Agents are unvalidated models running in production. Evaluation grades their outputs
offline; this watches how they *behave* at runtime and says when a run does not look like
the ones before it.

    from agentnorm import RunRecorder, Monitor

    rec = RunRecorder(agent="triage", version="v3", principal="acme")
    with rec.tool_call("search", {"q": q}, scope="acme") as call:
        rows = search(q)
        call.result_size = len(rows)

    monitor = Monitor.fit(history)          # benign runs
    verdict = monitor.score(rec.finish())
    if verdict.flagged:
        print(verdict.explain())

Or instrument tools you already have, without restructuring the agent:

    session = Session(agent="triage", version="v3", principal="acme")
    tools = session.wrap({"search": search, "fetch": fetch})
    ...
    verdict = monitor.score(session.finish())

Three checks on the monitor itself:

    detection_power(monitor, held_out)        # can it fire? TPR per detector, exact CIs
    RateAlarm(baseline=0.01).update(flagged)  # rate alarm safe to check after every run
    model_equality_test(before, after)        # did the model behind the API change?

No database, no framework, no context propagation required.
"""
from agentnorm.audit import AuditChain, AuditLog, verify_chain
from agentnorm.detectors import DetectorSuite
from agentnorm.equality import EqualityResult, model_equality_test
from agentnorm.integrations import Session, default_size_of
from agentnorm.monitor import Alert, Monitor, Verdict
from agentnorm.power import PowerReport, detection_power, measure_power
from agentnorm.sequential import RateAlarm, RateConfidenceSequence
from agentnorm.store import JsonlStore, Store
from agentnorm.trace import Run, RunRecorder, ToolCall

__version__ = "0.2.0"
__all__ = [
    "Alert", "AuditChain", "AuditLog", "DetectorSuite", "EqualityResult", "JsonlStore",
    "Monitor", "PowerReport", "RateAlarm", "RateConfidenceSequence", "Run", "RunRecorder",
    "Session", "Store", "ToolCall", "Verdict", "default_size_of", "detection_power",
    "measure_power", "model_equality_test", "verify_chain",
]
