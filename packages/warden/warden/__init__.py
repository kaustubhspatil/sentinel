"""warden - behavioural monitoring for AI agents.

Agents are unvalidated models running in production. Evaluation grades their outputs
offline; this watches how they *behave* at runtime and says when a run does not look like
the ones before it.

    from warden import RunRecorder, Monitor

    rec = RunRecorder(agent="triage", version="v3", principal="acme")
    with rec.tool_call("search", {"q": q}, scope="acme") as call:
        rows = search(q)
        call.result_size = len(rows)

    monitor = Monitor.fit(history)          # benign runs
    verdict = monitor.score(rec.finish())
    if verdict.flagged:
        print(verdict.explain())

No database, no framework, no context propagation required.
"""
from warden.detectors import DetectorSuite
from warden.monitor import Alert, Monitor, Verdict
from warden.trace import Run, RunRecorder, ToolCall

__version__ = "0.1.0"
__all__ = [
    "Alert", "DetectorSuite", "Monitor", "Run", "RunRecorder", "ToolCall", "Verdict",
]
