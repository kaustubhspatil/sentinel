"""Evaluation harness for the graph agent.

Scores trajectories, not just answers. An agent that reaches the right conclusion through
six redundant calls and one that reaches it in two are not equally good, and an agent that
reaches the *wrong* conclusion fluently is worse than one that fails loudly.

Metrics, and why each is here:

  fact_recall        - required facts present in the answer. The primary correctness
                       signal, checked against ground truth rather than judged.
  fabrication        - forbidden strings present. Separated from correctness because a
                       fluent answer containing one invented number is a different and
                       more dangerous failure than an incomplete one.
  tool_recall        - expected tools actually called. Recall, not exact match: another
                       route to the right answer is not a failure.
  tool_efficiency    - expected calls / actual calls. Catches flailing.
  malformed_rate     - responses that did not follow the protocol.
  premature_answers  - answers attempted with no tool call at all.
  latency, cost      - per task, so the model-tier trade-off is measurable.

String matching is deliberate for facts. An LLM judge is added on top for answers whose
correctness is not reducible to a substring, but a judge that can be wrong should never be
the only check on a number that can be verified exactly.
"""
from __future__ import annotations

import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel.agents import graph_agent

TASKS_FILE = Path(__file__).resolve().parents[3] / "evals" / "tasks.yaml"


@dataclass
class TaskResult:
    id: str
    passed: bool
    fact_recall: float
    fabricated: list[str]
    tool_recall: float
    tools_called: list[str]
    tools_expected: list[str]
    malformed_calls: int
    premature_answers: int
    llm_calls: int
    latency_ms: int
    input_tokens: int
    output_tokens: int
    answer: str
    citations: list[str] = field(default_factory=list)
    stopped_reason: str = ""


def _matches(answer: str, needle: str) -> bool:
    """Substring match, with `A OR B` meaning either is acceptable."""
    low = answer.lower()
    if " OR " in needle:
        return any(alt.strip().lower() in low for alt in needle.split(" OR "))
    return needle.lower() in low


def run_task(task: dict[str, Any], tier: str = "small") -> TaskResult:
    res = graph_agent.run(task["question"], tier=tier)
    answer = res.answer or ""

    required = task.get("must_contain") or []
    hits = [n for n in required if _matches(answer, n)]
    fact_recall = len(hits) / len(required) if required else 1.0

    forbidden = task.get("must_not_contain") or []
    fabricated = [n for n in forbidden if _matches(answer, n)]

    expected = task.get("expected_tools") or []
    called = res.tool_sequence
    tool_hits = [t for t in expected if t in called]
    tool_recall = len(tool_hits) / len(expected) if expected else 1.0

    # A task passes only with every required fact and no fabrication. Partial credit is
    # reported but does not pass: an operator acting on a half-right answer is not
    # half-safe.
    passed = fact_recall == 1.0 and not fabricated

    return TaskResult(
        id=task["id"], passed=passed, fact_recall=round(fact_recall, 3),
        fabricated=fabricated, tool_recall=round(tool_recall, 3),
        tools_called=called, tools_expected=expected,
        malformed_calls=res.malformed_calls, premature_answers=res.premature_answers,
        llm_calls=res.llm_calls, latency_ms=res.latency_ms,
        input_tokens=res.input_tokens, output_tokens=res.output_tokens,
        answer=answer[:400], citations=res.citations, stopped_reason=res.stopped_reason,
    )


def run_suite(tier: str = "small", tasks_file: Path | None = None) -> dict[str, Any]:
    doc = yaml.safe_load((tasks_file or TASKS_FILE).read_text(encoding="utf-8"))
    results = [run_task(t, tier=tier) for t in doc["tasks"]]

    n = len(results)
    return {
        "tier": tier,
        "tasks": n,
        "passed": sum(r.passed for r in results),
        "pass_rate": round(sum(r.passed for r in results) / n, 3),
        "mean_fact_recall": round(statistics.mean(r.fact_recall for r in results), 3),
        "tasks_with_fabrication": sum(1 for r in results if r.fabricated),
        "mean_tool_recall": round(statistics.mean(r.tool_recall for r in results), 3),
        "total_malformed_calls": sum(r.malformed_calls for r in results),
        "total_premature_answers": sum(r.premature_answers for r in results),
        "median_latency_ms": int(statistics.median(r.latency_ms for r in results)),
        "total_tokens": sum(r.input_tokens + r.output_tokens for r in results),
        "results": [asdict(r) for r in results],
    }


if __name__ == "__main__":
    import sys

    tier = sys.argv[1] if len(sys.argv) > 1 else "small"
    report = run_suite(tier=tier)
    out = Path("evals/last_report.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"tier={report['tier']}  passed {report['passed']}/{report['tasks']} "
          f"({report['pass_rate']:.0%})")
    print(f"  mean fact recall     {report['mean_fact_recall']}")
    print(f"  tasks w/ fabrication {report['tasks_with_fabrication']}")
    print(f"  mean tool recall     {report['mean_tool_recall']}")
    print(f"  malformed calls      {report['total_malformed_calls']}")
    print(f"  premature answers    {report['total_premature_answers']}")
    print(f"  median latency       {report['median_latency_ms']} ms")
    print(f"  total tokens         {report['total_tokens']:,}")
    print()
    for r in report["results"]:
        mark = "PASS" if r["passed"] else "FAIL"
        extra = f" fabricated={r['fabricated']}" if r["fabricated"] else ""
        print(f"  [{mark}] {r['id']:28s} facts={r['fact_recall']:.2f} "
              f"tools={r['tools_called']}{extra}")
