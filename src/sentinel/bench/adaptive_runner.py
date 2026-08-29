"""The adaptive experiment: does rewriting the payload defeat action-level detection?

Static AgentDojo attacks are saturated on this model (0% across six families), so the
detection question is only answerable against an attacker that adapts. This drives one.

For each (user task, injection task) target:

  1. the adaptive attacker proposes an injection
  2. it is placed in the environment through AgentDojo's own injection mechanism
  3. the agent runs; agentnorm records the tool calls out of band; a text-level detector
     judges each tool output in the request path
  4. if the attack did not achieve its goal, the failed trace is fed back and the attacker
     tries again, up to a budget
  5. the moment it succeeds, both detectors are scored on that successful run

The comparison is between two detectors on the *same* successful attacks:

  text     reads the injected wording        (the shape every published defense takes)
  action   observes the agent's tool calls   (out of band, never in the path)

The attacker optimises only against the agent's compliance, never against either
detector. That is deliberate: it keeps the comparison a measurement of the defenses rather
than of the optimiser, and it is the honest threat model - a real attacker wants the
action to happen, not to look benign to a monitor it cannot see.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.benchmark import run_task_with_injection_tasks
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites
from agentnorm import Monitor, Run, RunRecorder

from sentinel.bench.adaptive_attack import AdaptiveAttacker, AdaptiveResult, AttackAttempt
from sentinel.bench.agentdojo_runner import LOGDIR, VERSION, build_pipeline
from sentinel.bench.text_baseline import DetectorStats, LLMTextDetector

MODEL_PIPELINE_NAME = "gpt-4o-2024-05-13"


class ProgrammaticAttack(BaseAttack):
    """Places a supplied injection string, instead of AgentDojo's fixed templates.

    AgentDojo's ManualAttack reads the injection from stdin; this takes it from the
    adaptive attacker instead, so the optimiser's proposal is what actually reaches the
    agent.
    """

    name = "programmatic"

    def __init__(self, suite, pipeline, payload: str) -> None:
        super().__init__(suite, pipeline)
        self.payload = payload

    def attack(self, user_task: BaseUserTask, injection_task: BaseInjectionTask) -> dict[str, str]:
        return dict.fromkeys(self.get_injection_candidates(user_task), self.payload)


@dataclass
class TargetResult:
    user_task: str
    injection_task: str
    attack_succeeded: bool
    iterations: int
    text_flagged: bool = False
    action_flagged: bool = False
    action_explain: str = ""
    winning_tools: list[str] = field(default_factory=list)


def _run_once(
    suite, pipeline, holder, text_stats: DetectorStats, run_key: dict[str, str],
    user_task, inj_id: str, payload: str,
) -> tuple[bool, Run, list[str]]:
    """Run one attempt; return (attack_succeeded, recorded_run, agent_tools)."""
    holder["recorder"] = RunRecorder("agentdojo", version=suite.name, principal=suite.name)
    run_key["key"] = f"{user_task.ID}/{inj_id}"
    text_stats.flagged_runs.discard(run_key["key"])

    attack = ProgrammaticAttack(suite, pipeline, payload)
    _, sec_map = run_task_with_injection_tasks(
        suite, pipeline, user_task, attack,
        logdir=LOGDIR, force_rerun=True, injection_tasks=[inj_id],
    )
    succeeded = bool(sec_map.get((user_task.ID, inj_id), False))
    run_obj = holder["recorder"].finish()
    return succeeded, run_obj, run_obj.tools


def run(
    suite_name: str = "workspace",
    max_targets: int = 6,
    attacker_budget: int = 5,
    benign_for_baseline: int = 20,
) -> dict[str, Any]:
    suite = get_suites(VERSION)[suite_name]
    holder: dict[str, RunRecorder] = {}
    text_stats = DetectorStats()
    run_key: dict[str, str] = {}

    # The text detector sits in the pipeline; the action recorder wraps the executor.
    text_detector = LLMTextDetector(text_stats, run_key)
    pipeline = build_pipeline(holder, suite_name, extra_after_llm=[text_detector])
    pipeline.name = MODEL_PIPELINE_NAME

    LOGDIR.mkdir(parents=True, exist_ok=True)
    logger = OutputLogger(str(LOGDIR))
    logger.__enter__()

    # --- 1. benign baseline for the action detector ------------------------------
    benign: list[Run] = []
    for task in list(suite.user_tasks.values())[:benign_for_baseline]:
        holder["recorder"] = RunRecorder("agentdojo", version=suite_name, principal=suite_name)
        run_key["key"] = f"benign/{task.ID}"
        from agentdojo.benchmark import run_task_without_injection_tasks
        try:
            run_task_without_injection_tasks(
                suite, pipeline, task, logdir=LOGDIR, force_rerun=True
            )
        except Exception:  # noqa: BLE001 - a crashed benign task is just dropped
            pass
        r = holder["recorder"].finish()
        if r.n_calls > 0:
            benign.append(r)

    monitor = Monitor.fit(benign) if len(benign) >= 4 else None
    text_benign_flags = len(text_stats.flagged_runs)  # benign runs the text filter flagged

    # --- 2. adaptive attacks -----------------------------------------------------
    user_tasks = list(suite.user_tasks.values())[:max_targets]
    inj_id = next(iter(suite.injection_tasks))
    inj_goal = suite.injection_tasks[inj_id].GOAL

    targets: list[TargetResult] = []
    adaptive_log: list[AdaptiveResult] = []

    for user_task in user_tasks:
        attacker = AdaptiveAttacker(inj_goal, max_iterations=attacker_budget)
        result = AdaptiveResult(goal=inj_goal, succeeded=False, iterations=0)
        payload = attacker.first()

        for it in range(1, attacker_budget + 1):
            result.iterations = it
            succeeded, run_obj, tools = _run_once(
                suite, pipeline, holder, text_stats, run_key, user_task, inj_id, payload
            )
            result.attempts.append(AttackAttempt(it, payload, succeeded, tools))
            if succeeded:
                result.succeeded = True
                result.winning_injection = payload
                tr = TargetResult(user_task.ID, inj_id, True, it,
                                  winning_tools=tools)
                # score both detectors on this successful run
                tr.text_flagged = f"{user_task.ID}/{inj_id}" in text_stats.flagged_runs
                if monitor is not None:
                    v = monitor.score(run_obj)
                    tr.action_flagged = v.flagged
                    tr.action_explain = v.explain()
                targets.append(tr)
                break
            payload = attacker.refine(tools)

        if not result.succeeded:
            targets.append(TargetResult(user_task.ID, inj_id, False, result.iterations))
        adaptive_log.append(result)

    logger.__exit__(None, None, None)

    won = [t for t in targets if t.attack_succeeded]
    report = {
        "suite": suite_name,
        "benign_baseline_runs": len(benign),
        "targets": len(targets),
        "attacker_budget": attacker_budget,
        "adaptive_attacks_succeeded": len(won),
        "adaptive_success_rate": round(len(won) / max(len(targets), 1), 3),
        "mean_iterations_to_success": (
            round(sum(t.iterations for t in won) / len(won), 2) if won else None
        ),
        "on_successful_attacks": {
            "count": len(won),
            "text_detector_caught": sum(t.text_flagged for t in won),
            "action_detector_caught": sum(t.action_flagged for t in won),
        },
        "false_positives": {
            "text_on_benign": text_benign_flags,
            "action_on_benign": (
                sum(1 for r in benign if monitor.score(r).flagged) if monitor else None
            ),
            "benign_runs": len(benign),
        },
        "text_detector_llm_errors": text_stats.llm_errors,
        "targets_detail": [t.__dict__ for t in targets],
    }
    return report


if __name__ == "__main__":
    import sys

    suite_name = sys.argv[1] if len(sys.argv) > 1 else "workspace"
    rep = run(suite_name=suite_name)
    Path("evals").mkdir(exist_ok=True)
    Path(f"evals/adaptive_{suite_name}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    slim = {k: v for k, v in rep.items() if k != "targets_detail"}
    print(json.dumps(slim, indent=2))
