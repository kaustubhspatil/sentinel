"""Behavioural anomaly detectors over agent tool-call traces.

Five detectors, each aimed at a failure mode the others cannot see. They are kept
separate rather than fused into one score because a fused score tells an operator that
something is wrong without saying what, and "what" is the entire value at 3am.

Fitted on benign traces only. Scored per run.

**Hierarchical Bayesian volume baseline.** Per (agent, tool), how much data does a call
usually return? The obvious approach - an independent mean and variance per pair - fails
exactly where it matters, on pairs with three observations, where the variance is
meaningless and every new call looks extreme. So each pair's parameters are shrunk toward
the population mean by a Normal-Normal conjugate update, with the shrinkage weight
determined by how much evidence that pair actually has. A pair with 500 observations
trusts itself; a pair with 3 mostly inherits the population. This is the piece that makes
a new agent version or a rarely-used tool stop generating false alarms on day one.

Log-space, because result sizes are heavy-tailed and a Gaussian on raw counts would treat
every large-but-normal query as an outlier.

**Sequence surprisal.** A bigram model over tool sequences: how unlikely is this ordering
of calls, given how this agent normally works? Catches paths where every individual call
is legitimate but the route is not - skipped discovery, repeated traversal - which no
per-call detector can see.

**Scope violation.** Did a run scoped to one tenant touch another tenant's zones? An
assertion, not a statistic. The first version asked whether the agent had ever seen the
zone and caught 1 escalation in 25: agents legitimately serve several tenants, so
familiarity was the wrong invariant. Scope consistency within a run is the right one.

**Novel tool.** A tool this agent has never called. Separate from scope violation so the
alert names which invariant broke.

**Rate.** Calls per run against the agent's own baseline. Crude and included deliberately -
it is the detector most likely to be redundant, and measuring that is the point.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

# Prior strength for the volume baseline: how many pseudo-observations of the population
# mean each (agent, tool) pair starts with. Higher means slower to trust a specific pair.
# 8 is a judgement call, and the sensitivity of results to it is reported in evaluate.py.
PRIOR_STRENGTH = 8.0
LAPLACE_ALPHA = 0.5  # bigram smoothing; 0.5 (Jeffreys) rather than 1 to avoid over-flattening


@dataclass
class Run:
    """One agent run, assembled from its trace rows."""

    run_id: str
    agent: str
    agent_version: str
    tenant: str
    tools: list[str] = field(default_factory=list)
    rows: list[int] = field(default_factory=list)
    zones: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    scenario: str = ""
    is_anomalous: int = -1

    @property
    def n_calls(self) -> int:
        return len(self.tools)


def assemble(rows: Iterable[dict[str, Any]]) -> list[Run]:
    """Group flat trace rows into runs, preserving call order."""
    by_run: dict[str, Run] = {}
    for r in sorted(rows, key=lambda x: (x["run_id"], x["step"])):
        run = by_run.get(r["run_id"])
        if run is None:
            run = Run(
                run_id=r["run_id"], agent=r["agent"], agent_version=r["agent_version"],
                tenant=r["tenant"], scenario=r.get("scenario", ""),
                is_anomalous=int(r.get("is_anomalous", -1)),
            )
            by_run[r["run_id"]] = run
        run.tools.append(r["tool"])
        run.rows.append(int(r["result_rows"]))
        run.zones.append(r.get("zone") or "")
        run.resources.append(r.get("resource") or "")
    return list(by_run.values())


class VolumeBaseline:
    """Hierarchical Normal-Normal baseline on log result size, per (agent, tool)."""

    def __init__(self, prior_strength: float = PRIOR_STRENGTH) -> None:
        self.k0 = prior_strength
        self.pop_mean = 0.0
        self.pop_var = 1.0
        self.params: dict[tuple[str, str], tuple[float, float]] = {}

    def fit(self, runs: list[Run]) -> "VolumeBaseline":
        obs: dict[tuple[str, str], list[float]] = defaultdict(list)
        everything: list[float] = []
        for run in runs:
            for tool, n in zip(run.tools, run.rows):
                v = math.log1p(max(0, n))
                obs[(run.agent, tool)].append(v)
                everything.append(v)

        if not everything:
            return self
        self.pop_mean = sum(everything) / len(everything)
        self.pop_var = max(
            1e-6, sum((x - self.pop_mean) ** 2 for x in everything) / len(everything)
        )

        for key, vals in obs.items():
            n = len(vals)
            mean = sum(vals) / n
            # Posterior mean: precision-weighted blend of population prior and local data.
            post_mean = (self.k0 * self.pop_mean + n * mean) / (self.k0 + n)
            local_var = (
                sum((x - mean) ** 2 for x in vals) / n if n > 1 else self.pop_var
            )
            # Variance is shrunk the same way, so a pair with few observations does not
            # get an implausibly tight interval and flag everything.
            post_var = (self.k0 * self.pop_var + n * local_var) / (self.k0 + n)
            self.params[key] = (post_mean, max(post_var, 1e-6))
        return self

    def score(self, run: Run) -> float:
        """Max absolute z-score across the run's calls, in log space."""
        worst = 0.0
        for tool, n in zip(run.tools, run.rows):
            mean, var = self.params.get(
                (run.agent, tool), (self.pop_mean, self.pop_var)
            )
            z = abs(math.log1p(max(0, n)) - mean) / math.sqrt(var)
            worst = max(worst, z)
        return worst


class SequenceModel:
    """Bigram surprisal over tool sequences, per agent."""

    def __init__(self, alpha: float = LAPLACE_ALPHA) -> None:
        self.alpha = alpha
        self.counts: dict[str, dict[tuple[str, str], float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self.context: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.vocab: dict[str, set[str]] = defaultdict(set)

    def fit(self, runs: list[Run]) -> "SequenceModel":
        for run in runs:
            seq = ["<start>"] + run.tools + ["<end>"]
            self.vocab[run.agent].update(seq)
            for a, b in zip(seq, seq[1:]):
                self.counts[run.agent][(a, b)] += 1
                self.context[run.agent][a] += 1
        return self

    def score(self, run: Run) -> float:
        """Mean negative log-probability per transition: average surprise per step.

        Mean rather than total, so a long benign run is not penalised simply for being
        long - that is the rate detector's job, and conflating them makes both harder
        to interpret.
        """
        agent = run.agent
        vocab = max(len(self.vocab.get(agent, ())), 1)
        seq = ["<start>"] + run.tools + ["<end>"]
        total = 0.0
        for a, b in zip(seq, seq[1:]):
            num = self.counts[agent].get((a, b), 0.0) + self.alpha
            den = self.context[agent].get(a, 0.0) + self.alpha * vocab
            total += -math.log(num / den)
        return total / max(len(seq) - 1, 1)


class ScopeViolation:
    """Cross-tenant access: did a run scoped to one tenant touch another's resources?

    The first version of this asked whether the agent had ever seen the zone before, and
    caught 1 of 25 escalations. The reason is instructive: agents legitimately serve
    multiple tenants, so by the time an agent has worked for both acme and globex, every
    zone is familiar and nothing looks novel. Familiarity was the wrong invariant.

    The right one is scope consistency *within a run*: a run declared for tenant T should
    not touch resources belonging to tenant U, regardless of what that agent has done for
    U in other runs. That is an assertion, not a statistic, so it is checked as one.

    Zone ownership is learned from benign traffic rather than declared, so the detector
    keeps working as the estate changes.
    """

    def __init__(self) -> None:
        self.zone_owner: dict[str, str] = {}

    def fit(self, runs: list[Run]) -> "ScopeViolation":
        tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for run in runs:
            for z in run.zones:
                if z:
                    tally[z][run.tenant] += 1
        for zone, owners in tally.items():
            self.zone_owner[zone] = max(owners.items(), key=lambda kv: kv[1])[0]
        return self

    def score(self, run: Run) -> float:
        """Number of calls reaching into a zone owned by a different tenant."""
        violations = 0
        for z in run.zones:
            owner = self.zone_owner.get(z)
            if owner and owner != run.tenant:
                violations += 1
        return float(violations)


class NovelTool:
    """A tool this agent has never used before.

    Kept separate from scope violation so the alert says which invariant broke. Set
    membership, not statistics: reaching a privileged tool for the first time is outside
    the support of the distribution, not merely far out in its tail.
    """

    def __init__(self) -> None:
        self.seen: dict[str, set[str]] = defaultdict(set)

    def fit(self, runs: list[Run]) -> "NovelTool":
        for run in runs:
            self.seen[run.agent].update(run.tools)
        return self

    def score(self, run: Run) -> float:
        return float(len(set(run.tools) - self.seen[run.agent]))


class RateBaseline:
    """Calls per run against the agent's own distribution."""

    def __init__(self) -> None:
        self.stats: dict[str, tuple[float, float]] = {}
        self.fallback = (1.0, 1.0)

    def fit(self, runs: list[Run]) -> "RateBaseline":
        per_agent: dict[str, list[float]] = defaultdict(list)
        for run in runs:
            per_agent[run.agent].append(math.log1p(run.n_calls))
        allv = [v for vals in per_agent.values() for v in vals]
        if allv:
            m = sum(allv) / len(allv)
            self.fallback = (m, max(1e-6, sum((x - m) ** 2 for x in allv) / len(allv)))
        for agent, vals in per_agent.items():
            m = sum(vals) / len(vals)
            var = sum((x - m) ** 2 for x in vals) / len(vals) if len(vals) > 1 else self.fallback[1]
            self.stats[agent] = (m, max(var, 1e-6))
        return self

    def score(self, run: Run) -> float:
        m, var = self.stats.get(run.agent, self.fallback)
        return abs(math.log1p(run.n_calls) - m) / math.sqrt(var)


@dataclass
class DetectorSuite:
    volume: VolumeBaseline
    sequence: SequenceModel
    scope: ScopeViolation
    novel_tool: NovelTool
    rate: RateBaseline

    NAMES = ("volume", "sequence", "scope", "novel_tool", "rate")

    @classmethod
    def fit(cls, benign_runs: list[Run], prior_strength: float = PRIOR_STRENGTH) -> "DetectorSuite":
        return cls(
            volume=VolumeBaseline(prior_strength).fit(benign_runs),
            sequence=SequenceModel().fit(benign_runs),
            scope=ScopeViolation().fit(benign_runs),
            novel_tool=NovelTool().fit(benign_runs),
            rate=RateBaseline().fit(benign_runs),
        )

    def score(self, run: Run) -> dict[str, float]:
        return {
            "volume": self.volume.score(run),
            "sequence": self.sequence.score(run),
            "scope": self.scope.score(run),
            "novel_tool": self.novel_tool.score(run),
            "rate": self.rate.score(run),
        }
