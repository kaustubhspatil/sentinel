"""Behavioural detectors over agent runs.

Five detectors, kept separate rather than fused into one score. A fused score tells an
operator that something is wrong without saying what, and "what" is the entire value at
3am — it decides whether you page someone, revoke a credential, or ignore it.

The design principle running through all of them is **graceful cold start**. In a system
where agent versions change weekly, a detector meeting an entity it has never seen is not
an edge case, it is the normal operating condition. Measured on a real deployment, a suite
without cold-start handling alerted on 100% of known-benign runs: every tool looked novel
because the *agent* was unseen. The same suite with pooling alerted on none of them, with
no loss of detection.

So each detector answers "what do I do about an entity I have not observed?" explicitly:

  volume      pool - shrink toward the population prior (a row is a row)
  sequence    suppress - transition structure is agent-specific, not comparable
  scope       assert - entitlement is checked, with scope ownership learned
  novel_tool  pool - fall back to the population's tool vocabulary
  rate        suppress - run length is not comparable across agents, so do not guess
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from agentnorm.trace import Run

PRIOR_STRENGTH = 8.0
LAPLACE_ALPHA = 0.5


@dataclass(frozen=True)
class Score:
    detector: str
    value: float
    calibrated: bool = True

    @property
    def suppressed(self) -> bool:
        return math.isnan(self.value)


class VolumeBaseline:
    """Hierarchical Normal-Normal baseline on log result size, per (agent-version, tool).

    Independent per-pair statistics fail exactly where it matters: on a pair with three
    observations the variance is meaningless and everything looks extreme. Each pair's
    parameters are therefore shrunk toward the population by a conjugate update weighted
    by how much evidence that pair actually has. A pair with 500 observations trusts
    itself; a pair with 3 mostly inherits the population.

    Log space, because result sizes are heavy-tailed and a Gaussian on raw counts treats
    every large-but-normal query as an outlier.
    """

    name = "volume"

    def __init__(self, prior_strength: float = PRIOR_STRENGTH) -> None:
        self.k0 = prior_strength
        self.pop_mean = 0.0
        self.pop_var = 1.0
        self.params: dict[tuple[str, str], tuple[float, float]] = {}

    def fit(self, runs: list[Run]) -> VolumeBaseline:
        obs: dict[tuple[str, str], list[float]] = defaultdict(list)
        allv: list[float] = []
        for run in runs:
            for call in run.calls:
                v = math.log1p(max(0, call.result_size))
                obs[(run.key, call.tool)].append(v)
                allv.append(v)
        if not allv:
            return self
        self.pop_mean = sum(allv) / len(allv)
        self.pop_var = max(1e-6, sum((x - self.pop_mean) ** 2 for x in allv) / len(allv))
        for key, vals in obs.items():
            n = len(vals)
            mean = sum(vals) / n
            local_var = sum((x - mean) ** 2 for x in vals) / n if n > 1 else self.pop_var
            self.params[key] = (
                (self.k0 * self.pop_mean + n * mean) / (self.k0 + n),
                max((self.k0 * self.pop_var + n * local_var) / (self.k0 + n), 1e-6),
            )
        return self

    def score(self, run: Run) -> Score:
        worst = 0.0
        for call in run.calls:
            mean, var = self.params.get((run.key, call.tool), (self.pop_mean, self.pop_var))
            worst = max(worst, abs(math.log1p(max(0, call.result_size)) - mean) / math.sqrt(var))
        return Score(self.name, worst)


class SequenceModel:
    """Bigram surprisal over tool sequences.

    Catches routes where every individual call is legitimate but the path is not - skipped
    discovery, repeated traversal, a planner that stopped planning. No per-call detector
    can see this.

    Scored as mean surprisal per transition rather than total, so a long benign run is not
    penalised for being long. That is the rate detector's job, and conflating them makes
    both harder to interpret.
    """

    name = "sequence"

    def __init__(self, alpha: float = LAPLACE_ALPHA) -> None:
        self.alpha = alpha
        self.counts: dict[str, dict[tuple[str, str], float]] = defaultdict(lambda: defaultdict(float))
        self.context: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.vocab: dict[str, set[str]] = defaultdict(set)

    def fit(self, runs: list[Run]) -> SequenceModel:
        for run in runs:
            seq = ["<start>", *run.tools, "<end>"]
            self.vocab[run.key].update(seq)
            for a, b in zip(seq, seq[1:], strict=False):
                self.counts[run.key][(a, b)] += 1
                self.context[run.key][a] += 1
        return self

    def score(self, run: Run) -> Score:
        # Transition structure is agent-specific, like run length and unlike result size.
        # A triage agent's normal path is not evidence about a reporting agent's, so the
        # population model describes neither. Measured: pooling it alerted on 100% of
        # known-benign runs from an unseen agent. Suppressed instead.
        if run.key not in self.vocab:
            return Score(self.name, math.nan, calibrated=False)
        counts = self.counts[run.key]
        context = self.context[run.key]
        vocab = max(len(self.vocab[run.key]), 1)

        seq = ["<start>", *run.tools, "<end>"]
        total = 0.0
        for a, b in zip(seq, seq[1:], strict=False):
            num = counts.get((a, b), 0.0) + self.alpha
            den = context.get(a, 0.0) + self.alpha * vocab
            total += -math.log(num / den)
        return Score(self.name, total / max(len(seq) - 1, 1))


class ScopeViolation:
    """Did a run entitled to one principal touch another principal's resources?

    An assertion, not a statistic, and the distinction is load-bearing. An earlier version
    asked "has this agent touched this scope before?" and caught 1 escalation in 25:
    agents legitimately serve many principals, so once one has worked for both, every
    scope is familiar and nothing looks novel. Familiarity was the wrong invariant.

    Scope *ownership* is the right one. In practice a scope is an opaque identifier - a
    VPC, a project, a workspace, a namespace - not a copy of the principal's name, so
    comparing the two strings directly is wrong in both directions. Deployed against a
    real estate where scopes were network-zone ids, a direct comparison marked every
    benign call a violation, which calibrated the threshold so high that it then caught
    none of 40 real escalations.

    So ownership is learned from benign traffic: which principal does each scope belong
    to? A run violates scope when it touches a scope owned by someone else. A scope never
    seen during fit falls back to direct comparison, which is the only safe guess.
    """

    name = "scope"

    def __init__(self) -> None:
        self.owner: dict[str, str] = {}

    def fit(self, runs: list[Run]) -> ScopeViolation:
        tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for run in runs:
            if not run.principal:
                continue
            for call in run.calls:
                if call.scope:
                    tally[call.scope][run.principal] += 1
        self.owner = {
            scope: max(owners.items(), key=lambda kv: kv[1])[0]
            for scope, owners in tally.items()
        }
        return self

    def score(self, run: Run) -> Score:
        if not run.principal:
            return Score(self.name, math.nan, calibrated=False)
        violations = 0
        for call in run.calls:
            if not call.scope:
                continue
            owner = self.owner.get(call.scope)
            if owner is None:
                # Unknown scope: fall back to the direct comparison.
                violations += int(call.scope != run.principal)
            elif owner != run.principal:
                violations += 1
        return Score(self.name, float(violations))


class NovelTool:
    """A tool this agent version has never used, falling back to the population.

    Without the fallback this fired on 100% of real runs: every tool looked novel because
    the agent was unseen, so the detector reported "I have not met you" on every run,
    forever. Set membership has no graceful cold start unless it is given one.
    """

    name = "novel_tool"

    def __init__(self) -> None:
        self.seen: dict[str, set[str]] = defaultdict(set)
        self.population: set[str] = set()

    def fit(self, runs: list[Run]) -> NovelTool:
        for run in runs:
            self.seen[run.key].update(run.tools)
            self.population.update(run.tools)
        return self

    def score(self, run: Run) -> Score:
        known = self.seen.get(run.key)
        vocab = known or self.population
        return Score(self.name, float(len(set(run.tools) - vocab)), calibrated=known is not None)


class RateBaseline:
    """Calls per run, against this agent version's own distribution only.

    Suppressed - not pooled - for an unseen agent, and that asymmetry is deliberate.
    Pooling result *sizes* across agents is defensible: a row is a row. Pooling run
    *lengths* is not. A triage agent making three calls and a reporting agent making forty
    are both behaving normally, so the population mean describes neither; scoring against
    it fired on 54% of known-benign runs.

    You cannot baseline what you have not observed. The correct output for a new agent is
    "not yet calibrated", not a guess.
    """

    name = "rate"

    def __init__(self) -> None:
        self.stats: dict[str, tuple[float, float]] = {}

    def fit(self, runs: list[Run]) -> RateBaseline:
        per_key: dict[str, list[float]] = defaultdict(list)
        for run in runs:
            per_key[run.key].append(math.log1p(run.n_calls))
        for key, vals in per_key.items():
            m = sum(vals) / len(vals)
            var = sum((x - m) ** 2 for x in vals) / len(vals) if len(vals) > 1 else 1.0
            self.stats[key] = (m, max(var, 1e-6))
        return self

    def score(self, run: Run) -> Score:
        stats = self.stats.get(run.key)
        if stats is None:
            return Score(self.name, math.nan, calibrated=False)
        m, var = stats
        return Score(self.name, abs(math.log1p(run.n_calls) - m) / math.sqrt(var))


@dataclass
class DetectorSuite:
    volume: VolumeBaseline = field(default_factory=VolumeBaseline)
    sequence: SequenceModel = field(default_factory=SequenceModel)
    scope: ScopeViolation = field(default_factory=ScopeViolation)
    novel_tool: NovelTool = field(default_factory=NovelTool)
    rate: RateBaseline = field(default_factory=RateBaseline)
    known_keys: set[str] = field(default_factory=set)

    NAMES = ("volume", "sequence", "scope", "novel_tool", "rate")

    @classmethod
    def fit(cls, runs: list[Run], prior_strength: float = PRIOR_STRENGTH) -> DetectorSuite:
        suite = cls(volume=VolumeBaseline(prior_strength))
        for det in (suite.volume, suite.sequence, suite.scope, suite.novel_tool, suite.rate):
            det.fit(runs)
        suite.known_keys = {r.key for r in runs}
        return suite

    def is_cold_start(self, run: Run) -> bool:
        """True when this agent version has no fitted history."""
        return run.key not in self.known_keys

    def score(self, run: Run) -> dict[str, Score]:
        return {
            d.name: d.score(run)
            for d in (self.volume, self.sequence, self.scope, self.novel_tool, self.rate)
        }
