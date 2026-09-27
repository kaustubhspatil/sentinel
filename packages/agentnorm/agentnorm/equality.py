"""Model equality testing: did the vendor change the model behind the API?

A hosted model can change without its name changing: a new snapshot, a quantised serving
path, a different model routed behind the same identifier. For a validated system that is
a model change, and under a model risk framework such as OSFI E-23 a model change is a
revalidation trigger. Nobody can revalidate after a change they never saw.

The approach follows Gao, Liang and Guestrin (ICLR 2025, "Model Equality Testing: Which
Model Is This API Serving?"): keep a fixed set of canary prompts, record the outputs once
as a reference, collect them again later, and run a two sample test on the outputs. If
the model is unchanged, the two collections are draws from the same distribution.

The test here is a kernel two sample test (maximum mean discrepancy) with a permutation
null, in the standard library:

* Features are prompt agnostic style features of the output text: a hashed profile of
  character trigrams (cosine kernel) plus a Gaussian kernel on log length. Content is
  prompt specific; style (phrasing, formatting, verbosity) is where models differ.
* **Paired design (default).** Both collections answer the same canary prompts, so the
  null is that for every prompt the two outputs are exchangeable. The permutation swaps
  the two outputs *within* a prompt. That is exact under the null for any number of
  prompts and needs no assumption about how prompts relate to each other.
* **Unpaired design.** Full relabelling, for collections on different prompts drawn from
  the same distribution. Exact when that holds; not the right null for shared prompts.

What a rejection means: the output distributions differ on these prompts. It does not
say *what* changed. A new retriever, a new system prompt or a new decoding setting is
detected exactly like a new model, and the test cannot tell them apart. Hold everything
else fixed when collecting canary outputs, or read a rejection as "the pipeline changed".

A limit worth knowing before trusting a small canary set: with one output per prompt and
n prompts, the paired test has 2^(n-1) distinct relabellings, so its smallest possible p
value is 1/2^(n-1). With five prompts that is 1/16, and the test *cannot* reject at 0.05
however different the models are. `EqualityResult.min_p_value` reports this.
"""
from __future__ import annotations

import itertools
import math
import operator
import random
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache

TRIGRAM_DIM = 4096


@lru_cache(maxsize=8192)
def _profile(text: str, n: int = 3, dim: int = TRIGRAM_DIM) -> tuple[tuple[int, float], ...]:
    """L2 normalised hashed character n gram counts, as a sparse sorted tuple."""
    if len(text) < n:
        grams = [text] if text else []
    else:
        grams = [text[i:i + n] for i in range(len(text) - n + 1)]
    counts: dict[int, float] = {}
    for g in grams:
        k = zlib.crc32(g.encode("utf-8")) % dim
        counts[k] = counts.get(k, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in counts.values()))
    return tuple(sorted((k, v / norm) for k, v in counts.items())) if norm else ()


def _cosine(u: tuple[tuple[int, float], ...], v: tuple[tuple[int, float], ...]) -> float:
    if len(u) > len(v):
        u, v = v, u
    dv = dict(v)
    return sum(w * dv.get(k, 0.0) for k, w in u)


def canary_kernel(texts: Sequence[str]) -> list[list[float]]:
    """Kernel matrix over output texts: trigram cosine plus a Gaussian on log length.

    The length bandwidth is the median pairwise distance of the pooled texts, which
    depends only on the pooled set, so it is unchanged by any relabelling and the
    permutation test stays exact.
    """
    profiles = [_profile(t) for t in texts]
    loglen = [math.log1p(len(t)) for t in texts]
    m = len(texts)
    dists = sorted(abs(loglen[i] - loglen[j]) for i in range(m) for j in range(i + 1, m))
    med = dists[len(dists) // 2] if dists else 0.0
    two_s2 = 2.0 * (med if med > 0 else 1.0) ** 2
    k = [[0.0] * m for _ in range(m)]
    for i in range(m):
        for j in range(i, m):
            v = _cosine(profiles[i], profiles[j]) + math.exp(-(loglen[i] - loglen[j]) ** 2 / two_s2)
            k[i][j] = k[j][i] = v
    return k


@dataclass(frozen=True)
class EqualityResult:
    statistic: float
    p_value: float
    n_a: int
    n_b: int
    paired: bool
    permutations: int
    exact: bool
    min_p_value: float

    def rejected(self, alpha: float = 0.05) -> bool:
        return self.p_value <= alpha

    def __str__(self) -> str:
        design = "paired" if self.paired else "unpaired"
        how = "exact" if self.exact else f"{self.permutations} permutations"
        return (f"MMD^2={self.statistic:.4f}, p={self.p_value:.4f} ({design}, "
                f"n={self.n_a}/{self.n_b}, {how}, smallest attainable p={self.min_p_value:.4f})")


def pair_outputs(
    a: Mapping[str, str], b: Mapping[str, str], *, drop_empty: bool = True
) -> tuple[list[str], list[str], list[str]]:
    """Align two {prompt_id: output} mappings on shared prompt ids.

    Returns (ids, outputs_a, outputs_b). With `drop_empty`, a prompt is dropped when
    either output is empty; the rule is symmetric in a and b, so it keeps the paired null
    exact.
    """
    ids = [k for k in a if k in b and (not drop_empty or (a[k] and b[k]))]
    ids.sort()
    return ids, [a[k] for k in ids], [b[k] for k in ids]


def _ge(x: float, ref: float) -> bool:
    return x >= ref - 1e-12 * max(1.0, abs(ref))


def _paired(kmat: list[list[float]], n: int, permutations: int,
            rng: random.Random) -> tuple[float, float, bool, float]:
    # Items 0..n-1 are a, n..2n-1 are b. Swapping pair i flips eps_i, and
    # MMD^2 = eps' H eps / n^2 with H_ij = K(ai,aj) - K(ai,bj) - K(bi,aj) + K(bi,bj).
    h = [[kmat[i][j] - kmat[i][n + j] - kmat[n + i][j] + kmat[n + i][n + j]
          for j in range(n)] for i in range(n)]
    scale = 1.0 / (n * n)

    def stat(eps: Sequence[int]) -> float:
        return scale * sum(e * sum(map(operator.mul, row, eps)) for e, row in zip(eps, h, strict=True))

    observed = stat([1] * n)
    patterns = 2 ** (n - 1)            # eps and -eps give the same statistic
    if patterns <= permutations + 1:
        hits = 0
        for signs in itertools.product((1, -1), repeat=n - 1):
            hits += _ge(stat((1, *signs)), observed)
        return observed, hits / patterns, True, 1.0 / patterns
    hits = 0
    for _ in range(permutations):
        eps = [rng.choice((1, -1)) for _ in range(n)]
        hits += _ge(stat(eps), observed)
    return observed, (1 + hits) / (1 + permutations), False, 1.0 / (1 + permutations)


def _unpaired(kmat: list[list[float]], na: int, nb: int, permutations: int,
              rng: random.Random) -> tuple[float, float, bool, float]:
    m = na + nb

    def stat(in_a: Sequence[bool]) -> float:
        s = [1.0 / na if x else -1.0 / nb for x in in_a]
        return sum(si * sum(map(operator.mul, row, s)) for si, row in zip(s, kmat, strict=True))

    observed = stat([True] * na + [False] * nb)
    total = math.comb(m, na)
    if total <= permutations + 1:
        hits = 0
        for chosen in itertools.combinations(range(m), na):
            mask = [False] * m
            for i in chosen:
                mask[i] = True
            hits += _ge(stat(mask), observed)
        return observed, hits / total, True, 1.0 / total
    hits = 0
    labels = [True] * na + [False] * nb
    for _ in range(permutations):
        rng.shuffle(labels)
        hits += _ge(stat(labels), observed)
    return observed, (1 + hits) / (1 + permutations), False, 1.0 / (1 + permutations)


def model_equality_test(
    outputs_a: Sequence[str],
    outputs_b: Sequence[str],
    *,
    paired: bool = True,
    permutations: int = 999,
    seed: int = 0,
) -> EqualityResult:
    """Two sample permutation test that the outputs come from the same model.

    Paired (default): outputs_a[i] and outputs_b[i] answer the same canary prompt i.
    Enumerates every relabelling exactly when there are at most `permutations + 1` of
    them, and samples `permutations` of them otherwise.
    """
    na, nb = len(outputs_a), len(outputs_b)
    if na < 2 or nb < 2:
        raise ValueError("need at least two outputs on each side")
    if paired and na != nb:
        raise ValueError("paired design needs one output per prompt on each side")
    if permutations < 1:
        raise ValueError("permutations must be positive")
    kmat = canary_kernel([*outputs_a, *outputs_b])
    rng = random.Random(seed)
    if paired:
        stat, p, exact, min_p = _paired(kmat, na, permutations, rng)
    else:
        stat, p, exact, min_p = _unpaired(kmat, na, nb, permutations, rng)
    return EqualityResult(statistic=stat, p_value=p, n_a=na, n_b=nb, paired=paired,
                          permutations=permutations, exact=exact, min_p_value=min_p)


__all__ = ["EqualityResult", "canary_kernel", "model_equality_test", "pair_outputs"]
