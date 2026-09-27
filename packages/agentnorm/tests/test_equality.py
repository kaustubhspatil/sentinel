"""Model equality testing on canary outputs."""
from __future__ import annotations

import random

import pytest

from agentnorm.equality import canary_kernel, model_equality_test, pair_outputs


def terse(rng: random.Random, i: int) -> str:
    return f"The limit for desk {i} is {rng.randint(10, 99)}."


def verbose(rng: random.Random, i: int) -> str:
    return (f"**Answer:** Based on the excerpts provided, the applicable limit for desk {i} "
            f"is set at `{rng.randint(10, 99)}` units, per the policy document.\n\n- Source: [1]")


def same_model(rng: random.Random, i: int) -> str:
    """A 'model' with randomness of its own, so equal models do not give equal text."""
    return terse(rng, i) if rng.random() < 0.6 else verbose(rng, i)


def test_identical_outputs_are_never_rejected():
    rng = random.Random(0)
    outs = [same_model(rng, i) for i in range(30)]
    result = model_equality_test(outs, list(outs))
    assert result.p_value == 1.0
    assert not result.rejected()


def test_different_styles_are_rejected():
    rng = random.Random(1)
    a = [terse(rng, i) for i in range(15)]
    b = [verbose(rng, i) for i in range(15)]
    result = model_equality_test(a, b)
    assert result.rejected(0.01)
    assert result.statistic > 0


def test_five_prompts_cannot_reject_at_five_percent():
    """With one output per prompt, the paired test has 2^(n-1) relabellings."""
    rng = random.Random(2)
    a = [terse(rng, i) for i in range(5)]
    b = [verbose(rng, i) for i in range(5)]
    result = model_equality_test(a, b)
    assert result.exact
    assert result.min_p_value == pytest.approx(1 / 16)
    assert result.p_value == pytest.approx(1 / 16)   # as extreme as possible, still > 0.05
    assert not result.rejected(0.05)


def test_small_designs_are_enumerated_exactly_and_large_ones_sampled():
    rng = random.Random(3)
    small = model_equality_test([same_model(rng, i) for i in range(8)],
                                [same_model(rng, i) for i in range(8)])
    assert small.exact and small.min_p_value == pytest.approx(1 / 128)
    large = model_equality_test([same_model(rng, i) for i in range(20)],
                                [same_model(rng, i) for i in range(20)], permutations=199)
    assert not large.exact and large.min_p_value == pytest.approx(1 / 200)


def test_paired_false_positive_rate_is_at_most_alpha_under_the_null():
    rng = random.Random(4)
    trials, rejections = 300, 0
    for t in range(trials):
        a = [same_model(rng, i) for i in range(10)]
        b = [same_model(rng, i) for i in range(10)]
        rejections += model_equality_test(a, b, seed=t).rejected(0.05)
    # exact test: rejection count is Binomial(300, <= 0.05); mean 15, sd 3.8
    assert rejections <= 27


def test_unpaired_design():
    rng = random.Random(5)
    a = [terse(rng, i) for i in range(5)]
    b = [verbose(rng, i + 100) for i in range(5)]
    result = model_equality_test(a, b, paired=False)
    assert result.exact and result.min_p_value == pytest.approx(1 / 252)
    assert result.rejected(0.05)
    uneven = model_equality_test(a, b + [verbose(rng, 7)], paired=False)
    assert uneven.n_b == 6


def test_unpaired_false_positive_rate_under_exchangeable_null():
    rng = random.Random(6)
    rejections = 0
    for t in range(200):
        a = [same_model(rng, rng.randint(0, 999)) for _ in range(12)]
        b = [same_model(rng, rng.randint(0, 999)) for _ in range(12)]
        rejections += model_equality_test(a, b, paired=False, permutations=199,
                                          seed=t).rejected(0.05)
    assert rejections <= 20   # Binomial(200, <= 0.05): mean 10, sd 3.1


def test_pair_outputs_aligns_and_drops_empty_symmetrically():
    a = {"q1": "x", "q2": "", "q3": "z", "q4": "only in a"}
    b = {"q3": "Z", "q1": "X", "q2": "y", "q5": "only in b"}
    ids, oa, ob = pair_outputs(a, b)
    assert ids == ["q1", "q3"] and oa == ["x", "z"] and ob == ["X", "Z"]
    ids, _, _ = pair_outputs(a, b, drop_empty=False)
    assert ids == ["q1", "q2", "q3"]


def test_kernel_is_symmetric_with_unit_components_on_the_diagonal():
    k = canary_kernel(["alpha beta", "gamma", "alpha beta gamma delta", ""])
    assert all(k[i][j] == pytest.approx(k[j][i]) for i in range(4) for j in range(4))
    assert k[0][0] == pytest.approx(2.0)   # cosine 1 plus Gaussian 1
    assert k[3][3] == pytest.approx(1.0)   # empty text has no trigram profile


def test_bad_arguments_are_rejected():
    with pytest.raises(ValueError):
        model_equality_test(["a", "b"], ["a", "b", "c"])
    with pytest.raises(ValueError):
        model_equality_test(["a"], ["b"], paired=False)
    with pytest.raises(ValueError):
        model_equality_test(["a", "b"], ["c", "d"], permutations=0)


def test_new_checks_are_exported_at_the_top_level():
    import agentnorm
    for name in ("detection_power", "measure_power", "PowerReport", "RateAlarm",
                 "RateConfidenceSequence", "model_equality_test", "EqualityResult"):
        assert hasattr(agentnorm, name) and name in agentnorm.__all__
