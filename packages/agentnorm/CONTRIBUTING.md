# Contributing to agentnorm

Contributions are welcome. This file covers the two things that are easy to get wrong here
and the standard that measured claims are held to.

## The hard constraint: no runtime dependencies

agentnorm imports nothing outside the standard library at module scope, and CI enforces it
with an AST walk (`tools/check_zero_deps.py`). This is not stylistic. The package is meant
to be installable into an existing agent stack without contributing anything to its
dependency resolution or its supply chain.

Optional integrations import lazily, inside the function that needs them:

```python
def agentnorm_callback(session):
    from langchain_core.callbacks import BaseCallbackHandler  # lazy, inside the function
```

The checker allows that and reports it, so the optional set stays visible. If a change
needs a third-party package at module scope, the answer is almost always to restructure
rather than to add it.

## Running the checks

```bash
pip install -e ".[dev]"
pytest                          # 71 tests
ruff check .
python tools/check_zero_deps.py
```

CI runs these against Python 3.10 through 3.13. Mind the floor: `datetime.UTC` is 3.11+,
so use `timezone.utc`. That one has already cost a red build.

## The standard for a claim

This project's value is that its numbers are real, so a change that asserts a detector is
better needs a measurement, on a split that the thresholds were not fitted on, and an
honest statement of what the measurement does not show.

Negative and partial results are genuinely welcome — the most useful finding in the
repository is that half the quantities cannot be pooled across agents, and it is documented
because it is true, not because it flatters the design. A PR that says "I tried this and it
did not work, here is the number" is a contribution.

Two things to avoid: reporting a recall figure from generated anomalies without saying it
is a ceiling, and tuning a threshold against the test split.

## Scope

In scope: detectors, the cold-start behaviour, the audit trail, adapters for agent
frameworks, documentation and tests.

Out of scope: anything that puts agentnorm in the agent's request path. It observes and
scores; it does not proxy, wrap, or block calls. That separation is the design and changing
it would make it a different tool.

## Before you open a PR

- Use synthetic data in issues and PRs. No real traces, audit records, credentials, or
  customer identifiers.
- Say what you ran and what it printed.
- Small, single-purpose changes get reviewed faster than large ones.

Behaviour in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Vulnerabilities go through the [security policy](SECURITY.md), not a public issue.
