# Contributing to Sentinel

Sentinel is a reference deployment and research repository. It exists so the method and the
measurements can be inspected and argued with, not as software to install. That shapes what
a useful contribution looks like.

## Do not point it at production

The estate here is a small, disposable lab. Configuration, firewall rules and topology are
sized for a demonstration and are not a recommendation for a production fleet. Please do
not run it against infrastructure you care about, and please do not open issues about the
lab's own hardening — that is out of scope and noted in [SECURITY.md](SECURITY.md).

## Running the checks

```bash
pytest tests
ruff check src tests
```

The library in `packages/agentnorm/` has its own suite and its own stricter rules; see
[`packages/agentnorm/CONTRIBUTING.md`](packages/agentnorm/CONTRIBUTING.md). Most changes to
detection logic belong there rather than here.

## What is most useful

**Corrections to the measurements.** If a number in the README or in `docs/` is wrong,
cannot be reproduced from what is in the repository, or is presented in a way that
overstates it, that is the single most valuable issue you can open. Several findings here
exist because an earlier version of the analysis was wrong and got checked — a name-based
CVE heuristic that claimed 28 matches had in fact found none of them.

**Faults in derived metadata.** The OpenAPI connector infers risk, resource and scope from
a specification. A destructive operation classified as safe, or a wrong scope parameter,
propagates into the monitoring policy. Those are real defects, not cosmetic ones.

**Reproduction failures.** If a documented result does not reproduce for you, say so with
what you ran.

## Conventions

- No secrets, credentials, live host addresses, or customer data in commits. Anything of
  that kind is a mistake — report it via the security policy and it will be rotated, not
  just deleted.
- Claims need a measurement, and the measurement needs its limitations stated alongside it.
- Say what you ran and what it printed.

Behaviour in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
