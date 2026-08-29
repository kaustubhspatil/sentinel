# Sentinel — working conventions

## What this is
An agentic IT-operations platform over a small, genuinely operated multi-cloud estate.
Ontology → knowledge graph → MCP tools → agents, with a validation layer that treats the
agents themselves as production models requiring back-testing and calibration.

Nothing is simulated unless the identifier says `synthetic_`. If a dataset is generated, it
is labelled, and it never enters an evaluation set unlabelled.

## Environment
- Python 3.11. Package is `sentinel`, source under `src/`, installed editable.
- Secrets load from outside the working tree (`~/.secrets/msp.env`). The repository is
  public: never commit a value, never inline a credential in code or docs.
- Host-specific addresses, keys and operator notes live in `docs/_private/` (gitignored).

## Design commitments
- **The graph holds meaning; the columnar store holds volume.** Time series never enter the
  graph.
- **Agent behaviour is modelled alongside the estate**, so scope escalation is a traversal
  rather than a log heuristic.
- **Measured or absent.** No number appears in the README until it has been produced by a
  reproducible run. A negative result that is measured beats a positive one asserted.
- Every design document states the alternative rejected and the cost accepted.

## Conventions
- No notebooks in the pipeline path; notebooks are for exploration only.
- Ingestion is idempotent and re-runnable; feeds are date-stamped in `data/raw/`.
- Prefer a plain function and a test over a framework.
