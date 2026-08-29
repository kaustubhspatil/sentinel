# Changelog

## 0.1.0 (unreleased)

First release.

- `RunRecorder` / `Session` for recording agent runs, with tool wrapping that leaves
  existing call signatures untouched
- Five detectors: hierarchical volume baseline, sequence surprisal, scope violation,
  novel tool, rate
- Cold-start handling as an explicit per-detector decision - pool, assert or suppress -
  after a suite without it alerted on 100% of known-benign runs from an unseen agent
- Thresholds set by false-positive budget, divided across detectors, with a warning when
  the calibration set is too small to estimate the requested quantile
- `JsonlStore` for zero-infrastructure history; `Store` is a protocol
- LangChain / LangGraph adapter with no hard dependency on either
- `agentnorm.evaluation` for measuring a suite against labelled runs and sweeping the
  settings chosen by judgement
- Tamper-evident audit trail (`agentnorm.audit`) following the IETF
  `draft-sharif-agent-audit-trail` format: SHA-256 chained over RFC 8785 canonical records,
  delegation records for multi-agent chains, and verification that reports the first broken
  record rather than a boolean
