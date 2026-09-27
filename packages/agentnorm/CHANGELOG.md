# Changelog

## 0.2.0 (2026-09-27)

Three checks on the monitor itself, each with a reproducible experiment under `tools/`.

- `agentnorm.power`: detection power at the calibrated budget. `detection_power` plants
  one anomaly per held out benign run (`ExtraCalls`, `UnseenTool`, `ForeignScope`,
  `OversizedResult`, `Burst`) and reports the true positive rate per detector and per
  anomaly type next to the observed false positive rate, both with exact Clopper Pearson
  intervals. `measure_power` does the fit, calibration and test split; `blind_spots` names
  injectors shown to stay below a target rate
- `agentnorm.sequential`: `RateAlarm`, a one sided mixture martingale test that a monitored
  rate (flag share, wrong answer rate) is at most its baseline, safe to check after every
  observation; `RateConfidenceSequence`, a two sided beta binomial confidence sequence.
  Both closed form, O(1) per update
- `agentnorm.equality`: `model_equality_test`, a paired permutation MMD test on canary
  prompt outputs (character trigram and length kernel) for detecting a silent model change
  behind an API, with exact enumeration for small canary sets and `min_p_value` reported
- `agentnorm.stats`: regularised incomplete beta, binomial tail and Clopper Pearson
  intervals in the standard library
- Measured: naive peeking at a 1% rate raised a false alarm on 34.9% of stationary streams
  within 10,000 runs against 3.1% for `RateAlarm` (alpha 0.05); a paired canary test with 5
  prompts cannot reject at 0.05 at all

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
