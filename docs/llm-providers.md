# LLM providers: what this account can actually reach

The plan was four providers — Gemini free tier for bulk evaluation traffic, Vertex AI and
Azure OpenAI for genuine production calls, Ollama as an offline fallback. Testing them
produced a different answer, and the gap between plan and reality is worth recording,
because every one of these failures would otherwise have surfaced in the middle of an
evaluation run.

| Provider | Configured | Reachable | What happened |
|---|---|---|---|
| Azure OpenAI | yes | **yes** | Working on `model-router` |
| Vertex AI | yes (ADC) | no | `FAILED_PRECONDITION` — generative models are not served on this billing account |
| Gemini (AI Studio) | yes | no | `429 prepayment credits are depleted` — this key has no free quota |
| Ollama | yes | no model | Installed, zero models pulled |

## Details worth keeping

**Gemini has no free tier on this account.** The assumption that AI Studio would carry
thousands of evaluation calls at zero cost was simply wrong here: the key authenticates,
lists 39 models, and then returns `429 Your prepayment credits are depleted` on every
generation request. Separately, the `gemini-2.5-*` family now returns *"no longer
available to new users"* and points at `gemini-3.6-flash` — so a model name that works in
one account's documentation may not exist for another.

**Vertex is enabled and authorised but still refuses.** The API is enabled, the caller
holds `roles/aiplatform.user`, and the request returns `400 FAILED_PRECONDITION` with no
further detail. Generative models on Vertex are not available under this billing account's
terms. Enabled ≠ entitled, and the error says nothing useful about which.

**Azure OpenAI worked, but not with the obvious model.** `gpt-4o-mini` is refused as
`ServiceModelDeprecating`; `o3-mini` likewise; `gpt-4o` is refused for **zero TPM quota**
on a student subscription. `model-router` deployed and serves normally.

First successful call:

```
[OK] azure/model-router  3832ms  in=60 out=96
"Yes — that package is vulnerable; update to 3.0.13-0ubuntu3.15."
```

## The failure that looked like a success

The router fell back from Azure to Vertex to Gemini and reported Gemini's `429` — while
the telemetry table showed Azure had returned `ok=1` with 150 completion tokens. Both were
true.

`model-router` routes to a reasoning model, and reasoning tokens are spent from the same
budget as the visible answer. At `max_tokens=150` the entire budget went to hidden
reasoning: HTTP 200, usage reported, `content` empty. Nothing raised, so the only symptom
was the router moving on and surfacing a *later* provider's error, which pointed
diagnosis at entirely the wrong provider.

Measured directly:

```
max_tokens=150   -> FAIL  gemini/gemini-3.6-flash  (Azure returned empty, fell through)
max_tokens=1200  -> OK    azure/model-router  4303ms  out=308  fell_back=False
```

Two changes came out of it. The Azure provider now reports an empty completion as an
explicit error naming `finish_reason` and the completion-token count, rather than
returning success with no text. And the router enforces a minimum output budget, because
a caller should not be able to request a budget arithmetically incapable of producing an
answer.

The general lesson is that per-call telemetry is what made this findable at all. Without
the `ok` and `fell_back` columns the observable behaviour was "Gemini is rate-limited",
which is true, irrelevant, and would have sent the investigation to the wrong provider.

## Consequences for the design

The router's provider ordering is therefore an outcome, not a preference: Azure first
because it is the one that answers, Ollama second once a model is pulled, then Vertex and
Gemini which remain configured so they work the moment entitlement changes.

This is also the argument for having built the abstraction at all. Three of four intended
providers failed for three unrelated reasons — billing entitlement, missing free quota,
model deprecation — and none of that touched calling code. Had the first Azure deployment
attempt been wired directly into the workflows, the fix would have been spread across
every call site.

**Authentication note:** Vertex uses Application Default Credentials, not a key file. The
GCP org policy blocks service-account key creation
(`constraints/iam.disableServiceAccountKeyCreation`), which is the correct default —
long-lived key files are the most commonly leaked cloud credential. ADC covers both real
cases: a developer's `gcloud` login locally, and the backbone VM's own metadata identity.
No key ever exists on disk.

## Open items

- Pull a local model so the offline fallback is real rather than declared.
- The backbone VM returns `403` on Vertex rather than the `400` seen locally: its compute
  identity has `aiplatform.user` but the instance lacks the `cloud-platform` access scope.
  Scopes can only be changed while the instance is stopped, and Vertex is blocked by
  billing entitlement regardless, so this is recorded rather than fixed.
- The latency–cost Pareto across model tiers needs at least two working providers; with
  one reachable provider it is not yet a comparison.
