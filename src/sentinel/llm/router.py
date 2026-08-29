"""Model routing, fallback and per-call telemetry.

Routing is by *tier*, not by model name, so calling code says what it needs - "this is a
cheap classification" or "this has to be right" - and the mapping from that to a specific
model lives in one place. Changing which model serves a tier is then a config change
rather than a code change across the project.

Every call is recorded: provider, model, tokens, latency, estimated cost, whether it fell
back, and what it was for. That table is what turns "which model should we use" from an
opinion into a measurement, and it is the same shape of question the anomaly detectors ask
of agent behaviour.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

from sentinel.llm.base import LLMResponse, Message, ModelSpec
from sentinel.llm.providers import PROVIDERS
from sentinel.store.clickhouse import client

LLM_DDL = """
CREATE TABLE IF NOT EXISTS llm_calls (
    ts             DateTime64(3),
    purpose        LowCardinality(String),
    tier           LowCardinality(String),
    provider       LowCardinality(String),
    model          LowCardinality(String),
    ok             UInt8,
    fell_back      UInt8,
    input_tokens   UInt32,
    output_tokens  UInt32,
    latency_ms     UInt32,
    cost_usd       Float64,
    error          String,
    run_id         String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (purpose, provider, model, ts)
"""

# Prices are USD per million tokens, correct as a snapshot and centralised so there is one
# place to fix when they change.
#
# Provider order here is the outcome of testing what this account can actually reach, not
# a preference. See docs/llm-providers.md - two of the four intended providers turned out
# to be unreachable on the credits available, which is exactly the sort of thing that is
# cheaper to discover now than during an evaluation run.
CATALOGUE: dict[str, list[ModelSpec]] = {
    "small": [
        ModelSpec("azure", "model-router", 0.15, 0.60, "small"),
        ModelSpec("ollama", "qwen3:8b", 0.0, 0.0, "small"),
        ModelSpec("vertex", "gemini-2.5-flash", 0.30, 2.50, "small"),
        ModelSpec("gemini", "gemini-3.6-flash", 0.0, 0.0, "small"),
    ],
    "large": [
        ModelSpec("azure", "model-router", 2.50, 10.00, "large"),
        ModelSpec("vertex", "gemini-2.5-pro", 1.25, 10.00, "large"),
        ModelSpec("ollama", "qwen3:8b", 0.0, 0.0, "large"),
    ],
}


def apply_schema() -> None:
    client().command(LLM_DDL)


# Deployments that route to a reasoning model spend hidden reasoning tokens out of the
# same budget as the visible answer. A budget that looks generous for the answer alone
# can be consumed entirely before a single output character is produced - measured here:
# max_tokens=150 returned an empty completion with 150 completion tokens billed, while
# 1200 returned 308 tokens of real output. The floor exists so a caller cannot ask for a
# budget that is arithmetically incapable of producing an answer.
MIN_OUTPUT_TOKENS = 1024


@dataclass
class Router:
    """Try the preferred model for a tier, fall back down the list on failure."""

    max_attempts: int = 3
    record_telemetry: bool = True

    def _candidates(self, tier: str, prefer: str | None) -> list[ModelSpec]:
        specs = list(CATALOGUE.get(tier, CATALOGUE["small"]))
        if prefer:
            specs.sort(key=lambda s: 0 if s.provider == prefer else 1)
        # Only providers that are actually configured. Attempting an unconfigured
        # provider would burn an attempt on a certain failure.
        return [s for s in specs if PROVIDERS[s.provider].available()]

    def complete(
        self,
        messages: list[Message],
        *,
        tier: str = "small",
        purpose: str = "unspecified",
        prefer: str | None = None,
        run_id: str = "",
        **kwargs,
    ) -> LLMResponse:
        kwargs["max_tokens"] = max(int(kwargs.get("max_tokens", MIN_OUTPUT_TOKENS)),
                                   MIN_OUTPUT_TOKENS)
        candidates = self._candidates(tier, prefer)
        if not candidates:
            return LLMResponse("", "none", "", error="no configured provider for tier")

        last: LLMResponse | None = None
        for attempt, spec in enumerate(candidates[: self.max_attempts]):
            provider = PROVIDERS[spec.provider]
            resp = provider.complete(messages, spec.model, **kwargs)
            resp.fell_back = attempt > 0
            if self.record_telemetry:
                self._record(resp, spec, purpose, tier, run_id)
            if resp.ok and resp.text.strip():
                return resp
            last = resp
            # Brief backoff before trying another provider; an immediate retry mostly
            # rediscovers the same transient failure.
            time.sleep(0.5 * (attempt + 1))

        return last or LLMResponse("", "none", "", error="all providers failed")

    def _record(self, resp: LLMResponse, spec: ModelSpec, purpose: str, tier: str,
                run_id: str) -> None:
        try:
            client().insert(
                "llm_calls",
                [(
                    datetime.now(UTC), purpose, tier, resp.provider, resp.model,
                    1 if resp.ok else 0, 1 if resp.fell_back else 0,
                    resp.input_tokens, resp.output_tokens, resp.latency_ms,
                    spec.cost_usd(resp.input_tokens, resp.output_tokens),
                    resp.error[:500], run_id,
                )],
                column_names=[
                    "ts", "purpose", "tier", "provider", "model", "ok", "fell_back",
                    "input_tokens", "output_tokens", "latency_ms", "cost_usd", "error",
                    "run_id",
                ],
            )
        except Exception:  # noqa: BLE001
            # Telemetry must never break the call it is measuring.
            pass


router = Router()
