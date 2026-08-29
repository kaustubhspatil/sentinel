"""Provider-agnostic LLM interface.

The point of this layer is not abstraction for its own sake. It exists so that three
things are true at once:

  * the same prompt can be scored against several providers and model tiers, which is
    what makes a latency-cost comparison possible rather than anecdotal
  * a provider outage degrades to a fallback instead of failing the workflow
  * every call is measured - tokens, latency, cost, outcome - because an agent's model
    spend and tail latency are operational facts, not implementation details

Providers are deliberately thin. Anything clever (retries, routing, telemetry) lives in
the router, so adding a provider stays a small, obvious change.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class Message:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    finish_reason: str = ""
    # True when this came from a fallback rather than the requested provider, so the
    # eval harness can separate "the model was worse" from "we were served by another".
    fell_back: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass(frozen=True)
class ModelSpec:
    """A model plus what it costs, so routing can reason about price.

    Prices are USD per million tokens and are a snapshot: they change, and a stale price
    silently corrupts a cost comparison. Recorded here rather than hard-coded at the call
    site so there is exactly one place to correct.
    """

    provider: str
    model: str
    input_per_mtok: float
    output_per_mtok: float
    # Rough capability tier used for routing: "small" for classification and extraction,
    # "large" for reasoning that has to be right.
    tier: str = "small"

    def cost_usd(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.input_per_mtok / 1_000_000
            + output_tokens * self.output_per_mtok / 1_000_000
        )


class Provider(Protocol):
    name: str

    def available(self) -> bool:
        """Whether this provider is configured. Never raises."""
        ...

    def complete(self, messages: list[Message], model: str, **kwargs) -> LLMResponse:
        ...


@dataclass
class Timer:
    started: float = field(default_factory=time.perf_counter)

    @property
    def ms(self) -> int:
        return int((time.perf_counter() - self.started) * 1000)


def render_prompt(messages: list[Message]) -> tuple[str | None, list[Message]]:
    """Split a leading system message from the rest.

    Providers disagree about whether the system prompt is a message, a top-level field,
    or unsupported; normalising here keeps that disagreement out of the router.
    """
    if messages and messages[0].role == "system":
        return messages[0].content, messages[1:]
    return None, messages
