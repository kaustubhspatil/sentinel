"""Instrumenting an existing agent.

Adoption is the whole game for a monitoring library. If wiring it in means restructuring
an agent loop, it does not get wired in, and a monitor nobody instruments monitors
nothing. So the contract is: hand over the tool callables you already have, get back
callables with the same signatures that record as a side effect.

    session = Session(agent="triage", version="v3", principal="acme")
    tools = session.wrap({"search": search, "fetch": fetch})
    ...
    verdict = monitor.score(session.finish())

This works with plain functions, LangChain tools, MCP tool functions and anything else
callable, because it makes no assumptions beyond that.

Two hooks exist because the library cannot know these and guessing them silently would be
worse than asking:

`size_of` - how much data did this call return? The default handles the common shapes
(sequences, and dicts with a `count`/`results`/`rows` key) and falls back to 1. Volume
detection is only as good as this number, so an agent returning a custom envelope should
supply its own.

`scope_of` - which principal does this call's data belong to? Without it, scope violation
cannot be detected at all: agentnorm can see that a call happened but not whose data it
touched. Returning None means "unknown", which is treated as in-scope rather than as a
violation, because a false accusation of cross-tenant access is worse than a miss.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sized
from typing import Any

from agentnorm.trace import Run, RunRecorder

SizeOf = Callable[[str, dict[str, Any], Any], int]
ScopeOf = Callable[[str, dict[str, Any], Any], str | None]


def default_size_of(tool: str, args: dict[str, Any], result: Any) -> int:  # noqa: ARG001
    """Best-effort result size for common return shapes."""
    if result is None:
        return 0
    if isinstance(result, Mapping):
        for key in ("count", "total", "n"):
            value = result.get(key)
            if isinstance(value, int):
                return value
        for key in ("results", "rows", "items", "data", "neighbours"):
            value = result.get(key)
            if isinstance(value, Sized):
                return len(value)
        return 1
    if isinstance(result, (str, bytes)):
        return 1
    if isinstance(result, Sized):
        return len(result)
    return 1


class Session:
    """One agent run, with tools instrumented in place."""

    def __init__(
        self,
        agent: str,
        *,
        version: str = "unversioned",
        principal: str = "",
        actor_kind: str = "agent",
        size_of: SizeOf | None = None,
        scope_of: ScopeOf | None = None,
    ) -> None:
        self._rec = RunRecorder(
            agent, version=version, principal=principal, actor_kind=actor_kind
        )
        self._size_of = size_of or default_size_of
        self._scope_of = scope_of

    def wrap(self, tools: Mapping[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
        """Return the same tools, recording as a side effect."""
        return {name: self.wrap_one(name, fn) for name, fn in tools.items()}

    def wrap_one(self, name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            # Positional arguments are recorded by index. Tool protocols are almost
            # always keyword-based, and inspecting signatures to name them would add a
            # failure mode for no real benefit.
            recorded = {**{str(i): a for i, a in enumerate(args)}, **kwargs}
            with self._rec.tool_call(name, recorded) as call:
                result = fn(*args, **kwargs)
                call.result_size = int(self._size_of(name, recorded, result))
                if self._scope_of is not None:
                    scope = self._scope_of(name, recorded, result)
                    call.scope = scope or ""
                return result

        wrapped.__name__ = getattr(fn, "__name__", name)
        wrapped.__doc__ = getattr(fn, "__doc__", None)
        return wrapped

    def finish(self) -> Run:
        return self._rec.finish()

    @property
    def run(self) -> Run:
        return self._rec.run
