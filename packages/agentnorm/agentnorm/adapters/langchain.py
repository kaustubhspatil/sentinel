"""LangChain / LangGraph adapter.

LangChain reports tool starts and ends as separate callback events, often interleaved
across concurrent tools, so the `with` block used elsewhere cannot express them. This
handler tracks open calls by the framework's `run_id` and closes each one when its
matching end or error arrives.

**agentnorm does not depend on LangChain.** The base class is imported lazily and only if it
is installed; without it the handler still works as a plain object, because LangChain
duck-types handlers in the paths that matter. Keeping the dependency optional is
deliberate: a monitoring library that drags in an agent framework is unusable by anyone
running a different one, and half the point of agentnorm is comparing agents across
frameworks on equal footing.

    from agentnorm import Session
    from agentnorm.adapters.langchain import agentnorm_callback

    session = Session(agent="researcher", version="v2", principal="acme")
    graph.invoke(state, config={"callbacks": [agentnorm_callback(session)]})

    verdict = monitor.score(session.finish())
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
from uuid import UUID

from agentnorm.integrations import Session, default_size_of
from agentnorm.trace import RunRecorder, ToolCall


def _base_class() -> type:
    """LangChain's handler base if available, else `object`."""
    try:  # pragma: no cover - depends on the host environment
        from langchain_core.callbacks import BaseCallbackHandler

        return BaseCallbackHandler
    except Exception:  # noqa: BLE001 - any import failure means "not installed"
        return object


class AgentNormCallbackHandlerMixin:
    """The recording logic, independent of whether LangChain is installed."""

    # LangChain inspects these on handlers; supplied so a plain object still behaves.
    raise_error: bool = False
    run_inline: bool = False

    def __init__(
        self,
        recorder: RunRecorder,
        *,
        size_of: Callable[[str, dict[str, Any], Any], int] | None = None,
        scope_of: Callable[[str, dict[str, Any], Any], str | None] | None = None,
    ) -> None:
        self._rec = recorder
        self._size_of = size_of or default_size_of
        self._scope_of = scope_of
        self._open: dict[str, ToolCall] = {}
        self._args: dict[str, dict[str, Any]] = {}

    # --- LangChain callback surface ------------------------------------------

    def on_tool_start(
        self,
        serialized: dict[str, Any] | None,
        input_str: str,
        *,
        run_id: UUID | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        name = (serialized or {}).get("name") or kwargs.get("name") or "unknown_tool"
        args = dict(inputs or {}) or {"input": input_str}
        scope = ""
        if self._scope_of is not None:
            scope = self._scope_of(name, args, None) or ""
        call = self._rec.start_call(name, args, scope=scope)
        key = str(run_id)
        self._open[key] = call
        self._args[key] = args

    def on_tool_end(self, output: Any, *, run_id: UUID | None = None, **kwargs: Any) -> None:
        key = str(run_id)
        call = self._open.pop(key, None)
        if call is None:
            # An end without a start means the handler was attached mid-run. Dropping it
            # is correct: a call with no beginning has no duration and no arguments, and
            # inventing them would corrupt the baseline it feeds.
            return
        args = self._args.pop(key, {})
        size = int(self._size_of(call.tool, args, output))
        if self._scope_of is not None and not call.scope:
            call.scope = self._scope_of(call.tool, args, output) or ""
        self._rec.complete_call(call, ok=True, result_size=size)

    def on_tool_error(
        self, error: BaseException, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        key = str(run_id)
        call = self._open.pop(key, None)
        self._args.pop(key, None)
        if call is None:
            return
        self._rec.complete_call(
            call, ok=False, error=f"{type(error).__name__}: {error}"
        )

    # --- results --------------------------------------------------------------

    def finish(self):
        """Close any calls the framework never ended, then return the run.

        An agent killed mid-tool leaves an open call. Recording it as failed is more
        honest than discarding it — a run that ends inside a tool is itself a signal.
        """
        for call in self._open.values():
            self._rec.complete_call(call, ok=False, error="unterminated: run ended mid-call")
        self._open.clear()
        self._args.clear()
        return self._rec.finish()


def agentnorm_callback(
    target: Session | RunRecorder,
    *,
    size_of: Callable[[str, dict[str, Any], Any], int] | None = None,
    scope_of: Callable[[str, dict[str, Any], Any], str | None] | None = None,
) -> Any:
    """Build a LangChain callback handler recording into `target`.

    Accepts a `Session` or a `RunRecorder`; call `.finish()` on whichever you passed.
    """
    recorder = target._rec if isinstance(target, Session) else target
    base = _base_class()
    handler_cls = type(
        "AgentNormCallbackHandler", (AgentNormCallbackHandlerMixin, base), {}
    )
    return handler_cls(recorder, size_of=size_of, scope_of=scope_of)
