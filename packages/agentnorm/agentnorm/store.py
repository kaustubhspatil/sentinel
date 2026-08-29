"""Persisting runs, with no database.

`Monitor.fit` needs history, so a monitoring library that cannot remember anything is
useless in practice even if its detectors are perfect. This is the smallest thing that
solves it: append-only JSON Lines, one run per line, standard library only.

Append-only rather than a mutable format is deliberate. Behavioural history is evidence;
if an incident is investigated later, a store that can be rewritten in place is worth
much less than one that can only be appended to. It is also crash-safe in the only way
that matters here — a truncated final line loses one run, not the file.

For real volume, use a real store. `Store` is a protocol so a ClickHouse or Postgres
implementation is a drop-in; the reference deployment uses ClickHouse.
"""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from agentnorm.trace import Run, ToolCall


class Store(Protocol):
    def append(self, run: Run) -> None: ...
    def read(self, *, agent: str | None = None, limit: int | None = None) -> list[Run]: ...


def _encode(run: Run) -> str:
    d = asdict(run)
    d["started_at"] = run.started_at.isoformat()
    for call, raw in zip(run.calls, d["calls"], strict=True):
        raw["started_at"] = call.started_at.isoformat()
        raw.pop("_started", None)   # monotonic timing slot, not part of the format
        # Arguments are recorded for post-hoc analysis, but they are the most likely
        # place for secrets and personal data to appear. Anything unserialisable is
        # stringified rather than dropped, so a trace never fails to persist because a
        # tool returned an exotic type.
        raw["args"] = {k: _safe(v) for k, v in raw["args"].items()}
    return json.dumps(d, separators=(",", ":"))


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)[:500]


def _decode(line: str) -> Run:
    d = json.loads(line)
    calls = [
        ToolCall(**{**c, "started_at": datetime.fromisoformat(c["started_at"])})
        for c in d.pop("calls", [])
    ]
    d["started_at"] = datetime.fromisoformat(d["started_at"])
    return Run(calls=calls, **d)


class JsonlStore:
    """Append-only run history in a JSON Lines file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, run: Run) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_encode(run) + "\n")

    def extend(self, runs: Iterable[Run]) -> int:
        n = 0
        with self.path.open("a", encoding="utf-8") as fh:
            for run in runs:
                fh.write(_encode(run) + "\n")
                n += 1
        return n

    def __iter__(self) -> Iterator[Run]:
        if not self.path.is_file():
            return
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield _decode(line)
                except (json.JSONDecodeError, TypeError, ValueError):
                    # A truncated final line from an interrupted write costs one run,
                    # not the file. Silently skipping it is the right trade for an
                    # append-only log.
                    continue

    def read(self, *, agent: str | None = None, limit: int | None = None) -> list[Run]:
        runs = [r for r in self if agent is None or r.agent == agent]
        return runs[-limit:] if limit else runs

    def __len__(self) -> int:
        return sum(1 for _ in self)
