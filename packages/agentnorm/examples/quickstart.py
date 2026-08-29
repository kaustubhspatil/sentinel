"""Instrument an agent you already have, in five lines.

Run:  python examples/quickstart.py
"""
import random
import tempfile
from pathlib import Path

from agentnorm import JsonlStore, Monitor, Session

# --- an agent you already have -------------------------------------------------
DB = {"acme": list(range(20)), "globex": list(range(400))}


def search_tickets(query: str, tenant: str = "acme") -> dict:
    rows = DB[tenant][: random.randint(5, 25)]
    return {"count": len(rows), "results": rows, "tenant": tenant}


def export_all(tenant: str = "acme") -> dict:
    return {"count": len(DB[tenant]), "results": DB[tenant], "tenant": tenant}


TOOLS = {"search_tickets": search_tickets, "export_all": export_all}


def run_agent(store, *, tenant="acme", tools=("search_tickets",), agent="triage",
              version="v1"):
    """One agent episode, instrumented."""
    session = Session(
        agent=agent, version=version, principal=tenant,
        scope_of=lambda tool, args, result: args.get("tenant"),
    )
    wrapped = session.wrap(TOOLS)
    for name in tools:
        wrapped[name]("urgent", tenant=tenant) if name == "search_tickets" else wrapped[name](tenant=tenant)
    run = session.finish()
    store.append(run)
    return run


def main() -> None:
    path = Path(tempfile.mkdtemp()) / "history.jsonl"
    store = JsonlStore(path)

    # 1. Accumulate normal behaviour.
    for _ in range(300):
        run_agent(store, tenant=random.choice(["acme", "globex"]))

    # 2. Learn from it.
    monitor = Monitor.fit(store.read())
    print(f"fitted on {len(store.read())} runs; thresholds: "
          + ", ".join(f"{k}={v:.2f}" for k, v in monitor.thresholds.items()))
    for w in monitor.warnings:
        print("  warning:", w)

    # 3. Score new runs.
    print("\nnormal run          ->", monitor.score(run_agent(store, tenant="acme")).explain())

    exfil = Session(agent="triage", version="v1", principal="acme",
                    scope_of=lambda t, a, r: a.get("tenant"))
    exfil.wrap(TOOLS)["export_all"](tenant="globex")   # wrong tenant AND huge result
    print("exfiltration attempt ->", monitor.score(exfil.finish()).explain())

    print("new agent version   ->",
          monitor.score(run_agent(store, agent="triage", version="v2")).explain())
    print("unknown agent       ->",
          monitor.score(run_agent(store, agent="rogue", version="v1")).explain())


if __name__ == "__main__":
    main()
