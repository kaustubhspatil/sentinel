"""Assert that agentnorm imports nothing third-party at module scope.

The zero-dependency claim is the library's main adoption argument, so it is enforced
rather than asserted in prose.

The rule is about *import time*, not about mentioning a package at all. An adapter may
import an optional framework lazily inside a function - that is precisely how an optional
dependency works, and `agentnorm.adapters.langchain` does it so the handler degrades to a
plain object when LangChain is absent. What must never happen is a module-scope import
that makes `import agentnorm` fail for someone who does not have that package.

So: imports at module scope must be standard library. Imports inside a function body are
allowed, and are reported so the set of optional dependencies stays visible.
"""
from __future__ import annotations

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1] / "agentnorm"
STDLIB = set(sys.stdlib_module_names)


def _module_level_imports(tree: ast.Module) -> set[str]:
    """Imports that run when the module is imported.

    Descends into conditionals and try/except at module scope, because those still
    execute on import, but never into function or class bodies.
    """
    found: set[str] = set()

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Import):
                found.update(a.name.split(".")[0] for a in child.names)
            elif isinstance(child, ast.ImportFrom) and child.module and child.level == 0:
                found.add(child.module.split(".")[0])
            visit(child)

    visit(tree)
    return found


def _deferred_imports(tree: ast.Module) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Import):
                    found.update(a.name.split(".")[0] for a in inner.names)
                elif isinstance(inner, ast.ImportFrom) and inner.module and inner.level == 0:
                    found.add(inner.module.split(".")[0])
    return found


def main() -> int:
    eager: set[str] = set()
    lazy: set[str] = set()
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        eager |= _module_level_imports(tree)
        lazy |= _deferred_imports(tree)

    external_eager = sorted(m for m in eager if m not in STDLIB and m != "agentnorm")
    external_lazy = sorted(m for m in lazy if m not in STDLIB and m != "agentnorm")

    if external_lazy:
        print("optional dependencies (imported lazily, safe):", ", ".join(external_lazy))
    if external_eager:
        print(f"FAIL: agentnorm imports these at module scope: {external_eager}")
        print("      `import agentnorm` would fail without them installed.")
        return 1
    print("zero-dependency claim holds: nothing third-party is imported at module scope")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
