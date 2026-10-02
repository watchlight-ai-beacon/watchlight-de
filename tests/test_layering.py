"""The package's layering rules, enforced on its source.

Each module of ``watchlight`` belongs to exactly one layer, and a layer may
import only the layers named for it in :data:`ALLOWED`. The rules keep each
guarantee enforced in one place:

* only the governor imports the compiled engine (``watchlight_engine``) — one
  engine boundary, so there is one place a decision is made;
* a framework integration reaches governance only through the backend seam
  (``watchlight.inprocess``) and the integration contract — never the
  governor's internals, the audit trail, or the scope code;
* the foundation (audit, scopes, approvals, annotations, …) never imports the
  governor, the CLI or an integration;
* no import cycles.

Deny by default: a module that is in no layer fails here, with a message saying
where to put it. Imports inside functions count — a lazy import is still a
dependency. Standard library only, so it runs on every interpreter CI runs.
"""

from __future__ import annotations

import ast
import pathlib
from typing import Dict, List, Optional, Set

import watchlight

PACKAGE = "watchlight"
SRC = pathlib.Path(watchlight.__file__).resolve().parent

# Module → layer. Integration modules (``watchlight.integrations.*``) are
# assigned by prefix in :func:`layer_of`.
LAYERS: Dict[str, str] = {
    # foundation: self-contained building blocks the governor composes
    "watchlight.principals": "foundation",
    "watchlight._annotations": "foundation",
    "watchlight._approval": "foundation",
    "watchlight._audit": "foundation",
    "watchlight._counters": "foundation",
    "watchlight.scope_token": "foundation",
    "watchlight.attenuation": "foundation",
    "watchlight.policytest": "foundation",
    # the backend seam framework plugins are wired to
    "watchlight.inprocess": "seam",
    # the governor: the decorator / guard API over the engine
    "watchlight": "governor",
    # public framework entry points (``watchlight.<framework>``)
    "watchlight.langgraph": "integration",
    "watchlight.pydantic_ai": "integration",
    "watchlight.claude_agent": "integration",
    # the command line sits on top of everything
    "watchlight.cli": "cli",
}

ALLOWED: Dict[str, Set[str]] = {
    "foundation": {"foundation"},
    "seam": set(),
    "governor": {"foundation"},
    "integration": {"seam", "integration"},
    "cli": {"foundation", "seam", "governor", "integration"},
}

# The compiled engine and the published framework/SDK packages, and the only
# modules allowed to import each.
EXTERNAL_OWNERS: Dict[str, Set[str]] = {
    "watchlight_engine": {"watchlight"},
    "watchlight_core": {"watchlight.inprocess"},
}
FRAMEWORK_PACKAGES = {"watchlight_langgraph", "watchlight_pydantic_ai", "watchlight_claude_agent"}
# Integrations not yet on the contract still import their plugin directly. The
# contract imports it lazily for the others. This set only shrinks: an entry
# that no longer imports its plugin fails :func:`test_the_legacy_allowance_only_shrinks`.
LEGACY_FRAMEWORK_IMPORTERS = {"watchlight.pydantic_ai", "watchlight.claude_agent"}


def layer_of(module: str) -> Optional[str]:
    if module == "watchlight.integrations" or module.startswith("watchlight.integrations."):
        return "integration"
    return LAYERS.get(module)


def module_name(path: pathlib.Path, root: pathlib.Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join([PACKAGE, *parts])


def imports_of(module: str, source: str, is_package: bool, known: Set[str]) -> Set[str]:
    """Every module ``source`` imports, top level or not."""
    found: Set[str] = set()
    package = module if is_package else module.rpartition(".")[0]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                found.add(candidate if candidate in known else base)
    return found


def check(sources: Dict[str, str], packages: Set[str]) -> List[str]:
    """Return every rule violation in ``sources`` (module name → source)."""
    known = set(sources)
    graph = {m: imports_of(m, src, m in packages, known) for m, src in sources.items()}
    violations: List[str] = []

    for module, deps in sorted(graph.items()):
        layer = layer_of(module)
        if layer is None:
            violations.append(
                f"{module} is in no layer: add it to LAYERS in tests/test_layering.py "
                f"(foundation, seam, governor, integration or cli)"
            )
            continue
        for dep in sorted(deps):
            top = dep.split(".")[0]
            if dep in known:
                dep_layer = layer_of(dep)
                if dep_layer is not None and dep_layer != layer and dep_layer not in ALLOWED[layer]:
                    violations.append(f"{module} ({layer}) imports {dep} ({dep_layer})")
            elif top in EXTERNAL_OWNERS and module not in EXTERNAL_OWNERS[top]:
                violations.append(f"{module} imports {top}: only {sorted(EXTERNAL_OWNERS[top])} may")
            elif top in FRAMEWORK_PACKAGES and module not in LEGACY_FRAMEWORK_IMPORTERS:
                violations.append(
                    f"{module} imports {top} directly: declare a FrameworkIntegration and "
                    f"let the contract import it"
                )

    # Cycles, over intra-package edges.
    WHITE, GREY, BLACK = 0, 1, 2
    colour = {m: WHITE for m in graph}
    stack: List[str] = []

    def visit(m: str) -> None:
        colour[m] = GREY
        stack.append(m)
        for dep in sorted(graph[m] & known):
            if colour[dep] == GREY:
                cycle = stack[stack.index(dep) :] + [dep]
                violations.append("import cycle: " + " -> ".join(cycle))
            elif colour[dep] == WHITE:
                visit(dep)
        stack.pop()
        colour[m] = BLACK

    for m in sorted(graph):
        if colour[m] == WHITE:
            visit(m)
    return violations


def package_sources():
    sources, packages = {}, set()
    for path in sorted(SRC.rglob("*.py")):
        name = module_name(path, SRC)
        sources[name] = path.read_text(encoding="utf-8")
        if path.name == "__init__.py":
            packages.add(name)
    return sources, packages


# ── the rules hold on the package as it is ──────────────────────────────────


def test_the_package_keeps_its_layers():
    sources, packages = package_sources()
    assert check(sources, packages) == []


def test_every_module_was_seen():
    # Guards the walker itself: a checker that finds nothing passes everything.
    sources, packages = package_sources()
    assert {"watchlight", "watchlight.integrations._contract", "watchlight.cli"} <= set(sources)
    # ... and resolves the edges it judges: the engine boundary, a relative
    # import two levels up, and a lazy import inside a function.
    known = set(sources)
    assert "watchlight_engine" in imports_of("watchlight", sources["watchlight"], True, known)
    contract = "watchlight.integrations._contract"
    assert "watchlight.inprocess" in imports_of(contract, sources[contract], False, known)
    assert "watchlight" in imports_of("watchlight.cli", sources["watchlight.cli"], False, known)


def test_the_legacy_allowance_only_shrinks():
    sources, packages = package_sources()
    for module in LEGACY_FRAMEWORK_IMPORTERS:
        deps = imports_of(module, sources[module], module in packages, set(sources))
        assert {d.split(".")[0] for d in deps} & FRAMEWORK_PACKAGES, (
            f"{module} no longer imports its plugin: remove it from LEGACY_FRAMEWORK_IMPORTERS"
        )


# ── the checker catches what it is for (revert-the-rule self-tests) ─────────


def _with(module: str, source: str, *, package: bool = False) -> List[str]:
    sources, packages = package_sources()
    sources[module] = source
    if package:
        packages.add(module)
    return check(sources, packages)


def test_it_catches_an_integration_reaching_into_the_audit_trail():
    found = _with("watchlight.integrations.langgraph", "from .._audit import AuditTrail\n")
    assert any("integrations.langgraph (integration) imports watchlight._audit" in v for v in found)


def test_it_catches_an_integration_importing_the_governor():
    found = _with("watchlight.integrations.langgraph", "def f():\n    from watchlight import govern\n")
    assert any("imports watchlight (governor)" in v for v in found)


def test_it_catches_the_foundation_importing_the_governor():
    found = _with("watchlight._audit", "from . import Watchlight\n")
    assert any("watchlight._audit (foundation) imports watchlight (governor)" in v for v in found)


def test_it_catches_a_second_engine_boundary():
    found = _with("watchlight.attenuation", "import watchlight_engine\n")
    assert any("watchlight.attenuation imports watchlight_engine" in v for v in found)


def test_it_catches_an_integration_importing_its_plugin_directly():
    found = _with("watchlight.integrations.langgraph", "from watchlight_langgraph import X\n")
    assert any("imports watchlight_langgraph directly" in v for v in found)


def test_it_catches_a_module_in_no_layer():
    found = _with("watchlight.newthing", "")
    assert any("watchlight.newthing is in no layer" in v for v in found)


def test_it_catches_a_cycle():
    found = _with("watchlight.principals", "from . import _counters\n")
    assert any(v.startswith("import cycle:") and "watchlight.principals" in v for v in found)
