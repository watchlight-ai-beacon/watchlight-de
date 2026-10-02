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
* no import cycles;
* no dynamic import the checker cannot read: ``importlib.import_module`` and
  ``__import__`` with a literal name count as imports, and any other dynamic
  import (or a reference to those functions) is refused outside the
  integration contract, whose one dynamic import is attributed to the plugin
  packages the registry declares;
* no other way of loading code in the foundation or an integration: calls to
  ``exec``/``eval``/``compile``, ``runpy``, ``importlib.util``, ``sys.modules``,
  and ``vars()``/``__dict__`` lookups on ``importlib`` or ``builtins``.

This catches the common forms of loading code by another route. It is not
exhaustive (Python offers more ways than a static check can enumerate); code
review catches the rest.

Deny by default: a module that is in no layer fails here, with a message saying
where to put it. Imports inside functions count — a lazy import is still a
dependency. Standard library only, so it runs on every interpreter CI runs.
"""

from __future__ import annotations

import ast
import pathlib
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

import pytest

import watchlight
from watchlight.integrations import INTEGRATIONS

PACKAGE = "watchlight"
# The source tree this test sits next to, so a stale installed copy is never
# what gets checked. Fall back to the installed package only when the tests run
# outside a checkout.
_CHECKOUT = pathlib.Path(__file__).resolve().parent.parent / "src" / PACKAGE
SRC = _CHECKOUT if (_CHECKOUT / "__init__.py").is_file() else pathlib.Path(watchlight.__file__).resolve().parent

CONTRACT = "watchlight.integrations._contract"

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
# Kept independent of the contract's own pattern on purpose: a weakened check
# there does not weaken this one.
PLUGIN_MODULE = re.compile(r"^watchlight_[a-z0-9_]+$")


def is_framework_package(top: str) -> bool:
    """A published framework plugin: one the registry declares, or any
    top-level ``watchlight_*`` package other than the engine and the SDK — so a
    new plugin is covered without editing this file."""
    declared = {i.plugin_module.split(".")[0] for i in INTEGRATIONS.values()}
    return top in declared or (top.startswith("watchlight_") and top not in EXTERNAL_OWNERS)


def plugin_module_violations(modules: Iterable[Tuple[str, str]]) -> List[str]:
    """(integration name, plugin_module) pairs that are not a framework plugin."""
    return [
        f"integration {name}: plugin_module {mod!r} is not a watchlight_* framework plugin"
        for name, mod in modules
        if not (isinstance(mod, str) and PLUGIN_MODULE.match(mod) and mod not in EXTERNAL_OWNERS)
    ]

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


_DYNAMIC_FUNCS = {"import_module", "__import__"}


def analyse(module: str, source: str, is_package: bool, known: Set[str]) -> Tuple[Set[str], List[str]]:
    """Every module ``source`` imports, top level or not, and every dynamic
    import in it the checker cannot resolve to a name."""
    found: Set[str] = set()
    dynamic: List[str] = []
    package = module if is_package else module.rpartition(".")[0]
    tree = ast.parse(source)

    # Names bound to importlib, builtins and import_module/__import__.
    importlib_names: Set[str] = set()
    builtins_names: Set[str] = set()
    import_fn_names: Set[str] = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if alias.name == "importlib" or alias.name.startswith("importlib."):
                    importlib_names.add(bound)
                elif alias.name == "builtins":
                    builtins_names.add(bound)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module in ("importlib", "builtins"):
            for alias in node.names:
                if alias.name in _DYNAMIC_FUNCS or alias.name == "*":
                    import_fn_names.add(alias.asname or alias.name)

    def is_import_fn(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in import_fn_names
        if isinstance(expr, ast.Attribute) and expr.attr in _DYNAMIC_FUNCS:
            return isinstance(expr.value, ast.Name) and expr.value.id in (importlib_names | builtins_names)
        return False

    called: Set[int] = set()
    for node in ast.walk(tree):
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
        elif isinstance(node, ast.Call):
            if is_import_fn(node.func):
                called.add(id(node.func))
                arg = node.args[0] if node.args else None
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, str)
                    and arg.value
                    and not arg.value.startswith(".")
                ):
                    found.add(arg.value)
                else:
                    dynamic.append(f"line {node.lineno}: dynamic import of a non-literal or relative name")
            elif (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in _DYNAMIC_FUNCS
            ):
                dynamic.append(f"line {node.lineno}: getattr(..., {node.args[1].value!r})")

    # A reference that is not a direct call (``f = importlib.import_module``)
    # hides the import from the walk above.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Name, ast.Attribute)) and is_import_fn(node) and id(node) not in called:
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                continue
            dynamic.append(f"line {node.lineno}: indirect reference to an import function")
    return found, dynamic


def imports_of(module: str, source: str, is_package: bool, known: Set[str]) -> Set[str]:
    return analyse(module, source, is_package, known)[0]


_CODE_EXEC = {"exec", "eval", "compile"}
#: Layers in which loading code by any route other than a plain import is refused.
NO_CODE_LOADING = {"foundation", "integration"}


def code_loading(source: str) -> List[str]:
    """Ways of loading or running code that bypass a plain import: the common
    forms only."""
    tree = ast.parse(source)
    found: List[str] = []
    sys_names: Set[str] = set()
    importlib_names: Set[str] = set()
    builtins_names: Set[str] = set()
    exec_names: Set[str] = set(_CODE_EXEC)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                if alias.name == "sys":
                    sys_names.add(bound)
                elif alias.name == "builtins":
                    builtins_names.add(bound)
                elif alias.name == "importlib":
                    importlib_names.add(bound)
                elif alias.name == "runpy" or alias.name.startswith("importlib.util"):
                    found.append(f"line {node.lineno}: imports {alias.name}")
                    if alias.name.startswith("importlib.") and not alias.asname:
                        importlib_names.add(bound)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            mod = node.module or ""
            names = {a.name for a in node.names}
            if mod == "runpy" or mod.startswith("importlib.util") or (mod == "importlib" and "util" in names):
                found.append(f"line {node.lineno}: imports from {mod}")
            elif mod == "sys" and ({"modules", "*"} & names):
                found.append(f"line {node.lineno}: imports sys.modules")
            elif mod == "builtins":
                exec_names.update(a.asname or a.name for a in node.names if a.name in _CODE_EXEC)

    def named(expr: ast.AST, names: Set[str]) -> bool:
        return isinstance(expr, ast.Name) and expr.id in names

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if named(node.func, exec_names) or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _CODE_EXEC
                and named(node.func.value, builtins_names)
            ):
                found.append(f"line {node.lineno}: runs code with {getattr(node.func, 'id', None) or node.func.attr}()")
            elif named(node.func, {"vars"}) and node.args and named(node.args[0], importlib_names | builtins_names):
                found.append(f"line {node.lineno}: vars() lookup on {node.args[0].id}")
        elif isinstance(node, ast.Attribute):
            if node.attr == "modules" and named(node.value, sys_names):
                found.append(f"line {node.lineno}: uses sys.modules")
            elif node.attr == "util" and named(node.value, importlib_names):
                found.append(f"line {node.lineno}: uses importlib.util")
            elif node.attr == "__dict__" and named(node.value, importlib_names | builtins_names):
                found.append(f"line {node.lineno}: __dict__ lookup on {node.value.id}")
    return found


def check(
    sources: Dict[str, str],
    packages: Set[str],
    plugin_modules: Optional[Iterable[Tuple[str, str]]] = None,
) -> List[str]:
    """Return every rule violation in ``sources`` (module name → source).

    ``plugin_modules`` are the (name, plugin_module) pairs the registry
    declares; the contract's dynamic import is attributed to them."""
    if plugin_modules is None:
        plugin_modules = [(i.name, i.plugin_module) for i in INTEGRATIONS.values()]
    plugin_modules = list(plugin_modules)
    known = set(sources)
    graph: Dict[str, Set[str]] = {}
    violations: List[str] = plugin_module_violations(plugin_modules)
    for m, src in sources.items():
        deps, dynamic = analyse(m, src, m in packages, known)
        if m == CONTRACT:
            deps |= {mod for _, mod in plugin_modules}
        else:
            violations.extend(f"{m} {d}: import by name, or move it into the integration contract" for d in dynamic)
        if layer_of(m) in NO_CODE_LOADING:
            violations.extend(f"{m} {d}: not allowed in the {layer_of(m)} layer" for d in code_loading(src))
        graph[m] = deps

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
            elif is_framework_package(top) and module not in LEGACY_FRAMEWORK_IMPORTERS | {CONTRACT}:
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


def test_the_source_tree_is_what_is_checked():
    if _CHECKOUT.is_dir():
        assert SRC == _CHECKOUT


def test_every_registered_plugin_module_is_a_framework_plugin():
    assert plugin_module_violations((i.name, i.plugin_module) for i in INTEGRATIONS.values()) == []


def test_the_legacy_allowance_only_shrinks():
    sources, packages = package_sources()
    for module in LEGACY_FRAMEWORK_IMPORTERS:
        deps = imports_of(module, sources[module], module in packages, set(sources))
        assert any(is_framework_package(d.split(".")[0]) for d in deps), (
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


# ── dynamic imports (each planted bypass must be caught) ────────────────────

IN = "watchlight.integrations.langgraph"


def test_it_catches_import_module_with_a_literal():
    found = _with(IN, "import importlib\nimportlib.import_module('watchlight._audit')\n")
    assert any(f"{IN} (integration) imports watchlight._audit" in v for v in found)


def test_it_catches_an_aliased_import_module():
    src = "from importlib import import_module as im\ndef f():\n    return im('watchlight_engine')\n"
    found = _with("watchlight.attenuation", src)
    assert any("watchlight.attenuation imports watchlight_engine" in v for v in found)


def test_it_catches_an_aliased_importlib():
    found = _with(IN, "import importlib as il\nil.import_module('watchlight')\n")
    assert any(f"{IN} (integration) imports watchlight (governor)" in v for v in found)


def test_it_catches_dunder_import_of_a_plugin():
    found = _with(IN, "__import__('watchlight_langgraph')\n")
    assert any(f"{IN} imports watchlight_langgraph directly" in v for v in found)


def test_it_catches_builtins_dunder_import():
    found = _with(IN, "import builtins\nbuiltins.__import__('watchlight_core')\n")
    assert any(f"{IN} imports watchlight_core" in v for v in found)


def test_it_catches_a_non_literal_import_outside_the_contract():
    found = _with(IN, "import importlib\ndef f(name):\n    return importlib.import_module(name)\n")
    assert any(f"{IN} line 3: dynamic import of a non-literal or relative name" in v for v in found)


def test_it_catches_a_non_literal_dunder_import():
    found = _with("watchlight._audit", "def f(n):\n    return __import__(n)\n")
    assert any("watchlight._audit line 2: dynamic import" in v for v in found)


def test_it_catches_a_relative_literal_import_module():
    found = _with(IN, "import importlib\nimportlib.import_module('.._audit', __name__)\n")
    assert any("dynamic import of a non-literal or relative name" in v for v in found)


def test_it_catches_an_indirect_reference():
    found = _with(IN, "import importlib\nload = importlib.import_module\nload('watchlight')\n")
    assert any("indirect reference to an import function" in v for v in found)


def test_it_catches_getattr_of_import_module():
    found = _with(IN, "import importlib\ngetattr(importlib, 'import_module')('watchlight')\n")
    assert any("getattr(..., 'import_module')" in v for v in found)


def test_it_catches_a_new_plugin_package_it_was_never_told_about():
    found = _with("watchlight", "import watchlight_engine\nimport watchlight_newframework\n", package=True)
    assert any("watchlight imports watchlight_newframework directly" in v for v in found)


def test_the_contract_itself_may_import_dynamically():
    sources, packages = package_sources()
    deps, dynamic = analyse(CONTRACT, sources[CONTRACT], False, set(sources))
    assert dynamic  # it does import dynamically …
    assert not [v for v in check(sources, packages) if CONTRACT in v]  # … and that is allowed


@pytest.mark.parametrize(
    "plugin_module",
    ["watchlight_engine", "watchlight_core", "os", "watchlight_x.sub", "Watchlight_X", "watchlight_"],
)
def test_it_refuses_a_registered_plugin_module_that_is_not_a_plugin(plugin_module):
    sources, packages = package_sources()
    found = check(sources, packages, plugin_modules=[("evil", plugin_module)])
    assert any("integration evil: plugin_module" in v for v in found)


# ── other routes to loading code (the common forms) ─────────────────────────

FOUNDATION = "watchlight._audit"


@pytest.mark.parametrize(
    "module, source, expected",
    [
        (IN, "exec('import watchlight')\n", "runs code with exec()"),
        (IN, "eval('1')\n", "runs code with eval()"),
        (FOUNDATION, "code = compile('x', 'f', 'exec')\n", "runs code with compile()"),
        (FOUNDATION, "import builtins as b\nb.exec('x')\n", "runs code with exec()"),
        (FOUNDATION, "from builtins import eval as e\ne('1')\n", "runs code with e()"),
        (IN, "import runpy\nrunpy.run_module('watchlight')\n", "imports runpy"),
        (IN, "from runpy import run_path\n", "imports from runpy"),
        (IN, "import importlib.util\n", "imports importlib.util"),
        (IN, "from importlib.util import spec_from_file_location\n", "imports from importlib.util"),
        (IN, "from importlib import util\n", "imports from importlib"),
        (FOUNDATION, "import importlib\nimportlib.util.find_spec('x')\n", "uses importlib.util"),
        (IN, "import sys\nsys.modules['watchlight']\n", "uses sys.modules"),
        (FOUNDATION, "import sys as s\ns.modules.get('watchlight_engine')\n", "uses sys.modules"),
        (IN, "from sys import modules\n", "imports sys.modules"),
        (IN, "import importlib\nvars(importlib)['import_module']('x')\n", "vars() lookup on importlib"),
        (FOUNDATION, "import builtins\nbuiltins.__dict__['__import__']('x')\n", "__dict__ lookup on builtins"),
    ],
)
def test_it_catches_another_route_to_loading_code(module, source, expected):
    found = _with(module, source)
    assert any(module in v and expected in v for v in found), found


def test_a_pattern_compile_is_not_code_loading():
    # ``re.compile`` is everywhere in the foundation and loads nothing.
    assert code_loading("import re\nre.compile('x')\n") == []
