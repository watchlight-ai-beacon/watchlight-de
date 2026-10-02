"""The package's layering rules, enforced on its source.

Each module of ``watchlight`` belongs to exactly one layer, and a layer may
import only the layers named for it in :data:`ALLOWED`. The rules keep each
guarantee enforced in one place:

* only the governor imports the compiled engine (``watchlight_engine``) — one
  engine boundary, so there is one place a decision is made;
* a framework integration reaches governance only through the backend seam
  (``watchlight.inprocess``) and the integration contract — never the
  governor's internals, the audit trail, or the scope code. Only the contract
  imports a framework plugin or references the seam's backend builders or the
  contract's own steps, with no exceptions (the common forms: a call, an
  alias, an assignment, an attribute, the name as a string);
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


#: The seam functions that choose a backend. Outside the contract an
#: integration may not call or otherwise reference them: a reference could
#: build a plugin past the contract's backend-keyword refusal. The one exception
#: is the plain re-export in each public alias (``from .inprocess import
#: Policies, _select_backend_kwargs``), a name those modules have always exposed.
SEAM_BUILDERS = {"_select_backend_kwargs", "in_process_backend"}
#: The contract's internal steps. Calling one directly skips the others (the
#: refusal, or the lazy import's narrowed error), so nothing outside
#: ``_contract.py`` may reference them.
CONTRACT_PRIVATES = {"_load_plugin_class", "_refuse_backend_overrides"}


def _is_seam_reexport(node: ast.ImportFrom, alias: ast.alias) -> bool:
    from_inprocess = (node.level == 1 and node.module == "inprocess") or (
        node.level == 0 and node.module == "watchlight.inprocess"
    )
    return from_inprocess and alias.name == "_select_backend_kwargs" and alias.asname is None


def guarded_references(module: str, source: str, public_aliases: Set[str]) -> List[str]:
    """References to a seam builder or a contract-internal step that the
    module may not make: the common forms (a call, an alias, an assignment,
    ``functools.partial``, ``map``, a decorator, an attribute, or the name as a
    string for ``getattr`` / ``__dict__`` / ``vars()``). The behavioural tests
    prove the refusal itself; this catches a route around it."""
    if module == CONTRACT:
        return []
    guarded = set(CONTRACT_PRIVATES)
    if layer_of(module) == "integration":
        guarded |= SEAM_BUILDERS
    tree = ast.parse(source)
    found: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                leaf = alias.name.rsplit(".", 1)[-1]
                if alias.asname and leaf in SEAM_BUILDERS | CONTRACT_PRIVATES:
                    found.append(f"line {node.lineno}: imports {leaf} as {alias.asname}")
                elif leaf in guarded:
                    if isinstance(node, ast.ImportFrom) and module in public_aliases and _is_seam_reexport(node, alias):
                        continue
                    found.append(f"line {node.lineno}: imports {leaf}")
        elif isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in guarded)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in guarded)
        ):
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            found.append(f"line {node.lineno}: calls {name}()")
        elif isinstance(node, ast.Name) and node.id in guarded:
            found.append(f"line {node.lineno}: references {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in guarded:
            found.append(f"line {node.lineno}: references {node.attr}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in guarded:
            found.append(f"line {node.lineno}: names {node.value} in a string")
    # A call's callee is also a Name/Attribute node: report it once, as the call.
    calls = {(f.split(":")[0], f.rsplit(" ", 1)[-1][:-2]) for f in found if " calls " in f}
    return [
        f
        for f in found
        if not (" references " in f and (f.split(":")[0], f.rsplit(" ", 1)[-1]) in calls)
    ]


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
    public_aliases = {f"watchlight.{name}" for name, _ in plugin_modules}
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
        violations.extend(
            f"{m} {d}: build the plugin with build_governed_plugin instead"
            for d in guarded_references(m, src, public_aliases)
        )
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
            elif is_framework_package(top) and module != CONTRACT:
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


def test_only_the_contract_imports_a_framework_plugin():
    # No exceptions: every integration, and every public alias, reaches its
    # plugin through the contract.
    sources, packages = package_sources()
    known = set(sources)
    importers = {
        m
        for m, src in sources.items()
        if any(is_framework_package(d.split(".")[0]) for d in imports_of(m, src, m in packages, known))
    }
    assert importers <= {CONTRACT}


@pytest.mark.parametrize("name", sorted(INTEGRATIONS))
def test_every_registered_integration_has_a_public_alias_in_its_layer(name):
    sources, _ = package_sources()
    assert f"watchlight.{name}" in sources
    assert layer_of(f"watchlight.{name}") == "integration"


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


@pytest.mark.parametrize("alias", [f"watchlight.{n}" for n in sorted(INTEGRATIONS)])
def test_it_catches_a_public_alias_importing_its_plugin_directly(alias):
    plugin = INTEGRATIONS[alias.split(".")[1]].plugin_module
    found = _with(alias, f"def f():\n    from {plugin} import X\n")
    assert any(f"{alias} imports {plugin} directly" in v for v in found)


@pytest.mark.parametrize("alias", [f"watchlight.{n}" for n in sorted(INTEGRATIONS)])
def test_it_catches_a_public_alias_reaching_into_the_governor(alias):
    found = _with(alias, "from . import govern\n")
    assert any(f"{alias} (integration) imports watchlight (governor)" in v for v in found)


@pytest.mark.parametrize("fn", sorted(SEAM_BUILDERS))
@pytest.mark.parametrize("module", ["watchlight.pydantic_ai", "watchlight.integrations.claude_agent"])
def test_it_catches_an_integration_choosing_the_backend_itself(module, fn):
    src = f"from watchlight import inprocess\ndef f():\n    return inprocess.{fn}(None, None, {{}})\n"
    found = _with(module, src)
    assert any(f"{module} line 3: calls {fn}()" in v for v in found), found


SEAM_ROUTES = [
    # (a) an aliased import, whether or not it is used
    ("from ..inprocess import _select_backend_kwargs as pick\n", "imports _select_backend_kwargs as pick"),
    ("from ..inprocess import in_process_backend as b\nb(None)\n", "imports in_process_backend as b"),
    ("from watchlight.inprocess import in_process_backend\n", "imports in_process_backend"),
    # (b) a reference that is not a direct call
    ("from .. import inprocess\nf = inprocess._select_backend_kwargs\n", "references _select_backend_kwargs"),
    ("from .. import inprocess\ngetattr(inprocess, '_select_backend_kwargs')\n", "names _select_backend_kwargs in a string"),
    ("from .. import inprocess\ninprocess.__dict__['in_process_backend']\n", "names in_process_backend in a string"),
    ("from .. import inprocess\nvars(inprocess)['in_process_backend']\n", "names in_process_backend in a string"),
    (
        "import functools\nfrom .. import inprocess\nf = functools.partial(inprocess.in_process_backend, None)\n",
        "references in_process_backend",
    ),
    ("from .. import inprocess\nlist(map(inprocess.in_process_backend, [None]))\n", "references in_process_backend"),
    ("from .. import inprocess\n@inprocess.in_process_backend\ndef f(): pass\n", "references in_process_backend"),
]


@pytest.mark.parametrize("source, expected", SEAM_ROUTES)
def test_it_catches_another_route_to_the_seam(source, expected):
    module = "watchlight.integrations.pydantic_ai"
    found = _with(module, source)
    assert any(module in v and expected in v for v in found), found


@pytest.mark.parametrize(
    "source, expected",
    [
        ("from .inprocess import _select_backend_kwargs as s\n", "imports _select_backend_kwargs as s"),
        ("from .inprocess import in_process_backend\n", "imports in_process_backend"),
        ("from . import inprocess\nx = inprocess._select_backend_kwargs\n", "references _select_backend_kwargs"),
    ],
)
def test_a_public_alias_may_only_reexport_the_seam_name(source, expected):
    found = _with("watchlight.claude_agent", source)
    assert any("watchlight.claude_agent" in v and expected in v for v in found), found


def test_the_public_alias_reexport_is_allowed():
    found = _with("watchlight.claude_agent", "from .inprocess import Policies, _select_backend_kwargs  # noqa\n")
    assert not [v for v in found if "watchlight.claude_agent" in v]


def test_an_aliased_seam_import_is_caught_outside_integrations_too():
    found = _with("watchlight.cli", "from .inprocess import in_process_backend as b\n")
    assert any("watchlight.cli line 1: imports in_process_backend as b" in v for v in found), found


@pytest.mark.parametrize("private", sorted(CONTRACT_PRIVATES))
@pytest.mark.parametrize(
    "module, template",
    [
        ("watchlight.integrations.langgraph", "from ._contract import {p}\n"),
        ("watchlight.integrations.langgraph", "from . import _contract\n_contract.{p}(None)\n"),
        ("watchlight.langgraph", "from .integrations import _contract\nf = _contract.{p}\n"),
        ("watchlight.cli", "from .integrations import _contract\ngetattr(_contract, '{p}')\n"),
        ("watchlight", "from .integrations._contract import {p} as q\n"),
    ],
)
def test_it_catches_a_contract_step_used_outside_the_contract(module, template, private):
    found = _with(module, template.format(p=private), package=(module == "watchlight"))
    assert any(module + " line" in v and private in v for v in found), found


def test_the_contract_may_use_the_seam_and_its_own_steps():
    sources, packages = package_sources()
    assert guarded_references(CONTRACT, sources[CONTRACT], set()) == []
    assert not [v for v in check(sources, packages) if "build_governed_plugin instead" in v]


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
