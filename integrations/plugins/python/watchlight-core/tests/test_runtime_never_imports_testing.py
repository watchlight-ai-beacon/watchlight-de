"""No runtime package imports the test-only distribution.

The test doubles and the conformance runner live in
``watchlight-agent-sdk-testing`` (import root ``watchlight_core_testing``).
The SDK never depends on it, so a runtime module that imports it would
either fail at import in a customer's install or, worse, ship a dependency
on an allow-capable test double. This reads every module of
``watchlight_core`` and of each plugin's runtime package with ``ast`` and
fails on any import of ``watchlight_core_testing``: at module level, inside
a function, ``importlib.import_module("watchlight_core_testing...")`` or
``__import__``. A docstring that names the package is fine.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator, List, Tuple

import pytest

PLUGINS = Path(__file__).resolve().parents[2]
TEST_ROOT = "watchlight_core_testing"


def _runtime_packages() -> List[Path]:
    """``watchlight_core`` plus every plugin's runtime package: a
    ``plugins/<dir>/<module>/__init__.py`` outside the test-only
    distribution."""
    out = []
    for init in sorted(PLUGINS.glob("*/*/__init__.py")):
        pkg = init.parent
        if pkg.name == TEST_ROOT or pkg.name in ("tests", "test"):
            continue
        if pkg.name.startswith("watchlight_"):
            out.append(pkg)
    return out


def _is_test_root(name: object) -> bool:
    return isinstance(name, str) and (name == TEST_ROOT or name.startswith(TEST_ROOT + "."))


def _testing_imports(tree: ast.AST) -> Iterator[Tuple[int, str]]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_test_root(alias.name):
                    yield node.lineno, f"import {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and _is_test_root(node.module):
                yield node.lineno, f"from {node.module} import ..."
        elif isinstance(node, ast.Call) and node.args:
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            arg = node.args[0]
            if name in ("import_module", "__import__") and isinstance(arg, ast.Constant) and _is_test_root(arg.value):
                yield node.lineno, f"{name}({arg.value!r})"


def test_the_scan_covers_core_and_every_plugin() -> None:
    names = {p.name for p in _runtime_packages()}
    assert "watchlight_core" in names
    # The framework plugins, and the template every new plugin is forked from.
    for plugin in ("template", "adk", "bedrock", "claude_agent", "deepagents", "langgraph", "msaf",
                   "pydantic_ai", "strands"):
        assert f"watchlight_{plugin}" in names, names


@pytest.mark.parametrize("pkg", _runtime_packages(), ids=lambda p: p.name)
def test_no_runtime_module_imports_the_test_only_package(pkg: Path) -> None:
    hits = []
    for path in sorted(pkg.rglob("*.py")):
        for line, what in _testing_imports(ast.parse(path.read_text(encoding="utf-8"), str(path))):
            hits.append(f"{path.relative_to(PLUGINS)}:{line}: {what}")
    assert hits == [], "a runtime module imports watchlight_core_testing:\n" + "\n".join(hits)


@pytest.mark.parametrize("source", [
    "from watchlight_core_testing import MockApdpClient\n",
    "import watchlight_core_testing.conformance as c\n",
    "def f():\n    from watchlight_core_testing._doubles import MockApdpClient\n",
    "import importlib\nm = importlib.import_module('watchlight_core_testing')\n",
    "m = __import__('watchlight_core_testing')\n",
])
def test_the_scan_finds_every_import_form(source: str) -> None:
    assert list(_testing_imports(ast.parse(source)))


def test_a_docstring_or_a_similar_name_is_not_an_import() -> None:
    source = ('"""See :class:`watchlight_core_testing.MockApdpClient`."""\n'
              "import watchlight_core\nfrom watchlight_core_testingx import y\n")
    assert list(_testing_imports(ast.parse(source))) == []
