"""``watchlight_core.langchain_backstop`` without a framework.

The module is shared by the LangChain-based plugins; the run marker and the
model-class check are tested end to end in watchlight-langgraph. Here: the
core imports without langchain_core, the known classes are the classes
their packages define, and reading fails closed.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from watchlight_core.langchain_backstop import (
    KNOWN_MODEL_CLASSES,
    binds_tools,
    model_class_names,
)


class _NoLangChain:
    """An import finder that refuses langchain_core, as if not installed."""

    def find_spec(self, name: str, path: object = None, target: object = None) -> None:
        if name == "langchain_core" or name.startswith("langchain_core."):
            raise ImportError("langchain_core is not installed")
        return None


def test_watchlight_core_imports_without_langchain_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh import of watchlight_core, with langchain_core unimportable.
    The modules already loaded are put back afterwards."""
    saved = dict(sys.modules)
    for name in list(sys.modules):
        if name.split(".")[0] in ("watchlight_core", "langchain_core"):
            del sys.modules[name]
    monkeypatch.setattr(sys, "meta_path", [_NoLangChain(), *sys.meta_path])
    try:
        core = importlib.import_module("watchlight_core")
        backstop = importlib.import_module("watchlight_core.langchain_backstop")
        assert core.__name__ == "watchlight_core"
        assert "langchain_core" not in sys.modules
        assert not backstop.intact()
        with pytest.raises(ImportError):
            backstop.install()
    finally:
        sys.modules.clear()
        sys.modules.update(saved)


@pytest.mark.parametrize("name", KNOWN_MODEL_CLASSES)
def test_each_known_class_is_the_class_its_package_defines(name: str) -> None:
    """A known class that moved inside its package would no longer match,
    and every model call of it would be refused."""
    module_name, _, qualname = name.partition(":")
    cls = getattr(pytest.importorskip(module_name), qualname)
    assert f"{cls.__module__}:{cls.__qualname__}" == name


@pytest.mark.parametrize(
    "params,binds",
    [
        ({"model": "m"}, False),
        ({"model": "m", "tools": []}, False),
        ({"tools": [{"type": "function", "function": {"name": "f"}}]}, True),
        ({"tool_choice": "auto"}, True),
        ({"model_kwargs": {"tools": [{"type": "web_search"}]}}, True),
        ({"model_kwargs": {"temperature": 0}}, False),
        (["not", "a", "mapping"], True),
        ({"model_kwargs": ["not", "a", "mapping"]}, True),
    ],
)
def test_binds_tools(params: object, binds: bool) -> None:
    assert binds_tools(params) is binds


def test_allowed_model_classes_are_module_colon_class() -> None:
    assert model_class_names(None) == frozenset()
    assert model_class_names(["pkg.mod:Model", "pkg:Outer.Inner"]) == {
        "pkg.mod:Model",
        "pkg:Outer.Inner",
    }
    for wrong in (
        "pkg:Model",
        ["Model"],
        ["pkg.Model"],
        ["pkg:"],
        [":Model"],
        ["pkg:Model x"],
        [3],
    ):
        with pytest.raises(ValueError):
            model_class_names(wrong)
