"""The shared check for tool code that can build an agent.

A stdlib package stands in for a framework, so the read itself is tested
without any agent framework installed: ``xml.dom.minidom`` plays the
framework, ``Document`` its agent class and ``parseString`` a factory.
"""

from __future__ import annotations

import functools
import importlib
import types
# nosemgrep: community.python.lang.security.use-defused-xml stand-in package for a framework; this test parses only the constant "<a/>", never outside XML
import xml
# nosemgrep: community.python.lang.security.use-defused-xml stand-in package for a framework; this test parses only the constant "<a/>", never outside XML
import xml.dom.minidom
from typing import Any
# nosemgrep: community.python.lang.security.use-defused-xml stand-in package for a framework; this test parses only the constant "<a/>", never outside XML
from xml.dom.minidom import Document, parseString

from watchlight_core import agent_construction
from watchlight_core.agent_construction import Builders, can_build_agents


def _builds(obj: Any) -> bool:
    if isinstance(obj, type):
        return issubclass(obj, Document)
    return obj is parseString


class _Held:
    pass


BUILDERS = Builders(
    prefixes=("xml.dom",),
    builds=_builds,
    held=lambda obj: isinstance(obj, _Held),
)


class _Subclass(Document):
    pass


def _helper() -> Any:
    return Document()


class _Factory:
    def make(self) -> Any:
        return Document()


_FACTORY = _Factory()
_PARTIAL = functools.partial(parseString, "<a/>")
_HELD = _Held()


def by_name() -> Any:
    return Document()


def by_factory_function() -> Any:
    return parseString("<a/>")


def by_module_attribute() -> Any:
    return xml.dom.minidom.Document()


def by_helper() -> Any:
    return _helper()


def by_method() -> Any:
    return _FACTORY.make()


def by_subclass() -> Any:
    return _Subclass()


def by_lambda() -> Any:
    make = lambda: Document()  # noqa: E731
    return make()


def by_partial() -> Any:
    return _PARTIAL()


def by_closure() -> Any:
    cls = Document

    def inner() -> Any:
        return cls()

    return inner


def by_default(cls: Any = Document) -> Any:
    return cls()


def by_import_module() -> Any:
    return getattr(importlib.import_module("xml.dom.minidom"), "Docu" + "ment")()


def by_eval() -> Any:
    return eval("Docu" + "ment")()


def by_dunder_import() -> Any:
    return getattr(__import__("xml.dom.minidom"), "dom")


def by_exec(source: str) -> Any:
    # nosemgrep: community.python.lang.security.audit.exec-detected never called; the test only reads this code to check that exec counts as able to build an agent
    return exec(source)


_CLASSES = types.SimpleNamespace(document=Document)


def by_instance_attribute() -> Any:
    return _CLASSES.document()


#: An application module that never imports the stand-in framework; the
#: code reaches the builder only through its attribute.
_APP = types.ModuleType("app_helpers")
_APP.__file__ = __file__
_APP.helper = _helper


def by_application_module_attribute() -> Any:
    return _APP.helper()


def refers_to_held() -> Any:
    return _HELD


def plain() -> int:
    return len("abc")


def test_each_way_of_naming_a_builder_is_seen() -> None:
    for func in (
        by_name,
        by_factory_function,
        by_module_attribute,
        by_helper,
        by_method,
        by_subclass,
        by_lambda,
        by_partial,
        by_closure(),
        by_default,
    ):
        assert can_build_agents(func, BUILDERS), func


def test_a_package_above_the_framework_leads_to_it() -> None:
    # ``xml`` is not the framework, but ``xml.dom.minidom.Document`` names it.
    assert BUILDERS.leads_to("xml")
    assert not BUILDERS.owns_module("xml")
    assert can_build_agents(by_module_attribute, BUILDERS)


def test_code_that_builds_nothing_is_not_refused() -> None:
    assert not can_build_agents(plain, BUILDERS)
    assert not can_build_agents(refers_to_held, BUILDERS)


def test_indirection_names_count_as_building() -> None:
    for func in (by_import_module, by_eval, by_dunder_import, by_exec):
        assert can_build_agents(func, BUILDERS), func


def test_an_instance_attribute_is_not_seen() -> None:
    """The documented gap: a class held in an instance attribute."""
    assert not can_build_agents(by_instance_attribute, BUILDERS)


def test_a_framework_refused_name_counts_as_building() -> None:
    builders = Builders(prefixes=("xml.dom",), builds=_builds, refused_names=frozenset({"_secret_context"}))

    def reaches_context(ctx: Any) -> Any:
        return ctx._secret_context

    assert can_build_agents(reaches_context, builders)
    assert not can_build_agents(reaches_context, BUILDERS)


def test_an_attribute_of_an_application_module_is_followed() -> None:
    assert can_build_agents(by_application_module_attribute, BUILDERS)


def test_a_standard_library_start_is_not_read() -> None:
    # The standard library is never the application's code, even as the start.
    import json

    assert not can_build_agents(json.dumps, BUILDERS)


def test_a_read_that_cannot_finish_counts_as_building(monkeypatch: Any) -> None:
    monkeypatch.setattr(agent_construction, "MAX_NODES", 2)
    assert can_build_agents(by_helper, BUILDERS)


def test_modules_that_do_not_import_the_framework_are_not_followed() -> None:
    # json's functions never name xml.dom, so the read does not descend.
    import json

    def uses_json() -> Any:
        return json.dumps({})

    assert not can_build_agents(uses_json, BUILDERS)
