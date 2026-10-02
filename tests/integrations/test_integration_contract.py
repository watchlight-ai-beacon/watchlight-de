"""Every framework integration meets the same contract — checked from the registry.

An integration is declared data (:class:`watchlight.integrations.FrameworkIntegration`)
plus a factory built on :func:`watchlight.integrations.build_governed_plugin`.
These tests iterate :data:`watchlight.integrations.INTEGRATIONS`, so an
integration added to the registry is held to every guarantee below without a
test being written for it — and an integration module that is NOT registered
fails :func:`test_every_integration_module_is_registered`, so none escapes them.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import pathlib
import sys
import types

import pytest

import watchlight.inprocess as inprocess
from watchlight.integrations import INTEGRATIONS, FrameworkIntegration
from watchlight.integrations._contract import BACKEND_KEYS

NAMES = sorted(INTEGRATIONS)
PER_CALL_TERMS = ("principal", "context", "resource")
SRC = pathlib.Path(inprocess.__file__).resolve().parent


def factory(name):
    return importlib.import_module(f"watchlight.{name}").governed_plugin


@pytest.fixture
def stub_plugin(monkeypatch):
    """Install a stand-in for one integration's published plugin package and
    record what the factory hands its constructor."""

    def install(integration):
        built = []

        class _Plugin:
            def __init__(self, **kwargs):
                built.append(kwargs)

        module = types.ModuleType(integration.plugin_module)
        setattr(module, integration.plugin_class, _Plugin)
        monkeypatch.setitem(sys.modules, integration.plugin_module, module)
        return built

    return install


# ── the registry and the public names ───────────────────────────────────────


def test_the_registry_is_read_only():
    with pytest.raises(TypeError):
        INTEGRATIONS["x"] = None  # type: ignore[index]


@pytest.mark.parametrize("name", NAMES)
def test_the_public_alias_is_the_implementation(name):
    impl = importlib.import_module(f"watchlight.integrations.{name}")
    assert impl.INTEGRATION is INTEGRATIONS[name]
    assert factory(name) is impl.governed_plugin
    # Its public home is the alias, whichever path imported it first.
    assert impl.governed_plugin.__module__ == f"watchlight.{name}"


def test_every_integration_module_is_registered():
    modules = {p.stem for p in (SRC / "integrations").glob("*.py") if not p.stem.startswith("_")}
    assert modules == set(INTEGRATIONS)


@pytest.mark.parametrize("name", NAMES)
def test_the_factory_signature_is_the_contract(name):
    sig = inspect.signature(factory(name))
    assert list(sig.parameters) == ["policies", "audit_path", "plugin_kwargs"]
    # No policies → fail-closed, and the default trail is the local one.
    assert sig.parameters["policies"].default is None
    assert sig.parameters["audit_path"].default == ".watchlight/audit.jsonl"


@pytest.mark.parametrize("name", NAMES)
def test_the_docstring_says_where_per_call_terms_go(name):
    doc = (inspect.getdoc(factory(name)) or "").lower()
    assert "authorize_action" in doc
    assert "principal=" in doc
    assert "allow beats a forbid" in doc


# ── what every factory refuses, and how it fails ────────────────────────────


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("term", PER_CALL_TERMS)
def test_a_per_call_term_is_refused_before_anything_is_built(stub_plugin, monkeypatch, name, term):
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    backends = []
    monkeypatch.setattr(inprocess, "in_process_backend", lambda *a, **k: backends.append(1))
    built = stub_plugin(INTEGRATIONS[name])
    with pytest.raises(TypeError) as excinfo:
        factory(name)(None, **{term: "anything"})
    assert f"`{term}`" in str(excinfo.value)
    assert "per-call term" in str(excinfo.value)
    assert built == [] and backends == []  # no plugin, no engine, nothing half-built


@pytest.mark.parametrize("name", NAMES)
def test_a_missing_extra_names_the_install(monkeypatch, name):
    integration = INTEGRATIONS[name]
    monkeypatch.setitem(sys.modules, integration.plugin_module, None)  # import fails
    with pytest.raises(ImportError) as excinfo:
        factory(name)(None)
    assert integration.install_hint in str(excinfo.value)


@pytest.mark.parametrize("name", NAMES)
def test_a_plugin_package_without_the_class_is_an_import_error(monkeypatch, name):
    integration = INTEGRATIONS[name]
    monkeypatch.setitem(sys.modules, integration.plugin_module, types.ModuleType(integration.plugin_module))
    with pytest.raises(ImportError) as excinfo:
        factory(name)(None)
    assert integration.install_hint in str(excinfo.value)


@pytest.mark.parametrize("name", NAMES)
def test_an_error_inside_the_plugin_import_is_not_disguised(monkeypatch, tmp_path, name):
    """Only "the plugin is not installed" becomes the install hint. A plugin
    that fails while importing raises its own error."""
    integration = INTEGRATIONS[name]
    pkg = tmp_path / integration.plugin_module
    pkg.mkdir()
    (pkg / "__init__.py").write_text("raise RuntimeError('plugin import failed')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, integration.plugin_module, raising=False)
    with pytest.raises(RuntimeError, match="plugin import failed"):
        factory(name)(None)


@pytest.mark.parametrize("name", NAMES)
def test_a_missing_dependency_of_the_plugin_is_named_as_itself(monkeypatch, tmp_path, name):
    integration = INTEGRATIONS[name]
    pkg = tmp_path / integration.plugin_module
    pkg.mkdir()
    (pkg / "__init__.py").write_text("import wl_absent_dependency_for_test\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, integration.plugin_module, raising=False)
    with pytest.raises(ModuleNotFoundError) as excinfo:
        factory(name)(None)
    assert excinfo.value.name == "wl_absent_dependency_for_test"
    assert integration.install_hint not in str(excinfo.value)


# ── the backend cannot be replaced from the call site ──────────────────────


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("key", sorted(BACKEND_KEYS))
@pytest.mark.parametrize("apdp_url", [None, "https://apdp.example"])
def test_a_backend_override_is_refused(stub_plugin, monkeypatch, name, key, apdp_url):
    if apdp_url:
        monkeypatch.setenv("WATCHLIGHT_APDP_URL", apdp_url)
    else:
        monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    backends = []
    monkeypatch.setattr(inprocess, "in_process_backend", lambda *a, **k: backends.append(1))
    built = stub_plugin(INTEGRATIONS[name])
    with pytest.raises(TypeError) as excinfo:
        factory(name)(None, **{key: "https://elsewhere.example"})
    assert f"`{key}`" in str(excinfo.value)
    assert built == [] and backends == []


@pytest.mark.parametrize("apdp_url", [None, "https://apdp.example"])
def test_every_key_the_backend_selection_sets_is_protected(monkeypatch, apdp_url):
    """If the seam starts setting another key, the contract must protect it too."""
    if apdp_url:
        monkeypatch.setenv("WATCHLIGHT_APDP_URL", apdp_url)
    else:
        monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    monkeypatch.setattr(inprocess, "in_process_backend", lambda *a, **k: object())
    assert set(inprocess._select_backend_kwargs(None, None, {})) <= BACKEND_KEYS


# ── which backend the plugin is given ───────────────────────────────────────


@pytest.mark.parametrize("name", NAMES)
def test_in_process_by_default(stub_plugin, monkeypatch, name):
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    calls = []
    sentinel = object()

    def fake_backend(policies, *, audit_path):
        calls.append((policies, audit_path))
        return sentinel

    monkeypatch.setattr(inprocess, "in_process_backend", fake_backend)
    built = stub_plugin(INTEGRATIONS[name])
    factory(name)(None, audit_path="trail.jsonl", tenant_id="acme")
    # Policies reach the engine untouched — None stays None, which the engine
    # treats as "nothing permitted".
    assert calls == [(None, "trail.jsonl")]
    assert built == [{"governance": sentinel, "tenant_id": "acme"}]


@pytest.mark.parametrize("name", NAMES)
def test_networked_when_an_apdp_url_is_set(stub_plugin, monkeypatch, name):
    monkeypatch.setenv("WATCHLIGHT_APDP_URL", "https://apdp.example")
    monkeypatch.setattr(inprocess, "in_process_backend", lambda *a, **k: pytest.fail("in-process built"))
    built = stub_plugin(INTEGRATIONS[name])
    factory(name)(None, tenant_id="acme")
    assert built == [{"apdp_url": "https://apdp.example", "tenant_id": "acme"}]


# ── the declaration itself ──────────────────────────────────────────────────


def test_a_declaration_is_frozen():
    integration = next(iter(INTEGRATIONS.values()))
    with pytest.raises(dataclasses.FrozenInstanceError):
        integration.plugin_module = "elsewhere"  # type: ignore[misc]


@pytest.mark.parametrize(
    "field, value",
    [
        ("name", "Lang-Graph"),
        ("name", "class"),
        ("extra", "Lang Graph"),
        ("display_name", "  "),
        ("plugin_module", "watchlight langgraph"),
        ("plugin_module", "a..b"),
        ("plugin_module", "watchlight_engine"),
        ("plugin_module", "watchlight_core"),
        ("plugin_module", "os"),
        ("plugin_module", "watchlight_example.sub"),
        ("plugin_module", "watchlight_"),
        ("plugin_class", "a.B"),
    ],
)
def test_a_malformed_declaration_is_refused_where_it_is_written(field, value):
    good = dict(
        name="example",
        extra="example",
        display_name="Example",
        plugin_module="watchlight_example",
        plugin_class="WatchlightExamplePlugin",
    )
    FrameworkIntegration(**good)
    with pytest.raises(ValueError):
        FrameworkIntegration(**{**good, field: value})


def test_every_extra_is_declared_in_pyproject():
    try:
        import tomllib  # Python 3.11+
    except ImportError:  # pragma: no cover - the 3.9/3.10 lanes
        pytest.skip("tomllib needs Python 3.11+")
    pyproject = SRC.parent.parent / "pyproject.toml"
    if not pyproject.is_file():  # pragma: no cover - installed, not a checkout
        pytest.skip("not running from a source checkout")
    extras = tomllib.loads(pyproject.read_text())["project"]["optional-dependencies"]
    for integration in INTEGRATIONS.values():
        assert integration.extra in extras, integration.name
