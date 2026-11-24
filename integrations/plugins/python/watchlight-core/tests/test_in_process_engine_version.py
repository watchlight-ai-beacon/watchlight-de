"""InProcessClient refuses a watchlight-engine older than the SDK requires.

Engine 0.2.2 refuses every spawn that names no time budget, and lacks the
engine hardening this SDK ships with, so construction refuses it with a typed
error that names the required version. Nothing falls back to another backend
or to an allow: no client and no engine are built.

Most cases use a stand-in ``watchlight_engine`` module placed in
``sys.modules`` for the test, so they run without the compiled engine. The
last case checks the real engine built from this tree is accepted.
"""

import sys
import types

import pytest

from watchlight_core import EngineVersionUnsupported, InProcessClient, WatchlightError
from watchlight_core.in_process_client import (
    REQUIRED_ENGINE_VERSION,
    _parse_engine_version,
)


def _standin_engine(version):
    """A stand-in engine module reporting ``version`` (a value, a callable
    that raises, or ``None`` for a module with no ``version()`` at all)."""
    mod = types.ModuleType("watchlight_engine")
    mod.built = 0

    class PolicyEngine:
        def __init__(self):
            mod.built += 1

        def add_policy(self, _policy_json):
            return None

        def ready(self):
            return True

    mod.PolicyEngine = PolicyEngine
    if callable(version):
        mod.version = version
    elif version is not None:
        mod.version = lambda: version
    return mod


def _use(monkeypatch, mod):
    monkeypatch.setitem(sys.modules, "watchlight_engine", mod)
    return mod


def test_required_version_is_0_2_5():
    assert REQUIRED_ENGINE_VERSION == "0.2.5"


@pytest.mark.parametrize("found", ["0.2.4", "0.2.3", "0.2.2", "0.2.1", "0.1.9", "0.2.5-rc.1", "0.0.0"])
def test_older_engine_is_refused_before_any_engine_is_built(monkeypatch, tmp_path, found):
    mod = _use(monkeypatch, _standin_engine(found))
    with pytest.raises(EngineVersionUnsupported) as info:
        InProcessClient(audit_path=str(tmp_path / "audit.jsonl"))
    err = info.value
    assert err.required == "0.2.5"
    assert err.found == found
    assert "0.2.5" in str(err) and found in str(err)
    assert mod.built == 0
    assert not (tmp_path / "audit.jsonl").exists()


def test_refusal_is_a_watchlight_error_and_not_an_import_error(monkeypatch, tmp_path):
    # Code that falls back when the engine is absent (ImportError) must not
    # also fall back when the engine is present but too old.
    _use(monkeypatch, _standin_engine("0.2.2"))
    with pytest.raises(EngineVersionUnsupported) as info:
        InProcessClient(audit_path=None)
    assert isinstance(info.value, WatchlightError)
    assert not isinstance(info.value, ImportError)


def _raises():
    raise RuntimeError("no version")


@pytest.mark.parametrize(
    "version",
    [None, _raises, 23, "", "latest", "0.2", "v0.2.3", "0.2.3.1", "0.2.x"],
    ids=["absent", "raises", "not-a-string", "empty", "word", "two-part",
         "prefixed", "four-part", "wildcard"],
)
def test_unreadable_version_is_refused(monkeypatch, version):
    mod = _use(monkeypatch, _standin_engine(version))
    with pytest.raises(EngineVersionUnsupported) as info:
        InProcessClient(audit_path=None)
    assert info.value.found == "unknown"
    assert info.value.required == "0.2.5"
    assert mod.built == 0


@pytest.mark.parametrize("found", ["0.2.5", "0.2.6", "0.2.10", "0.2.5+local"])
def test_required_or_newer_engine_is_accepted(monkeypatch, found):
    mod = _use(monkeypatch, _standin_engine(found))
    InProcessClient(audit_path=None)
    assert mod.built == 1


@pytest.mark.parametrize("found", ["0.3.0", "0.3.0-rc.1", "0.10.0", "1.0.0"])
def test_engine_of_a_later_minor_is_refused(monkeypatch, found):
    # A new engine minor may change the contract this SDK speaks: refused,
    # never used, until an SDK is released for it.
    mod = _use(monkeypatch, _standin_engine(found))
    with pytest.raises(EngineVersionUnsupported) as info:
        InProcessClient(audit_path=None)
    assert info.value.found == found
    assert mod.built == 0


def test_versions_compare_numerically_not_as_strings():
    assert _parse_engine_version("0.2.10") > _parse_engine_version("0.2.3")
    assert _parse_engine_version("0.10.0") > _parse_engine_version("0.2.3")
    assert _parse_engine_version("0.2.3-rc.1") < _parse_engine_version("0.2.3")


def test_engine_built_from_this_tree_is_accepted(tmp_path):
    engine = pytest.importorskip("watchlight_engine")
    assert _parse_engine_version(engine.version()) >= _parse_engine_version(
        REQUIRED_ENGINE_VERSION
    ), f"the engine in this tree reports {engine.version()}"
    InProcessClient(audit_path=str(tmp_path / "audit.jsonl"))


def test_only_a_short_ascii_version_parses():
    # Non-ASCII digits and oversized parts are not versions: refused.
    assert _parse_engine_version("\u0660.\u0662.\u0663") is None
    assert _parse_engine_version("0.2." + "9" * 5000) is None
    assert _parse_engine_version("0.2.3+" + "x" * 65) is None
    assert _parse_engine_version("0.2.3+build.7") == (0, 2, 3, 0)
