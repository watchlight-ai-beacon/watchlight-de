"""Shared fixtures for watchlight-pydantic-ai tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_application_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert.

    ``WATCHLIGHT_APPLICATION_ID`` is a deployment default the plugin
    reads at construction. Tests that want it set it explicitly.
    """
    monkeypatch.delenv("WATCHLIGHT_APPLICATION_ID", raising=False)


@pytest.fixture(autouse=True)
def _fresh_live_run_registry():
    """Each test starts with no governed run live in the process.

    Many tests open a handle directly and never close it; without this, the
    next test's root would be refused as an escaped nested run.
    """
    _forget_live_runs()
    yield
    _forget_live_runs()


def _forget_live_runs() -> None:
    from watchlight_core import root_admission

    with root_admission._lock:
        root_admission._runs.clear()
        root_admission._refused_spawns.clear()
        root_admission._pending_roots = 0
