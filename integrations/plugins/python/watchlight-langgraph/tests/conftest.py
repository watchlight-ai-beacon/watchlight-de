"""Shared fixtures for watchlight-langgraph tests."""

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
def _no_leaked_active_handler():
    """No test may leave a handler attached to the context.

    ``RunHandle.callback_handler()`` attaches via a ContextVar, and a
    synchronous test shares its context with the tests that follow. A
    handler left attached would be injected into the next test's
    callback managers by the configure hook and quietly change what it
    asserts.
    """
    from watchlight_langgraph.callbacks import _ACTIVE_HANDLER

    token = _ACTIVE_HANDLER.set(None)
    try:
        yield
    finally:
        _ACTIVE_HANDLER.reset(token)


@pytest.fixture(autouse=True)
def _no_leaked_open_runs():
    """Many tests open a run and never complete it. An open run makes every
    tool start in the process need a grant, so forget the runs a
    test left open before the next one starts."""
    yield
    from watchlight_langgraph import tool_gate

    with tool_gate._lock:
        tool_gate._live.clear()
