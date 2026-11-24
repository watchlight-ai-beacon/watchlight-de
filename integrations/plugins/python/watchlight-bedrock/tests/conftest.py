"""Shared fixtures for watchlight-bedrock tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_application_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert.

    ``WATCHLIGHT_APPLICATION_ID`` is a deployment default the plugin
    reads at construction. Tests that want it set it explicitly.
    """
    monkeypatch.delenv("WATCHLIGHT_APPLICATION_ID", raising=False)


def as_session(apdp, payload):
    """A ``SessionInfo`` for a stubbed ``create_session``, built from the
    wire-shaped ``POST /sessions`` body a test describes. Any run
    credential in it goes into ``apdp``'s run table (as ``ApdpClient``
    does), so the plugin only ever sees the run reference."""
    from watchlight_core.backend import SessionInfo
    from watchlight_core_testing import register_test_run

    if payload is None or isinstance(payload, SessionInfo):
        return payload
    sid = payload["session"]["id"]
    run = register_test_run(
        apdp,
        payload.get("session_token") or f"sst_{sid}",
        sid,
        proxy_token=payload.get("proxy_token") or None,
    )
    return SessionInfo(
        run=run,
        session_id=sid,
        agent_id=str(payload["session"].get("agent_id") or ""),
        execution_id=payload.get("execution_id"),
        root_run_handle_id=payload.get("root_run_handle_id"),
        session=payload["session"],
    )
