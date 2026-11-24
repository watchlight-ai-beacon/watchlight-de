"""Shared fixtures for watchlight-adk tests."""

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
def _no_ambient_proxy_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """A configured ``WATCHLIGHT_PROXY_URL`` makes the CONNECT route a hard
    requirement of every run. Tests that want it set it explicitly."""
    monkeypatch.delenv("WATCHLIGHT_PROXY_URL", raising=False)


@pytest.fixture
def governed_run_live():  # type: ignore[no-untyped-def]
    """For tests that drive the plugin's callbacks directly, with no
    Runner: a governed run is live and the test runs inside it, as the
    wrapped ``Runner.run_async`` arranges for a real run. Without
    it a root agent is refused at ``before_agent_callback``."""
    from watchlight_adk import run_backstop

    run_backstop.install()
    run_backstop._enter()
    token = run_backstop._governed_run.set(True)
    try:
        yield
    finally:
        run_backstop._governed_run.reset(token)
        run_backstop._leave()


@pytest.fixture(autouse=True)
def _no_governed_run_leaks():  # type: ignore[no-untyped-def]
    """No test starts inside a governed run, and none leaves one behind:
    the live count is zero and the per-run marker unset, before and after
    (the ``governed_run_live`` fixture is torn down first)."""
    from watchlight_adk import run_backstop

    assert run_backstop._live == 0, "a governed run was left live by an earlier test"
    assert run_backstop.in_governed_run() is False
    yield
    import gc

    gc.collect()  # an abandoned run_async generator is closed when collected
    assert run_backstop._live == 0, "this test left a governed run live"
    assert run_backstop.in_governed_run() is False


#: Key under which :func:`probe_tool_args` adds the raw argument text.
PROBE_KEY = "test_probe_args"


@pytest.fixture
def probe_tool_args(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-only probe: the plugin sends value-free argument metadata to
    wl-apdp. Tests that trace each authorization back to the run that
    made it through the argument values swap in a probe that adds the
    raw text next to the real metadata. Never used in shipped code."""
    import watchlight_adk.plugin as plugin_module

    real = plugin_module.redacted_arg_metadata

    def _probe(tool_args):  # type: ignore[no-untyped-def]
        return {**real(tool_args), PROBE_KEY: str(tool_args)}

    monkeypatch.setattr(plugin_module, "redacted_arg_metadata", _probe)


def probed_args(context) -> str:  # type: ignore[no-untyped-def]
    """The raw argument text :func:`probe_tool_args` recorded, or ``""``."""
    meta = (context or {}).get("tool_arg_metadata") or {}
    return str(meta.get(PROBE_KEY, ""))


# ── Stand-in run references (the backend keeps the credentials) ───────
#
# The plugin names a run only by its opaque ``RunRef``. The hand-written
# APDP stand-ins in these tests keep their stand-in ``sst_`` values in the
# reference itself (``run::<token>``) so a test can still assert which
# run's credential a request would have carried.

from typing import Any, Dict, Optional  # noqa: E402

from watchlight_core.backend import RunRef, SessionInfo  # noqa: E402

_RUN_PREFIX = "run::"


def run_for(token: Optional[str]) -> Optional[RunRef]:
    """The stand-in run reference for ``token`` (``None`` for none)."""
    return RunRef(_RUN_PREFIX + token) if token else None


def token_of(run: Any) -> Optional[str]:
    """The stand-in credential a stand-in run reference names."""
    if isinstance(run, str) and run.startswith(_RUN_PREFIX):
        return run[len(_RUN_PREFIX):]
    return None


def stand_in_session(
    session_id: str,
    session_token: Optional[str],
    *,
    agent_id: str = "agent",
    execution_id: Optional[str] = None,
    root_run_handle_id: Optional[str] = None,
) -> SessionInfo:
    """What a backend's ``create_session`` returns, for a stand-in."""
    return SessionInfo(
        run=run_for(session_token) or RunRef(_RUN_PREFIX),
        session_id=session_id,
        agent_id=agent_id,
        execution_id=execution_id,
        root_run_handle_id=root_run_handle_id,
        session={"id": session_id},
    )


def stand_in_spawn(response: Dict[str, Any]) -> Dict[str, Any]:
    """A wire-shaped spawn response as a backend returns it: the child's
    credential moves into ``child_run`` (none when the wire carried none,
    which the SDK refuses)."""
    response = dict(response)
    token = response.pop("child_session_token", None)
    response.pop("child_proxy_token", None)
    response.pop("child_proxy_token_expires_at", None)
    if token:
        response["child_run"] = run_for(token)
    return response
