"""Fail-closed hardening for the deepagents plugin.

- A sub-agent accepts only the live handle its own ``task`` spawn
  produced, once, and only while that ``task`` call is running. A
  handle left in the context variable by an earlier sibling is never
  reused.
- A configured wl-proxy URL with no issued proxy token, or a sidecar
  that fails to start, refuses the run.
- A model turn with no governed run handle is refused.
- A missing constraint manifest refuses the run (strict default), and
  any failure after the session was opened closes it.
- A spawned child reports its real elapsed time on completion.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import patch

import pytest

from watchlight_core import GovernanceUnavailable

from conftest import (
    CHILD_UUID,
    RecordingHandler,
    StubModelRequest,
    make_child_middleware,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)
from watchlight_deepagents.middleware import STATE_TOKEN_KEY, _HANDLE_REGISTRY


# ─── a child accepts only its own live spawn handle ─────────────────────────


async def test_child_started_after_the_task_call_ended_is_refused(plugin, mock_apdp):
    """A sibling's spawn leaves its handle in the SDK context variable.
    A child graph that starts after that ``task`` call has ended must not
    pick the stale handle up."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        RecordingHandler(),
    )
    child_mw = make_child_middleware(plugin)
    with pytest.raises(GovernanceUnavailable):
        await child_mw.abefore_agent({}, runtime=None)


async def test_a_spawn_handle_is_claimed_once(plugin, mock_apdp):
    """Two child graphs inside one ``task`` call cannot share the spawn's
    handle: the second is refused."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    child_mw = make_child_middleware(plugin)
    seen: Dict[str, Any] = {}

    async def _run_two_children(request: Any) -> Any:
        first = await child_mw.abefore_agent({}, runtime=None)
        seen["first"] = _HANDLE_REGISTRY[first[STATE_TOKEN_KEY]].handle
        with pytest.raises(GovernanceUnavailable):
            await child_mw.abefore_agent({}, runtime=None)
        seen["second_refused"] = True
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _run_two_children,
    )
    assert seen["first"].agent_uuid == CHILD_UUID
    assert seen.get("second_refused") is True


async def test_a_completed_spawn_handle_is_refused(plugin, mock_apdp):
    """A spawn handle that is no longer live (completed) is refused."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    child_mw = make_child_middleware(plugin)
    seen: Dict[str, Any] = {}

    async def _complete_then_start(request: Any) -> Any:
        from watchlight_core.run_handle import _current_subagent_handle

        await _current_subagent_handle.get().complete()
        with pytest.raises(GovernanceUnavailable):
            await child_mw.abefore_agent({}, runtime=None)
        seen["refused"] = True
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _complete_then_start,
    )
    assert seen.get("refused") is True


async def test_a_handle_planted_in_the_sdk_context_variable_is_refused(plugin, mock_apdp):
    """Only the plugin's own spawn grants a child handle. A handle that is
    merely present in the SDK context variable (not granted by a running
    ``task`` spawn) is refused."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    root = _HANDLE_REGISTRY[root_state[STATE_TOKEN_KEY]].handle
    from watchlight_core.run_handle import _current_subagent_handle

    token = _current_subagent_handle.set(root)
    try:
        child_mw = make_child_middleware(plugin)
        with pytest.raises(GovernanceUnavailable):
            await child_mw.abefore_agent({}, runtime=None)
    finally:
        _current_subagent_handle.reset(token)


# ─── wl-proxy configured ────────────────────────────────────────────────────


async def test_proxy_url_without_proxy_token_refuses_the_run(plugin, mock_apdp):
    plugin.connect_proxy_url = "http://wl-proxy:8080"
    with patch("watchlight_core.install_sidecar") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("research-orchestrator")
    mock_install.assert_not_called()


async def test_failed_sidecar_install_refuses_the_run(plugin, mock_apdp, monkeypatch):
    plugin.connect_proxy_url = "http://wl-proxy:8080"
    # wl-apdp issues a proxy token for the run (held by the backend).
    mock_apdp.proxy_token_prefix = "eyJ.t.k"
    with patch("watchlight_core.install_sidecar", side_effect=OSError("bind failed")):
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("research-orchestrator")


# ─── a model turn with no governed handle is refused ────────────────────────


async def test_model_turn_without_a_run_handle_is_refused(plugin, mock_apdp):
    mw = make_root_middleware(plugin)
    handler = RecordingHandler()
    with pytest.raises(GovernanceUnavailable):
        await mw.awrap_model_call(StubModelRequest(state={}), handler)
    assert handler.ran is False


# ─── the child's terminal event is canonical ────────────────────────────────


async def test_child_execution_completed_is_canonical(plugin, mock_apdp):
    """The child's ``execution_completed`` must pass the canonical schema;
    a non-canonical event is rejected at ingest with its whole batch."""
    from watchlight_core_testing.conformance import assert_canonical_event

    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    child_mw = make_child_middleware(plugin)

    async def _run_child(request: Any) -> Any:
        child_state = await child_mw.abefore_agent({}, runtime=None)
        await child_mw.aafter_agent(child_state, runtime=None)
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _run_child,
    )
    completed = [
        e
        for e in mock_apdp.published_events
        if e["event_type"] == "execution_completed"
        and e.get("parent_execution_id") is not None
    ]
    assert completed, "the child must emit execution_completed"
    for ev in completed:
        assert_canonical_event(ev, expected_uri_prefix="deepagents://")


# ─── manifest gate and session cleanup ──────────────────────────────────────


async def test_missing_manifest_refuses_the_run_and_closes_the_session(
    plugin, mock_apdp, monkeypatch
):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)

    async def _no_manifest(*args: Any, **kwargs: Any) -> Any:
        return None

    monkeypatch.setattr(mock_apdp, "get_manifest", _no_manifest)
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run("research-orchestrator")
    assert len(mock_apdp._closed_sessions) == 1


async def test_missing_manifest_runs_degraded_only_on_explicit_opt_in(
    plugin, mock_apdp, monkeypatch
):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")

    async def _no_manifest(*args: Any, **kwargs: Any) -> Any:
        return None

    monkeypatch.setattr(mock_apdp, "get_manifest", _no_manifest)
    await plugin.start_run("research-orchestrator")
    assert plugin.last_governance_mode == "degraded"


async def test_any_failure_after_session_create_closes_the_session(
    plugin, mock_apdp, monkeypatch
):
    async def _boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(mock_apdp, "get_manifest", _boom)
    with pytest.raises(RuntimeError):
        await plugin.start_run("research-orchestrator")
    assert len(mock_apdp._closed_sessions) == 1


async def test_child_execution_completed_reports_real_duration(plugin, mock_apdp):
    import time as _time

    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    child_mw = make_child_middleware(plugin)

    async def _run_child(request: Any) -> Any:
        child_state = await child_mw.abefore_agent({}, runtime=None)
        _time.sleep(0.02)
        await child_mw.aafter_agent(child_state, runtime=None)
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _run_child,
    )
    completed = [
        e
        for e in mock_apdp.published_events
        if e["event_type"] == "execution_completed"
        and e.get("parent_execution_id") is not None
    ]
    assert completed
    assert all(e["payload"]["duration_ms"] >= 15 for e in completed)
