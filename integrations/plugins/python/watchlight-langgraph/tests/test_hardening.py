"""Fail-closed hardening for the LangGraph plugin.

Covers:

* a configured wl-proxy URL with no issued proxy token refuses the run
  (never silent direct egress), and the refused session is closed;
* a failed wl-sidecar install refuses the run;
* a session create the backend does not accept refuses the run;
* a failed sub-agent contextvar bind refuses the spawn instead of
  leaving the parent's handle in force;
* the approval request id (a bearer value) never reaches a log line;
* the README describes what is enforced and keeps credentials out of
  code samples.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from watchlight_core import AuthorizeResult, GovernanceUnavailable
from watchlight_core_testing import MockApdpClient, stub_session_info

from watchlight_langgraph import WatchlightLangGraphPlugin

_README = Path(__file__).resolve().parent.parent / "README.md"


def _plugin(proxy_token: str | None, connect_proxy_url: str | None):
    plugin = WatchlightLangGraphPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(return_value={"id": "agent-uuid"})  # type: ignore[method-assign]
    payload = stub_session_info(
        plugin.apdp, "ses_test", session_token="sst_test", proxy_token=proxy_token
    )
    plugin.apdp.create_session = AsyncMock(return_value=payload)  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_configured_proxy_without_token_refuses_run():
    plugin = _plugin(None, "https://wl-proxy:8443")
    with patch("watchlight_core.install_sidecar") as mock_install:
        with pytest.raises(GovernanceUnavailable, match="proxy token"):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once_with(
        plugin.apdp.create_session.return_value.run
    )


@pytest.mark.asyncio
async def test_failed_sidecar_install_refuses_run():
    plugin = _plugin("eyJ.secret.token", "https://wl-proxy:8443")
    with patch(
        "watchlight_core.install_sidecar",
        side_effect=RuntimeError("wl-sidecar did not announce its listen port"),
    ), pytest.raises(GovernanceUnavailable) as excinfo:
        await plugin.start_run("agent-x")
    # The token never appears in the refusal.
    assert "eyJ.secret.token" not in str(excinfo.value)
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_session_not_accepted_refuses_run():
    plugin = _plugin(None, None)
    plugin.apdp.create_session = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run("agent-x")


class _UnbindableVar:
    """Stand-in for the SDK's sub-agent contextvar: clearing it works,
    binding a child handle to it fails."""

    def set(self, value):
        if value is None:
            return None
        raise RuntimeError("bind failed")

    def get(self, default=None):
        return default


@pytest.mark.asyncio
async def test_spawn_refused_when_subagent_bind_fails(monkeypatch):
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = "11111111-1111-4111-8111-aaaaaaaaaaaa"
    plugin.apdp.known_agents["child-agent"] = "11111111-1111-4111-8111-bbbbbbbbbbbb"
    parent = await plugin.start_run("parent-agent")

    import watchlight_core.run_handle as rh

    monkeypatch.setattr(rh, "_current_subagent_handle", _UnbindableVar())
    with pytest.raises(GovernanceUnavailable, match="bind"):
        await parent.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, parent_execution_id="exec_parent")


class _ApprovalHandle:
    def __init__(self):
        self.calls = 0

    async def authorize_action_detailed(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return AuthorizeResult(
                decision="needs_approval",
                reason="approval required",
                approval_request_id="apr_SECRET_bearer_value_123",
            )
        return AuthorizeResult(decision="allow")


@pytest.mark.asyncio
async def test_approval_request_id_never_logged(caplog):
    from watchlight_langgraph import governance

    handle = _ApprovalHandle()
    caplog.set_level(logging.DEBUG)
    with patch.object(governance, "_lg_interrupt", return_value="apr_SECRET_bearer_value_123"):
        result = await governance.governed_tool_call(
            handle,  # type: ignore[arg-type]
            "send_email",
            intent={},
            context={},
            impl=lambda: "ok",
        )
    assert result == "ok"
    assert "apr_SECRET_bearer_value_123" not in caplog.text
    assert "approval_ref=" in caplog.text


def test_readme_has_no_inline_api_key():
    text = _README.read_text()
    assert not re.search(r"api_key\s*=\s*[\"']", text)


def test_readme_states_callbacks_only_observe():
    text = _README.read_text()
    assert "authorize every agent action" not in text
    assert "only observe" in text
    assert "governed_tool_call" in text


@pytest.mark.asyncio
async def test_start_run_closes_session_on_any_open_failure():
    """Any exception while opening the run (not only a governance
    refusal) closes the session start_run created."""
    plugin = _plugin(None, None)
    plugin.apdp.get_manifest = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await plugin.start_run("agent-x")
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_spawned_child_unbinds_itself_with_its_token_on_complete():
    from watchlight_core import current_subagent_handle

    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = "11111111-1111-4111-8111-aaaaaaaaaaaa"
    plugin.apdp.known_agents["child-agent"] = "11111111-1111-4111-8111-bbbbbbbbbbbb"
    parent = await plugin.start_run("parent-agent")
    child = await parent.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, parent_execution_id="exec_parent")
    assert child._subagent_cv_token is not None
    assert current_subagent_handle() is child
    await child.complete()
    assert current_subagent_handle() is None


class _DenyHandle:
    async def authorize_action_detailed(self, **kwargs):
        return AuthorizeResult(decision="deny", reason="policy secret-policy-7 matched")


@pytest.mark.asyncio
async def test_tool_denied_message_carries_no_server_reason():
    """Opaque deny: ToolDenied's message (what ToolNode hands the model)
    is a generic refusal."""
    from watchlight_langgraph import governance

    with pytest.raises(governance.ToolDenied) as info:
        await governance.governed_tool_call(
            _DenyHandle(),  # type: ignore[arg-type]
            "send_email",
            intent={},
            context={},
            impl=lambda: "ok",
        )
    assert "secret-policy-7" not in str(info.value)
    assert str(info.value) == "send_email: denied by Watchlight policy"
