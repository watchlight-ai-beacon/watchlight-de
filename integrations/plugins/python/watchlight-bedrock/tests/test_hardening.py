"""Fail-closed hardening for the Bedrock plugin.

Each test pins one behaviour:

- a configured wl-proxy URL with no issued proxy token refuses the run
  instead of letting egress go direct;
- a failed CONNECT sidecar install refuses the run;
- the Lambda fallback root needs an explicit action scope and is closed
  after the invocation;
- an invocation that carries a Watchlight parent reference never opens
  a fresh root, and a hand-off without a run credential is refused;
- the ``/authorize`` context carries argument metadata, never values.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from watchlight_bedrock import WatchlightBedrockPlugin, watchlight_bedrock_action
from watchlight_bedrock.collaborator import SESSION_ATTR_PARENT_RUN_HANDLE_ID
from watchlight_core import GovernanceUnavailable

from watchlight_core_testing import register_test_run

from .conftest import as_session

SECRET = "sk-live-do-not-leak-0123456789"


def _mocked_plugin(session_payload: dict, *, connect_proxy_url=None):
    plugin = WatchlightBedrockPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(return_value={"id": "agent-uuid"})
    plugin.apdp.create_session = AsyncMock(return_value=as_session(plugin.apdp, session_payload))
    plugin.apdp.get_manifest = AsyncMock(return_value={})
    plugin.apdp.complete_session = AsyncMock(return_value=True)
    plugin.apdp.publish_events = AsyncMock(return_value=True)
    plugin.apdp.authorize = AsyncMock(return_value={"decision": "Allow"})
    return plugin


# ─── proxy URL configured, no proxy token ───────────────────────


@pytest.mark.asyncio
async def test_proxy_url_without_proxy_token_refuses_the_run():
    plugin = _mocked_plugin(
        {"session": {"id": "ses_x"}, "session_token": "sst_x"},
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    # The half-open session is closed, not left dangling.
    plugin.apdp.complete_session.assert_awaited_once()


# ─── CONNECT install fails ──────────────────────────────────────


@pytest.mark.asyncio
async def test_failed_connect_install_refuses_the_run():
    plugin = _mocked_plugin(
        {
            "session": {"id": "ses_x"},
            "session_token": "sst_x",
            "proxy_token": "eyJ.t.k",
            "proxy_token_expires_at": "2026-06-08T15:00:00Z",
        },
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch(
        "watchlight_core.install_connect_proxy",
        side_effect=OSError("bind failed"),
    ):
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    plugin.apdp.complete_session.assert_awaited_once()


# ─── fallback root needs an explicit scope and is closed ────────


def _event(attrs: dict, *, value: str = SECRET) -> dict:
    return {
        "messageVersion": "1.0",
        "agent": {"id": "AG1", "name": "collab", "alias": "PROD", "version": "1"},
        "actionGroup": "research_tools",
        "apiPath": "/search",
        "httpMethod": "POST",
        "parameters": [{"name": "api_key", "type": "string", "value": value}],
        "sessionId": "bedrock-session-1",
        "sessionState": {"sessionAttributes": attrs},
        "inputText": "look something up",
    }


def test_fallback_without_explicit_scope_is_rejected_at_decoration():
    with pytest.raises(ValueError, match="fallback_allowed_actions"):
        watchlight_bedrock_action(
            apdp_url="https://apdp.test", fallback_agent_slug="collab"
        )


def test_fallback_refuses_actions_outside_its_scope_without_opening_a_root():
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    ran = {}
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/other"],
        )
        def handler(event, context):
            ran["yes"] = True
            return {"ok": True}

        result = handler(_event({}), None)
    assert "yes" not in ran
    assert result["response"]["httpStatusCode"] == 403
    plugin.apdp.create_session.assert_not_awaited()


def test_fallback_session_is_completed_after_the_invocation():
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/search"],
        )
        def handler(event, context):
            # The session is still open while the tool body runs.
            assert plugin.apdp.complete_session.await_count == 0
            return {"ok": True}

        result = handler(_event({}), None)
    assert result == {"ok": True}
    plugin.apdp.complete_session.assert_awaited_once()
    # The run that closes is the one whose credential is sst_f.
    assert plugin.apdp.complete_session.await_args.args == (
        register_test_run(plugin.apdp, "sst_f"),
    )


def test_fallback_session_is_completed_on_deny():
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    plugin.apdp.authorize = AsyncMock(return_value={"decision": "Deny"})
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/search"],
        )
        def handler(event, context):
            raise AssertionError("must not run")

        result = handler(_event({}), None)
    assert result["response"]["httpStatusCode"] == 403
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.parametrize(
    "attrs",
    [
        # A collaborator hand-off: a parent run reference is present.
        {
            "watchlight_session_id": "ses_parent",
            "watchlight_agent_id": "parent-uuid",
            SESSION_ATTR_PARENT_RUN_HANDLE_ID: "rh_parent",
        },
        # A partial reference: only the run-handle id crossed.
        {SESSION_ATTR_PARENT_RUN_HANDLE_ID: "rh_parent"},
        # A partial reference: only the agent id crossed.
        {"watchlight_agent_id": "parent-uuid"},
    ],
)
def test_parent_reference_never_falls_back_to_a_fresh_root(attrs):
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/search"],
        )
        def handler(event, context):
            raise AssertionError("must not run")

        result = handler(_event(attrs), None)
    assert result["response"]["httpStatusCode"] == 403
    plugin.apdp.create_session.assert_not_awaited()
    plugin.apdp.authorize.assert_not_awaited()


def test_orchestrator_handoff_without_run_credential_is_refused():
    """The orchestrator hand-off carries no ``sst_`` run credential, so
    the Lambda cannot act under the parent's run. It is refused, and no
    uncredentialed authorize is sent under the parent's principal."""
    plugin = _mocked_plugin({"session": {"id": "ses_f"}})
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(apdp_url="https://apdp.test")
        def handler(event, context):
            raise AssertionError("must not run")

        result = handler(
            _event(
                {
                    "watchlight_session_id": "ses_parent",
                    "watchlight_agent_id": "parent-uuid",
                }
            ),
            None,
        )
    assert result["response"]["httpStatusCode"] == 403
    plugin.apdp.authorize.assert_not_awaited()


# ─── no raw argument values in the authorize context ───────────


def test_authorize_context_carries_no_argument_values():
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/search"],
        )
        def handler(event, context):
            return {"ok": True}

        handler(_event({}), None)
    plugin.apdp.authorize.assert_awaited_once()
    ctx = plugin.apdp.authorize.await_args.kwargs["context"]
    assert SECRET not in repr(ctx)
    meta = ctx["bedrock"]["parameters"]
    assert meta["arg_count"] == 1
    assert meta["arg_names"] == ["api_key"]
    assert meta["arg_types"] == {"api_key": "string"}


def test_deny_response_carries_no_server_reason():
    """Opaque deny: the agent sees a generic refusal; the server's reason
    stays in its audit trail."""
    plugin = _mocked_plugin({"session": {"id": "ses_f"}, "session_token": "sst_f"})
    plugin.apdp.authorize = AsyncMock(
        return_value={"decision": "Deny", "reason": "policy secret-policy-7 matched"}
    )
    with patch("watchlight_bedrock.plugin._get_cached_plugin", return_value=plugin):

        @watchlight_bedrock_action(
            apdp_url="https://apdp.test",
            fallback_agent_slug="collab",
            fallback_allowed_actions=["research_tools/search"],
        )
        def handler(event, context):
            raise AssertionError("must not run")

        result = handler(_event({}), None)
    assert result["response"]["httpStatusCode"] == 403
    assert "secret-policy-7" not in repr(result)
