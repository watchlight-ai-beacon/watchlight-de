"""Tests for the AWS Bedrock plugin.

Covers the same governance surface as the LangGraph and ADK plugin
suites — normalize_plan, PlanResult, PreflightResult, start_run,
RunHandle lifecycle, state adapter parity — plus the Bedrock-specific
pieces:

- ``parse_bedrock_event`` against REST-style and function-style events
- ``watchlight_bedrock_action`` decorator: allow path, deny path,
  missing-session path, fallback bootstrap path, transport-failure path
- Bedrock-shaped deny response carries the original action group / path
  so Bedrock surfaces the refusal in the agent's reasoning trace
"""

from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from watchlight_bedrock import (
    AgentNotRegistered,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    WatchlightBedrockPlugin,
    governance_mode,
    state_from_bedrock_plugin,
    watchlight_bedrock_action,
)
from watchlight_bedrock.plugin import (
    _bedrock_deny_response,
    parse_bedrock_event,
)
from watchlight_core import normalize_plan

from .conftest import as_session


# ─── normalize_plan (parity with LangGraph plugin) ────────────────────


def test_normalize_str_plan_assigns_step_ids_and_default_resource():
    out = normalize_plan(["search the kb", "summarize", "report"])
    assert len(out) == 3
    assert [s["step_id"] for s in out] == ["s1", "s2", "s3"]
    assert out[0]["resource_pattern"] == "*"
    assert out[0]["estimated_risk"] == "medium"


def test_normalize_dict_plan_passes_through_with_defaults():
    plan = [
        {
            "step_id": "custom",
            "action": "execute_trade",
            "resource_pattern": "Order::*",
            "estimated_risk": "high",
            "depends_on": ["s0"],
        }
    ]
    out = normalize_plan(plan)
    assert out[0]["step_id"] == "custom"
    assert out[0]["resource_pattern"] == "Order::*"
    assert out[0]["estimated_risk"] == "high"


def test_normalize_dict_plan_resource_alias():
    out = normalize_plan([{"action": "read", "resource": "Document::x"}])
    assert out[0]["resource_pattern"] == "Document::x"


def test_normalize_drops_dict_steps_missing_action():
    out = normalize_plan([{"step_id": "s1"}, {"action": "read"}])
    assert len(out) == 1
    assert out[0]["action"] == "read"


def test_normalize_rejects_non_list():
    with pytest.raises(TypeError):
        normalize_plan({"plan": ["a"]})


# ─── PlanResult / PreflightResult (parity) ─────────────────────────────


def test_plan_result_allow():
    r = PlanResult({"decision": {"decision": "allow"}, "violations": []})
    assert r.is_allow() and not r.is_deny()


def test_plan_result_modify_carries_modified_plan():
    r = PlanResult(
        {
            "decision": {
                "decision": "modify",
                "modified_plan": [{"step_id": "s1", "action": "read"}],
                "modifications": [{"kind": "removed", "step_id": "s2"}],
            },
            "violations": [],
        }
    )
    assert r.is_modify()
    assert len(r.modified_plan) == 1


def test_plan_result_transport_failure_is_deny():
    r = PlanResult.deny_transport_failure()
    assert r.is_deny()
    assert any(v["code"] == "apdp_unreachable" for v in r.violations)


def test_preflight_transport_failure_denies():
    r = PreflightResult.transport_failure()
    assert not r.allowed
    assert "unreachable" in r.reason


# ─── WatchlightBedrockPlugin.start_run ─────────────────────────────────


@pytest.fixture
def plugin():
    p = WatchlightBedrockPlugin(apdp_url="https://apdp.test", tenant_id="acme")
    p.apdp.resolve_agent = AsyncMock()
    p.apdp.create_session = AsyncMock()
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": ["read"]})
    p.apdp.complete_session = AsyncMock(return_value=True)
    p.apdp.terminate_session = AsyncMock(return_value=True)
    p.apdp.submit_plan = AsyncMock()
    p.apdp.preflight_step = AsyncMock()
    p.apdp.authorize = AsyncMock()
    # The SDK defensively emits ``execution_started`` on the first
    # authorize/publish call so the lineage contract guard has a parent
    # row. The helper is fail-loud, so the fixture mocks
    # ``publish_events`` to succeed; otherwise the real ApdpClient would
    # attempt a network POST to ``https://apdp.test`` and raise.
    p.apdp.publish_events = AsyncMock(return_value=True)
    return p


@pytest.mark.asyncio
async def test_start_run_promotes_to_strong_when_manifest_present(plugin):
    plugin.apdp.resolve_agent.return_value = {
        "id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
        "slug": "research-analyst",
    }
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_b"}})

    handle = await plugin.start_run(agent_slug="research-analyst")

    # Bedrock has no native plan-time hook — manifest alone earns "strong"
    # only because the manifest carried tool_allowlist; without manifest
    # we'd be "degraded" until the customer submits a plan.
    assert plugin.last_governance_mode == "strong"
    assert handle.session_id == "ses_b"
    assert handle._bedrock_session_attributes() == {
        "watchlight_session_id": "ses_b",
        "watchlight_agent_id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
    }


@pytest.mark.asyncio
async def test_start_run_refused_and_session_closed_when_no_manifest(plugin, monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_x"}})
    plugin.apdp.get_manifest.return_value = None
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run(agent_slug="x")
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_run_degraded_without_manifest_only_on_explicit_opt_in(
    plugin, monkeypatch
):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_x"}})
    plugin.apdp.get_manifest.return_value = None
    await plugin.start_run(agent_slug="x")
    assert plugin.last_governance_mode == "degraded"


@pytest.mark.asyncio
async def test_start_run_closes_session_on_any_open_failure(plugin):
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_x"}})
    plugin.apdp.get_manifest.side_effect = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        await plugin.start_run(agent_slug="x")
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_run_fails_closed_on_unknown_slug(plugin):
    plugin.apdp.resolve_agent.return_value = None
    with pytest.raises(AgentNotRegistered):
        await plugin.start_run(agent_slug="nope")
    plugin.apdp.create_session.assert_not_called()


@pytest.mark.asyncio
async def test_start_run_fails_closed_on_session_rejection(plugin):
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = None
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run(agent_slug="x")


@pytest.mark.asyncio
async def test_start_run_resets_last_state(plugin):
    plugin.last_actions_denied = 99
    plugin.last_proposed_plan = [{"stale": True}]
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_y"}})
    await plugin.start_run(agent_slug="x")
    assert plugin.last_actions_denied == 0
    assert plugin.last_proposed_plan is None


# ─── RunHandle.submit_plan ─────────────────────────────────────────────


@pytest_asyncio.fixture
async def handle(plugin):
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = as_session(plugin.apdp, {"session": {"id": "ses_z"}})
    h = await plugin.start_run(agent_slug="x")
    # Synthetic test handle bypasses the production ``async with``
    # entry path; flip the fail-closed flag.
    h._aentered = True
    return h


@pytest.mark.asyncio
async def test_submit_plan_promotes_mode_to_strong(plugin, handle):
    plugin.last_governance_mode = "degraded"  # simulate no manifest
    plugin.apdp.submit_plan.return_value = {
        "validation": {
            "decision": {"decision": "allow"},
            "violations": [],
            "escalations": [],
        }
    }
    result = await handle.submit_plan(["search", "summarize"])
    assert result.is_allow()
    # Successful plan submission promotes the run from degraded → strong.
    assert plugin.last_governance_mode == "strong"


@pytest.mark.asyncio
async def test_submit_plan_deny_records_violations(plugin, handle):
    plugin.apdp.submit_plan.return_value = {
        "validation": {
            "decision": {"decision": "deny"},
            "violations": [
                {"rule_family": "constraint", "code": "forbidden_action"}
            ],
            "escalations": [],
        }
    }
    result = await handle.submit_plan(["send_email"])
    assert result.is_deny()
    assert plugin.last_plan_validation["decision"]["decision"] == "deny"


@pytest.mark.asyncio
async def test_submit_plan_transport_failure_synthesizes_deny(plugin, handle):
    plugin.apdp.submit_plan.return_value = None
    result = await handle.submit_plan(["search"])
    assert result.is_deny()


# ─── RunHandle.authorize_action / preflight ────────────────────────────


@pytest.mark.asyncio
async def test_authorize_action_increments_counters(plugin, handle):
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    ok = await handle.authorize_action("read", "Document::x")
    assert ok is True
    assert plugin.last_actions_allowed == 1
    assert plugin.last_actions_denied == 0


@pytest.mark.asyncio
async def test_authorize_action_deny_increments_denied(plugin, handle):
    plugin.apdp.authorize.return_value = {"decision": "Deny", "reason": "no"}
    ok = await handle.authorize_action("send_email", "Email::external")
    assert ok is False
    assert plugin.last_actions_denied == 1


@pytest.mark.asyncio
async def test_preflight_allowed(plugin, handle):
    plugin.apdp.preflight_step.return_value = {
        "preflight": {"allowed": True, "explanation": "ok"}
    }
    r = await handle.preflight_step("read", "Document::x")
    assert r.allowed


# ─── async context manager lifecycle ───────────────────────────────────


@pytest.mark.asyncio
async def test_complete_is_idempotent(plugin, handle):
    await handle.complete()
    await handle.complete()
    assert plugin.apdp.complete_session.call_count == 1


@pytest.mark.asyncio
async def test_async_context_calls_terminate_on_exception(plugin, handle):
    with pytest.raises(RuntimeError):
        async with handle:
            raise RuntimeError("bedrock blew up")
    plugin.apdp.terminate_session.assert_called_once()
    plugin.apdp.complete_session.assert_not_called()


# ─── parse_bedrock_event ───────────────────────────────────────────────


def _rest_event(**overrides) -> dict:
    """Canonical Bedrock REST-style action-group event."""
    base = {
        "messageVersion": "1.0",
        "agent": {
            "id": "AG12345",
            "name": "research-analyst",
            "alias": "PROD",
            "version": "1",
        },
        "actionGroup": "research_tools",
        "apiPath": "/search",
        "httpMethod": "POST",
        "parameters": [{"name": "q", "type": "string", "value": "watchlight"}],
        "sessionId": "bedrock-session-123",
        "sessionState": {
            "sessionAttributes": {
                "watchlight_session_id": "ses_apdp",
                "watchlight_agent_id": "uuid-xyz",
            }
        },
        "inputText": "search for X",
    }
    base.update(overrides)
    return base


def test_parse_rest_style_event():
    parsed = parse_bedrock_event(_rest_event())
    assert parsed["agent_id"] == "AG12345"
    assert parsed["action_group"] == "research_tools"
    assert parsed["api_path"] == "/search"
    assert parsed["http_method"] == "POST"
    assert parsed["session_attributes"]["watchlight_session_id"] == "ses_apdp"


def test_parse_function_style_event_synthesizes_path():
    """Function-style action groups don't carry apiPath; we synthesize
    `/<function>` so the authz call shape stays consistent."""
    event = {
        "messageVersion": "1.0",
        "agent": {"id": "AG2", "name": "x", "alias": "TST", "version": "1"},
        "actionGroup": "tools",
        "function": "lookup_kb",
        "parameters": [],
        "sessionId": "s",
        "sessionState": {"sessionAttributes": {}},
    }
    parsed = parse_bedrock_event(event)
    assert parsed["api_path"] == "/lookup_kb"
    assert parsed["http_method"] == "POST"


def test_parse_event_with_legacy_session_attrs_at_top_level():
    """Older Bedrock SDK shapes put sessionAttributes at top level rather
    than under sessionState — be tolerant."""
    event = _rest_event(sessionState={})
    event["sessionAttributes"] = {"watchlight_session_id": "ses_legacy"}
    parsed = parse_bedrock_event(event)
    assert parsed["session_attributes"]["watchlight_session_id"] == "ses_legacy"


def test_parse_event_extracts_request_body_properties_when_no_top_level_params():
    event = _rest_event(parameters=[])
    event["requestBody"] = {
        "content": {
            "application/json": {
                "properties": [{"name": "q", "type": "string", "value": "x"}]
            }
        }
    }
    parsed = parse_bedrock_event(event)
    assert parsed["parameters"][0]["name"] == "q"


# ─── _bedrock_deny_response ────────────────────────────────────────────


def test_deny_response_preserves_action_group_and_path():
    """Bedrock surfaces the deny response back into the agent's reasoning
    trace — the action_group + api_path must round-trip so the agent
    knows *which* tool got refused."""
    event = _rest_event()
    resp = _bedrock_deny_response(event, "policy denied")
    assert resp["messageVersion"] == "1.0"
    assert resp["response"]["actionGroup"] == "research_tools"
    assert resp["response"]["apiPath"] == "/search"
    assert resp["response"]["httpStatusCode"] == 403
    body = resp["response"]["responseBody"]["application/json"]["body"]
    assert "policy denied" in body
    assert "watchlight_denied" in body


def test_deny_response_handles_non_dict_event_gracefully():
    """Defensive: malformed events shouldn't crash the deny path."""
    resp = _bedrock_deny_response("not a dict", "unparseable", http_status=500)
    assert resp["response"]["httpStatusCode"] == 500


# ─── @watchlight_bedrock_action decorator ──────────────────────────────


def _bedrock_event_with_attrs(allow_attrs: bool = True) -> dict:
    e = _rest_event()
    if not allow_attrs:
        e["sessionState"] = {"sessionAttributes": {}}
    return e


def test_decorator_allow_calls_wrapped_function():
    """When APDP allows, the wrapped Lambda body executes."""

    captured = {}

    @watchlight_bedrock_action(apdp_url="https://apdp.test")
    def handler(event, context):
        captured["called"] = True
        return {"messageVersion": "1.0", "response": {"ok": True}}

    with patch("watchlight_bedrock.plugin._enforce_authz", return_value=(True, None, None)):
        result = handler(_bedrock_event_with_attrs(), None)

    assert captured.get("called") is True
    assert result["response"]["ok"] is True


def test_decorator_deny_short_circuits_with_bedrock_response():
    """When APDP denies, the wrapped Lambda body must NOT execute and
    the decorator returns the Bedrock-formatted deny verbatim."""

    captured = {}

    @watchlight_bedrock_action(apdp_url="https://apdp.test")
    def handler(event, context):
        captured["called"] = True
        return {"unreachable": True}

    deny_payload = {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": "research_tools",
            "apiPath": "/search",
            "httpMethod": "POST",
            "httpStatusCode": 403,
            "responseBody": {"application/json": {"body": "{}"}},
        },
    }

    with patch(
        "watchlight_bedrock.plugin._enforce_authz",
        return_value=(False, deny_payload, None),
    ):
        result = handler(_bedrock_event_with_attrs(), None)

    assert "called" not in captured  # wrapped body never ran
    assert result["response"]["httpStatusCode"] == 403


def test_decorator_fails_closed_on_enforcement_error():
    """If the enforcement layer itself raises, the decorator must
    fail-closed with a 500 — never silently allow the call."""

    @watchlight_bedrock_action(apdp_url="https://apdp.test")
    def handler(event, context):
        return {"oops": "should-not-run"}

    with patch(
        "watchlight_bedrock.plugin._enforce_authz",
        side_effect=RuntimeError("boom"),
    ):
        result = handler(_bedrock_event_with_attrs(), None)

    assert result["response"]["httpStatusCode"] == 500
    assert "RuntimeError" in result["response"]["responseBody"]["application/json"]["body"]


def test_decorator_missing_session_attrs_without_fallback_denies():
    """Without watchlight session attrs and without fallback_agent_slug,
    the call must be refused — we will not silently mint a session
    behind the operator's back."""

    @watchlight_bedrock_action(apdp_url="https://apdp.test")
    def handler(event, context):
        return {"unreachable": True}

    # Don't patch _enforce_authz — let the real path run, which will
    # short-circuit on missing session attrs without ever touching the
    # network (no fallback configured).
    result = handler(_bedrock_event_with_attrs(allow_attrs=False), None)
    assert result["response"]["httpStatusCode"] == 403


# ─── state_from_bedrock_plugin shape parity ────────────────────────────


def test_state_adapter_unavailable_when_plugin_is_none():
    s = state_from_bedrock_plugin(None)
    assert s["mode"] == "unavailable"
    assert s["framework"] == "aws_bedrock"


def test_state_adapter_strong_mode():
    class P:
        last_governance_mode = "strong"
        last_session_id = "ses_q"
        last_manifest = {"tool_allowlist": ["read"]}
        last_plan_validation = {"decision": {"decision": "allow"}}
        last_proposed_plan = [{"step_id": "s1", "action": "read"}]
        last_actions_allowed = 2
        last_actions_denied = 0

    s = state_from_bedrock_plugin(P(), dashboard_base_url="http://dash:3000")
    assert s["mode"] == "strong"
    assert s["framework"] == "aws_bedrock"
    assert s["actions_allowed"] == 2


def test_state_adapter_normalizes_none_counters_to_zero():
    class P:
        last_governance_mode = "degraded"
        last_session_id = None
        last_manifest = None
        last_plan_validation = None
        last_proposed_plan = None
        last_actions_allowed = None
        last_actions_denied = None

    s = state_from_bedrock_plugin(P())
    assert s["actions_allowed"] == 0
    assert s["actions_denied"] == 0


def test_state_adapter_shape_matches_other_frameworks():
    """Cross-framework parity — same key set as ADK and LangGraph
    adapters. If this test fails, governance_card will silently render
    differently for one framework."""

    class P:
        last_governance_mode = "strong"
        last_session_id = "ses_p"
        last_manifest = {}
        last_plan_validation = {}
        last_proposed_plan = []
        last_actions_allowed = 0
        last_actions_denied = 0

    s = state_from_bedrock_plugin(P())
    expected_keys = {
        "mode",
        "session_id",
        "framework",
        "manifest",
        "plan_validation",
        "proposed_plan",
        "actions_allowed",
        "actions_denied",
        "dashboard_base_url",
    }
    assert set(s.keys()) == expected_keys


# ─── governance_mode env ───────────────────────────────────────────────


def test_governance_mode_default_is_strict(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert governance_mode() == "strict"


def test_governance_mode_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "strict")
    assert governance_mode() == "strict"


def test_governance_mode_unknown_falls_back_to_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "yolo")
    assert governance_mode() == "strict"


# ─── sub-agent spawn no-override lock ─────────────────────────────────


def test_run_handle_does_not_override_spawn_subagent():
    """The Bedrock plugin has no sub-agent primitive of its own
    (Bedrock orchestrations are flat, not multi-tier). Its
    :class:`RunHandle` inherits the canonical
    :meth:`BaseRunHandle.spawn_subagent` directly so any spawn that
    DOES happen goes through the canonical wire shape.

    Locks the no-override contract: any future plugin-side override MUST
    still route through the base ``spawn_subagent`` round-trip (so wl-apdp
    sees + server-attests the spawn) and MUST NOT emit
    ``agent_spawn_observed`` itself — that class is SERVER-emitted by
    wl-apdp's ``spawn_handler`` and is rejected at ``/v1/events``
    ingest. This plugin passes the spawn-lineage invariant vacuously
    (zero spawn events emitted from the synthetic lifecycle)."""
    from watchlight_bedrock.plugin import RunHandle as BedrockRunHandle
    from watchlight_core.run_handle import BaseRunHandle

    assert (
        BedrockRunHandle.spawn_subagent  # type: ignore[attr-defined]
        is BaseRunHandle.spawn_subagent
    ), (
        "BedrockRunHandle.spawn_subagent has been overridden. Any override "
        "MUST route through the base spawn_subagent round-trip (so wl-apdp "
        "server-attests the spawn) and MUST NOT emit `agent_spawn_observed` "
        "itself — that class is rejected at /v1/events ingest. "
        "Update this assertion only if the override preserves that contract."
    )
