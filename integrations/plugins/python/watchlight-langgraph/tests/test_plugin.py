"""Tests for WatchlightLangGraphPlugin.

Covers:
- normalize_plan with `list[str]`, `list[dict]`, mixed, malformed
- start_run resolves slug → UUID, opens session, fetches manifest
- start_run fails closed when slug unknown (AgentNotRegistered)
- start_run fails closed when session create rejected (GovernanceUnavailable)
- RunHandle.submit_plan: Allow / Modify / Deny / transport-failure paths
- RunHandle.preflight_step: allowed / denied / transport-failure
- RunHandle.complete is idempotent + as async context manager
- state_from_langgraph_plugin matches the GovernanceState shape from ADK
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_langgraph import (
    AgentNotRegistered,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    WatchlightLangGraphPlugin,
    governance_mode,
    state_from_langgraph_plugin,
)
from watchlight_core import normalize_plan
from watchlight_core_testing import stub_session_info


# ─── normalize_plan ─────────────────────────────────────────────────


def test_normalize_str_plan_assigns_step_ids_and_default_resource():
    out = normalize_plan(["search the kb", "summarize", "report"])
    assert len(out) == 3
    assert [s["step_id"] for s in out] == ["s1", "s2", "s3"]
    assert out[0]["action"] == "search the kb"
    assert out[0]["resource_pattern"] == "*"
    assert out[0]["estimated_risk"] == "medium"
    assert out[0]["depends_on"] == []


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
    assert out[0]["depends_on"] == ["s0"]


def test_normalize_dict_plan_resource_alias():
    """Models that emit `resource` instead of `resource_pattern`."""
    out = normalize_plan([{"action": "read", "resource": "Document::x"}])
    assert out[0]["resource_pattern"] == "Document::x"


def test_normalize_drops_dict_steps_missing_action():
    out = normalize_plan([{"step_id": "s1"}, {"action": "read"}])
    assert len(out) == 1
    assert out[0]["action"] == "read"


def test_normalize_drops_non_str_non_dict_items():
    out = normalize_plan([42, None, "good_step", {"action": "ok"}])
    actions = [s["action"] for s in out]
    assert "good_step" in actions
    assert "ok" in actions
    assert len(out) == 2


def test_normalize_rejects_non_list():
    with pytest.raises(TypeError) as excinfo:
        normalize_plan({"plan": ["a"]})
    assert "list[str] or list[dict]" in str(excinfo.value)


# ─── PlanResult predicates ───────────────────────────────────────────


def test_plan_result_allow_predicates():
    r = PlanResult({"decision": {"decision": "allow"}, "violations": []})
    assert r.is_allow()
    assert not r.is_modify()
    assert not r.is_deny()


def test_plan_result_modify_carries_modified_plan():
    r = PlanResult(
        {
            "decision": {
                "decision": "modify",
                "modified_plan": [{"step_id": "s1", "action": "read"}],
                "modifications": [
                    {"kind": "removed", "step_id": "s2", "reason": "blocked"}
                ],
            },
            "violations": [],
        }
    )
    assert r.is_modify()
    assert len(r.modified_plan) == 1
    assert len(r.modifications) == 1


def test_plan_result_deny_with_violations():
    r = PlanResult(
        {
            "decision": {"decision": "deny"},
            "violations": [
                {
                    "rule_family": "constraint",
                    "code": "forbidden_action",
                    "message": "blocked",
                }
            ],
        }
    )
    assert r.is_deny()
    assert len(r.violations) == 1


def test_plan_result_transport_failure_is_deny():
    r = PlanResult.deny_transport_failure()
    assert r.is_deny()
    assert any(v["code"] == "apdp_unreachable" for v in r.violations)


def test_plan_result_handles_legacy_string_decision():
    """Defensive: very old APDPs may emit decision as a bare string."""
    r = PlanResult({"decision": "allow", "violations": []})
    assert r.is_allow()


# ─── PreflightResult ─────────────────────────────────────────────────


def test_preflight_result_allowed():
    r = PreflightResult({"allowed": True, "explanation": "ok"})
    assert r.allowed
    assert r.reason == "ok"


def test_preflight_result_denied():
    r = PreflightResult({"allowed": False, "explanation": "forbidden"})
    assert not r.allowed
    assert r.reason == "forbidden"


def test_preflight_transport_failure_denies_with_reason():
    r = PreflightResult.transport_failure()
    assert not r.allowed
    assert "unreachable" in r.reason


# ─── WatchlightLangGraphPlugin.start_run ─────────────────────────────


@pytest.fixture
def plugin():
    p = WatchlightLangGraphPlugin(apdp_url="https://apdp.test")
    p.apdp.resolve_agent = AsyncMock()
    p.apdp.create_session = AsyncMock()
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": ["read"]})
    p.apdp.complete_session = AsyncMock(return_value=True)
    p.apdp.terminate_session = AsyncMock(return_value=True)
    p.apdp.submit_plan = AsyncMock()
    p.apdp.preflight_step = AsyncMock()
    return p


@pytest.mark.asyncio
async def test_start_run_resolves_slug_and_opens_session(plugin):
    plugin.apdp.resolve_agent.return_value = {
        "id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
        "slug": "research-analyst",
        "name": "Research Analyst",
        "trust_state": "trusted",
    }
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_abc", session_token="sst_abc")

    handle = await plugin.start_run(agent_slug="research-analyst")

    assert handle.agent_uuid == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    assert handle.session_id == "ses_abc"
    assert plugin.last_governance_mode == "strong"
    assert plugin.last_session_id == "ses_abc"
    plugin.apdp.resolve_agent.assert_called_once_with("research-analyst")
    # create_session called with the resolved UUID, not the slug
    args = plugin.apdp.create_session.call_args.kwargs
    assert args["agent_id"] == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    # No end user: nothing extra is sent, so an older SDK keeps working.
    assert "subject_token" not in args


@pytest.mark.asyncio
async def test_start_run_presents_the_end_users_token(plugin):
    """The token reaches session creation untouched."""
    plugin.apdp.resolve_agent.return_value = {"id": "a-1", "slug": "x", "name": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_abc", session_token="sst_abc")
    await plugin.start_run(agent_slug="x", subject_token="eyJ.subject.token")
    args = plugin.apdp.create_session.call_args.kwargs
    assert args["subject_token"] == "eyJ.subject.token"


@pytest.mark.asyncio
async def test_start_run_fails_closed_on_unknown_slug(plugin):
    plugin.apdp.resolve_agent.return_value = None
    with pytest.raises(AgentNotRegistered):
        await plugin.start_run(agent_slug="nonexistent")
    # Session was never created — fail-close is total
    plugin.apdp.create_session.assert_not_called()


@pytest.mark.asyncio
async def test_start_run_fails_closed_on_session_rejection(plugin):
    plugin.apdp.resolve_agent.return_value = {"id": "uuid-1", "slug": "x"}
    plugin.apdp.create_session.return_value = None
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run(agent_slug="x")


@pytest.mark.asyncio
async def test_start_run_refuses_when_manifest_fetch_fails(plugin, monkeypatch):
    """A missing manifest refuses the run (strict default) and the
    session it opened is closed."""
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_x", session_token="sst_x")
    plugin.apdp.get_manifest.return_value = None  # simulate manifest failure
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run(agent_slug="x")
    plugin.apdp.complete_session.assert_awaited()


@pytest.mark.asyncio
async def test_start_run_degrades_without_manifest_only_on_explicit_opt_in(
    plugin, monkeypatch
):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_x", session_token="sst_x")
    plugin.apdp.get_manifest.return_value = None
    handle = await plugin.start_run(agent_slug="x")
    assert plugin.last_governance_mode == "degraded"
    assert handle.session_id == "ses_x"


@pytest.mark.asyncio
async def test_start_run_resets_last_state(plugin):
    """Stale state from a prior run must not bleed into the next run's
    governance card."""
    # Pretend a previous run left state:
    plugin.last_governance_mode = "strong"
    plugin.last_actions_denied = 5
    plugin.last_proposed_plan = [{"step_id": "stale"}]

    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_y", session_token="sst_y")
    await plugin.start_run(agent_slug="x")
    assert plugin.last_actions_denied == 0
    assert plugin.last_proposed_plan is None


# ─── RunHandle.submit_plan ───────────────────────────────────────────


@pytest_asyncio.fixture
async def handle(plugin):
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_z", session_token="sst_z")
    return await plugin.start_run(agent_slug="x")


@pytest.mark.asyncio
async def test_submit_plan_allow(plugin, handle):
    plugin.apdp.submit_plan.return_value = {
        "validation": {
            "decision": {"decision": "allow"},
            "violations": [],
            "escalations": [],
            "plan_hash": "abc",
        }
    }
    result = await handle.submit_plan(["search", "summarize"])
    assert result.is_allow()
    # Plan was normalized before submission
    sent = plugin.apdp.submit_plan.call_args.args[1]
    assert sent[0]["action"] == "search"
    assert sent[0]["step_id"] == "s1"


@pytest.mark.asyncio
async def test_submit_plan_modify_returns_corrected_plan(plugin, handle):
    plugin.apdp.submit_plan.return_value = {
        "validation": {
            "decision": {
                "decision": "modify",
                "modified_plan": [{"step_id": "s1", "action": "search", "resource_pattern": "*"}],
                "modifications": [{"kind": "removed", "step_id": "s2", "reason": "blocked"}],
            },
            "violations": [],
            "escalations": [],
        }
    }
    result = await handle.submit_plan(["search", "send_email"])
    assert result.is_modify()
    assert len(result.modified_plan) == 1
    assert result.modifications[0]["kind"] == "removed"


@pytest.mark.asyncio
async def test_submit_plan_deny_with_violations(plugin, handle):
    plugin.apdp.submit_plan.return_value = {
        "validation": {
            "decision": {"decision": "deny"},
            "violations": [
                {
                    "rule_family": "constraint",
                    "code": "forbidden_action",
                    "message": "external email blocked",
                }
            ],
            "escalations": [],
        }
    }
    result = await handle.submit_plan(["send_email"])
    assert result.is_deny()
    assert result.violations[0]["code"] == "forbidden_action"


@pytest.mark.asyncio
async def test_submit_plan_transport_failure_synthesizes_deny(plugin, handle):
    plugin.apdp.submit_plan.return_value = None  # transport failure
    result = await handle.submit_plan(["search"])
    assert result.is_deny()
    assert any(v["code"] == "apdp_unreachable" for v in result.violations)


# ─── RunHandle.preflight_step ────────────────────────────────────────


@pytest.mark.asyncio
async def test_preflight_step_allowed(plugin, handle):
    plugin.apdp.preflight_step.return_value = {
        "preflight": {"allowed": True, "explanation": "ok"}
    }
    r = await handle.preflight_step("read", "Document::x")
    assert r.allowed


@pytest.mark.asyncio
async def test_preflight_step_transport_failure_denies(plugin, handle):
    plugin.apdp.preflight_step.return_value = None
    r = await handle.preflight_step("read", "Document::x")
    assert not r.allowed


# ─── RunHandle.complete + async context manager ──────────────────────


@pytest.mark.asyncio
async def test_complete_is_idempotent(plugin, handle):
    await handle.complete()
    await handle.complete()  # second call must not double-call APDP
    assert plugin.apdp.complete_session.call_count == 1


@pytest.mark.asyncio
async def test_async_context_manager_calls_complete_on_clean_exit(plugin, handle):
    async with handle as h:
        assert h is handle
    plugin.apdp.complete_session.assert_called_once()


@pytest.mark.asyncio
async def test_async_context_manager_calls_terminate_on_exception(plugin, handle):
    with pytest.raises(RuntimeError):
        async with handle:
            raise RuntimeError("graph blew up")
    plugin.apdp.terminate_session.assert_called_once()
    plugin.apdp.complete_session.assert_not_called()


# ─── state_from_langgraph_plugin shape parity ────────────────────────


def test_state_adapter_unavailable_when_plugin_is_none():
    s = state_from_langgraph_plugin(None)
    assert s["mode"] == "unavailable"
    assert s["framework"] == "langgraph"


def test_state_adapter_strong_mode():
    class P:
        last_governance_mode = "strong"
        last_session_id = "ses_q"
        last_manifest = {"tool_allowlist": ["read"]}
        last_plan_validation = {"decision": {"decision": "allow"}}
        last_proposed_plan = [{"step_id": "s1", "action": "read"}]
        last_actions_allowed = 2
        last_actions_denied = 0

    s = state_from_langgraph_plugin(P(), dashboard_base_url="http://dash:3000")
    assert s["mode"] == "strong"
    assert s["framework"] == "langgraph"
    assert s["actions_allowed"] == 2
    assert s["dashboard_base_url"] == "http://dash:3000"


def test_state_adapter_handles_missing_attrs():
    """Bare plugin without last_* attrs shouldn't crash — returns
    'unavailable' so the host renders fail-closed banner."""

    class Bare:
        pass

    s = state_from_langgraph_plugin(Bare())
    assert s["mode"] == "unavailable"
    assert s["actions_allowed"] == 0


def test_state_adapter_normalizes_none_counters_to_zero():
    class P:
        last_governance_mode = "degraded"
        last_session_id = None
        last_manifest = None
        last_plan_validation = None
        last_proposed_plan = None
        last_actions_allowed = None
        last_actions_denied = None

    s = state_from_langgraph_plugin(P())
    assert s["actions_allowed"] == 0
    assert s["actions_denied"] == 0


def test_state_adapter_shape_matches_adk():
    """The framework-agnostic contract requires identical key sets so
    the same governance_card renders for both. Compares keys against
    the canonical shape documented in proxy-plugin-interop.md §6."""

    class P:
        last_governance_mode = "strong"
        last_session_id = "ses_p"
        last_manifest = {}
        last_plan_validation = {}
        last_proposed_plan = []
        last_actions_allowed = 0
        last_actions_denied = 0

    s = state_from_langgraph_plugin(P())
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


# ─── governance_mode env ─────────────────────────────────────────────


def test_governance_mode_default_is_strict(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert governance_mode() == "strict"


def test_governance_mode_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "strict")
    assert governance_mode() == "strict"


def test_governance_mode_unknown_falls_back_to_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "yolo")
    assert governance_mode() == "strict"


# ─── A refused agent never runs, in every mode ──────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "degrade"])
async def test_start_run_refused_manifest_refuses_in_every_mode(plugin, monkeypatch, mode):
    """A refused manifest (e.g. revoked trust) is a typed refusal, never
    "no manifest": even degrade mode returns no handle, and the session
    opened for it is closed."""
    from watchlight_core import GovernanceRefused

    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", mode)
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.return_value = stub_session_info(plugin.apdp, "ses_x", session_token="sst_x")
    plugin.apdp.get_manifest.side_effect = GovernanceRefused(
        "refused", status_code=403, error="agent_trust_revoked"
    )
    with pytest.raises(GovernanceRefused) as exc:
        await plugin.start_run(agent_slug="x")
    assert exc.value.code == "agent_trust_revoked"
    plugin.apdp.complete_session.assert_awaited()
    assert plugin.last_governance_mode != "degraded"


@pytest.mark.asyncio
async def test_start_run_refused_session_opens_nothing(plugin, monkeypatch):
    from watchlight_core import GovernanceRefused

    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin.apdp.resolve_agent.return_value = {"id": "u", "slug": "x"}
    plugin.apdp.create_session.side_effect = GovernanceRefused(
        "refused", status_code=403, error="agent_unverified"
    )
    with pytest.raises(GovernanceRefused):
        await plugin.start_run(agent_slug="x")
    plugin.apdp.get_manifest.assert_not_called()
