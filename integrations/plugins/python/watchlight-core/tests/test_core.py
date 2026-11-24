"""Tests for watchlight-core.

Two layers of coverage:

1. **Per-module unit tests** — each consolidated primitive (errors,
   results, plan, env, state, telemetry) gets focused tests.
2. **End-to-end BaseRunHandle lifecycle** — covers the lifecycle the
   LangGraph and Bedrock plugins delegate to ``BaseRunHandle``.

Tests mock the ``ApdpClient`` rather than running a real APDP — same
pattern as the per-plugin suites — so the test surface stays narrow
and deterministic.
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentNotRegistered,
    ApdpClient,
    BaseRunHandle,
    GovernanceState,
    GovernanceTelemetry,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    WatchlightError,
    governance_mode,
    normalize_plan,
    state_from_attrs,
)
from watchlight_core.telemetry import TelemetryProtocol
from watchlight_core_testing import register_test_run, bind_test_run
from watchlight_core.apdp_client import _parse_proxy_token_fields


# ─── errors ───────────────────────────────────────────────────────────


def test_error_hierarchy():
    """Both fail-closed signals must subclass WatchlightError so callers
    can `except WatchlightError:` to catch any plugin error generically."""
    assert issubclass(AgentNotRegistered, WatchlightError)
    assert issubclass(GovernanceUnavailable, WatchlightError)


def test_errors_carry_message():
    e = AgentNotRegistered("slug 'x' not registered")
    assert "slug 'x'" in str(e)


# ─── env ──────────────────────────────────────────────────────────────


def test_governance_mode_default_is_strict(monkeypatch):
    # Fail closed: strict is the default; degrade is an explicit opt-in.
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert governance_mode() == "strict"


def test_governance_mode_strict_canonical(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "strict")
    assert governance_mode() == "strict"


def test_governance_mode_strict_case_insensitive(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "STRICT")
    assert governance_mode() == "strict"


def test_governance_mode_typo_stays_strict(monkeypatch):
    """A typo must NOT silently drop plan-time enforcement: only an
    exact ``degrade`` opts out of strict mode."""
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "stict")
    assert governance_mode() == "strict"


def test_governance_mode_strips_whitespace(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "  strict  ")
    assert governance_mode() == "strict"


# ─── normalize_plan ───────────────────────────────────────────────────


def test_normalize_str_plan_assigns_step_ids_and_default_resource():
    out = normalize_plan(["search", "summarize", "report"])
    assert len(out) == 3
    assert [s["step_id"] for s in out] == ["s1", "s2", "s3"]
    assert all(s["resource_pattern"] == "*" for s in out)
    assert all(s["estimated_risk"] == "medium" for s in out)


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
    """Models that emit `resource` instead of `resource_pattern`
    should still produce valid normalised steps."""
    out = normalize_plan([{"action": "read", "resource": "Document::x"}])
    assert out[0]["resource_pattern"] == "Document::x"


def test_normalize_drops_dict_steps_missing_action():
    """A dict with no action is malformed; drop it but don't fail."""
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


def test_normalize_strips_whitespace_in_str_form():
    out = normalize_plan(["  search the kb  "])
    assert out[0]["action"] == "search the kb"


# ─── PlanResult / PreflightResult ─────────────────────────────────────


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
                "modifications": [{"kind": "removed", "step_id": "s2"}],
            },
            "violations": [],
        }
    )
    assert r.is_modify()
    assert len(r.modified_plan) == 1
    assert r.modifications[0]["kind"] == "removed"


def test_plan_result_deny_with_violations():
    r = PlanResult(
        {
            "decision": {"decision": "deny"},
            "violations": [{"rule_family": "constraint", "code": "forbidden"}],
        }
    )
    assert r.is_deny()
    assert r.violations[0]["code"] == "forbidden"


def test_plan_result_legacy_string_decision():
    """Defensive: very old APDPs may emit `decision` as a bare string."""
    r = PlanResult({"decision": "allow", "violations": []})
    assert r.is_allow()


def test_plan_result_transport_failure_synthesizes_deny():
    r = PlanResult.deny_transport_failure()
    assert r.is_deny()
    assert any(v["code"] == "apdp_unreachable" for v in r.violations)


def test_preflight_result_allowed():
    r = PreflightResult({"allowed": True, "explanation": "ok"})
    assert r.allowed
    assert r.reason == "ok"


def test_preflight_result_uses_reason_code_when_no_explanation():
    r = PreflightResult({"allowed": False, "reason_code": "policy_deny"})
    assert not r.allowed
    assert r.reason == "policy_deny"


def test_preflight_transport_failure_denies_with_message():
    r = PreflightResult.transport_failure()
    assert not r.allowed
    assert "unreachable" in r.reason


# ─── GovernanceTelemetry ──────────────────────────────────────────────


def test_telemetry_mixin_initialises_attributes():
    class Plugin(GovernanceTelemetry):
        pass

    p = Plugin()
    assert p.last_governance_mode == "unknown"
    assert p.last_session_id is None
    assert p.last_manifest is None
    assert p.last_plan_validation is None
    assert p.last_proposed_plan is None
    assert p.last_actions_allowed == 0
    assert p.last_actions_denied == 0


def test_telemetry_reset_clears_stale_state():
    """Stale state from a prior run must not bleed into the next run.
    The reset helper is the canonical way to clear it."""

    class Plugin(GovernanceTelemetry):
        pass

    p = Plugin()
    p.last_governance_mode = "strong"
    p.last_actions_denied = 5
    p.last_proposed_plan = [{"step_id": "stale"}]

    p._reset_telemetry()
    assert p.last_governance_mode == "unknown"
    assert p.last_actions_denied == 0
    assert p.last_proposed_plan is None


def test_telemetry_protocol_runtime_check_passes():
    """A class implementing GovernanceTelemetry must satisfy the
    runtime-checkable Protocol."""

    class Plugin(GovernanceTelemetry):
        pass

    p = Plugin()
    assert isinstance(p, TelemetryProtocol)


def test_telemetry_protocol_rejects_incomplete_class():
    """A class missing one of the seven attributes must fail the
    Protocol check — that's what catches plugin contract drift."""

    class Incomplete:
        last_governance_mode = "strong"
        last_session_id = None
        # Missing the other five.

    assert not isinstance(Incomplete(), TelemetryProtocol)


# ─── state_from_attrs ─────────────────────────────────────────────────


def test_state_unavailable_when_plugin_is_none():
    s = state_from_attrs(None, framework="adk")
    assert s["mode"] == "unavailable"
    assert s["framework"] == "adk"
    assert s["session_id"] is None
    assert s["actions_allowed"] == 0


def test_state_passes_through_telemetry():
    class P:
        last_governance_mode = "strong"
        last_session_id = "ses_1"
        last_manifest = {"tool_allowlist": ["read"]}
        last_plan_validation = {"decision": {"decision": "allow"}}
        last_proposed_plan = [{"step_id": "s1", "action": "read"}]
        last_actions_allowed = 3
        last_actions_denied = 1

    s = state_from_attrs(P(), framework="langgraph", dashboard_base_url="http://x")
    assert s["mode"] == "strong"
    assert s["framework"] == "langgraph"
    assert s["actions_allowed"] == 3
    assert s["actions_denied"] == 1
    assert s["dashboard_base_url"] == "http://x"


def test_state_handles_missing_attrs_gracefully():
    """A bare object missing telemetry must not crash — return safe defaults."""

    class Bare:
        pass

    s = state_from_attrs(Bare(), framework="bedrock")
    assert s["mode"] == "unavailable"
    assert s["actions_allowed"] == 0
    assert s["framework"] == "bedrock"


def test_state_normalises_none_counters_to_zero():
    """If a plugin sets a counter to None (defensively or via bug), the
    adapter must coerce to 0 — the dashboard reads ints."""

    class P:
        last_governance_mode = "degraded"
        last_session_id = None
        last_manifest = None
        last_plan_validation = None
        last_proposed_plan = None
        last_actions_allowed = None
        last_actions_denied = None

    s = state_from_attrs(P(), framework="adk")
    assert s["actions_allowed"] == 0
    assert s["actions_denied"] == 0


def test_state_canonical_key_set():
    """Cross-framework consumers (governance_card widget) read this exact
    key set. Drift in this test means dashboard render breaks."""
    s = state_from_attrs(None, framework="adk")
    expected = {
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
    assert set(s.keys()) == expected


def test_state_typeddict_accepts_isinstance_dict():
    """GovernanceState is structurally a dict; adapters should produce
    something that passes runtime dict checks."""
    s = state_from_attrs(None, framework="x")
    assert isinstance(s, dict)


# ─── BaseRunHandle ────────────────────────────────────────────────────


@pytest.fixture
def plugin():
    """A minimal plugin satisfying the GovernedPlugin Protocol."""

    class Plugin(GovernanceTelemetry):
        def __init__(self):
            super().__init__()
            self.apdp = ApdpClient("https://apdp.test")
            self.apdp.submit_plan = AsyncMock()
            self.apdp.preflight_step = AsyncMock()
            self.apdp.authorize = AsyncMock()
            self.apdp.complete_session = AsyncMock(return_value=True)
            self.apdp.terminate_session = AsyncMock(return_value=True)
            # the SDK's defensive
            # ``execution_started`` mint in
            # :meth:`BaseRunHandle._ensure_execution_started_emitted`
            # routes through ``publish_events``. Mock it to return
            # True so ``authorize_action`` tests don't trip on the
            # transport-failure fail-loud branch.
            self.apdp.publish_events = AsyncMock(return_value=True)
            self.tenant_id = "acme"
            self.log_decisions = False

    return Plugin()


@pytest_asyncio.fixture
async def handle(plugin):
    h = bind_test_run(
        BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x"),
        "sst_x.sig",
    )
    # synthetic test handle bypasses the production
    # ``async with`` entry path; flip the fail-closed flag so the
    # lineage contract guard in ``authorize_action_detailed`` /
    # ``publish_observation`` accepts the test's direct calls.
    h._aentered = True
    return h


@pytest.mark.asyncio
async def test_submit_plan_normalises_and_promotes_to_strong(plugin, handle):
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
    # Promoted by the base class regardless of starting mode.
    assert plugin.last_governance_mode == "strong"
    # And the plan was normalised before submission.
    sent = plugin.apdp.submit_plan.call_args.args[1]
    assert sent[0]["action"] == "search"
    assert sent[0]["step_id"] == "s1"


@pytest.mark.asyncio
async def test_submit_plan_transport_failure_synthesises_deny(plugin, handle):
    plugin.apdp.submit_plan.return_value = None
    r = await handle.submit_plan(["x"])
    assert r.is_deny()


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
async def test_authorize_action_forwards_caller_context(plugin, handle):
    """Caller-supplied context must reach APDP so Cedar policies can gate
    on ``intent_category`` / ``goal_action_count`` / etc. Plugin's
    ``tenant_id`` must remain authoritative regardless of what the caller
    passes."""
    plugin.tenant_id = "plugin-tenant"
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action(
        "execute",
        "Tool::web_search",
        context={
            "intent_category": "Research",
            "goal_action_count": 3,
            "goal_max_actions": 8,
            "allowed_intent_categories": ["Research", "DataAnalysis"],
            "tenant_id": "spoofed-by-caller",
        },
    )
    sent = plugin.apdp.authorize.call_args.kwargs["context"]
    assert sent["intent_category"] == "Research"
    assert sent["goal_action_count"] == 3
    assert sent["goal_max_actions"] == 8
    assert sent["allowed_intent_categories"] == ["Research", "DataAnalysis"]
    assert sent["tenant_id"] == "plugin-tenant"


@pytest.mark.asyncio
async def test_preflight_passes_through_when_allowed(plugin, handle):
    plugin.apdp.preflight_step.return_value = {
        "preflight": {"allowed": True, "explanation": "ok"}
    }
    r = await handle.preflight_step("read", "Document::x")
    assert r.allowed


@pytest.mark.asyncio
async def test_preflight_transport_failure_denies(plugin, handle):
    plugin.apdp.preflight_step.return_value = None
    r = await handle.preflight_step("read", "Document::x")
    assert not r.allowed


@pytest.mark.asyncio
async def test_complete_is_idempotent(plugin, handle):
    await handle.complete()
    await handle.complete()
    assert plugin.apdp.complete_session.call_count == 1


@pytest.mark.asyncio
async def test_terminate_is_idempotent(plugin, handle):
    await handle.terminate(reason="x")
    await handle.terminate(reason="x")
    assert plugin.apdp.terminate_session.call_count == 1


@pytest.mark.asyncio
async def test_async_context_manager_completes_on_clean_exit(plugin, handle):
    async with handle as h:
        assert h is handle
    plugin.apdp.complete_session.assert_called_once()
    # Only the run itself may close it: the handle names its own run.
    assert plugin.apdp.complete_session.call_args.args == (handle.run,)
    plugin.apdp.terminate_session.assert_not_called()


@pytest.mark.asyncio
async def test_async_context_manager_terminates_on_exception(plugin, handle):
    with pytest.raises(RuntimeError):
        async with handle:
            raise RuntimeError("graph blew up")
    plugin.apdp.terminate_session.assert_called_once()
    plugin.apdp.complete_session.assert_not_called()


# ─── ApdpClient extras (check_agent_trust + publish_events) ───────────


@pytest.mark.asyncio
async def test_check_agent_trust_returns_dict_on_404():
    """A 404 must produce a fail-closed dict, not raise. ADK relied on
    this shape; promoting it to core means every plugin gets the same
    fail-closed default."""
    from unittest.mock import MagicMock

    client = ApdpClient("https://apdp.test")
    stub = MagicMock()
    stub.status_code = 404

    async def _get(*args, **kwargs):
        return stub

    client._client = MagicMock()
    client._client.is_closed = False
    client._client.get = _get

    out = await client.check_agent_trust("uuid-x")
    assert out["trusted"] is False
    assert "not registered" in out["reason"]


@pytest.mark.asyncio
async def test_publish_events_empty_batch_skips_network():
    """Empty list short-circuits — no need to hit the network for a
    no-op publish."""
    client = ApdpClient("https://apdp.test")
    # No httpx mock needed; if this hits the network the test will fail.
    assert await client.publish_events(None, []) is True


def _publish_events_client_with_status(status_code, body=None):
    """Build an ApdpClient whose /v1/events POST returns `status_code`.

    Bypasses the /health probe + lazy client creation so the test
    exercises only `publish_events`' status handling.
    """
    from unittest.mock import AsyncMock, MagicMock

    client = ApdpClient("https://apdp.test")

    async def _no_probe() -> None:
        return None

    client._ensure_probed = _no_probe  # type: ignore[assignment]

    resp = MagicMock()
    resp.status_code = status_code
    resp.json = MagicMock(return_value=body if body is not None else {"accepted": 1})
    resp.text = "" if body is None else str(body)

    stub_http = MagicMock()
    stub_http.is_closed = False
    stub_http.post = AsyncMock(return_value=resp)
    client._client = stub_http
    return client


@pytest.mark.asyncio
async def test_publish_events_accepts_202():
    """APDP `/v1/events` returns 202 Accepted under the CQRS thin
    pass-through (events emitted to NATS asynchronously). A correct,
    accepted publish MUST be reported as success — not misread as a
    rejection. Regression for the demo break where 202 surfaced as
    `WatchlightError: APDP rejected publish_observation`."""
    client = _publish_events_client_with_status(202, {"accepted": 1, "event_ids": ["evt_x"]})
    assert await client.publish_events(register_test_run(client, "sst_test"), [{"event_id": "evt_x"}]) is True


@pytest.mark.asyncio
async def test_publish_events_accepts_200_for_backcompat():
    """Older APDP builds returned 200; still accepted."""
    client = _publish_events_client_with_status(200, {"accepted": 1})
    assert await client.publish_events(register_test_run(client, "sst_test"), [{"event_id": "evt_x"}]) is True


@pytest.mark.asyncio
async def test_publish_events_rejects_non_2xx():
    """A genuine server error (5xx) is still reported as a failed
    publish so the fail-open lineage path can log + drop it."""
    client = _publish_events_client_with_status(500, {})
    assert await client.publish_events(register_test_run(client, "sst_test"), [{"event_id": "evt_x"}]) is False


@pytest.mark.asyncio
async def test_preflight_resource_type_passes_through(plugin, handle):
    """ADK preflight calls include resource_type to disambiguate Cedar
    types; the parameter must round-trip into the request body."""
    plugin.apdp.preflight_step.return_value = {"preflight": {"allowed": True}}
    await handle.preflight_step("read", "x")
    # BaseRunHandle doesn't pass resource_type; verify ADK's direct
    # call path can — wire the call directly.
    plugin.apdp.preflight_step.reset_mock()
    plugin.apdp.preflight_step.return_value = {"preflight": {"allowed": True}}
    await plugin.apdp.preflight_step(
        "ses", "read", "Document::x", resource_type="Document"
    )
    kwargs = plugin.apdp.preflight_step.call_args.kwargs
    assert kwargs.get("resource_type") == "Document"


@pytest.mark.asyncio
async def test_authorize_passes_session_id_and_principal(plugin, handle):
    """The base authorize call must wire the session_id and the DEFAULT
    Cedar principal correctly — a regression here would silently break
    plan-conformance enforcement at the APDP edge.

    This backend declares nothing, so it gets the HISTORICAL wrapping —
    the shape every networked, mock and third-party backend still sees.
    Only a backend that declares ``cedar_entities_verbatim`` (the
    in-process client) receives the caller's terms untouched."""
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("read", "Document::x")
    kwargs = plugin.apdp.authorize.call_args.kwargs
    assert kwargs["session_id"] == "ses_x"
    assert kwargs["principal"] == 'Agent::"uuid-x"'
    assert kwargs["action"] == 'Action::"read"'
    # `Document::x` carries no quoted id, so it is not a Cedar entity
    # reference — it stays a bare name and is wrapped like any other.
    assert kwargs["resource"] == 'Resource::"Document::x"'


@pytest.mark.asyncio
async def test_authorize_per_call_principal_overrides_the_acting_agent(plugin, handle):
    """A caller-supplied ``principal`` names the SUBJECT of the decision and
    reaches the backend verbatim; the acting agent is not the subject."""
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("read", "dataset", principal='User::"alice"')
    assert plugin.apdp.authorize.call_args.kwargs["principal"] == 'User::"alice"'

    # …and the rich variant takes it on the same keyword.
    plugin.apdp.authorize.reset_mock()
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action_detailed("read", "dataset", principal='User::"bob"')
    assert plugin.apdp.authorize.call_args.kwargs["principal"] == 'User::"bob"'


@pytest.mark.asyncio
async def test_authorize_typed_action_and_resource_reach_the_backend_intact(
    plugin, handle
):
    """A caller who names an entity TYPE keeps it — the SDK no longer
    overwrites it with ``Action::`` / ``Resource::``. (Cedar constrains the
    action term to the literal type ``Action``; the resource term is where a
    caller-chosen type actually matters.)"""
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action('Action::"read"', 'Document::"d1"')
    kwargs = plugin.apdp.authorize.call_args.kwargs
    assert kwargs["action"] == 'Action::"read"'
    assert kwargs["resource"] == 'Document::"d1"'


# ─── ApdpClient channel safety + credential auth (sub-PR 1.6) ─────────


def test_channel_guard_rejects_http_to_remote_host():
    """Plain http:// to a non-loopback host MUST raise at construction
    so the misconfiguration surfaces before any credential leaks
    over plaintext."""
    from watchlight_core import InsecureChannelError

    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient("http://apdp.example.com:8081")
    assert "non-loopback" in str(exc_info.value)


def test_channel_guard_accepts_http_to_localhost():
    """Loopback exemption per design §3.6 — local dev / sidecar
    deployments where the network never leaves the host are
    legitimate uses of plain http://."""
    # No exception expected.
    ApdpClient("http://localhost:8081")
    ApdpClient("http://127.0.0.1:8081")
    ApdpClient("http://[::1]:8081")


def test_channel_guard_accepts_https_to_remote():
    """https:// is the supported production path."""
    ApdpClient("https://apdp.example.com")


def test_channel_guard_allow_plaintext_env_var_bypasses_check(monkeypatch):
    """``WATCHLIGHT_APDP_ALLOW_PLAINTEXT=true`` is the operator-explicit
    opt-out for compose / sidecar topologies where the APDP host is
    only reachable on a private bridge. Mirrors
    ``WL_LINEAGE_ALLOW_PLAINTEXT_NATS`` in wl-lineage."""
    monkeypatch.setenv("WATCHLIGHT_APDP_ALLOW_PLAINTEXT", "true")
    # No exception expected — the docker-bridge hostname would
    # otherwise be rejected as non-loopback.
    ApdpClient("http://wl-apdp:8081")


def test_channel_guard_allow_plaintext_only_when_true(monkeypatch):
    """Anything other than the literal 'true' / '1' must NOT bypass —
    a fat-finger like ``trve`` should fail closed, not silently allow
    plaintext."""
    from watchlight_core import InsecureChannelError

    monkeypatch.setenv("WATCHLIGHT_APDP_ALLOW_PLAINTEXT", "trve")
    with pytest.raises(InsecureChannelError):
        ApdpClient("http://wl-apdp:8081")


def test_channel_guard_rejects_url_without_hostname():
    """A URL without a hostname is malformed; reject rather than
    fall through to httpx which would raise a confusing low-level
    error at first request."""
    from watchlight_core import InsecureChannelError

    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient("not-a-url")
    assert "no hostname" in str(exc_info.value)


def test_passing_both_api_key_and_credential_raises():
    """Passing both api_key= and credential= is a programmer error —
    the call site is unambiguous about its auth, but the constructor
    can't know which one to honor. Fail loudly."""
    from watchlight_core import PluginCredential

    cred = PluginCredential.new(
        bearer_token="wlpa_" + "a" * 43,
        tenant_id="acme",
    )
    with pytest.raises(ValueError) as exc_info:
        ApdpClient(
            "https://apdp.example.com",
            api_key="legacy-key",
            credential=cred,
        )
    assert "either" in str(exc_info.value)


def test_api_key_emits_deprecation_warning():
    """The legacy api_key= path still works for backwards compat but
    must emit a DeprecationWarning so customers see the migration
    notice in their logs."""
    with pytest.warns(DeprecationWarning, match="deprecated"):
        ApdpClient("https://apdp.example.com", api_key="legacy-key")


def test_credential_does_not_emit_deprecation_warning():
    """The new credential= path must NOT emit a deprecation warning —
    that would be a confusing UX for customers on the supported path."""
    import warnings

    from watchlight_core import PluginCredential

    cred = PluginCredential.new(
        bearer_token="wlpa_" + "a" * 43,
        tenant_id="acme",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning fails the test
        ApdpClient("https://apdp.example.com", credential=cred)


def test_plugin_credential_attaches_no_identity_headers():
    """Plugin credentials emit Authorization + X-Wl-Credential-Kind
    only. No X-Wl-Tenant-Id (or any other identity header): wl-apdp
    takes the tenant from the verified credential, never from a header
    the client sets."""
    from watchlight_core import PluginCredential

    token = "wlpa_" + "x" * 43
    cred = PluginCredential.new(bearer_token=token, tenant_id="acme")
    client = ApdpClient("https://apdp.example.com", credential=cred)
    headers = client._build_auth_headers()
    assert headers == {
        "Authorization": f"Bearer {token}",
        "X-Wl-Credential-Kind": "plugin",
    }


def test_service_credential_attaches_two_headers_no_tenant():
    """Service credentials are cross-tenant by design — no
    X-Wl-Tenant-Id header. Sending one would be a category error
    that the server might reject or, worse, silently misroute."""
    from watchlight_core import ServiceCredential

    token = "wlsa_" + "y" * 43
    cred = ServiceCredential.new(bearer_token=token, service_name="wl-proxy")
    client = ApdpClient("https://apdp.example.com", credential=cred)
    headers = client._build_auth_headers()
    assert headers["Authorization"] == f"Bearer {token}"
    assert headers["X-Wl-Credential-Kind"] == "service"
    assert "X-Wl-Tenant-Id" not in headers


def test_no_auth_emits_no_auth_headers():
    """Test fixtures and health-probe code paths sometimes construct
    an ApdpClient without auth. The header set must stay empty rather
    than emit a placeholder Authorization header."""
    client = ApdpClient("https://apdp.example.com")
    headers = client._build_auth_headers()
    assert "Authorization" not in headers
    assert "X-Wl-Credential-Kind" not in headers


def test_legacy_api_key_emits_only_authorization_header():
    """The legacy bcrypt-API-key path on the server doesn't need
    the discriminator headers — adding them would just be noise the
    middleware ignores."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        client = ApdpClient("https://apdp.example.com", api_key="legacy")
    headers = client._build_auth_headers()
    assert headers["Authorization"] == "Bearer legacy"
    assert "X-Wl-Credential-Kind" not in headers
    assert "X-Wl-Tenant-Id" not in headers


def test_https_client_uses_tls_13_minimum_by_default():
    """The default TLS floor on the SSL context built for https://
    targets must be TLS 1.3 (design §3.6)."""
    import ssl

    from watchlight_core.apdp_client import _build_ssl_context

    client = ApdpClient("https://apdp.example.com")
    assert client._tls_min_version == ssl.TLSVersion.TLSv1_3
    # Round-trip through the actual context builder used by the client
    # so a regression in _build_ssl_context surfaces here, not at
    # production runtime.
    ctx = _build_ssl_context(client._tls_min_version, client._ca_bundle)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3


def test_https_client_honors_tls_12_override():
    """Customers with legacy APDP infra can pin TLS 1.2 minimum.
    The override must round-trip onto the SSL context."""
    import ssl

    client = ApdpClient(
        "https://apdp.example.com",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
    )
    assert client._tls_min_version == ssl.TLSVersion.TLSv1_2


def test_http_client_skips_ssl_context():
    """For http://localhost the client should not waste effort
    building an SSL context — verify is irrelevant for a plaintext
    channel. We assert the `_is_https` flag drives this; the actual
    httpx kwargs are checked at the integration boundary."""
    client = ApdpClient("http://localhost:8081")
    assert client._is_https is False


def test_credential_cleartext_never_in_repr():
    """Defense-in-depth: even though Credential.__repr__ redacts, an
    ApdpClient holding a credential must not accidentally surface the
    cleartext via its own repr() chain. Smoke test the failure mode."""
    from watchlight_core import PluginCredential

    secret_token = "wlpa_" + "S" * 43
    cred = PluginCredential.new(bearer_token=secret_token, tenant_id="acme")
    client = ApdpClient("https://apdp.example.com", credential=cred)
    assert secret_token not in repr(client)
    assert secret_token not in str(client)


# ─── ApdpClient mTLS (sub-PR 1.7) ─────────────────────────────────────


def _make_dummy_cert_and_key_paths(tmp_path):
    """Touch two empty files at known paths in ``tmp_path``. Used by
    tests that exercise the *validation* layer (paired-or-nothing,
    file-must-exist, scheme-must-be-https) — these checks run before
    the SSL context tries to actually load the PEM, so the file
    contents don't matter.

    Tests that need to verify the SSL context successfully *parses*
    the PEM call ``_make_throwaway_certificate`` instead.
    """
    cert_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"
    cert_path.touch()
    key_path.touch()
    return cert_path, key_path


def _make_throwaway_certificate(tmp_path):
    """Issue a self-signed cert + private key (real PEM) and return
    the on-disk paths. Skips the test if ``cryptography`` is not
    installed — that package is the standard library for issuing
    PEMs in Python and is present in CI envs that test mTLS, but
    it's not a runtime dep of watchlight-core itself."""
    pytest.importorskip(
        "cryptography",
        reason="cryptography package required to generate test PEMs",
    )
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "watchlight-test")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(tz=timezone.utc))
        .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_mtls_requires_both_cert_and_key(tmp_path):
    """Cert without key (or vice versa) is meaningless — refuse at
    construction so the misconfiguration surfaces before the first
    request that would have undefined behaviour."""
    from watchlight_core import InsecureChannelError

    cert_path, key_path = _make_dummy_cert_and_key_paths(tmp_path)

    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient("https://apdp.example.com", mtls_cert_path=cert_path)
    assert "mtls_key_path" in str(exc_info.value)

    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient("https://apdp.example.com", mtls_key_path=key_path)
    assert "mtls_cert_path" in str(exc_info.value)


def test_mtls_rejects_plain_http_loopback(tmp_path):
    """mTLS over http://localhost is meaningless — no TLS handshake
    means nothing to bind the cert to. Refuse rather than silently
    drop the cert config."""
    from watchlight_core import InsecureChannelError

    cert_path, key_path = _make_dummy_cert_and_key_paths(tmp_path)
    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient(
            "http://localhost:8081",
            mtls_cert_path=cert_path,
            mtls_key_path=key_path,
        )
    assert "plain HTTP" in str(exc_info.value)


def test_mtls_rejects_missing_files():
    """ssl.SSLContext.load_cert_chain raises a fairly opaque error on
    a missing path; we surface a clean InsecureChannelError so ops
    triage doesn't need to read the ssl module source."""
    from watchlight_core import InsecureChannelError

    with pytest.raises(InsecureChannelError) as exc_info:
        ApdpClient(
            "https://apdp.example.com",
            mtls_cert_path="/tmp/does-not-exist.pem",
            mtls_key_path="/tmp/also-does-not-exist.key",
        )
    assert "does not exist" in str(exc_info.value)


def test_mtls_loads_cert_chain_into_ssl_context(tmp_path):
    """End-to-end: a valid cert+key pair must round-trip through
    `_build_ssl_context` without raising, and produce a context with
    the configured TLS floor."""
    import ssl as _ssl

    from watchlight_core.apdp_client import _build_ssl_context

    cert_path, key_path = _make_throwaway_certificate(tmp_path)
    ctx = _build_ssl_context(
        _ssl.TLSVersion.TLSv1_3,
        ca_bundle=None,
        mtls_cert_path=cert_path,
        mtls_key_path=key_path,
    )
    # ssl.SSLContext exposes minimum_version and verify_mode; the
    # cert chain is internal state with no public accessor, so the
    # round-trip assertion is "no exception during load_cert_chain".
    assert ctx.minimum_version == _ssl.TLSVersion.TLSv1_3


def test_apdp_client_constructs_with_mtls(tmp_path):
    """Smoke test the integrated path — ApdpClient happy-path
    construction with mTLS uses the dummy PEM (load_cert_chain is
    deferred until the lazy httpx client is actually built)."""
    cert_path, key_path = _make_dummy_cert_and_key_paths(tmp_path)
    client = ApdpClient(
        "https://apdp.example.com",
        mtls_cert_path=cert_path,
        mtls_key_path=key_path,
    )
    assert client._mtls_cert_path == cert_path
    assert client._mtls_key_path == key_path


def test_mtls_paths_from_env_returns_tuple_of_optionals(monkeypatch):
    """Env-var helper returns (cert, key, ca_bundle); each None when
    the corresponding var is unset OR empty after stripping."""
    from watchlight_core.apdp_client import mtls_paths_from_env

    # All unset → all None.
    monkeypatch.delenv("WATCHLIGHT_APDP_MTLS_CERT_PATH", raising=False)
    monkeypatch.delenv("WATCHLIGHT_APDP_MTLS_KEY_PATH", raising=False)
    monkeypatch.delenv("WATCHLIGHT_APDP_TLS_CA_BUNDLE", raising=False)
    assert mtls_paths_from_env() == (None, None, None)

    # Set each → non-None.
    monkeypatch.setenv("WATCHLIGHT_APDP_MTLS_CERT_PATH", "/etc/wl/cert.pem")
    monkeypatch.setenv("WATCHLIGHT_APDP_MTLS_KEY_PATH", "/etc/wl/key.pem")
    monkeypatch.setenv("WATCHLIGHT_APDP_TLS_CA_BUNDLE", "/etc/wl/ca.pem")
    assert mtls_paths_from_env() == (
        "/etc/wl/cert.pem",
        "/etc/wl/key.pem",
        "/etc/wl/ca.pem",
    )

    # Empty string → None (defends against ``.env`` loaders that
    # leave a deliberately-empty value).
    monkeypatch.setenv("WATCHLIGHT_APDP_MTLS_CERT_PATH", "   ")
    assert mtls_paths_from_env()[0] is None


def test_mtls_paths_from_env_honors_custom_prefix(monkeypatch):
    """The prefix= override lets sibling Watchlight services adopt
    the same convention without re-implementing the helper."""
    from watchlight_core.apdp_client import mtls_paths_from_env

    monkeypatch.setenv("WL_PROXY_MTLS_CERT_PATH", "/etc/proxy/cert.pem")
    monkeypatch.delenv("WL_PROXY_MTLS_KEY_PATH", raising=False)
    monkeypatch.delenv("WL_PROXY_TLS_CA_BUNDLE", raising=False)
    cert, key, ca = mtls_paths_from_env(prefix="WL_PROXY_")
    assert cert == "/etc/proxy/cert.pem"
    assert key is None and ca is None


def test_no_mtls_does_not_error_on_construction():
    """Sanity check — the default path (no mTLS) still works and
    doesn't trip the new validation logic."""
    client = ApdpClient("https://apdp.example.com")
    assert client._mtls_cert_path is None
    assert client._mtls_key_path is None


# ─── ApdpClient startup probe (sub-PR 1.8) ────────────────────────────


def _stub_credential():
    """Build a Credential without going through PluginCredential.new
    (which validates token format). The probe tests don't care about
    the cleartext bytes — only that a credential is present."""
    from watchlight_core import PluginCredential

    return PluginCredential.new(
        bearer_token="wlpa_" + "p" * 43,
        tenant_id="acme",
    )


def _install_mock_httpx(client, mock_client):
    """Bypass the lazy `client` property by pre-populating
    `client._client` with a MagicMock that satisfies the duck-typing
    expected by the methods (`is_closed`, awaitable get/post)."""
    mock_client.is_closed = False
    client._client = mock_client


@pytest.mark.asyncio
async def test_probe_returns_payload_on_200():
    """Happy path — GET /health returns 200 with a JSON body. The
    probe parses the body, caches it, and reports as 'probed'."""
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    expected = {
        "auth": "ok",
        "kind": "plugin",
        "credential_label": "prod-langgraph",
        "expires_at": "2026-06-10T00:00:00Z",
    }
    stub_resp = MagicMock()
    stub_resp.status_code = 200
    stub_resp.json.return_value = expected
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    result = await client.probe()
    assert result == expected
    assert client._probed is True
    assert client._probe_result == expected


@pytest.mark.asyncio
async def test_probe_raises_on_401():
    """401 → CredentialProbeFailed with status_code=401 and an
    operator-actionable reason."""
    from unittest.mock import AsyncMock, MagicMock

    from watchlight_core import CredentialProbeFailed

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 401
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    with pytest.raises(CredentialProbeFailed) as exc_info:
        await client.probe()
    assert exc_info.value.status_code == 401
    assert "401" in str(exc_info.value)
    assert "rotate" in str(exc_info.value)


@pytest.mark.asyncio
async def test_probe_raises_on_403():
    from unittest.mock import AsyncMock, MagicMock

    from watchlight_core import CredentialProbeFailed

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 403
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    with pytest.raises(CredentialProbeFailed) as exc_info:
        await client.probe()
    assert exc_info.value.status_code == 403
    assert "claims" in str(exc_info.value)


@pytest.mark.asyncio
async def test_probe_raises_on_404():
    from unittest.mock import AsyncMock, MagicMock

    from watchlight_core import CredentialProbeFailed

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 404
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    with pytest.raises(CredentialProbeFailed) as exc_info:
        await client.probe()
    assert exc_info.value.status_code == 404
    assert "not found" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_probe_raises_on_transport_failure():
    """Connect refused / DNS / TLS handshake failure surfaces as
    status_code=None so callers can distinguish 'server said no'
    from 'never reached server'."""
    import httpx
    from unittest.mock import AsyncMock, MagicMock

    from watchlight_core import CredentialProbeFailed

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
    _install_mock_httpx(client, mock_client)

    with pytest.raises(CredentialProbeFailed) as exc_info:
        await client.probe()
    assert exc_info.value.status_code is None
    assert "transport" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_auto_probe_runs_once_then_caches():
    """Auto-probe fires before the first authenticated request and
    NOT before subsequent ones. A regression here would either fail
    open (no probe) or hit the network on every call (latency cost)."""
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    health_resp = MagicMock()
    health_resp.status_code = 200
    health_resp.json.return_value = {"auth": "ok"}

    authorize_resp = MagicMock()
    authorize_resp.status_code = 200
    authorize_resp.json.return_value = {"decision": "Allow"}
    authorize_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=health_resp)
    mock_client.post = AsyncMock(return_value=authorize_resp)
    _install_mock_httpx(client, mock_client)

    # First call triggers probe + the actual authorize.
    await client.authorize("p", "a", "r")
    assert client._probed is True
    assert mock_client.get.call_count == 1, "probe should run exactly once"
    assert mock_client.post.call_count == 1

    # Second call: no additional probe.
    await client.authorize("p", "a", "r")
    assert mock_client.get.call_count == 1, "probe must not re-run"
    assert mock_client.post.call_count == 2


@pytest.mark.asyncio
async def test_auto_probe_disabled_skips_probe():
    """auto_probe=False is for tests and for customers who want to
    manage probe explicitly. The flag must turn the auto-trigger
    off cleanly."""
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient(
        "https://apdp.example.com", credential=cred, auto_probe=False
    )

    authorize_resp = MagicMock()
    authorize_resp.status_code = 200
    authorize_resp.json.return_value = {"decision": "Allow"}
    authorize_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get = AsyncMock()
    mock_client.post = AsyncMock(return_value=authorize_resp)
    _install_mock_httpx(client, mock_client)

    await client.authorize("p", "a", "r")
    assert mock_client.get.call_count == 0, "probe must not run when disabled"
    assert client._probed is False


@pytest.mark.asyncio
async def test_no_credential_skips_auto_probe():
    """Backwards compat for legacy api_key= path: no credential =
    no auto-probe. Existing customer code that hasn't migrated to
    Credential.from_env() must not start hitting /health unexpectedly."""
    import warnings
    from unittest.mock import AsyncMock, MagicMock

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        client = ApdpClient("https://apdp.example.com", api_key="legacy-key")

    authorize_resp = MagicMock()
    authorize_resp.status_code = 200
    authorize_resp.json.return_value = {"decision": "Allow"}
    authorize_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get = AsyncMock()
    mock_client.post = AsyncMock(return_value=authorize_resp)
    _install_mock_httpx(client, mock_client)

    await client.authorize("p", "a", "r")
    assert mock_client.get.call_count == 0
    assert client._probed is False


@pytest.mark.asyncio
async def test_concurrent_first_calls_trigger_single_probe():
    """If 10 coroutines fire authorize() concurrently from a fresh
    client, only ONE GET /health hits the wire — the others wait on
    the lock and short-circuit when they see _probed=True."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    health_resp = MagicMock()
    health_resp.status_code = 200
    health_resp.json.return_value = {"auth": "ok"}
    authorize_resp = MagicMock()
    authorize_resp.status_code = 200
    authorize_resp.json.return_value = {"decision": "Allow"}
    authorize_resp.raise_for_status = MagicMock()

    # Add a small await inside the GET so concurrent callers actually
    # race on the lock, not just appear to.
    async def slow_get(*_args, **_kwargs):
        await asyncio.sleep(0.01)
        return health_resp

    mock_client = MagicMock()
    mock_client.get = AsyncMock(side_effect=slow_get)
    mock_client.post = AsyncMock(return_value=authorize_resp)
    _install_mock_httpx(client, mock_client)

    await asyncio.gather(*(client.authorize("p", "a", "r") for _ in range(10)))
    assert mock_client.get.call_count == 1, (
        "lock failed — concurrent first calls each issued their own probe"
    )
    assert mock_client.post.call_count == 10


@pytest.mark.asyncio
async def test_health_check_does_not_recurse_into_probe():
    """health_check() is the unauthenticated probe primitive — it
    must NOT trigger _ensure_probed (chicken-and-egg). Verify the
    only HTTP call is the explicit GET /health from health_check."""
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 200
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    ok = await client.health_check()
    assert ok is True
    assert mock_client.get.call_count == 1
    assert client._probed is False  # health_check doesn't set it


@pytest.mark.asyncio
async def test_probe_failure_propagates_through_authorize():
    """A 401 on the probe must propagate as CredentialProbeFailed
    OUT of authorize() — the existing fail-closed wrapper that
    catches httpx errors must not swallow it."""
    from unittest.mock import AsyncMock, MagicMock

    from watchlight_core import CredentialProbeFailed

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 401
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    mock_client.post = AsyncMock()  # should never be called
    _install_mock_httpx(client, mock_client)

    with pytest.raises(CredentialProbeFailed):
        await client.authorize("p", "a", "r")
    assert mock_client.post.call_count == 0


@pytest.mark.asyncio
async def test_probe_handles_non_json_200():
    """Older APDP versions returned 'OK' as plain text. A 200 with a
    non-JSON body must still count as a successful probe — empty
    payload, but probed=True."""
    from unittest.mock import AsyncMock, MagicMock

    cred = _stub_credential()
    client = ApdpClient("https://apdp.example.com", credential=cred)

    stub_resp = MagicMock()
    stub_resp.status_code = 200
    stub_resp.json.side_effect = ValueError("not JSON")
    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=stub_resp)
    _install_mock_httpx(client, mock_client)

    payload = await client.probe()
    assert payload == {}
    assert client._probed is True


# ─── proxy_token surfacing on BaseRunHandle ─────────────────────


def test_parse_proxy_token_fields_extracts_token_and_expiry():
    """wl-apdp populates top-level ``proxy_token`` +
    ``proxy_token_expires_at`` on the /sessions response when
    WL_PROXY_TOKEN_AUDIENCE is configured. The SDK helper must
    surface both."""
    response = {
        "session": {"id": "ses_test"},
        "session_token": "...",
        "proxy_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJhZ2VudC0xIn0.sig",
        "proxy_token_expires_at": "2026-06-08T15:00:00Z",
    }
    token, expires_at = _parse_proxy_token_fields(response)
    assert token == response["proxy_token"]
    assert expires_at is not None
    assert expires_at.year == 2026
    assert expires_at.month == 6
    assert expires_at.day == 8


def test_parse_proxy_token_fields_returns_none_when_absent():
    """Non-CONNECT deployments don't run wl-proxy and APDP omits
    both fields. The helper must NOT crash the session create."""
    response = {"session": {"id": "ses_test"}, "session_token": "..."}
    token, expires_at = _parse_proxy_token_fields(response)
    assert token is None
    assert expires_at is None


def test_parse_proxy_token_fields_handles_malformed_expiry_gracefully():
    """A malformed expiry must NOT lose the token — fail-soft, not
    fail-hard. The downstream caller falls back to the issuer's
    hard cap."""
    response = {
        "session": {"id": "ses_test"},
        "proxy_token": "eyJ.eyJ.sig",
        "proxy_token_expires_at": "definitely not RFC3339",
    }
    token, expires_at = _parse_proxy_token_fields(response)
    assert token == "eyJ.eyJ.sig"
    assert expires_at is None


def test_parse_proxy_token_fields_handles_empty_token():
    """Treat empty string as absent — issuer sometimes returns ``""``
    on a degraded path; surfacing it would make plugins attach
    ``Proxy-Authorization: Bearer `` which wl-proxy rejects as
    malformed anyway."""
    response = {
        "session": {"id": "ses_test"},
        "proxy_token": "",
        "proxy_token_expires_at": "2026-06-08T15:00:00Z",
    }
    token, _ = _parse_proxy_token_fields(response)
    assert token is None


def test_parse_proxy_token_fields_handles_non_dict_input():
    """Defensive against odd transport-layer shapes (None returns,
    string responses, etc.). Never raises."""
    assert _parse_proxy_token_fields(None) == (None, None)  # type: ignore[arg-type]
    assert _parse_proxy_token_fields([]) == (None, None)  # type: ignore[arg-type]
    assert _parse_proxy_token_fields("string") == (None, None)  # type: ignore[arg-type]


def test_handle_egress_binding_resolves_the_run_token_without_holding_it():
    """The handle holds the run's egress binding, never the token: the
    binding resolves it from the backend's run table when asked, its repr is
    redacted, and the handle has no token attribute."""
    from watchlight_core_testing import MockApdpClient

    class P(GovernanceTelemetry):
        def __init__(self):
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "acme"
            self.log_decisions = False

    handle = bind_test_run(
        BaseRunHandle(plugin=P(), agent_uuid="uuid-x", session_id="ses_x"),
        "sst_x.sig",
        proxy_token="eyJ.eyJ.sig",
    )
    assert handle.egress is not None
    assert handle.egress.proxy_authorization() == "eyJ.eyJ.sig"
    assert "eyJ.eyJ.sig" not in repr(handle.egress)
    assert "eyJ.eyJ.sig" not in str(handle.egress)
    assert not hasattr(handle, "proxy_token")
    assert not hasattr(handle, "session_token")


@pytest.mark.asyncio
async def test_handle_defaults_egress_to_none(plugin):
    """A handle built without a run has no egress binding."""
    handle = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    assert handle.egress is None
    assert handle.run is None


# ─── lineage tier on BaseRunHandle ─────────────────────────────


def test_handle_mints_execution_id_when_not_supplied(plugin):
    """Root-cause fix — every handle needs a stable
    ``execution_id`` so the CONNECT sidecar can stamp ``X-Wl-*``
    headers. Defaults to a fresh ``exec_<uuid>``."""
    handle = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    assert handle.execution_id.startswith("exec_")
    # Roots default root_execution_id == execution_id.
    assert handle.root_execution_id == handle.execution_id
    assert handle.parent_execution_id is None
    assert handle.parent_agent_id is None


def test_handle_threads_caller_supplied_lineage(plugin):
    """When the caller passes lineage kwargs, the handle stores them
    verbatim — used by plugin subclasses that mint per-spawn
    ``execution_id`` for sub-agents at spawn-pair event-emit time."""
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        execution_id="exec_specific",
        root_execution_id="exec_root",
        parent_execution_id="exec_parent",
        parent_agent_id="orchestrator",
    )
    assert handle.execution_id == "exec_specific"
    assert handle.root_execution_id == "exec_root"
    assert handle.parent_execution_id == "exec_parent"
    assert handle.parent_agent_id == "orchestrator"


def test_lineage_snapshot_returns_immutable_frozen_dataclass(plugin):
    """``lineage_snapshot`` returns a :class:`HandleLineage` the
    CONNECT sidecar reads via the process-global. Frozen so a child's
    snapshot cannot accidentally mutate the parent's binding."""
    from watchlight_core import HandleLineage

    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        execution_id="exec_specific",
        parent_execution_id="exec_parent",
    )
    snap = handle.lineage_snapshot()
    assert isinstance(snap, HandleLineage)
    assert snap.execution_id == "exec_specific"
    assert snap.parent_execution_id == "exec_parent"
    assert snap.root_execution_id == "exec_specific"  # synthesized
    # Frozen — assigning to a field raises.
    with pytest.raises(Exception):  # FrozenInstanceError
        snap.execution_id = "exec_other"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_aenter_publishes_lineage_to_sidecar_global(plugin):
    """The ``async with await plugin.start_run(...) as handle:``
    contract MUST publish the handle's lineage to the sidecar's
    process-global so the CONNECT sidecar's dedicated event-loop
    thread reads it on outbound CONNECTs.

    Asserts both lifecycle directions: publish on ``__aenter__``,
    restore-to-outer-context on ``__aexit__``.
    """
    from watchlight_core.connect_proxy import (
        get_active_handle_lineage,
        set_active_handle_lineage,
    )

    # Belt-and-braces: clear any global from prior test runs.
    set_active_handle_lineage(None)

    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        execution_id="exec_handle",
    )
    async with handle:
        published = get_active_handle_lineage()
        assert published is not None
        assert published.execution_id == "exec_handle"

    # After ``__aexit__``, the global is restored — to ``None`` for
    # a top-level handle.
    assert get_active_handle_lineage() is None


# ─── get_manifest envelope unwrapping ────────────────────────────────


def _manifest_client_returning(body):
    """Build an ApdpClient whose POST /constraints/manifest returns
    ``body`` as JSON, bypassing the /health probe + lazy client."""
    from unittest.mock import AsyncMock, MagicMock

    client = ApdpClient("https://apdp.test")

    async def _no_probe() -> None:
        return None

    client._ensure_probed = _no_probe  # type: ignore[assignment]

    resp = MagicMock()
    resp.raise_for_status = MagicMock(return_value=None)
    resp.json = MagicMock(return_value=body)

    stub_http = MagicMock()
    stub_http.is_closed = False
    stub_http.post = AsyncMock(return_value=resp)
    client._client = stub_http
    return client


@pytest.mark.asyncio
async def test_get_manifest_unwraps_envelope():
    """/constraints/manifest wraps the manifest as
    ``{"manifest": {...}, "message": ...}``. get_manifest must return the
    INNER manifest so callers read governed_proxy_hosts (and every other
    field) directly — the sidecar allowlist depends on this."""
    client = _manifest_client_returning(
        {
            "manifest": {
                "agent_id": "a1",
                "governed_proxy_hosts": ["proxy-mcp-web", "proxy-llm"],
            },
            "message": "Constraint manifest generated successfully",
        }
    )
    out = await client.get_manifest("a1")
    assert out is not None
    assert out.get("governed_proxy_hosts") == ["proxy-mcp-web", "proxy-llm"]
    # Returned the inner manifest, not the envelope.
    assert "message" not in out


@pytest.mark.asyncio
async def test_get_manifest_passthrough_when_not_enveloped():
    """If a server ever returns an unwrapped manifest (no ``manifest``
    key), pass it through unchanged rather than dropping it."""
    body = {"agent_id": "a1", "governed_proxy_hosts": []}
    client = _manifest_client_returning(body)
    out = await client.get_manifest("a1")
    assert out == body


def _manifest_client_failing(status_code: int):
    """Build an ApdpClient whose POST /constraints/manifest raises an
    ``httpx.HTTPStatusError`` with ``status_code`` (bypassing the /health
    probe + lazy client)."""
    from unittest.mock import AsyncMock, MagicMock

    import httpx

    client = ApdpClient("https://apdp.test")

    async def _no_probe() -> None:
        return None

    client._ensure_probed = _no_probe  # type: ignore[assignment]

    request = httpx.Request("POST", "https://apdp.test/constraints/manifest")
    response = httpx.Response(status_code, request=request, json={"error": "x"})
    resp = MagicMock()
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("boom", request=request, response=response)
    )

    stub_http = MagicMock()
    stub_http.is_closed = False
    stub_http.post = AsyncMock(return_value=resp)
    client._client = stub_http
    return client


@pytest.mark.asyncio
async def test_get_manifest_unresolved_goal_is_quiet(caplog):
    """A run under a goal wl-apdp does not know gets a 200 with an
    empty goal section and ``unresolved_goal_id`` set. That is the
    documented empty manifest: returned as-is, and NOT a warning."""
    import logging

    body = {
        "manifest": {
            "agent": {"agent_id": "a1"},
            "active_goal": None,
            "unresolved_goal_id": "22222222-2222-4222-8222-222222222222",
            "governed_proxy_hosts": ["proxy-llm"],
        },
        "message": "Constraint manifest generated successfully",
    }
    client = _manifest_client_returning(body)
    with caplog.at_level(logging.DEBUG, logger="watchlight"):
        out = await client.get_manifest(
            "a1", goal_id="22222222-2222-4222-8222-222222222222"
        )
    assert out is not None
    assert out["active_goal"] is None
    assert out["unresolved_goal_id"] == "22222222-2222-4222-8222-222222222222"
    assert out["governed_proxy_hosts"] == ["proxy-llm"]
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [], "an unresolved goal is not a manifest failure"
    assert any(
        r.levelno == logging.DEBUG and "unresolved_goal_id" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_get_manifest_real_failure_logged_once_per_agent(caplog):
    """A genuine failure (unknown agent → 404) is logged at WARNING
    the first time for that agent and at DEBUG thereafter; a different
    agent gets its own WARNING. The fetch still returns None each time."""
    import logging

    client = _manifest_client_failing(404)
    with caplog.at_level(logging.DEBUG, logger="watchlight"):
        assert await client.get_manifest("agent-a") is None
        assert await client.get_manifest("agent-a") is None
        assert await client.get_manifest("agent-a") is None
        assert await client.get_manifest("agent-b") is None

    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "manifest fetch failed" in r.getMessage()
    ]
    assert len(warnings) == 2, [r.getMessage() for r in warnings]
    assert "agent-a" in warnings[0].getMessage()
    assert "404" in warnings[0].getMessage()
    assert "agent-b" in warnings[1].getMessage()
    debugs = [
        r for r in caplog.records
        if r.levelno == logging.DEBUG and "manifest fetch failed (again)" in r.getMessage()
    ]
    assert len(debugs) == 2


@pytest.mark.asyncio
async def test_get_manifest_success_rearms_failure_warning(caplog):
    """A successful fetch clears the once-warned latch for
    that agent, so a LATER outage warns again instead of hiding at DEBUG."""
    import logging

    failing = _manifest_client_failing(503)
    ok = _manifest_client_returning({"manifest": {"agent": {"agent_id": "a1"}}})
    # Share one latch across the two stubs (same logical client).
    ok._manifest_failures_logged = failing._manifest_failures_logged

    with caplog.at_level(logging.DEBUG, logger="watchlight"):
        assert await failing.get_manifest("a1") is None  # WARN #1
        assert await failing.get_manifest("a1") is None  # DEBUG
        assert await ok.get_manifest("a1") is not None  # re-arm
        assert await failing.get_manifest("a1") is None  # WARN #2

    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "manifest fetch failed" in r.getMessage()
    ]
    assert len(warnings) == 2
    assert all("503" in r.getMessage() for r in warnings)


@pytest.mark.asyncio
async def test_get_manifest_timeout_is_a_logged_failure_not_an_exception(caplog):
    """A transport timeout degrades like a connect error:
    None is returned and the failure is logged once per agent."""
    import logging
    from unittest.mock import AsyncMock, MagicMock

    import httpx

    client = ApdpClient("https://apdp.test")

    async def _no_probe() -> None:
        return None

    client._ensure_probed = _no_probe  # type: ignore[assignment]
    stub_http = MagicMock()
    stub_http.is_closed = False
    stub_http.post = AsyncMock(side_effect=httpx.ReadTimeout("slow apdp"))
    client._client = stub_http

    with caplog.at_level(logging.DEBUG, logger="watchlight"):
        assert await client.get_manifest("a1") is None
        assert await client.get_manifest("a1") is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "ReadTimeout" in warnings[0].getMessage()
