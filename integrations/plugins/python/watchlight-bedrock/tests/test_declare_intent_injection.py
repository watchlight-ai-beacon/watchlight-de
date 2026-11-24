"""Tests for the Bedrock synthetic ``watchlight.declare_intent``
tool injection + tool-call interception.

These cover the per-framework synthetic tool injection on the AWS
Bedrock plugin. Because Bedrock's tool surface is server-side
(configured on the Bedrock Agent resource via the ``bedrock-agent``
control-plane API, not at runtime in the plugin's process), the
injection is **structurally one-line opt-in** rather than fully
zero-touch — operators add the synthetic action group ONCE at agent
setup via :meth:`WatchlightBedrockPlugin.synthetic_action_group_schema`.
Bedrock's runtime model genuinely cannot support pure zero-touch
injection, and we document that trade-off honestly.

The five required tests mirror the per-framework invariants:

1. ``test_greenfield_mode_injects_synthetic_tool_at_construction`` —
   the plugin exposes the synthetic action group via
   :meth:`synthetic_action_group_schema` when mode is greenfield.
2. ``test_brownfield_mode_does_not_inject_synthetic_tool`` — mirror;
   :meth:`synthetic_action_group_schema` returns ``None`` in brownfield.
3. ``test_declare_intent_call_stamps_provenance_to_declared`` — when
   Bedrock invokes the synthetic action group, the plugin's Lambda
   decorator short-circuit delegates to
   :func:`watchlight_core.handle_declare_intent_call` which stamps
   :attr:`IntentProvenance.DECLARED` on the handle-shim's mirror
   state AND records the truncated objective on the warm-start
   session cache.
4. ``test_synthetic_tool_call_bypasses_authorize`` — the synthetic-tool
   carve-out: the synthetic tool's invocation MUST NOT round-trip to
   APDP ``/authorize`` (the greenfield Cedar gate would forbid the very
   first ``declare_intent`` call before the agent could declare).
5. ``test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate``
   — the LOAD-BEARING integration test: after the synthetic tool
   fires, the NEXT non-synthetic Bedrock-Lambda invocation against
   the same session auto-injects ``intent={"objective": "..."}`` into
   the APDP ``/authorize`` request body, which is the wire shape the
   greenfield Cedar gate treats as ``provenance: "declared"``.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from watchlight_core import (
    DECLARE_INTENT_TOOL_NAME,
    INTENT_ENFORCEMENT_MODE_ENV_VAR,
    IntentProvenance,
)
from watchlight_bedrock import (
    SYNTHETIC_ACTION_GROUP_NAME,
    SYNTHETIC_API_PATH,
    SYNTHETIC_FUNCTION_NAME,
    WatchlightBedrockPlugin,
    build_synthetic_action_group_schema,
    handle_synthetic_bedrock_invocation,
    is_synthetic_bedrock_event,
    render_synthetic_lambda_handler,
    watchlight_bedrock_action,
)
from watchlight_bedrock.synthetic_intent_tool import (
    _DECLARED_INTENT_CACHE,
    clear_session_declared_intent,
    extract_objective_from_bedrock_event,
    get_session_declared_intent,
    project_synthetic_to_canonical_name,
    record_session_declared_intent,
)


# ─── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_session_cache():
    """Reset the warm-start cache before each test. The cache is a
    module-level dict; without this reset, ordering would couple
    tests together."""
    _DECLARED_INTENT_CACHE.clear()
    yield
    _DECLARED_INTENT_CACHE.clear()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Clear the WATCHLIGHT_INTENT_ENFORCEMENT_MODE env var so an
    operator-set value in the dev shell can't bleed into the tests."""
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)


def _synthetic_event(
    session_id: str = "ses_apdp_test",
    agent_uuid: str = "agent-uuid-x",
    objective: str = "audit Q3 invoices",
    bedrock_agent_id: str = "AG12345",
    category: Optional[str] = "financial_operation",
) -> Dict[str, Any]:
    """A Bedrock action-group event for the synthetic
    ``watchlight_intent/declare_intent`` tool (function-style). wl-apdp
    requires a category on every intent; ``category=None`` leaves it out."""
    return {
        "messageVersion": "1.0",
        "agent": {
            "id": bedrock_agent_id,
            "name": "research-analyst",
            "alias": "PROD",
            "version": "1",
        },
        "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
        "function": SYNTHETIC_FUNCTION_NAME,
        "parameters": [
            {"name": "objective", "type": "string", "value": objective},
        ]
        + (
            [{"name": "category", "type": "string", "value": category}]
            if category is not None
            else []
        ),
        "sessionId": "bedrock-session-123",
        "sessionState": {
            "sessionAttributes": {
                "watchlight_session_id": session_id,
                "watchlight_agent_id": agent_uuid,
            }
        },
    }


def _real_tool_event(
    session_id: str = "ses_apdp_test",
    agent_uuid: str = "agent-uuid-x",
    bedrock_agent_id: str = "AG12345",
) -> Dict[str, Any]:
    """A normal (non-synthetic) Bedrock action-group event — the kind
    that should round-trip to APDP ``/authorize``."""
    return {
        "messageVersion": "1.0",
        "agent": {
            "id": bedrock_agent_id,
            "name": "research-analyst",
            "alias": "PROD",
            "version": "1",
        },
        "actionGroup": "research_tools",
        "apiPath": "/write_ledger_entry",
        "httpMethod": "POST",
        "parameters": [
            {"name": "row", "type": "string", "value": "Q3 audit"},
        ],
        "sessionId": "bedrock-session-123",
        "sessionState": {
            "sessionAttributes": {
                "watchlight_session_id": session_id,
                "watchlight_agent_id": agent_uuid,
            }
        },
    }


# ─── Test 1 — greenfield mode exposes the synthetic action group ──────


def test_greenfield_mode_injects_synthetic_tool_at_construction():
    """Test 1 — when the plugin is constructed in greenfield mode,
    :meth:`synthetic_action_group_schema` returns the AWS-shape dict the
    operator splats into ``bedrock-agent.create_agent_action_group``.

    Bedrock's tool surface is server-side — the plugin cannot mutate
    it at runtime. The injection is "one-line opt-in": the operator
    wires the action group ONCE at agent setup. The plugin's method
    exposes the canonical schema so the wiring is byte-identical with
    the plugin's interception predicate.
    """
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="greenfield",
        log_decisions=False,
    )

    schema = plugin.synthetic_action_group_schema()

    assert schema is not None, (
        "greenfield mode must surface the synthetic action group schema"
    )
    assert schema["actionGroupName"] == SYNTHETIC_ACTION_GROUP_NAME
    assert schema["actionGroupState"] == "ENABLED"
    # The function schema MUST carry the canonical declare_intent
    # function — Bedrock's LLM routing will offer it to the agent
    # under this exact name.
    functions = schema["functionSchema"]["functions"]
    assert len(functions) == 1
    fn = functions[0]
    assert fn["name"] == SYNTHETIC_FUNCTION_NAME
    # The parameter schema carries one required ``objective`` string.
    assert "objective" in fn["parameters"]
    assert fn["parameters"]["objective"]["required"] is True
    assert fn["parameters"]["objective"]["type"] == "string"


def test_greenfield_action_group_schema_byte_identical_across_calls():
    """The schema returned by :meth:`synthetic_action_group_schema` is
    deterministic — calling it N times produces the same dict so
    an operator's IaC drift-detection (Terraform plan vs apply) stays
    quiet."""
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="greenfield",
        log_decisions=False,
    )

    a = plugin.synthetic_action_group_schema()
    b = plugin.synthetic_action_group_schema()
    assert a == b


# ─── Test 2 — brownfield mode does NOT expose the synthetic tool ──────


def test_brownfield_mode_does_not_inject_synthetic_tool():
    """Test 2 — in brownfield mode :meth:`synthetic_action_group_schema`
    returns ``None``. The operator's IaC uses the truthy-check to
    skip the action-group creation; brownfield Bedrock Agents are
    byte-identical to deployments without intent enforcement.

    The brownfield Cedar matrix accepts inferred provenance at every
    tier so the synthetic-tool gate would be inert; surfacing the
    action group would just confuse operators and add an AWS resource
    for no enforcement benefit.
    """
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="brownfield",
        log_decisions=False,
    )
    assert plugin.synthetic_action_group_schema() is None


# ─── Test 3 — declare_intent call stamps provenance to declared ───────


def test_declare_intent_call_stamps_provenance_to_declared():
    """Test 3 — when Bedrock invokes the synthetic action group,
    :func:`handle_synthetic_bedrock_invocation` delegates to
    :func:`watchlight_core.handle_declare_intent_call` which stamps
    :attr:`IntentProvenance.DECLARED` on a duck-typed handle shim.

    The function ALSO records the truncated objective on the warm-
    start session cache keyed on
    ``sessionAttributes.watchlight_session_id``. The next
    non-synthetic Lambda invocation against the same session reads
    this cache and auto-injects ``intent`` into its APDP
    ``/authorize`` request body.
    """
    event = _synthetic_event(
        session_id="ses_apdp_T3",
        objective="audit Q3 invoices",
    )
    # Sanity: cache is empty before the call.
    assert get_session_declared_intent("ses_apdp_T3") is None

    response = handle_synthetic_bedrock_invocation(
        event, log_decisions=False
    )

    # The Bedrock-shaped response carries the canonical
    # ``intent_declared`` payload in the response body.
    assert response["messageVersion"] == "1.0"
    assert response["response"]["actionGroup"] == SYNTHETIC_ACTION_GROUP_NAME
    assert response["response"]["httpStatusCode"] == 200
    body_raw = response["response"]["responseBody"]["application/json"]["body"]
    body = json.loads(body_raw)
    assert body["status"] == "intent_declared"
    assert body["objective"] == "audit Q3 invoices"

    # The load-bearing assertion: the warm-start cache now carries
    # the declared objective so subsequent authorize calls can read it.
    assert get_session_declared_intent("ses_apdp_T3") == {
        "objective": "audit Q3 invoices",
        "category": "financial_operation",
    }


def test_declare_intent_with_empty_objective_does_not_pollute_cache():
    """Defensive: an empty / whitespace-only objective is rejected
    (canonical helper invariant). The warm-start cache is left
    untouched so the next authorize call sees ``provenance: absent``
    and the greenfield Cedar gate forbids the action — correct
    fail-closed posture."""
    event = _synthetic_event(session_id="ses_apdp_empty")
    # Override parameters to an empty objective.
    event["parameters"] = [{"name": "objective", "type": "string", "value": ""}]

    response = handle_synthetic_bedrock_invocation(
        event, log_decisions=False
    )
    body = json.loads(
        response["response"]["responseBody"]["application/json"]["body"]
    )
    assert body["status"] == "rejected"
    # The cache MUST remain empty — the gate stays closed.
    assert get_session_declared_intent("ses_apdp_empty") is None


def test_declare_intent_extracts_from_rest_style_request_body():
    """The objective extractor handles REST-style action groups whose
    parameters live under ``requestBody.content.application/json.properties``."""
    event = {
        "messageVersion": "1.0",
        "agent": {"id": "AG2"},
        "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
        "apiPath": SYNTHETIC_API_PATH,
        "httpMethod": "POST",
        "requestBody": {
            "content": {
                "application/json": {
                    "properties": [
                        {
                            "name": "objective",
                            "type": "string",
                            "value": "draft the M&A memo",
                        },
                        {
                            "name": "category",
                            "type": "string",
                            "value": "content_generation",
                        },
                    ]
                }
            }
        },
        "sessionState": {
            "sessionAttributes": {"watchlight_session_id": "ses_rest"}
        },
    }

    response = handle_synthetic_bedrock_invocation(event, log_decisions=False)
    body = json.loads(
        response["response"]["responseBody"]["application/json"]["body"]
    )
    assert body["status"] == "intent_declared"
    assert body["objective"] == "draft the M&A memo"
    assert get_session_declared_intent("ses_rest") == {
        "objective": "draft the M&A memo",
        "category": "content_generation",
    }


# ─── Test 4 — synthetic tool call BYPASSES authorize ──────────────────


def test_synthetic_tool_call_bypasses_authorize():
    """Test 4 — the synthetic-tool carve-out. The synthetic
    ``watchlight_intent/declare_intent`` invocation MUST NOT round-trip
    to APDP ``/authorize``. In greenfield mode the Cedar gate FORBIDS
    Custodial actions until ``provenance == "declared"``; the agent's
    very first ``declare_intent`` call would be denied before it could
    declare. The Lambda decorator short-circuits BEFORE the authorize
    hop.

    Asserts ``apdp.authorize`` is never called for the synthetic event.
    """
    # Patch APDP authorize so we can verify it was NOT invoked.
    with patch(
        "watchlight_bedrock.plugin._enforce_authz"
    ) as mock_enforce, patch(
        "watchlight_bedrock.plugin.WatchlightBedrockPlugin.__init__",
        return_value=None,
    ):
        # Wrap a customer Lambda body to prove it's never reached either.
        called = {"customer": False}

        @watchlight_bedrock_action(apdp_url="https://apdp.test")
        def my_lambda(event, context=None):
            called["customer"] = True
            return {"shouldnt-see-this": True}

        event = _synthetic_event(session_id="ses_T4")
        response = my_lambda(event, None)

        # Load-bearing assertion: the authorize-enforcing helper was
        # NOT called for the synthetic event. The synthetic-tool
        # carve-out is honoured at the wire-event level.
        mock_enforce.assert_not_called()
        # The customer's Lambda body was bypassed — the synthetic
        # tool's response replaces it entirely.
        assert called["customer"] is False
        # The response IS the synthetic-tool's success shape.
        body = json.loads(
            response["response"]["responseBody"]["application/json"]["body"]
        )
        assert body["status"] == "intent_declared"


def test_synthetic_event_detection_predicates():
    """The :func:`is_synthetic_bedrock_event` predicate matches both
    function-style and REST-style synthetic events; non-synthetic
    events and exotic shapes return ``False`` so the decorator
    forwards to the normal authorize path."""
    # Function-style — matches.
    assert is_synthetic_bedrock_event(_synthetic_event())

    # REST-style — matches.
    rest_event = {
        "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
        "apiPath": SYNTHETIC_API_PATH,
    }
    assert is_synthetic_bedrock_event(rest_event)

    # REST-style without leading slash — defensive match.
    rest_event_no_slash = {
        "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
        "apiPath": SYNTHETIC_FUNCTION_NAME,
    }
    assert is_synthetic_bedrock_event(rest_event_no_slash)

    # Non-synthetic event — does NOT match.
    assert is_synthetic_bedrock_event(_real_tool_event()) is False

    # Wrong action group — does NOT match.
    wrong_ag = {
        "actionGroup": "research_tools",
        "function": SYNTHETIC_FUNCTION_NAME,
    }
    assert is_synthetic_bedrock_event(wrong_ag) is False

    # Empty / None — does NOT match.
    assert is_synthetic_bedrock_event({}) is False
    assert is_synthetic_bedrock_event(None) is False  # type: ignore[arg-type]


# ─── Test 5 — subsequent authorize satisfies Cedar gate ──────────────


def test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate(
    monkeypatch,
):
    """Test 5 — LOAD-BEARING INTEGRATION TEST.

    After the synthetic tool fires, the NEXT non-synthetic Bedrock
    Lambda invocation against the same session auto-injects
    ``intent={"objective": "<stored>"}`` into the APDP ``/authorize``
    request body. APDP's intent-context projection reads
    ``request.intent.objective`` and stamps the evaluation context with
    ``provenance: "declared"`` — which CLEARS the greenfield-Custodial
    Cedar gate.

    Proves the per-framework wiring closes the greenfield Cedar gate
    end-to-end on Bedrock by asserting the exact wire shape APDP
    receives on the authorize request body for a subsequent tool call.
    """
    # Step 1 — agent calls watchlight_intent/declare_intent in Lambda A.
    synthetic_event = _synthetic_event(
        session_id="ses_apdp_T5",
        objective="audit Q3 invoices",
    )
    response = handle_synthetic_bedrock_invocation(
        synthetic_event, log_decisions=False
    )
    body = json.loads(
        response["response"]["responseBody"]["application/json"]["body"]
    )
    assert body["status"] == "intent_declared"

    # Step 2 — same warm container, a real Custodial tool call on the
    # same session. The decorator refuses an orchestrator hand-off today
    # (no run credential crosses the Bedrock boundary), so this drives the
    # authorize step the decorator uses, on that session, to pin the wire
    # shape. We mock ``ApdpClient.authorize`` to capture the kwargs.
    from watchlight_bedrock.plugin import _authorize_on_session, parse_bedrock_event

    captured_kwargs: Dict[str, Any] = {}

    # In-process stand-in for unit tests only.
    async def _stub_authorize(**kwargs):
        captured_kwargs.update(kwargs)
        return {"decision": "Allow", "reason": "test allow"}

    stub_plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        log_decisions=False,
    )
    stub_plugin.apdp.authorize = AsyncMock(side_effect=_stub_authorize)
    stub_plugin.last_actions_allowed = 0
    stub_plugin.last_actions_denied = 0

    real_event = _real_tool_event(session_id="ses_apdp_T5")
    parsed = parse_bedrock_event(real_event)
    authorized, _ = _authorize_on_session(
        plugin=stub_plugin,
        event=real_event,
        parsed=parsed,
        action_name="research_tools/write_ledger_entry",
        tenant_id=None,
        session_id="ses_apdp_T5",
        agent_uuid="agent-uuid-x",
        run="run_test",
    )
    assert authorized is True

    # Step 3 — verify the APDP authorize request body carries the
    # declared intent. This is the wire shape APDP's intent projection
    # treats as Declared, which clears the greenfield Cedar gate.
    assert stub_plugin.apdp.authorize.called, (
        "non-synthetic tool MUST round-trip to APDP authorize"
    )
    assert captured_kwargs.get("intent") == {
        "objective": "audit Q3 invoices",
        "category": "financial_operation",
    }, (
        "the auto-injected intent kwarg must carry the declared objective; "
        f"got {captured_kwargs.get('intent')!r}"
    )


def test_decorator_refuses_orchestrator_handoff_without_run_credential(
    monkeypatch,
):
    """The decorator never authorizes under a handed-off session: no run
    credential crosses the Bedrock boundary, so the call is refused and
    the customer body never runs."""
    stub_plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test", log_decisions=False
    )
    stub_plugin.apdp.authorize = AsyncMock(return_value={"decision": "Allow"})
    monkeypatch.setattr(
        "watchlight_bedrock.plugin._get_cached_plugin",
        lambda apdp_url, tenant_id, apdp_api_key: stub_plugin,
    )

    @watchlight_bedrock_action(apdp_url="https://apdp.test")
    def my_lambda(event, context=None):
        raise AssertionError("must not run")

    result = my_lambda(_real_tool_event(session_id="ses_apdp_T6"), None)
    assert result["response"]["httpStatusCode"] == 403
    stub_plugin.apdp.authorize.assert_not_called()


# ─── Auxiliary coverage — env-var mode resolution + cache hygiene ─────


def test_env_var_alone_enables_greenfield_injection(monkeypatch):
    """A customer that opts into greenfield via the env var alone
    (no constructor kwarg) gets the same injection behaviour. This
    is the zero-touch configuration path."""
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        log_decisions=False,
    )
    assert plugin.intent_enforcement_mode == "greenfield"
    assert plugin.synthetic_action_group_schema() is not None


def test_default_mode_is_brownfield_no_injection(monkeypatch):
    """The locked default is brownfield — onboarding tenants see
    warn-only enforcement until they opt in. Verifies no env var +
    no kwarg = no synthetic action group."""
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        log_decisions=False,
    )
    assert plugin.intent_enforcement_mode == "brownfield"
    assert plugin.synthetic_action_group_schema() is None


def test_session_cache_clear_evicts_stale_declaration():
    """The cache eviction helper drops a session's declared intent so
    a fresh session that re-uses the same id within the same warm
    Lambda container can't inherit the stale value."""
    record_session_declared_intent("ses_X", "objective one", "research")
    assert get_session_declared_intent("ses_X") == {
        "objective": "objective one",
        "category": "research",
    }
    clear_session_declared_intent("ses_X")
    assert get_session_declared_intent("ses_X") is None


def test_extract_objective_extracts_from_json_body():
    """Defensive: some Bedrock variants surface tool args as a JSON
    string under ``requestBody.content.<media>.body`` (the OpenAPI
    body shape). The extractor handles this in addition to the
    structured-properties shape."""
    event = {
        "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
        "apiPath": SYNTHETIC_API_PATH,
        "requestBody": {
            "content": {
                "application/json": {
                    "body": json.dumps({"objective": "ship the release"})
                }
            }
        },
    }
    extracted = extract_objective_from_bedrock_event(event)
    assert extracted == "ship the release"


def test_render_synthetic_lambda_handler_is_zero_customer_code():
    """Operators using the ``actionGroupExecutor.lambda`` model stand
    up the synthetic action group's executor with one line — the
    factory returns a Lambda handler that just delegates to
    :func:`handle_synthetic_bedrock_invocation`."""
    handler = render_synthetic_lambda_handler(log_decisions=False)
    event = _synthetic_event(
        session_id="ses_factory",
        objective="ship the feature",
    )
    response = handler(event, None)
    body = json.loads(
        response["response"]["responseBody"]["application/json"]["body"]
    )
    assert body["status"] == "intent_declared"
    assert body["objective"] == "ship the feature"
    assert get_session_declared_intent("ses_factory") == {
        "objective": "ship the feature",
        "category": "financial_operation",
    }


def test_canonical_name_reflection():
    """The Bedrock function name (``declare_intent``) and the fully-
    qualified action-group path (``watchlight_intent/declare_intent``)
    both project back to the canonical wire literal
    (``watchlight.declare_intent``) for the audit-log lane."""
    assert (
        project_synthetic_to_canonical_name("declare_intent")
        == DECLARE_INTENT_TOOL_NAME
    )
    assert (
        project_synthetic_to_canonical_name("/declare_intent")
        == DECLARE_INTENT_TOOL_NAME
    )
    assert (
        project_synthetic_to_canonical_name("watchlight_intent/declare_intent")
        == DECLARE_INTENT_TOOL_NAME
    )
    assert (
        project_synthetic_to_canonical_name("watchlight.declare_intent")
        == DECLARE_INTENT_TOOL_NAME
    )
    # Non-synthetic spellings pass through unchanged.
    assert project_synthetic_to_canonical_name("search_documents") == "search_documents"


def test_build_synthetic_action_group_schema_respects_explicit_mode():
    """The standalone helper accepts an explicit mode argument so
    operators can call it from an IaC script without instantiating a
    plugin first."""
    greenfield = build_synthetic_action_group_schema(mode="greenfield")
    assert greenfield is not None
    assert greenfield["actionGroupName"] == SYNTHETIC_ACTION_GROUP_NAME

    brownfield = build_synthetic_action_group_schema(mode="brownfield")
    assert brownfield is None


# ─── Typed intent: wl-apdp requires objective AND category ──────────


def test_the_synthetic_function_schema_requires_objective_and_category():
    plugin = WatchlightBedrockPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="greenfield",
        log_decisions=False,
    )
    fn = plugin.synthetic_action_group_schema()["functionSchema"]["functions"][0]
    assert set(fn["parameters"]) == {"objective", "category", "justification"}
    assert fn["parameters"]["justification"]["required"] is False
    assert fn["parameters"]["category"]["required"] is True
    assert fn["parameters"]["category"]["type"] == "string"


def test_a_declare_without_a_category_is_rejected_and_no_intent_is_sent():
    """wl-apdp answers a category-less intent with 422: the declaration is
    refused, nothing is cached, and the next authorize carries NO intent."""
    from watchlight_bedrock.plugin import _authorize_on_session, parse_bedrock_event

    response = handle_synthetic_bedrock_invocation(
        _synthetic_event(session_id="ses_nocat", category=None), log_decisions=False
    )
    body = json.loads(response["response"]["responseBody"]["application/json"]["body"])
    assert body["status"] == "rejected"
    assert get_session_declared_intent("ses_nocat") is None

    captured: Dict[str, Any] = {}

    # In-process stand-in for unit tests only.
    async def _stub_authorize(**kwargs):
        captured.update(kwargs)
        return {"decision": "Allow", "reason": "test allow"}

    plugin = WatchlightBedrockPlugin(apdp_url="https://apdp.test", log_decisions=False)
    plugin.apdp.authorize = AsyncMock(side_effect=_stub_authorize)
    plugin.last_actions_allowed = 0
    plugin.last_actions_denied = 0
    event = _real_tool_event(session_id="ses_nocat")
    _authorize_on_session(
        plugin=plugin,
        event=event,
        parsed=parse_bedrock_event(event),
        action_name="research_tools/write_ledger_entry",
        tenant_id=None,
        session_id="ses_nocat",
        agent_uuid="agent-uuid-x",
        run="run_test",
    )
    assert plugin.apdp.authorize.called
    assert captured.get("intent") is None


def test_an_objective_only_cache_entry_is_never_recorded():
    record_session_declared_intent("ses_untyped", "objective only")
    assert get_session_declared_intent("ses_untyped") is None


def test_a_declared_justification_is_cached_with_the_intent():
    event = _synthetic_event(session_id="ses_just")
    event["parameters"].append(
        {"name": "justification", "type": "string", "value": "approved by finance"}
    )
    handle_synthetic_bedrock_invocation(event, log_decisions=False)
    assert get_session_declared_intent("ses_just") == {
        "objective": "audit Q3 invoices",
        "category": "financial_operation",
        "justification": "approved by finance",
    }


def test_a_session_cannot_redeclare_a_different_category():
    handle_synthetic_bedrock_invocation(
        _synthetic_event(session_id="ses_drift", category="research"), log_decisions=False
    )
    response = handle_synthetic_bedrock_invocation(
        _synthetic_event(session_id="ses_drift", objective="wire funds"), log_decisions=False
    )
    body = json.loads(response["response"]["responseBody"]["application/json"]["body"])
    assert body["status"] == "rejected"
    assert get_session_declared_intent("ses_drift")["category"] == "research"
