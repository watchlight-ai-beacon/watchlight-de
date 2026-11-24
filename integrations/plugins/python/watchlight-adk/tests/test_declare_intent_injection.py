"""Tests for the ADK synthetic ``watchlight.declare_intent``
tool injection + tool-call interception.

These cover the per-framework synthetic tool injection on
the ADK plugin. The five tests below mirror the per-framework
invariants the implementation guide lists:

1. ``greenfield_mode_injects_synthetic_tool_at_construction`` — the
   plugin's ``before_agent_callback`` adds the synthetic tool to the
   agent's ``tools`` list when the effective enforcement mode is
   greenfield.
2. ``brownfield_mode_does_not_inject_synthetic_tool`` — mirror; the
   agent's ``tools`` list is left untouched in brownfield.
3. ``declare_intent_call_stamps_provenance_to_declared`` — when the
   ADK agent invokes the synthetic tool, ``before_tool_callback``
   delegates to :func:`watchlight_core.handle_declare_intent_call`
   which stamps :attr:`IntentProvenance.DECLARED` on the plugin's
   mirror state.
4. ``synthetic_tool_call_bypasses_authorize`` — the declare-intent
   carve-out: the synthetic tool's invocation MUST NOT round-trip to
   APDP ``/authorize`` (the greenfield gate would forbid the very first
   ``declare_intent`` call before the agent could declare).
5. ``subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate``
   — the LOAD-BEARING integration test: after the synthetic tool
   fires, the NEXT non-synthetic tool's ``before_tool_callback``
   auto-injects ``intent={"objective": <stored>}`` into the APDP
   request body, which is the wire shape the greenfield Cedar gate
   treats as ``provenance: "declared"``.
"""

from __future__ import annotations

from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_core import (
    DECLARE_INTENT_TOOL_NAME,
    INTENT_ENFORCEMENT_MODE_ENV_VAR,
    IntentProvenance,
)
from watchlight_adk import WatchlightPlugin
from watchlight_adk.synthetic_intent_tool import WatchlightDeclareIntentTool
from watchlight_core_testing import stub_session_info

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")


# ─── Fixtures ─────────────────────────────────────────────────────────


# In-process stand-in for unit tests only.
def _stub_tool(name: str) -> Any:
    """Stand-in for an ADK BaseTool with a ``.name`` attribute. The
    plugin's ``before_tool_callback`` reads ``tool.name`` and falls
    back to ``str(tool)`` — a MagicMock with ``name`` set covers both
    paths."""
    tool = MagicMock()
    tool.name = name
    return tool


# In-process stand-in for unit tests only.
def _stub_adk_agent(name: str = "research_analyst", tools: list | None = None) -> Any:
    """A stub ADK agent the runner would pass to ``before_agent_callback``.

    Carries a mutable ``tools`` list so the injector can append the
    synthetic tool.
    """

    class _Agent:
        pass

    agent = _Agent()
    agent.name = name
    agent.tools = list(tools) if tools is not None else []
    return agent


# In-process stand-in for unit tests only.
def _stub_callback_ctx() -> Any:
    """Minimal CallbackContext stub the plugin's bootstrap touches.
    Only ``state`` is read; we give it a dict so the
    ``_open_session_and_manifest`` helper's manifest-stash path works.
    """

    class _Ctx:
        state: dict = {}
        # Intent extractor walks ``user_content`` /
        # ``invocation_context`` paths — leaving them ``None`` makes
        # the extractor return ``None`` (Absent provenance), which
        # is the simplest baseline for these tests.
        user_content = None
        invocation_context = None

    return _Ctx()


@pytest.fixture
def greenfield_plugin(monkeypatch):
    """A :class:`WatchlightPlugin` constructed in GREENFIELD mode with
    apdp + lineage + registry methods stubbed.

    Resolver is wired to return a valid agent so ``before_agent_callback``
    progresses past the bootstrap and reaches the synthetic-tool
    injection. ``apdp.authorize`` is stubbed to return Allow so
    ``before_tool_callback`` doesn't short-circuit on a Deny.
    """
    # Make sure no leftover env var bleeds into the test.
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="greenfield",
        log_decisions=False,
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    p.apdp.resolve_agent = AsyncMock(
        return_value={
            "id": "agent-uuid-x",
            "slug": "research-analyst",
            "name": "Research Analyst",
            "trust_state": "trusted",
        }
    )
    p.apdp.check_agent_trust = AsyncMock(
        return_value={"trusted": True, "reason": ""}
    )
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test", session_token="sst_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": []})
    p.apdp.authorize = AsyncMock(return_value={"decision": "Allow", "reason": ""})
    p.apdp.preflight_step = AsyncMock(
        return_value={"preflight": {"allowed": True}}
    )
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()
    p.lineage.emit_tool_call = AsyncMock()
    return p


@pytest.fixture
def brownfield_plugin(monkeypatch):
    """Mirror of ``greenfield_plugin`` but constructed in
    BROWNFIELD mode. Used by test 2 to verify the synthetic tool is
    NOT injected when greenfield is off."""
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode="brownfield",
        log_decisions=False,
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    p.apdp.resolve_agent = AsyncMock(
        return_value={
            "id": "agent-uuid-x",
            "slug": "research-analyst",
            "name": "Research Analyst",
            "trust_state": "trusted",
        }
    )
    p.apdp.check_agent_trust = AsyncMock(
        return_value={"trusted": True, "reason": ""}
    )
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test", session_token="sst_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": []})
    p.apdp.authorize = AsyncMock(return_value={"decision": "Allow", "reason": ""})
    p.apdp.preflight_step = AsyncMock(
        return_value={"preflight": {"allowed": True}}
    )
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()
    p.lineage.emit_tool_call = AsyncMock()
    return p


def _has_synthetic_tool(tools: List[Any]) -> bool:
    """True iff the agent's tools list contains the synthetic
    declare-intent tool (matched by canonical name)."""
    for t in tools:
        name = getattr(t, "name", None)
        if isinstance(name, str) and name == DECLARE_INTENT_TOOL_NAME:
            return True
    return False


# ─── Test 1 — greenfield mode injects synthetic tool at construction ──


@pytest.mark.asyncio
async def test_greenfield_mode_injects_synthetic_tool_at_construction(
    greenfield_plugin,
):
    """Test 1 — when the plugin's effective enforcement mode is
    greenfield, ``before_agent_callback`` adds the synthetic
    ``watchlight.declare_intent`` tool to the agent's ``tools`` list.

    The injection happens BEFORE ADK reads the tools for the LLM's
    first turn, so the synthetic tool is part of the offered tool
    set from the start. The injected tool is the canonical
    :class:`WatchlightDeclareIntentTool` carrying the exact wire
    name ``watchlight.declare_intent``.
    """
    agent = _stub_adk_agent(tools=[_stub_tool("search_documents")])
    ctx = _stub_callback_ctx()
    assert not _has_synthetic_tool(agent.tools), (
        "fixture sanity: agent must start without the synthetic tool"
    )

    result = await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )

    assert result is None, "bootstrap should return None to let the agent proceed"
    assert _has_synthetic_tool(agent.tools), (
        "synthetic declare_intent tool must be present on the agent in "
        "greenfield mode"
    )
    # The injected tool is the BaseTool subclass — proves we wired the
    # ADK-native registration (BaseTool), not a dict or a stub.
    synthetic = next(
        t for t in agent.tools if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )
    assert isinstance(synthetic, WatchlightDeclareIntentTool)
    # The customer's own tool is still present — we union, not replace.
    assert any(
        getattr(t, "name", None) == "search_documents" for t in agent.tools
    ), "customer's own tools must NOT be removed by the injection"


@pytest.mark.asyncio
async def test_greenfield_injection_is_idempotent(greenfield_plugin):
    """Re-running ``before_agent_callback`` on the same agent (e.g.
    a multi-turn run) must NOT add a second synthetic tool — the
    injector keys on the canonical name and short-circuits."""
    agent = _stub_adk_agent(tools=[])
    ctx = _stub_callback_ctx()
    # A multi-turn run: each turn is a full before→after agent lifecycle.
    # The intervening ``after_agent_callback`` closes turn 1 so turn 2 is a
    # fresh ROOT run (not a nested sub-agent transfer, which would
    # route through the governed spawn path).
    await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )
    await greenfield_plugin.after_agent_callback(
        agent=agent, callback_context=ctx
    )
    await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )
    synthetic_count = sum(
        1 for t in agent.tools if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )
    assert synthetic_count == 1, (
        f"expected exactly one synthetic tool after re-injection; got {synthetic_count}"
    )


# ─── Test 2 — brownfield mode does NOT inject the synthetic tool ──────


@pytest.mark.asyncio
async def test_brownfield_mode_does_not_inject_synthetic_tool(brownfield_plugin):
    """Test 2 — in brownfield mode the agent's tools list is
    left untouched. The brownfield Cedar matrix accepts inferred
    provenance at every tier and the synthetic-tool gate would be
    inert; surfacing the tool would confuse operators.
    """
    agent = _stub_adk_agent(tools=[_stub_tool("search_documents")])
    ctx = _stub_callback_ctx()
    original_names = [getattr(t, "name", None) for t in agent.tools]

    await brownfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )

    assert not _has_synthetic_tool(agent.tools), (
        "synthetic declare_intent tool must NOT be present in brownfield"
    )
    # The customer's tool list is exactly what it started as.
    final_names = [getattr(t, "name", None) for t in agent.tools]
    assert final_names == original_names, (
        "brownfield must leave agent.tools byte-identical"
    )


# ─── Test 3 — declare_intent call stamps provenance to declared ──────


@pytest.mark.asyncio
async def test_declare_intent_call_stamps_provenance_to_declared(greenfield_plugin):
    """Test 3 — when the agent CALLS the synthetic tool, the
    plugin's ``before_tool_callback`` short-circuit invokes
    ``handle_declare_intent_call`` which mutates the plugin's
    mirror state: ``_intent_objective`` carries the truncated
    objective, ``_intent_provenance`` flips to
    :attr:`IntentProvenance.DECLARED`.
    """
    # Bootstrap so the plugin's _current_agent_id is populated and
    # the synthetic tool is on the agent.
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )
    assert greenfield_plugin._intent_objective is None
    assert greenfield_plugin._intent_provenance is None

    # Simulate the agent invoking the synthetic tool via ADK's
    # ``before_tool_callback`` contract.
    tool = _stub_tool(DECLARE_INTENT_TOOL_NAME)
    result = await greenfield_plugin.before_tool_callback(
        tool=tool,
        tool_args={"objective": "audit Q3 invoices", "category": "financial_operation"},
        tool_context=None,
    )

    # The short-circuit returns the synthetic-tool response dict
    # (ADK's contract: returning a dict bypasses tool execution
    # and surfaces the dict as the result).
    assert isinstance(result, dict)
    assert result.get("status") == "intent_declared"
    assert result.get("objective") == "audit Q3 invoices"

    # The mutation landed on the plugin instance — this is the
    # load-bearing state the next authorize call reads.
    assert greenfield_plugin._intent_objective == "audit Q3 invoices"
    assert greenfield_plugin._intent_provenance == IntentProvenance.DECLARED


# ─── Test 4 — synthetic tool call BYPASSES authorize ─────────────────


@pytest.mark.asyncio
async def test_synthetic_tool_call_bypasses_authorize(greenfield_plugin):
    """Test 4 — the declare-intent carve-out. The synthetic
    ``watchlight.declare_intent`` invocation MUST NOT round-trip to
    APDP ``/authorize``. The greenfield Cedar gate FORBIDS Custodial
    actions in greenfield until ``provenance == "declared"``; the
    agent's very first ``declare_intent`` call would be denied
    before it could declare. The plugin's ``before_tool_callback``
    short-circuits BEFORE the authorize hop.
    """
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )
    # Reset the authorize mock so the assertion below only counts
    # post-bootstrap calls (the bootstrap path itself does not call
    # authorize, but we reset to harden the test against future
    # bootstrap-time authorize calls).
    greenfield_plugin.apdp.authorize.reset_mock()

    tool = _stub_tool(DECLARE_INTENT_TOOL_NAME)
    result = await greenfield_plugin.before_tool_callback(
        tool=tool,
        tool_args={"objective": "audit Q3 invoices", "category": "financial_operation"},
        tool_context=None,
    )

    assert isinstance(result, dict)
    assert result.get("status") == "intent_declared"
    # The load-bearing assertion: APDP ``/authorize`` was NOT called
    # for the synthetic tool. The audit trail is still produced
    # (via ``after_tool_callback``) but the authorize hop is elided.
    greenfield_plugin.apdp.authorize.assert_not_called()
    # And the preflight hop is also skipped — the short-circuit
    # happens before any APDP I/O.
    greenfield_plugin.apdp.preflight_step.assert_not_called()


# ─── Test 5 — subsequent authorize satisfies Cedar gate ──────────────


@pytest.mark.asyncio
async def test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate(
    greenfield_plugin,
):
    """Test 5 — LOAD-BEARING INTEGRATION TEST.

    After the synthetic tool fires, the NEXT non-synthetic tool's
    ``before_tool_callback`` MUST auto-inject
    ``intent={"objective": "<stored>"}`` into the APDP
    ``/authorize`` request body. APDP's Cedar context projection
    reads ``request.intent.objective`` and stamps
    the evaluation context with ``provenance: "declared"`` —
    which CLEARS the greenfield-Custodial Cedar gate (the policy that
    forbids Custodial actions until intent is declared).

    This test proves the per-framework wiring closes the greenfield gate
    end-to-end on ADK by asserting the exact wire shape APDP receives
    on the authorize request body for a subsequent tool call.
    """
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(
        agent=agent, callback_context=ctx
    )

    # Step 1 — agent calls watchlight.declare_intent("audit Q3 invoices").
    declare_tool = _stub_tool(DECLARE_INTENT_TOOL_NAME)
    declare_response = await greenfield_plugin.before_tool_callback(
        tool=declare_tool,
        tool_args={"objective": "audit Q3 invoices", "category": "financial_operation"},
        tool_context=None,
    )
    assert declare_response.get("status") == "intent_declared"

    # Reset authorize mock so the next call's kwargs are the only
    # ones we inspect.
    greenfield_plugin.apdp.authorize.reset_mock()

    # Step 2 — agent's next tool call (a real Custodial action that
    # would be FORBID'd in greenfield without a declared intent).
    real_tool = _stub_tool("write_ledger_entry")
    await greenfield_plugin.before_tool_callback(
        tool=real_tool,
        tool_args={"row": "Q3 audit"},
        tool_context=None,
    )

    # Step 3 — verify the APDP authorize request body carries the
    # declared intent. This is the wire shape APDP's Cedar context
    # projection treats as Declared, which clears the greenfield gate.
    assert greenfield_plugin.apdp.authorize.called, (
        "non-synthetic tool MUST round-trip to APDP authorize"
    )
    call_kwargs = greenfield_plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs.get("intent") == {
        "objective": "audit Q3 invoices",
        "category": "financial_operation",
    }, (
        "the auto-injected intent kwarg must carry the declared objective; "
        f"got {call_kwargs.get('intent')!r}"
    )


# ─── Auxiliary coverage — env-var mode resolution ─────────────────────


@pytest.mark.asyncio
async def test_env_var_alone_enables_greenfield_injection(monkeypatch):
    """A customer that opts into greenfield via the env var alone
    (no constructor kwarg) gets the same injection behaviour. This
    is the zero-touch path (minimal required configuration knobs).
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        log_decisions=False,
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    p.apdp.resolve_agent = AsyncMock(
        return_value={
            "id": "agent-uuid-x",
            "slug": "research-analyst",
            "name": "Research Analyst",
            "trust_state": "trusted",
        }
    )
    p.apdp.check_agent_trust = AsyncMock(
        return_value={"trusted": True, "reason": ""}
    )
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={})
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()

    agent = _stub_adk_agent(tools=[])
    ctx = _stub_callback_ctx()
    await p.before_agent_callback(agent=agent, callback_context=ctx)

    assert _has_synthetic_tool(agent.tools), (
        "env-var greenfield opt-in must inject the synthetic tool"
    )


@pytest.mark.asyncio
async def test_default_mode_is_brownfield_no_injection(monkeypatch):
    """The default is brownfield —
    onboarding tenants see warn-only enforcement until they opt in.
    Verifies no env var + no kwarg = no synthetic tool.
    """
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        log_decisions=False,
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    p.apdp.resolve_agent = AsyncMock(
        return_value={
            "id": "agent-uuid-x",
            "slug": "research-analyst",
            "name": "Research Analyst",
            "trust_state": "trusted",
        }
    )
    p.apdp.check_agent_trust = AsyncMock(
        return_value={"trusted": True, "reason": ""}
    )
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={})
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()

    agent = _stub_adk_agent(tools=[])
    ctx = _stub_callback_ctx()
    await p.before_agent_callback(agent=agent, callback_context=ctx)

    assert not _has_synthetic_tool(agent.tools), (
        "default (brownfield) must NOT inject the synthetic tool"
    )


# ─── Typed intent: wl-apdp requires objective AND category ──────────


@pytest.mark.asyncio
async def test_a_declare_without_a_category_is_rejected_and_no_intent_is_sent(
    greenfield_plugin,
):
    """wl-apdp answers a category-less intent with 422, so a declaration
    without a category is refused and the next authorize carries NO
    intent (never an objective-only one)."""
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(agent=agent, callback_context=ctx)

    declare_response = await greenfield_plugin.before_tool_callback(
        tool=_stub_tool(DECLARE_INTENT_TOOL_NAME),
        tool_args={"objective": "audit Q3 invoices"},
        tool_context=None,
    )
    assert declare_response.get("status") == "rejected"
    assert greenfield_plugin._intent_category is None

    greenfield_plugin.apdp.authorize.reset_mock()
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool("write_ledger_entry"),
        tool_args={"row": "Q3 audit"},
        tool_context=None,
    )
    assert greenfield_plugin.apdp.authorize.called
    assert greenfield_plugin.apdp.authorize.call_args.kwargs.get("intent") is None


@pytest.mark.asyncio
async def test_a_custom_category_reaches_authorize_in_wire_form(greenfield_plugin):
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(agent=agent, callback_context=ctx)
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool(DECLARE_INTENT_TOOL_NAME),
        tool_args={"objective": "triage alerts", "category": "custom:triage"},
        tool_context=None,
    )
    greenfield_plugin.apdp.authorize.reset_mock()
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool("write_ledger_entry"), tool_args={}, tool_context=None
    )
    assert greenfield_plugin.apdp.authorize.call_args.kwargs.get("intent") == {
        "objective": "triage alerts",
        "category": {"custom": "triage"},
    }


def test_the_rendered_declaration_requires_objective_and_category(greenfield_plugin):
    declaration = WatchlightDeclareIntentTool(greenfield_plugin)._get_declaration()
    params = declaration.parameters
    assert set(params.properties) == {"objective", "category", "justification"}
    assert sorted(params.required) == ["category", "objective"]


@pytest.mark.asyncio
async def test_a_declared_justification_reaches_authorize(greenfield_plugin):
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(agent=agent, callback_context=ctx)
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool(DECLARE_INTENT_TOOL_NAME),
        tool_args={
            "objective": "pay invoice 7",
            "category": "financial_operation",
            "justification": "approved by finance",
        },
        tool_context=None,
    )
    greenfield_plugin.apdp.authorize.reset_mock()
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool("write_ledger_entry"), tool_args={}, tool_context=None
    )
    assert greenfield_plugin.apdp.authorize.call_args.kwargs.get("intent") == {
        "objective": "pay invoice 7",
        "category": "financial_operation",
        "justification": "approved by finance",
    }


@pytest.mark.asyncio
async def test_a_different_category_cannot_be_redeclared(greenfield_plugin):
    agent = _stub_adk_agent()
    ctx = _stub_callback_ctx()
    await greenfield_plugin.before_agent_callback(agent=agent, callback_context=ctx)
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool(DECLARE_INTENT_TOOL_NAME),
        tool_args={"objective": "look things up", "category": "research"},
        tool_context=None,
    )
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool(DECLARE_INTENT_TOOL_NAME),
        tool_args={"objective": "wire funds", "category": "financial_operation"},
        tool_context=None,
    )
    greenfield_plugin.apdp.authorize.reset_mock()
    await greenfield_plugin.before_tool_callback(
        tool=_stub_tool("write_ledger_entry"), tool_args={}, tool_context=None
    )
    assert greenfield_plugin.apdp.authorize.call_args.kwargs.get("intent") == {
        "objective": "look things up",
        "category": "research",
    }
