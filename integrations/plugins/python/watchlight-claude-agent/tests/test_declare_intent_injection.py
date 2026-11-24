"""Synthetic tool injection tests for the Claude Agent SDK (Python lane).

Five load-bearing tests:

1. ``greenfield_mode_injects_synthetic_tool_at_construction`` —
   ``plugin.synthetic_tools()`` returns the canonical
   ``watchlight.declare_intent`` definition when greenfield mode is
   resolved at plugin construction.
2. ``brownfield_mode_does_not_inject_synthetic_tool`` — mirror; the
   list is empty so brownfield agents never see the tool.
3. ``declare_intent_call_stamps_provenance_to_declared`` — when the
   plugin's interceptor processes a synthetic tool capture, the
   run-handle's ``_intent_provenance`` flips to ``DECLARED`` and the
   stored objective matches the (truncated) input.
4. ``synthetic_tool_call_bypasses_authorize`` — the interceptor MUST
   NOT round-trip to APDP ``/authorize`` when it handles a synthetic
   tool capture (the intentional authorization carve-out).
5. ``subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate``
   — load-bearing integration: after the synthetic tool fires, the
   next ``authorize_action()`` call auto-injects
   ``intent={"objective": "<stored>"}`` into the APDP request body —
   the exact wire shape ``compute_execution_intent_projection`` treats
   as ``provenance: "declared"``, which clears the greenfield-Custodial
   Cedar gate that forbids privileged actions unless intent was declared.

Test #5 is the intent-enforcement gate-closure proof for the Claude
Agent SDK (Python) lane.

# Source pointers (watchlight_core primitives)
- :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` — canonical tool shape
- :func:`watchlight_core.handle_declare_intent_call` — mutator
- :func:`watchlight_core.is_declare_intent_tool_call` — predicate
- :func:`watchlight_core.resolve_intent_enforcement_mode` — mode resolution
- :class:`watchlight_core.BaseRunHandle` — ``_intent_objective`` / ``_intent_provenance``
  fields auto-injected into ``authorize_action_detailed`` request body
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_claude_agent import (
    DECLARE_INTENT_TOOL_NAME,
    RunHandle,
    WatchlightClaudeAgentSDKPlugin,
    is_synthetic_tool_capture,
)
from watchlight_core import IntentProvenance
from watchlight_core.declare_intent import INTENT_ENFORCEMENT_MODE_ENV_VAR
from watchlight_core_testing import stub_session_info


# ─── Fixtures ─────────────────────────────────────────────────────────


def _build_plugin(
    *,
    intent_enforcement_mode: str | None = None,
) -> WatchlightClaudeAgentSDKPlugin:
    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="tenant-test",
        intent_enforcement_mode=intent_enforcement_mode,
    )
    # Mock the APDP transport so the test never hits the network and we
    # can assert call-counts + request bodies precisely.
    plugin.apdp.resolve_agent = AsyncMock(  # type: ignore[method-assign]
        return_value={"id": "agent-uuid-test"}
    )
    plugin.apdp.create_session = AsyncMock(  # type: ignore[method-assign]
        return_value=stub_session_info(plugin.apdp, "ses_test", agent_id="agent-uuid-test")
    )
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.authorize = AsyncMock(  # type: ignore[method-assign]
        return_value={"decision": "Allow"}
    )
    plugin.apdp.publish_events = AsyncMock()  # type: ignore[method-assign]
    return plugin


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Tests must not be affected by ambient
    ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` in the developer's shell —
    clear it so every test starts from the locked brownfield default."""
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)


@pytest_asyncio.fixture
async def greenfield_plugin_and_handle():
    plugin = _build_plugin(intent_enforcement_mode="greenfield")
    handle = await plugin.start_run("my-claude-agent")
    handle._aentered = True  # synthetic test handle
    return plugin, handle


@pytest_asyncio.fixture
async def brownfield_plugin_and_handle():
    plugin = _build_plugin(intent_enforcement_mode="brownfield")
    handle = await plugin.start_run("my-claude-agent")
    handle._aentered = True  # synthetic test handle
    return plugin, handle


# ─── 1. greenfield_mode_injects_synthetic_tool_at_construction ────────


def test_greenfield_mode_injects_synthetic_tool_at_construction():
    """Test 1 — greenfield agents see the synthetic
    ``watchlight.declare_intent`` tool in the plugin's tool-injection
    surface AT CONSTRUCTION TIME.

    Mode resolution sits at plugin construction so the tool list is
    stable from the agent's first turn. The customer spreads
    ``plugin.synthetic_tools()`` (or the merged variant) into
    ``options["tools"]`` when calling ``query()``.
    """
    plugin = _build_plugin(intent_enforcement_mode="greenfield")
    tools = plugin.synthetic_tools()

    assert plugin.intent_enforcement_mode == "greenfield"
    assert len(tools) == 1
    assert tools[0]["name"] == DECLARE_INTENT_TOOL_NAME
    assert tools[0]["name"] == "watchlight.declare_intent"
    # The schema is the canonical declare_intent contract — assert the
    # load-bearing parameter shape is preserved through the plugin's
    # injection surface.
    assert "objective" in tools[0]["parameters"]["required"]
    # wl-apdp's intent requires a category too.
    assert "category" in tools[0]["parameters"]["required"]
    assert tools[0]["parameters"]["additionalProperties"] is False


def test_greenfield_merge_places_synthetic_first():
    """When merged with customer tools, the synthetic tool comes FIRST
    so the LLM's tool-discovery heuristic surfaces it at the top of the
    list — maximising the chance the agent calls declare_intent BEFORE
    any privileged tool."""
    plugin = _build_plugin(intent_enforcement_mode="greenfield")
    customer_tools = [
        {"name": "search_documents", "description": "search", "parameters": {}},
        {"name": "fetch_data", "description": "fetch", "parameters": {}},
    ]
    merged = plugin.merge_synthetic_tools(customer_tools)
    assert merged[0]["name"] == DECLARE_INTENT_TOOL_NAME
    assert merged[1]["name"] == "search_documents"
    assert merged[2]["name"] == "fetch_data"


def test_greenfield_merge_dedupes_customer_collision():
    """A customer tool that collides with the reserved synthetic name is
    dropped — the SDK's canonical definition wins. Defensive against
    accidental customer code; the namespace is reserved."""
    plugin = _build_plugin(intent_enforcement_mode="greenfield")
    bad_customer_tools = [
        {
            "name": DECLARE_INTENT_TOOL_NAME,
            "description": "customer's accidental shadow",
            "parameters": {},
        },
        {"name": "fetch_data", "description": "fetch", "parameters": {}},
    ]
    merged = plugin.merge_synthetic_tools(bad_customer_tools)
    # Exactly one synthetic + one customer tool — the duplicate is dropped.
    assert len(merged) == 2
    assert merged[0]["name"] == DECLARE_INTENT_TOOL_NAME
    assert merged[1]["name"] == "fetch_data"


def test_greenfield_mode_resolution_falls_back_to_env_var(monkeypatch):
    """Mode resolution: env var fallback. Customer that sets
    ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE=greenfield`` without passing
    the constructor arg STILL gets the synthetic tool injected.
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    plugin = _build_plugin()  # no explicit mode arg
    assert plugin.intent_enforcement_mode == "greenfield"
    assert len(plugin.synthetic_tools()) == 1


# ─── 2. brownfield_mode_does_not_inject_synthetic_tool ────────────────


def test_brownfield_mode_does_not_inject_synthetic_tool():
    """Test 2 — brownfield agents NEVER see the synthetic tool.

    The brownfield Cedar matrix accepts inferred provenance at every
    tier so the synthetic-tool gate is inert; surfacing the tool would
    confuse operators and waste LLM tokens.
    """
    plugin = _build_plugin(intent_enforcement_mode="brownfield")
    assert plugin.intent_enforcement_mode == "brownfield"
    assert plugin.synthetic_tools() == []
    # Merged variant: only the customer's tools survive in brownfield.
    customer_tools = [
        {"name": "search_documents", "description": "search", "parameters": {}},
    ]
    assert plugin.merge_synthetic_tools(customer_tools) == customer_tools


def test_default_mode_is_brownfield_no_synthetic_tool():
    """The locked default — no explicit arg + no env var =
    brownfield. Customers must OPT INTO greenfield mode."""
    plugin = _build_plugin()  # no arg, no env var (autouse fixture)
    assert plugin.intent_enforcement_mode == "brownfield"
    assert plugin.synthetic_tools() == []


# ─── 3. declare_intent_call_stamps_provenance_to_declared ─────────────


@pytest.mark.asyncio
async def test_declare_intent_call_stamps_provenance_to_declared(
    greenfield_plugin_and_handle,
):
    """Test 3 — the load-bearing mutation step.

    When ``intercept_tool_call`` handles a PreToolUse capture for the
    synthetic tool, the handle's intent state mutates: provenance flips
    to ``DECLARED`` and the truncated objective is stored. Returns the
    canonical LLM-visible tool response dict.
    """
    plugin, handle = greenfield_plugin_and_handle

    # Baseline — fresh handle has no declared intent.
    assert handle.declared_intent_objective is None
    assert handle.declared_intent_provenance is None

    # Claude Agent SDK PreToolUse capture shape — the same shape the
    # customer's hook loop captures into the translator queue.
    capture = {
        "hook": "PreToolUse",
        "tool_name": "watchlight.declare_intent",
        "tool_input": {"objective": "audit Q3 invoices", "category": "data_analysis"},
    }
    response = plugin.intercept_tool_call(handle, capture)

    assert response is not None
    assert response["status"] == "intent_declared"
    assert response["objective"] == "audit Q3 invoices"
    # Handle mutation — the public read surface.
    assert handle.declared_intent_objective == "audit Q3 invoices"
    assert handle.declared_intent_provenance == IntentProvenance.DECLARED


@pytest.mark.asyncio
async def test_non_synthetic_tool_capture_returns_none(
    greenfield_plugin_and_handle,
):
    """A capture for a customer-defined tool returns ``None`` so the
    customer's hook loop falls through to its normal
    authorize + translate path.

    Confirms the predicate gates intercept correctly — only
    ``watchlight.declare_intent`` short-circuits.
    """
    plugin, handle = greenfield_plugin_and_handle
    capture = {
        "hook": "PreToolUse",
        "tool_name": "search_documents",
        "tool_input": {"query": "Q3"},
    }
    assert plugin.intercept_tool_call(handle, capture) is None
    # Handle state unchanged.
    assert handle.declared_intent_objective is None
    assert handle.declared_intent_provenance is None


# ─── 4. synthetic_tool_call_bypasses_authorize ────────────────────────


@pytest.mark.asyncio
async def test_synthetic_tool_call_bypasses_authorize(
    greenfield_plugin_and_handle,
):
    """Test 4 — authorization carve-out: the synthetic tool MUST NOT
    round-trip to APDP ``/authorize``.

    Calling ``intercept_tool_call`` on a synthetic capture mutates
    handle state in-process WITHOUT calling ``plugin.apdp.authorize``.
    The Cedar gate would forbid the call before the agent could declare;
    the bypass is the load-bearing escape valve.

    This is an intentionally accepted trade-off documented in the
    security-hardening notes.
    """
    plugin, handle = greenfield_plugin_and_handle
    capture = {
        "hook": "PreToolUse",
        "tool_name": "watchlight.declare_intent",
        "tool_input": {"objective": "audit Q3 invoices", "category": "data_analysis"},
    }

    response = plugin.intercept_tool_call(handle, capture)
    assert response is not None
    assert response["status"] == "intent_declared"

    # Load-bearing assertion — NO authorize round-trip happened.
    plugin.apdp.authorize.assert_not_called()


def test_is_synthetic_tool_capture_predicate_distinguishes_calls():
    """The predicate gates correctly across the framework-agnostic
    shapes the customer's hook loop might capture."""
    # Claude Agent SDK PreToolUse shape.
    assert is_synthetic_tool_capture(
        {"hook": "PreToolUse", "tool_name": DECLARE_INTENT_TOOL_NAME, "tool_input": {}}
    ) is True
    # Anthropic / OpenAI canonical tool-call shape.
    assert is_synthetic_tool_capture(
        {"name": DECLARE_INTENT_TOOL_NAME, "arguments": {"objective": "x"}}
    ) is True
    # LangChain shape — defer to the SDK predicate.
    assert is_synthetic_tool_capture(
        {"tool": DECLARE_INTENT_TOOL_NAME, "args": {"objective": "x"}}
    ) is True
    # A real tool call → False (falls through to authorize).
    assert is_synthetic_tool_capture(
        {"hook": "PreToolUse", "tool_name": "search_documents", "tool_input": {}}
    ) is False
    # Defensive shapes.
    assert is_synthetic_tool_capture(None) is False
    assert is_synthetic_tool_capture("not_a_dict") is False
    assert is_synthetic_tool_capture({}) is False


# ─── 5. subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate ──


@pytest.mark.asyncio
async def test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate(
    greenfield_plugin_and_handle,
):
    """Test 5 — LOAD-BEARING INTEGRATION TEST for the intent-enforcement
    gate.

    End-to-end proof that the synthetic-tool path closes the
    intent-enforcement Cedar gate for the Claude Agent SDK (Python) lane:

    1. Agent calls ``watchlight.declare_intent({"objective": "audit Q3"})``
       through the SDK's PreToolUse hook.
    2. ``plugin.intercept_tool_call(handle, capture)`` short-circuits —
       mutates handle state to provenance=Declared, NO authorize call.
    3. Agent's next privileged call goes through the customer's normal
       loop: ``await handle.authorize_action("read", "Document::ledger")``.
    4. The wire shape APDP receives includes
       ``intent={"objective": "audit Q3 invoices"}`` — the exact field
       ``compute_execution_intent_projection`` reads to stamp
       ``provenance: "declared"`` on the evaluation context.
    5. That projection clears the greenfield-Custodial Cedar gate that
       forbids privileged actions unless intent was declared, and the
       action is Allowed.

    This test pins the wire shape APDP receives so a regression to the
    auto-inject path or to the synthetic-tool mutator surface fails CI
    loudly.
    """
    plugin, handle = greenfield_plugin_and_handle

    # Step 1 + 2 — synthetic tool fires; handle mutates; NO authorize.
    capture = {
        "hook": "PreToolUse",
        "tool_name": "watchlight.declare_intent",
        "tool_input": {"objective": "audit Q3 invoices", "category": "data_analysis"},
    }
    assert plugin.intercept_tool_call(handle, capture) is not None
    plugin.apdp.authorize.assert_not_called()

    # Step 3 — agent's next privileged call.
    await handle.authorize_action("read", "Document::ledger")

    # Step 4 — verify the wire shape APDP saw the declared intent.
    plugin.apdp.authorize.assert_called_once()
    call_kwargs = plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs["intent"] == {
        "objective": "audit Q3 invoices",
        "category": "data_analysis",
    }
    # Cedar context projection's load-bearing input — the field name
    # the intent-enforcement projection treats as Declared.
    assert call_kwargs["intent"]["objective"] == "audit Q3 invoices"


# ─── Typed intent (wl-apdp requires objective AND category) ──────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_input",
    [{"objective": "audit Q3 invoices"}, {"objective": "audit Q3 invoices", "category": "audit"}],
    ids=["no_category", "unknown_category"],
)
async def test_declare_without_a_valid_category_is_rejected_and_sends_no_intent(
    greenfield_plugin_and_handle, tool_input
):
    plugin, handle = greenfield_plugin_and_handle
    response = plugin.intercept_tool_call(
        handle,
        {"hook": "PreToolUse", "tool_name": "watchlight.declare_intent", "tool_input": tool_input},
    )
    assert response["status"] == "rejected"
    assert handle.declared_intent_provenance is None
    await handle.authorize_action("read", "Document::ledger")
    # wl-apdp answers a category-less intent with 422: none is sent.
    assert plugin.apdp.authorize.call_args.kwargs["intent"] is None
