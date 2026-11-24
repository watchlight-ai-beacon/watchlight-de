"""LangGraph per-framework synthetic tool injection tests.

Five load-bearing tests covering the synthetic-tool injection contract:

1. ``test_greenfield_mode_injects_synthetic_tool_at_construction``
   — the synthetic tool appears in the bound tools when the plugin's
   mode is ``"greenfield"``.
2. ``test_brownfield_mode_does_not_inject_synthetic_tool`` — the
   synthetic tool is ABSENT when the plugin's mode is
   ``"brownfield"``.
3. ``test_declare_intent_call_stamps_provenance_to_declared`` —
   invoking the bound tool mutates the handle's
   ``_intent_provenance`` to :attr:`IntentProvenance.DECLARED`.
4. ``test_synthetic_tool_call_bypasses_authorize`` — no
   ``apdp.authorize`` call fires for ``watchlight.declare_intent``
   (the authorize-bypass carve-out).
5. ``test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate``
   — integration: declare intent via the synthetic tool, then make a
   normal ``authorize_action`` call, assert the APDP ``/authorize``
   body carries ``intent={"objective": "..."}`` — which the Cedar
   intent projection treats as ``provenance: "declared"`` and the
   greenfield intent-declaration gate clears.

These are pure-Python tests with mocked APDP I/O — they exercise
the plugin's tool-translation layer against a scripted LangChain chat
model, not a real LLM. The integration test against a live
LangGraph + Claude model lives in
``test_integration_real_langgraph.py``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_core import (
    DECLARE_INTENT_TOOL_NAME,
    IntentProvenance,
)
from watchlight_langgraph import WatchlightLangGraphPlugin
from watchlight_core_testing import stub_session_info


# ─── Test fixtures ───────────────────────────────────────────────────


# In-process stand-in for unit tests only.
class _StubChatModel:
    """Stand-in for a LangChain :class:`BaseChatModel` that only
    exposes :meth:`bind_tools`.

    Real chat models (``ChatAnthropic``, ``ChatOpenAI``, …) inherit
    ``bind_tools`` from ``BaseChatModel`` which wraps the model in a
    ``RunnableBinding`` and stores the tool definitions in
    ``.kwargs["tools"]``. We mirror just enough of that shape so
    the tests can assert which tools were bound, without pulling
    a real provider SDK into the test deps.
    """

    def __init__(self) -> None:
        self.last_bound_tools: Optional[List[Any]] = None
        self.last_bind_kwargs: Dict[str, Any] = {}

    def bind_tools(self, tools: List[Any], **kwargs: Any) -> "_StubBoundChatModel":
        self.last_bound_tools = list(tools)
        self.last_bind_kwargs = dict(kwargs)
        return _StubBoundChatModel(parent=self, tools=list(tools))


# In-process stand-in for unit tests only.
class _StubBoundChatModel:
    """The ``RunnableBinding``-shaped return value of ``bind_tools``."""

    def __init__(self, parent: _StubChatModel, tools: List[Any]) -> None:
        self.parent = parent
        self.tools = tools


def _plugin_with_mode(mode: Optional[str]) -> WatchlightLangGraphPlugin:
    """Construct a plugin with the given enforcement mode + a fully
    mocked APDP client.

    All APDP wire calls are AsyncMocks so the tests never hit a real
    network — and so test #4 (no ``authorize`` call fired on the
    synthetic tool invocation) can assert against the mock's call
    history.
    """
    p = WatchlightLangGraphPlugin(
        apdp_url="https://apdp.test",
        intent_enforcement_mode=mode,
    )
    p.apdp.resolve_agent = AsyncMock(
        return_value={
            "id": "ag-uuid-x",
            "slug": "research-analyst",
            "trust_state": "trusted",
        }
    )
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_x", session_token="sst_x")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": ["read"]})
    p.apdp.authorize = AsyncMock(return_value={"decision": "Allow"})
    p.apdp.complete_session = AsyncMock(return_value=True)
    p.apdp.terminate_session = AsyncMock(return_value=True)
    p.apdp.publish_events = AsyncMock(return_value=True)
    return p


@pytest_asyncio.fixture
async def greenfield_handle():
    """Plugin + handle pre-configured for greenfield mode."""
    plugin = _plugin_with_mode("greenfield")
    handle = await plugin.start_run(agent_slug="research-analyst")
    # Synthetic test handle bypasses the production ``async with``
    # entry path; flip the fail-closed flag.
    handle._aentered = True
    return plugin, handle


@pytest_asyncio.fixture
async def brownfield_handle():
    """Plugin + handle pre-configured for brownfield mode."""
    plugin = _plugin_with_mode("brownfield")
    handle = await plugin.start_run(agent_slug="research-analyst")
    # Synthetic test handle bypasses the production ``async with``
    # entry path; flip the fail-closed flag.
    handle._aentered = True
    return plugin, handle


# A simple customer tool used to anchor the bind_tools call signature
# in the tests. The exact shape doesn't matter — we only assert the
# customer tool sits in the bound list alongside (or instead of) the
# synthetic tool.
def _customer_search_tool(query: str) -> str:
    """Search a knowledge base for ``query``."""
    return f"results for: {query}"


def _customer_tools() -> List[Any]:
    from langchain_core.tools import StructuredTool

    return [
        StructuredTool.from_function(
            func=_customer_search_tool,
            name="search_kb",
            description="Search the knowledge base.",
        )
    ]


def _names(tools: List[Any]) -> List[str]:
    return [getattr(t, "name", None) for t in tools]


# ─── Test 1 — greenfield injects ─────────────────────────────────────


@pytest.mark.asyncio
async def test_greenfield_mode_injects_synthetic_tool_at_construction(
    greenfield_handle,
):
    """Injection test 1.

    In greenfield mode the synthetic ``watchlight.declare_intent``
    tool MUST be appended to the bound tool list when the customer
    calls ``handle.bind_tools(model, customer_tools)`` — without any
    customer code change.
    """
    _plugin, handle = greenfield_handle
    model = _StubChatModel()
    customer_tools = _customer_tools()

    bound = handle.bind_tools(model, customer_tools)

    assert model.last_bound_tools is not None, (
        "bind_tools should have been called on the underlying model"
    )
    names = _names(model.last_bound_tools)
    assert DECLARE_INTENT_TOOL_NAME in names, (
        f"synthetic tool missing from bound tools: {names}"
    )
    assert "search_kb" in names, (
        f"customer tool dropped from bound tools: {names}"
    )
    # Customer's tool comes first; synthetic tool appended.
    assert names.index("search_kb") < names.index(DECLARE_INTENT_TOOL_NAME)
    assert isinstance(bound, _StubBoundChatModel)


# ─── Test 2 — brownfield does not inject ─────────────────────────────


@pytest.mark.asyncio
async def test_brownfield_mode_does_not_inject_synthetic_tool(
    brownfield_handle,
):
    """Injection test 2.

    In brownfield mode the synthetic tool MUST NOT appear in the
    bound tool list — brownfield Cedar policies accept inferred
    provenance at every tier and the gate is inert there.
    """
    _plugin, handle = brownfield_handle
    model = _StubChatModel()
    customer_tools = _customer_tools()

    handle.bind_tools(model, customer_tools)

    assert model.last_bound_tools is not None
    names = _names(model.last_bound_tools)
    assert DECLARE_INTENT_TOOL_NAME not in names, (
        f"synthetic tool incorrectly bound in brownfield: {names}"
    )
    assert names == ["search_kb"], (
        f"only the customer's tool should be bound: {names}"
    )


# ─── Test 3 — provenance flips to DECLARED on call ───────────────────


@pytest.mark.asyncio
async def test_declare_intent_call_stamps_provenance_to_declared(
    greenfield_handle,
):
    """Injection test 3.

    Invoking the synthetic tool's callable (the same callable the
    LangChain runtime would invoke when the agent emits a tool call
    for ``watchlight.declare_intent``) mutates the handle's stored
    intent state: ``_intent_provenance`` becomes
    :attr:`IntentProvenance.DECLARED` and ``_intent_objective``
    becomes the agent's declared string.
    """
    _plugin, handle = greenfield_handle
    model = _StubChatModel()

    # Baseline — no declared intent before the call.
    assert handle._intent_objective is None
    assert handle._intent_provenance is None

    handle.bind_tools(model, _customer_tools())
    synthetic = next(
        t
        for t in (model.last_bound_tools or [])
        if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )

    # Invoke the tool the way LangChain's tool runtime would: through
    # ``.invoke(<args dict>)``. The StructuredTool's ``func`` is a
    # closure over the handle so the mutation lands on THIS handle.
    response = synthetic.invoke({"objective": "audit Q3 invoices", "category": "data_analysis"})

    assert response["status"] == "intent_declared"
    assert response["objective"] == "audit Q3 invoices"
    assert handle._intent_objective == "audit Q3 invoices"
    assert handle._intent_provenance == IntentProvenance.DECLARED
    # Public surface mirrors the internal state.
    assert handle.declared_intent_provenance == IntentProvenance.DECLARED
    assert handle.declared_intent_objective == "audit Q3 invoices"


# ─── Test 4 — authorize bypass ───────────────────────────────────────


@pytest.mark.asyncio
async def test_synthetic_tool_call_bypasses_authorize(greenfield_handle):
    """Injection test 4 — authorize-bypass carve-out.

    A call to ``watchlight.declare_intent`` MUST NOT round-trip to
    :meth:`authorize_action` — otherwise the Cedar intent-declaration
    gate would deny the agent's first declaration before it could
    clear the gate (chicken-and-egg).

    The mechanism in the LangGraph plugin is structural: the
    StructuredTool's ``func`` is a direct closure over
    :func:`handle_declare_intent_call`, never emitting an authorize
    call. This test asserts that mechanism end-to-end by checking
    the mocked ``apdp.authorize`` has zero calls after the synthetic
    tool fires.
    """
    plugin, handle = greenfield_handle
    model = _StubChatModel()
    handle.bind_tools(model, _customer_tools())

    # Reset call history — start_run may have already exercised some
    # APDP calls but ``authorize`` should not have been called yet.
    assert plugin.apdp.authorize.call_count == 0

    synthetic = next(
        t
        for t in (model.last_bound_tools or [])
        if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )
    synthetic.invoke({"objective": "audit Q3 invoices", "category": "data_analysis"})

    # Load-bearing assertion: the synthetic tool's invocation did
    # NOT fire ``apdp.authorize``. The authorize-bypass carve-out holds.
    assert plugin.apdp.authorize.call_count == 0, (
        "watchlight.declare_intent MUST NOT round-trip to "
        "authorize_action — see the declare_intent carve-out."
    )
    # The bookkeeping for actions allowed/denied must also be
    # untouched — the synthetic tool is not an authorize event.
    assert plugin.last_actions_allowed == 0
    assert plugin.last_actions_denied == 0

    # The async variant also bypasses authorize.
    await synthetic.ainvoke({"objective": "investigate alert", "category": "security_compliance"})
    assert plugin.apdp.authorize.call_count == 0


# ─── Test 5 — Cedar gate satisfied by subsequent authorize call ─────


@pytest.mark.asyncio
async def test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate(
    greenfield_handle,
):
    """Injection test 5 — END-TO-END INTEGRATION.

    Three-step narrative:

    1. The customer calls ``handle.bind_tools(model, customer_tools)``
       and the synthetic tool is injected.
    2. The agent (simulated here by directly invoking the
       StructuredTool) calls ``watchlight.declare_intent("...")``.
    3. The agent then calls a privileged action, which the
       customer's graph routes through ``handle.authorize_action``.
       The APDP ``/authorize`` request body MUST carry
       ``intent={"objective": "..."}`` — the wire shape that wl-apdp
       stamps as ``provenance: "declared"`` and which clears the
       greenfield intent-declaration gate.
    """
    plugin, handle = greenfield_handle
    model = _StubChatModel()
    handle.bind_tools(model, _customer_tools())

    # Step 1 — agent calls the synthetic tool.
    synthetic = next(
        t
        for t in (model.last_bound_tools or [])
        if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )
    declare_response = synthetic.invoke(
        {"objective": "audit Q3 invoices and produce a summary", "category": "data_analysis"}
    )
    assert declare_response["status"] == "intent_declared"

    # Step 2 — agent calls a privileged tool; customer's graph
    # routes through authorize_action.
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    allowed = await handle.authorize_action("read", "Document::ledger")
    assert allowed is True

    # Step 3 — verify the APDP wire body carries declared intent.
    call_kwargs = plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs["intent"] == {
        "objective": "audit Q3 invoices and produce a summary",
        "category": "data_analysis",
    }, (
        "authorize_action after declare_intent MUST auto-inject the typed "
        "intent={'objective', 'category'} into the APDP request "
        "body — that is the wire shape the Cedar projection "
        "stamps as provenance=declared, clearing the greenfield-"
        "Custodial gate."
    )


# ─── Extra coverage — mode override at the bind call site ────────────


@pytest.mark.asyncio
async def test_call_site_mode_override_wins_over_plugin_default(
    brownfield_handle,
):
    """The ``mode=`` kwarg on :meth:`RunHandle.bind_tools` overrides
    the plugin-level default. This is the per-invocation knob for
    operators piloting greenfield on a single workflow without
    flipping the deployment-wide default.
    """
    _plugin, handle = brownfield_handle
    model = _StubChatModel()

    # Plugin default is brownfield; override at call site.
    handle.bind_tools(model, _customer_tools(), mode="greenfield")
    names = _names(model.last_bound_tools or [])
    assert DECLARE_INTENT_TOOL_NAME in names


@pytest.mark.asyncio
async def test_bind_tools_with_no_customer_tools_still_injects_synthetic(
    greenfield_handle,
):
    """Greenfield-only path: customer passes no tools (e.g., a
    declare-intent-then-route demo). The synthetic tool is still
    bound so the agent has a satisfaction path for the Cedar gate.
    """
    _plugin, handle = greenfield_handle
    model = _StubChatModel()

    handle.bind_tools(model, customer_tools=None)
    names = _names(model.last_bound_tools or [])
    assert names == [DECLARE_INTENT_TOOL_NAME]


@pytest.mark.asyncio
async def test_bind_tools_with_no_customer_tools_brownfield_is_passthrough(
    brownfield_handle,
):
    """Brownfield + no customer tools = nothing to bind. The model is
    returned unchanged so chat models that reject ``bind_tools([])``
    aren't invoked with an empty list.
    """
    _plugin, handle = brownfield_handle
    model = _StubChatModel()

    result = handle.bind_tools(model, customer_tools=None)
    assert model.last_bound_tools is None
    assert result is model


@pytest.mark.asyncio
async def test_bind_tools_forwards_bind_kwargs(greenfield_handle):
    """Customer-side knobs like ``tool_choice`` flow through to
    ``model.bind_tools(**kwargs)`` untouched.
    """
    _plugin, handle = greenfield_handle
    model = _StubChatModel()

    handle.bind_tools(
        model,
        _customer_tools(),
        tool_choice="auto",
        parallel_tool_calls=True,
    )
    assert model.last_bind_kwargs == {
        "tool_choice": "auto",
        "parallel_tool_calls": True,
    }


# ─── Typed intent (wl-apdp requires objective AND category) ──────────


def _synthetic_tool(plugin, handle):
    model = _StubChatModel()
    handle.bind_tools(model, _customer_tools())
    return next(
        t for t in (model.last_bound_tools or [])
        if getattr(t, "name", None) == DECLARE_INTENT_TOOL_NAME
    )


def test_synthetic_tool_schema_requires_category(greenfield_handle):
    plugin, handle = greenfield_handle
    schema = _synthetic_tool(plugin, handle).args_schema.model_json_schema()
    assert set(schema["required"]) == {"objective", "category"}


@pytest.mark.asyncio
@pytest.mark.parametrize("category", ["not-a-category", "", "custom:"])
async def test_declare_without_a_valid_category_is_rejected_and_sends_no_intent(
    greenfield_handle, category
):
    plugin, handle = greenfield_handle
    response = _synthetic_tool(plugin, handle).invoke(
        {"objective": "audit Q3 invoices", "category": category}
    )
    assert response["status"] == "rejected"
    assert handle.declared_intent_provenance is None
    await handle.authorize_action("read", "Document::ledger")
    # wl-apdp answers a category-less intent with 422: none is sent.
    assert plugin.apdp.authorize.call_args.kwargs["intent"] is None


@pytest.mark.asyncio
async def test_declared_custom_category_reaches_the_wire_typed(greenfield_handle):
    plugin, handle = greenfield_handle
    _synthetic_tool(plugin, handle).invoke(
        {"objective": "triage the queue", "category": "custom:triage"}
    )
    await handle.authorize_action("read", "Document::ledger")
    assert plugin.apdp.authorize.call_args.kwargs["intent"] == {
        "objective": "triage the queue",
        "category": {"custom": "triage"},
    }


def test_the_justification_is_optional_in_the_tool_schema(greenfield_handle):
    plugin, handle = greenfield_handle
    schema = _synthetic_tool(plugin, handle).args_schema.model_json_schema()
    assert "justification" in schema["properties"]
    assert "justification" not in schema["required"]


@pytest.mark.asyncio
async def test_a_declared_justification_reaches_the_wire(greenfield_handle):
    plugin, handle = greenfield_handle
    _synthetic_tool(plugin, handle).invoke(
        {"objective": "pay invoice 7", "category": "financial_operation",
         "justification": "approved by finance"}
    )
    await handle.authorize_action("pay", "Invoice::7")
    assert plugin.apdp.authorize.call_args.kwargs["intent"] == {
        "objective": "pay invoice 7",
        "category": "financial_operation",
        "justification": "approved by finance",
    }
