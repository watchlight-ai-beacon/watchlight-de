"""Greenfield mode injects the synthetic ``watchlight.declare_intent``
tool via the middleware ``tools`` slot; its invocation bypasses the
authorize round-trip (the declare_intent carve-out) and stamps intent on
the handle.
Brownfield (the locked default) injects nothing."""

from __future__ import annotations

from watchlight_core import DECLARE_INTENT_TOOL_NAME

from conftest import (
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin


def test_brownfield_injects_no_synthetic_tool(plugin):
    plugin.intent_enforcement_mode = "brownfield"
    mw = make_root_middleware(plugin)
    assert mw.tools == []


def test_greenfield_injects_declare_intent_tool(mock_apdp):
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    mw = make_root_middleware(plugin)
    names = [t.name for t in mw.tools]
    assert DECLARE_INTENT_TOOL_NAME in names


async def test_declare_intent_call_bypasses_authorize(mock_apdp):
    """The declare_intent tool call short-circuits — it must NOT
    round-trip to authorize (would be denied before intent is declared)."""
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    # The real ToolCallRequest carries the invoked BaseTool instance; the
    # short-circuit keys on THAT instance identity.
    req = make_tool_call_request(
        DECLARE_INTENT_TOOL_NAME,
        {"objective": "research", "category": "research"},
        state=state,
        tool=mw.tools[0],
    )
    await mw.awrap_tool_call(req, handler)

    # The declare_intent handler ran (the tool executed) ...
    assert handler.ran is True
    # ... but NO authorize round-trip happened for it.
    assert mock_apdp.authorize_calls == []


async def test_synthetic_tool_stamps_intent_on_active_handle(mock_apdp):
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    mw = make_root_middleware(plugin)
    await start_root(mw)  # sets the active-handle contextvar

    tool = mw.tools[0]
    result = tool.func(objective="summarize the Q3 filings", category="research")
    assert result.get("status") == "intent_declared"

    from watchlight_deepagents.middleware import current_active_handle

    handle = current_active_handle()
    assert handle is not None
    assert handle.declared_intent_objective == "summarize the Q3 filings"


# ─── Typed intent (wl-apdp requires objective AND category) ──────────


async def _greenfield(mock_apdp):
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    return mw, state


async def _call_tool(mw, state):
    await mw.awrap_tool_call(
        make_tool_call_request("web_search", {"q": "x"}, state=state), RecordingHandler()
    )


def test_synthetic_tool_schema_requires_category(mock_apdp):
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    schema = make_root_middleware(plugin).tools[0].args_schema.model_json_schema()
    assert set(schema["required"]) == {"objective", "category"}


async def test_declare_without_a_valid_category_is_rejected_and_sends_no_intent(mock_apdp):
    mw, state = await _greenfield(mock_apdp)
    result = mw.tools[0].func(objective="summarize the Q3 filings", category="filings")
    assert result.get("status") == "rejected"
    await _call_tool(mw, state)
    # wl-apdp answers a category-less intent with 422: none is sent.
    assert mock_apdp.authorize_calls[-1]["intent"] is None


async def test_after_a_typed_declare_the_authorize_intent_is_typed(mock_apdp):
    mw, state = await _greenfield(mock_apdp)
    mw.tools[0].func(objective="summarize the Q3 filings", category="research")
    await _call_tool(mw, state)
    assert mock_apdp.authorize_calls[-1]["intent"] == {
        "objective": "summarize the Q3 filings",
        "category": "research",
    }
