"""The ``task`` tool spawns an ATTENUATED child handle, strict-subset
gated server-side; a non-subset request is denied and no child runs."""

from __future__ import annotations

from conftest import (
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)


async def test_task_spawns_subagent_with_attenuated_scope(plugin, mock_apdp):
    scopes = {
        "researcher": {
            "allowed_tools": ["deepagents://tool/search"],
            "allowed_intents": ["research"],
            "max_depth": 0,
            "time_budget_seconds": 300,
        }
    }
    mw = make_root_middleware(plugin, subagent_scopes=scopes)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request(
        "task",
        {"description": "dig into filings", "subagent_type": "researcher"},
        state=state,
    )
    result = await mw.awrap_tool_call(req, handler)

    # The child graph ran (handler invoked) after a successful spawn.
    assert handler.ran is True
    assert result == "HANDLER_RAN"

    # spawn_subagent round-tripped to APDP with the ATTENUATED scope.
    assert len(mock_apdp.spawn_subagent_calls) == 1
    body = mock_apdp.spawn_subagent_calls[0]
    requested = body["requested_scope"]
    assert requested["allowed_tools"] == ["deepagents://tool/search"]
    assert requested["allowed_intents"] == ["research"]
    assert requested["max_depth"] == 0

    # The plugin no longer emits ``agent_spawn_observed``; spawn
    # attestation (with the server-validated granted scope) is emitted by
    # wl-apdp's ``spawn_handler`` as it processes the ``spawn_subagent``
    # round-trip asserted above, and the class is rejected at
    # ``/v1/events`` ingest. The plugin's on-wire signal for the spawn is
    # the CHILD's own ``execution_started``.
    assert not [
        e
        for e in mock_apdp.published_events
        if e["event_type"] == "agent_spawn_observed"
    ]
    child_started = [
        e
        for e in mock_apdp.published_events
        if e["event_type"] == "execution_started"
        and e.get("parent_execution_id") is not None
    ]
    assert child_started, "child execution_started must still be emitted"
    assert child_started[-1]["metadata"]["source"] == "deepagents.spawn"


async def test_unmapped_subagent_gets_zero_privilege_child(plugin, mock_apdp):
    """A subagent with NO scope entry is spawned fail-closed
    (zero-privilege): empty allowed_tools + max_depth 0."""
    mw = make_root_middleware(plugin)  # no subagent_scopes
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request("task", {"subagent_type": "researcher"}, state=state)
    await mw.awrap_tool_call(req, handler)

    body = mock_apdp.spawn_subagent_calls[0]
    requested = body["requested_scope"]
    assert requested["allowed_tools"] == []
    assert requested["max_depth"] == 0


async def test_non_subset_scope_is_denied_no_child_runs(plugin, mock_apdp):
    from langchain_core.messages import ToolMessage
    from watchlight_core import ScopeAttenuationDenied

    mock_apdp.spawn_error_override = ScopeAttenuationDenied(
        "requested allowed_tools not a subset of parent"
    )
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request(
        "task", {"subagent_type": "researcher"}, state=state, tool_call_id="c_x"
    )
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False, "no child graph runs on a denied spawn"
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert "more than the parent can give" in result.content


async def test_task_missing_subagent_type_fails_closed(plugin, mock_apdp):
    from langchain_core.messages import ToolMessage

    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request("task", {}, state=state)
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False
    assert isinstance(result, ToolMessage)
    assert not mock_apdp.spawn_subagent_calls


async def test_task_spawn_declares_the_child_intent_from_the_task(plugin, mock_apdp):
    """Every spawn declares the child's intent. The
    objective is the ``task`` tool's description; a scope that pins one
    intent names the category (wl-apdp requires allowed_intents to be
    empty or exactly that category)."""
    scopes = {"researcher": {"allowed_intents": ["research"], "max_depth": 0}}
    mw = make_root_middleware(plugin, subagent_scopes=scopes)
    state = await start_root(mw)
    req = make_tool_call_request(
        "task",
        {"description": "dig into filings", "subagent_type": "researcher"},
        state=state,
    )
    await mw.awrap_tool_call(req, RecordingHandler())
    body = mock_apdp.spawn_subagent_calls[0]
    assert body["child_intent"] == {"category": "research", "objective": "dig into filings"}
    assert body["requested_scope"]["allowed_intents"] == ["research"]


async def test_task_spawn_without_description_uses_configured_category(plugin, mock_apdp):
    plugin.child_intent_category = "data_analysis"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    req = make_tool_call_request("task", {"subagent_type": "researcher"}, state=state)
    await mw.awrap_tool_call(req, RecordingHandler())
    sent = mock_apdp.spawn_subagent_calls[0]["child_intent"]
    assert sent["category"] == "data_analysis"
    assert sent["objective"] == "deepagents task for researcher"
