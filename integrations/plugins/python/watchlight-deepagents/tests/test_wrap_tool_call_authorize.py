"""``wrap_tool_call`` is the authoritative Cedar gate: allow runs the
tool, deny returns a ``ToolMessage`` error and the tool never runs."""

from __future__ import annotations

from conftest import (
    ROOT_UUID,
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)


async def test_allow_runs_the_tool(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request("search", {"q": "q3 filings"}, state=state)
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is True
    assert result == "HANDLER_RAN"
    # Authorized under the ROOT principal.
    assert mock_apdp.authorize_calls
    assert mock_apdp.authorize_calls[-1]["principal"] == f'Agent::"{ROOT_UUID}"'


async def test_deny_blocks_the_tool_and_returns_toolmessage(plugin, mock_apdp):
    from langchain_core.messages import ToolMessage

    mock_apdp.default_decision = "Deny"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request(
        "delete_records", {"id": 5}, state=state, tool_call_id="call_deny"
    )
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False, "denied tool must NOT run"
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert result.tool_call_id == "call_deny"


async def test_needs_approval_pauses_without_running_tool(plugin, mock_apdp):
    from langchain_core.messages import ToolMessage

    mock_apdp.default_decision = "needs_approval"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request("wire_funds", {"amt": 100}, state=state)
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False
    assert isinstance(result, ToolMessage)
    assert result.status == "error"


async def test_fs_tool_resource_uri_is_namespaced(plugin, mock_apdp):
    """Denied FS tool call still records the ``deepagents://`` URI on the
    emitted tool_call_observed event (conformance invariant 4)."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request("read_file", {"file_path": "notes.md"}, state=state)
    await mw.awrap_tool_call(req, handler)

    tool_events = [
        e for e in mock_apdp.published_events if e["event_type"] == "tool_call_observed"
    ]
    assert tool_events
    uri = tool_events[-1]["payload"]["tool"]["endpoint"]
    assert uri.startswith("deepagents://fs/")


async def test_deny_message_carries_no_server_reason(plugin, mock_apdp, monkeypatch):
    """Opaque deny: the model sees a generic refusal; the server's reason
    stays in its audit trail."""
    real = mock_apdp.authorize

    async def _deny_with_reason(*args, **kwargs):
        response = await real(*args, **kwargs)
        response.update({"decision": "Deny", "reason": "policy secret-policy-7 matched"})
        return response

    monkeypatch.setattr(mock_apdp, "authorize", _deny_with_reason)
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    req = make_tool_call_request("delete_records", {"id": 5}, state=state, tool_call_id="c1")
    result = await mw.awrap_tool_call(req, RecordingHandler())
    assert "secret-policy-7" not in str(result.content)
    assert "Denied by Watchlight policy" in str(result.content)
