"""Every event the plugin emits satisfies the seven conformance
invariants (envelope shape, source attribution, canonical type,
``deepagents://`` URI namespacing, ``evt_`` id, bounded sizes, closed
set) via ``watchlight_core_testing.assert_canonical_event``."""

from __future__ import annotations

from watchlight_core_testing import assert_canonical_event

from conftest import (
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)


async def test_all_emitted_events_are_canonical(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"
    scopes = {
        "researcher": {
            "allowed_tools": ["deepagents://tool/search"],
            "max_depth": 0,
        }
    }
    mw = make_root_middleware(plugin, subagent_scopes=scopes)
    state = await start_root(mw)

    # Emit a model observation, a tool_call_observed, and a spawn pair.
    from conftest import StubModelRequest

    await mw.awrap_model_call(StubModelRequest(state=state), RecordingHandler())
    await mw.awrap_tool_call(
        make_tool_call_request("read_file", {"file_path": "a.md"}, state=state),
        RecordingHandler(),
    )
    await mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=state),
        RecordingHandler(),
    )

    assert mock_apdp.published_events, "no events emitted"
    seen_types = set()
    for ev in mock_apdp.published_events:
        seen_types.add(ev["event_type"])
        # Every event must be canonical. Tool-bearing events additionally
        # carry the deepagents:// URI prefix.
        assert_canonical_event(ev, expected_uri_prefix="deepagents://")

    # We exercised each of these emitters.
    assert "api_request_observed" in seen_types
    assert "tool_call_observed" in seen_types
    assert "execution_started" in seen_types
    # The plugin no longer emits ``agent_spawn_observed``. Spawn
    # attestation is SERVER-emitted by wl-apdp's ``spawn_handler`` (the
    # class is rejected at ``/v1/events`` ingest). The ``task`` sub-agent
    # spawn now surfaces on the wire only as the child's own
    # ``execution_started`` (already asserted above).
    assert "agent_spawn_observed" not in seen_types
    assert "policy_decision_made" not in seen_types


async def test_source_tags_are_deepagents_namespaced(plugin, mock_apdp):
    mw = make_root_middleware(plugin, subagent_scopes={"researcher": {}})
    state = await start_root(mw)
    await mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=state),
        RecordingHandler(),
    )
    for ev in mock_apdp.published_events:
        source = ev.get("metadata", {}).get("source", "")
        assert source.startswith("deepagents"), f"non-namespaced source: {source!r}"
