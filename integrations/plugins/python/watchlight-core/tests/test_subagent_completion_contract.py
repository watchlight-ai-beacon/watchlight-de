"""A sub-agent's ``execution_completed`` must survive the wire.

The defect this file locks: the LangGraph and Pydantic-AI spawn helpers
put ``depth`` and ``spawned_by_agent_id`` on the ``execution_completed``
payload. ``wl_lineage::events::ExecutionCompletedPayload`` models
neither, and the Rust payload structs do not set
``deny_unknown_fields`` — so serde ACCEPTED the event and dropped both
keys on the floor. Nothing was rejected, nothing was logged, and the
dashboard timeline's "sub-agent completed: X · depth N · spawned by Y"
branch read two fields that had never once arrived.

Both facts already have a canonical home, so the fix is to use it:

  * the spawner rides the ENVELOPE's ``parent_agent_id`` — the field
    ``EventEnvelope`` models for exactly this, which ``BaseRunHandle``
    already stamps on every event a spawned agent emits and which the
    lineage signature covers;
  * the depth is computed SERVER-side by wl-execution-graph from the
    child's ``execution_started`` and its position in the tree, and
    served on ``lineage.executions.depth``.

The dashboard's timeline view pins the same contract with the event
asserted here. Change one, change both.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

pytest.importorskip(
    "watchlight_langgraph",
    reason="this contract covers the LangGraph spawn emitter",
)
pytest.importorskip(
    "watchlight_pydantic_ai",
    reason="this contract covers the Pydantic-AI spawn emitter",
)

from watchlight_core.events_schema import (  # noqa: E402
    ExecutionCompletedPayload,
    unknown_payload_keys,
)
from watchlight_core_testing import (  # noqa: E402
    ConformanceFailure,
    MockApdpClient,
    assert_canonical_event,
)
from watchlight_langgraph import WatchlightLangGraphPlugin  # noqa: E402
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin  # noqa: E402


_PARENT_UUID = "11111111-1111-4111-8111-aaaaaaaaaaaa"
_CHILD_UUID = "11111111-1111-4111-8111-bbbbbbbbbbbb"

#: The only keys ``ExecutionCompletedPayload`` models that the spawn
#: helpers set. Anything else on the payload is dropped at ingest.
_EXPECTED_PAYLOAD_KEYS = {"duration_ms", "actions_taken", "actions_denied"}


def _make_plugin(cls: Any) -> Any:
    plugin = cls(apdp_url="http://localhost")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = _PARENT_UUID
    plugin.apdp.known_agents["child-agent"] = _CHILD_UUID
    return plugin


async def _spawn_and_complete(cls: Any) -> List[Dict[str, Any]]:
    """Run a real parent → sub-agent → complete cycle through the
    plugin and return every event it published."""
    plugin = _make_plugin(cls)
    parent = await plugin.start_run("parent-agent")
    child = await parent.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_parent",
        allowed_tools=["web_search"],
    )
    await child.complete()
    return list(plugin.apdp.published_events)


def _child_completion(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    matches = [
        e
        for e in events
        if e.get("event_type") == "execution_completed"
        and (e.get("metadata") or {}).get("kind") == "child_completed"
    ]
    assert matches, (
        "the spawn helper published no child execution_completed event; "
        f"published: {[e.get('event_type') for e in events]}"
    )
    return matches[0]


PLUGINS = [
    pytest.param(WatchlightLangGraphPlugin, id="langgraph"),
    pytest.param(WatchlightPydanticAIPlugin, id="pydantic-ai"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_cls", PLUGINS)
async def test_child_completion_payload_carries_no_key_the_server_drops(
    plugin_cls: Any,
) -> None:
    """The regression lock. ``depth`` and ``spawned_by_agent_id`` on
    this payload were discarded by serde; the payload must now carry
    only fields the canonical struct models."""
    event = _child_completion(await _spawn_and_complete(plugin_cls))
    payload = event["payload"]

    assert unknown_payload_keys("execution_completed", payload) == []
    assert set(payload) == _EXPECTED_PAYLOAD_KEYS
    assert "depth" not in payload
    assert "spawned_by_agent_id" not in payload


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_cls", PLUGINS)
async def test_child_completion_survives_the_canonical_model(
    plugin_cls: Any,
) -> None:
    """The payload deserializes into the pydantic mirror of the Rust
    struct wl-apdp decodes it as — with ``extra='forbid'``, so a key
    the server would silently drop fails here instead."""
    event = _child_completion(await _spawn_and_complete(plugin_cls))
    model = ExecutionCompletedPayload.model_validate(event["payload"])
    assert model.duration_ms >= 0
    assert model.actions_taken >= 0


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_cls", PLUGINS)
async def test_child_completion_names_its_spawner_on_the_envelope(
    plugin_cls: Any,
) -> None:
    """The fact the dropped payload key was trying to carry now rides
    ``parent_agent_id``, which the envelope models, the SDK already
    stamps elsewhere, and the lineage signature covers."""
    event = _child_completion(await _spawn_and_complete(plugin_cls))
    assert event.get("parent_agent_id") == _PARENT_UUID
    # And the tree linkage the dashboard falls back to is present too.
    assert event.get("parent_execution_id")
    assert event.get("root_execution_id")


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_cls", PLUGINS)
async def test_every_event_the_spawn_path_publishes_is_conformant(
    plugin_cls: Any,
) -> None:
    """Invariant 16 across the whole spawn path, not just the
    completion: no event published by a spawn may carry a payload key
    the server does not model."""
    for event in await _spawn_and_complete(plugin_cls):
        assert_canonical_event(event)


def test_invariant_16_rejects_completion_fields_outside_the_schema() -> None:
    """The other half of the contract. A check that silently accepted
    everything would look green forever, so pin that the exact payload
    the two plugins used to build is now a FAILURE — not a warning.
    Silent data loss on an audit record is not the lesser bug."""
    event = {
        "event_id": "evt_33333333-3333-4333-8333-333333333333",
        "event_type": "execution_completed",
        "timestamp": "2026-06-15T18:00:09Z",
        "execution_id": "exec_child",
        "agent_id": _CHILD_UUID,
        "metadata": {"source": "langgraph.spawn_subagent", "kind": "child_completed"},
        "payload": {
            "duration_ms": 140,
            "actions_taken": 2,
            "actions_denied": 1,
            "depth": 1,
            "spawned_by_agent_id": _PARENT_UUID,
        },
    }
    with pytest.raises(ConformanceFailure) as exc:
        assert_canonical_event(event)
    assert exc.value.args[0] == 16
    assert "depth" in exc.value.args[1]
    assert "spawned_by_agent_id" in exc.value.args[1]

    # Same event without the two dropped keys passes.
    del event["payload"]["depth"]
    del event["payload"]["spawned_by_agent_id"]
    assert_canonical_event(event)
