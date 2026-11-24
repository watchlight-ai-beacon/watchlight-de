"""Propagation tests for the LangGraph ``spawn_subagent`` override.

The plugin's ``RunHandle.spawn_subagent`` is the customer-facing
surface that flows the canonical scope-attenuation kwargs through to
wl-apdp's ``/v1/spawn_subagent`` handler. The override was migrated
from the legacy ``delegation_scope`` dict to the canonical
``allowed_tools`` / ``allowed_resources`` / ``allowed_intents`` /
``max_depth`` / ``time_budget_seconds`` quintuple.

These tests lock the migration:

  1. Canonical kwargs marshal to the wire envelope correctly.
  2. Legacy ``delegation_scope`` emits ``DeprecationWarning`` and
     maps onto the canonical kwargs (``allowed_actions`` →
     ``allowed_tools``).
  3. Mixing legacy + canonical raises ``ValueError``.
  4. Tree-stamp telemetry + ``agent_spawn_observed`` events fire as
     before (regression guard for the override's plugin-specific
     plumbing — workflow root, depth, parent linkage).
"""

from __future__ import annotations

import asyncio

import warnings

import pytest

from watchlight_core_testing import MockApdpClient
from watchlight_langgraph import WatchlightLangGraphPlugin


# Canonical test UUIDs — the spawn handler enforces the wire
# shape, so synthetic non-UUID slugs no longer suffice.
_PARENT_UUID = "11111111-1111-4111-8111-aaaaaaaaaaaa"
_CHILD_UUID = "11111111-1111-4111-8111-bbbbbbbbbbbb"


@pytest.fixture
def plugin() -> WatchlightLangGraphPlugin:
    """Plugin instance whose APDP client is a :class:`MockApdpClient`
    with the parent + child slugs pre-registered."""
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = _PARENT_UUID
    plugin.apdp.known_agents["child-agent"] = _CHILD_UUID
    return plugin


# ─── 1. Canonical kwargs marshal to wire ──────────────────────────────


@pytest.mark.asyncio
async def test_m43_canonical_kwargs_marshal_to_requested_scope(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_parent",
        allowed_tools=["web_search", "summarize"],
        allowed_resources=["doc::*"],
        allowed_intents=["research"],
        max_depth=2,
        time_budget_seconds=300,
    )
    assert len(plugin.apdp.spawn_subagent_calls) == 1
    body = plugin.apdp.spawn_subagent_calls[0]
    scope = body["requested_scope"]
    assert scope["allowed_tools"] == ["web_search", "summarize"]
    assert scope["allowed_resources"] == [{"matcher": "doc::*"}]
    assert scope["allowed_intents"] == ["research"]
    assert scope["max_depth"] == 2
    assert scope["time_budget_seconds"] == 300


@pytest.mark.asyncio
async def test_fail_closed_when_no_scope_passed(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_parent",
    )
    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    # Fail-closed by design — every scope dimension is empty / zero,
    # so the sub-agent has zero privileges.
    assert scope["allowed_tools"] == []
    assert scope["allowed_resources"] == []
    assert scope["allowed_intents"] == []
    assert scope["max_depth"] == 0
    assert "time_budget_seconds" not in scope  # none named: inherits, never 0


# ─── 2. Legacy delegation_scope → canonical kwargs ────────────────────


@pytest.mark.asyncio
async def test_legacy_delegation_scope_emits_deprecation_warning_and_maps(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id="exec_parent",
            delegation_scope={
                "allowed_actions": ["web_search", "doc_read"],
                "allowed_intents": ["research"],
            },
        )

    deprecation = [
        w for w in caught if issubclass(w.category, DeprecationWarning)
    ]
    assert len(deprecation) == 1
    assert "delegation_scope" in str(deprecation[0].message)
    assert "canonical" in str(deprecation[0].message)

    # Field mapping — allowed_actions → allowed_tools; allowed_intents
    # passes through verbatim.
    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["allowed_tools"] == ["web_search", "doc_read"]
    assert scope["allowed_intents"] == ["research"]
    # ``max_depth`` / ``time_budget_seconds`` are NEVER inferred from
    # the legacy dict (on security grounds) — they default to
    # fail-closed zero.
    assert scope["max_depth"] == 0
    assert "time_budget_seconds" not in scope  # none named: inherits, never 0


@pytest.mark.asyncio
async def test_legacy_delegation_scope_missing_keys_fails_closed(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id="exec_parent",
            # Empty legacy dict — should map to all-empty scope.
            delegation_scope={},
        )
    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["allowed_tools"] == []
    assert scope["allowed_resources"] == []
    assert scope["allowed_intents"] == []


# ─── 3. Mixed use raises ValueError ───────────────────────────────────


@pytest.mark.asyncio
async def test_mixing_legacy_and_canonical_raises_value_error(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with pytest.raises(ValueError, match="delegation_scope.*deprecated"):
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id="exec_parent",
            allowed_tools=["web_search"],
            delegation_scope={"allowed_actions": ["doc_read"]},
        )


@pytest.mark.asyncio
async def test_mixing_legacy_with_max_depth_raises_value_error(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with pytest.raises(ValueError, match="delegation_scope.*deprecated"):
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id="exec_parent",
            max_depth=3,
            delegation_scope={"allowed_actions": ["doc_read"]},
        )


# ─── 4. Tree-stamp telemetry + audit events still fire ────────────────


@pytest.mark.asyncio
async def test_child_handle_inherits_tree_linkage(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    parent_handle.root_execution_id = "exec_root"

    # Execution-lineage integrity. The client-supplied
    # `parent_execution_id` / `child_execution_id` hints are now IGNORED —
    # the child's tree position is SERVER-derived. We pass them to prove
    # they no longer leak into the child's lineage.
    child_handle = await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_client_supplied_parent",
        child_execution_id="exec_client_supplied_child",
        allowed_tools=["web_search"],
    )
    # The child's parent-exec is the PARENT's OWN (server-verified)
    # execution_id — NOT the client-supplied hint.
    assert child_handle.parent_execution_id == parent_handle.execution_id
    assert child_handle.parent_execution_id != "exec_client_supplied_parent"
    assert child_handle.parent_agent_id == parent_handle.agent_uuid
    assert child_handle.delegation_depth == 1
    assert child_handle.root_execution_id == "exec_root"
    # The child adopts the SERVER-minted execution_id (not the client hint).
    assert child_handle.spawned_execution_id == child_handle.execution_id
    assert child_handle.execution_id.startswith("exec_")
    assert child_handle.execution_id != "exec_client_supplied_child"
    # The child carries its OWN per-run credential (from the mock spawn).
    assert child_handle.run is not None
    assert plugin.apdp.token_for(child_handle.run).startswith("sst_mock_child_")
    # Server-attested grant is carried through.
    assert child_handle.granted_scope is not None


@pytest.mark.asyncio
async def test_spawn_emits_child_started_not_agent_spawn_observed(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    """The LangGraph override no longer publishes
    ``agent_spawn_observed``: spawn attestation (with the server-validated
    granted scope) is emitted by wl-apdp's spawn handler when it
    processes the ``spawn_subagent`` round-trip, and the class is rejected
    at ``/v1/events`` ingest. The plugin's on-wire spawn signal is now the
    CHILD's own ``execution_started``, carrying the parent + root linkage."""
    parent_handle = await plugin.start_run("parent-agent")
    parent_handle.root_execution_id = "exec_root"
    await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_parent",
        child_execution_id="exec_child",
        allowed_tools=["web_search"],
        allowed_intents=["research"],
        max_depth=1,
        time_budget_seconds=120,
    )

    # No plugin-emitted spawn attestation.
    assert not [
        e
        for e in plugin.apdp.published_events
        if e.get("event_type") == "agent_spawn_observed"
    ]

    # The child's own execution_started IS emitted with parent linkage.
    child_started = [
        e
        for e in plugin.apdp.published_events
        if e.get("event_type") == "execution_started"
        and e.get("parent_execution_id") is not None
    ]
    assert len(child_started) == 1
    started = child_started[0]
    assert started["parent_execution_id"] == parent_handle.execution_id
    assert started["root_execution_id"] is not None


# ─── The child carries its OWN egress token ─────────────────────


@pytest.mark.asyncio
async def test_child_handle_carries_its_own_proxy_token(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    plugin.apdp.proxy_token_prefix = "pxt"
    parent_handle = await plugin.start_run("parent-agent")
    assert parent_handle.egress is not None
    # Live siblings each in their own task (two live siblings in
    # one context are refused).
    a = await asyncio.create_task(parent_handle.spawn_subagent(
        "child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, parent_execution_id="exec_parent"
    ))
    b = await asyncio.create_task(parent_handle.spawn_subagent(
        "child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, parent_execution_id="exec_parent"
    ))
    a_token = a.egress.proxy_authorization()
    b_token = b.egress.proxy_authorization()
    assert a_token == f"pxt_child_{a.run_handle_id}"
    assert b_token == f"pxt_child_{b.run_handle_id}"
    assert a_token != b_token, "siblings get distinct tokens"
    assert parent_handle.egress.proxy_authorization() not in (a_token, b_token)


@pytest.mark.asyncio
async def test_child_never_inherits_the_parent_proxy_token(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    # The server minted no child token: the child has none, never the
    # parent's.
    plugin.apdp.proxy_token_prefix = "pxt"
    parent_handle = await plugin.start_run("parent-agent")
    assert parent_handle.egress is not None
    plugin.apdp.proxy_token_prefix = None
    child = await parent_handle.spawn_subagent(
        "child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, parent_execution_id="exec_parent"
    )
    assert child.egress is None


# ─── The child is its own run ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_child_run_equal_to_the_parent_run_is_refused(plugin) -> None:
    """A backend that hands back the parent's own run for the child would
    let the child act, and emit lineage, as its parent: refused."""
    import uuid as _uuid

    from watchlight_core import GovernanceUnavailable

    parent_handle = await plugin.start_run("parent-agent")
    plugin.apdp.spawn_response_override = {
        "child_run_handle_id": str(_uuid.uuid4()),
        "granted_scope": {
            "allowed_tools": [],
            "allowed_resources": [],
            "allowed_intents": [],
            "max_depth": 0,
            "time_budget_seconds": 60,
            "depth": 1,
        },
        "child_session_token": "sst_child.sig",
        "child_run": parent_handle.run,
    }
    with pytest.raises(GovernanceUnavailable, match="parent's own run"):
        await parent_handle.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})


# ─── Child intent ─────────────────────────────────


@pytest.mark.asyncio
async def test_spawn_requires_child_intent(plugin: WatchlightLangGraphPlugin) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with pytest.raises(TypeError):
        await parent_handle.spawn_subagent("child-agent")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        await parent_handle.spawn_subagent("child-agent", child_intent=None)
    assert plugin.apdp.spawn_subagent_calls == []


@pytest.mark.asyncio
async def test_spawn_sends_child_intent_and_stamps_the_derived_intent(
    plugin: WatchlightLangGraphPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    child = await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Collect the Q3 filings"},
        allowed_intents=["research"],
    )
    body = plugin.apdp.spawn_subagent_calls[-1]
    assert body["child_intent"] == {"category": "research", "objective": "Collect the Q3 filings"}
    assert child.derived_intent["intent_category"] == "research"
    started = [
        e
        for e in plugin.apdp.published_events
        if e["event_type"] == "execution_started" and e["execution_id"] == child.execution_id
    ]
    assert started, "the child's execution_started must be emitted"
    payload = started[-1]["payload"]
    assert payload["intent_category"] == "research"
    assert payload["intent_objective"] == "Collect the Q3 filings"
    assert payload["intent_provenance"] == "plugin_derived"
