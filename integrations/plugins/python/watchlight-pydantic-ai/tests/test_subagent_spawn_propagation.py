"""Propagation tests for the Pydantic AI ``spawn_subagent`` override.

Mirrors the LangGraph propagation suite at
``watchlight-langgraph/tests/test_subagent_spawn_propagation.py``.
Pydantic AI's auto-instrumentation calls ``spawn_subagent`` from
the runtime patch when a nested ``Agent.run`` is detected; the
plugin still exposes the explicit primitive for customers wiring
spawn declarations directly.
"""

from __future__ import annotations

import warnings

import pytest

from watchlight_core_testing import MockApdpClient
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin


_PARENT_UUID = "11111111-1111-4111-8111-aaaaaaaaaaaa"
_CHILD_UUID = "11111111-1111-4111-8111-bbbbbbbbbbbb"


@pytest.fixture
def plugin() -> WatchlightPydanticAIPlugin:
    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost", auto_instrument=False
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = _PARENT_UUID
    plugin.apdp.known_agents["child-agent"] = _CHILD_UUID
    return plugin


# ─── 1. Canonical scope kwargs marshal to wire ────────────────────────


@pytest.mark.asyncio
async def test_m43_canonical_kwargs_marshal_to_requested_scope(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
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
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    await parent_handle.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["allowed_tools"] == []
    assert scope["allowed_resources"] == []
    assert scope["allowed_intents"] == []
    assert scope["max_depth"] == 0
    # No budget named: none is sent (never 0); the child inherits the
    # parent's remaining time.
    assert "time_budget_seconds" not in scope


# ─── 2. Legacy delegation_scope → canonical kwargs ────────────────────


@pytest.mark.asyncio
async def test_legacy_delegation_scope_emits_deprecation_warning_and_maps(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
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
    assert "canonical scope kwargs" in str(deprecation[0].message)

    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["allowed_tools"] == ["web_search", "doc_read"]
    assert scope["allowed_intents"] == ["research"]
    assert scope["max_depth"] == 0
    # No budget named: none is sent (never 0); the child inherits the
    # parent's remaining time.
    assert "time_budget_seconds" not in scope


# ─── 3. Mixed use raises ValueError ───────────────────────────────────


@pytest.mark.asyncio
async def test_mixing_legacy_and_canonical_raises_value_error(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    with pytest.raises(ValueError, match="delegation_scope.*deprecated"):
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["web_search"],
            delegation_scope={"allowed_actions": ["doc_read"]},
        )


# ─── 4. Tree-stamp telemetry + audit events still fire ────────────────


@pytest.mark.asyncio
async def test_child_handle_inherits_tree_linkage(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    parent_handle = await plugin.start_run("parent-agent")
    parent_handle.root_execution_id = "exec_root"

    # Execution-lineage integrity. The client-supplied
    # `parent_execution_id` / `child_execution_id` hints are IGNORED — the
    # child's tree position is SERVER-derived.
    child_handle = await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_client_supplied_parent",
        child_execution_id="exec_client_supplied_child",
        allowed_tools=["web_search"],
    )
    # The child's parent-exec is the PARENT's OWN (server-verified) id.
    assert child_handle.parent_execution_id == parent_handle.execution_id
    assert child_handle.parent_execution_id != "exec_client_supplied_parent"
    assert child_handle.parent_agent_id == parent_handle.agent_uuid
    assert child_handle.delegation_depth == 1
    assert child_handle.root_execution_id == "exec_root"
    # The child adopts the SERVER-minted execution_id + its own credential.
    assert child_handle.spawned_execution_id == child_handle.execution_id
    assert child_handle.execution_id != "exec_client_supplied_child"
    assert child_handle.run is not None
    assert child_handle.run != parent_handle.run
    assert plugin.apdp.token_for(child_handle.run) != plugin.apdp.token_for(parent_handle.run)
    assert child_handle.granted_scope is not None


@pytest.mark.asyncio
async def test_spawn_emits_child_started_not_agent_spawn_observed(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    """The Pydantic AI override does not publish
    ``agent_spawn_observed``: spawn attestation (with the server-validated
    granted scope) is emitted by wl-apdp's ``spawn_handler`` when it
    processes the ``spawn_subagent`` round-trip, and the class is rejected
    at ``/v1/events`` ingest. The plugin's on-wire spawn signal is the
    CHILD's own ``execution_started``, carrying the parent + root linkage."""
    parent_handle = await plugin.start_run("parent-agent")
    parent_handle.root_execution_id = "exec_root"
    await parent_handle.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        parent_execution_id="exec_parent",
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
    assert child_started[0]["parent_execution_id"] == parent_handle.execution_id
    assert child_started[0]["root_execution_id"] is not None


# ─── The child carries its OWN egress token ─────────────────────


@pytest.mark.asyncio
async def test_child_handle_carries_its_own_proxy_token(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    plugin.apdp.proxy_token_prefix = "pxt"
    parent_handle = await plugin.start_run("parent-agent")
    assert parent_handle.egress is not None
    parent_token = parent_handle.egress.proxy_authorization()
    a = await parent_handle.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
    b = await parent_handle.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
    a_token = a.egress.proxy_authorization()
    b_token = b.egress.proxy_authorization()
    assert a_token == f"pxt_child_{a.run_handle_id}"
    assert b_token == f"pxt_child_{b.run_handle_id}"
    assert a_token != b_token, "siblings get distinct tokens"
    assert parent_token not in (a_token, b_token)


@pytest.mark.asyncio
async def test_child_never_inherits_the_parent_proxy_token(
    plugin: WatchlightPydanticAIPlugin,
) -> None:
    # The server minted no child token: the child has none, never the
    # parent's.
    plugin.apdp.proxy_token_prefix = "pxt"
    parent_handle = await plugin.start_run("parent-agent")
    assert parent_handle.egress is not None
    plugin.apdp.proxy_token_prefix = None
    child = await parent_handle.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
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


# ─── 4. Nested-agent default budget (auto-instrumentation) ─────────────


def test_nested_agent_default_budget_is_validated() -> None:
    for bad in (0, -1, 1.5, "60", True):
        with pytest.raises(ValueError):
            WatchlightPydanticAIPlugin(
                apdp_url="http://localhost",
                auto_instrument=False,
                nested_agent_time_budget_seconds=bad,
            )


def test_nested_agent_budget_is_absent_by_default_and_never_clamped() -> None:
    from types import SimpleNamespace

    from watchlight_pydantic_ai.instrumentation import _nested_time_budget

    unset = SimpleNamespace(nested_agent_time_budget_seconds=None)
    root_parent = SimpleNamespace(granted_scope=None)
    sub_parent = SimpleNamespace(granted_scope=SimpleNamespace(time_budget_seconds=90))
    # Unset: the nested agent names no budget and inherits.
    assert _nested_time_budget(unset, root_parent) is None
    assert _nested_time_budget(unset, sub_parent) is None
    tight = SimpleNamespace(nested_agent_time_budget_seconds=60)
    loose = SimpleNamespace(nested_agent_time_budget_seconds=600)
    # Sent exactly as configured, under a root or a sub-agent. A budget the
    # parent cannot give is refused by the governance backend, never
    # shortened here.
    assert _nested_time_budget(tight, root_parent) == 60
    assert _nested_time_budget(tight, sub_parent) == 60
    assert _nested_time_budget(loose, sub_parent) == 600


@pytest.mark.asyncio
async def test_auto_instrumented_nested_agent_sends_the_configured_default() -> None:
    from types import SimpleNamespace

    from watchlight_pydantic_ai import instrumentation

    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost",
        auto_instrument=False,
        nested_agent_time_budget_seconds=45,
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["planner"] = _PARENT_UUID
    plugin.apdp.known_agents["worker"] = _CHILD_UUID
    root, root_token = await instrumentation._open_handle_for_call(
        plugin, SimpleNamespace(name="planner")
    )
    try:
        child, child_token = await instrumentation._open_handle_for_call(
            plugin, SimpleNamespace(name="worker")
        )
        instrumentation._current_handle.reset(child_token)
    finally:
        instrumentation._current_handle.reset(root_token)
    scope = plugin.apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["time_budget_seconds"] == 45


@pytest.mark.asyncio
async def test_a_nested_budget_the_parent_cannot_give_is_refused_and_never_runs() -> None:
    """A configured nested budget is never shortened. A
    grandchild that names the same 60 s its parent was granted asks for more
    than the parent has left; the backend refuses the spawn with a typed
    ``time_budget`` violation (wl-apdp and the in-process engine alike, see
    watchlight-core's ``test_in_process_budget_refusal_parity.py``). The
    plugin sends the budget unchanged, surfaces the refusal, and the nested
    agent never runs."""
    from types import SimpleNamespace

    from watchlight_core.errors import ScopeAttenuationDenied, ScopeViolationDimension

    from watchlight_pydantic_ai import instrumentation

    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost",
        auto_instrument=False,
        nested_agent_time_budget_seconds=60,
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["planner"] = _PARENT_UUID
    plugin.apdp.known_agents["worker"] = _CHILD_UUID
    plugin.apdp.known_agents["helper"] = "11111111-1111-4111-8111-cccccccccccc"
    root, root_token = await instrumentation._open_handle_for_call(
        plugin, SimpleNamespace(name="planner")
    )
    try:
        child, child_token = await instrumentation._open_handle_for_call(
            plugin, SimpleNamespace(name="worker")
        )
        try:
            plugin.apdp.spawn_error_override = ScopeAttenuationDenied(
                "time_budget_seconds 60 exceeds the 59 seconds the parent has left",
                [ScopeViolationDimension.TIME_BUDGET_SECONDS],
            )
            with pytest.raises(ScopeAttenuationDenied) as exc:
                await instrumentation._open_handle_for_call(
                    plugin, SimpleNamespace(name="helper")
                )
            assert exc.value.violations == [ScopeViolationDimension.TIME_BUDGET_SECONDS]
            # Sent exactly as configured at both levels, never shortened.
            budgets = [
                c["requested_scope"]["time_budget_seconds"]
                for c in plugin.apdp.spawn_subagent_calls
            ]
            assert budgets == [60, 60]
            # The nested agent never ran: the current handle is still the
            # worker's.
            assert instrumentation._current_handle.get() is child
        finally:
            instrumentation._current_handle.reset(child_token)
    finally:
        instrumentation._current_handle.reset(root_token)
