"""Regression: a single governed LangGraph run materialises exactly ONE
root execution — no orphaned duplicate.

Bug (operator-reported, live governed stack): an ALLOWED run showed the
root execution TWICE on the dashboard ``/lineage`` view — once as an
orphan carrying only the orchestrator node (root edge only), and once as
a second root carrying the orchestrator PLUS the rest of the lineage
(tool calls, sub-agents).

Root cause: two ``execution_started`` events landed under DIFFERENT
``execution_id``s for the same root run:

  (a) The SDK's ``BaseRunHandle.__aenter__`` emits ``execution_started``
      for ``handle.execution_id`` (id B), and every ``authorize_action``
      attaches its ``policy_decision_made`` to that same id.
  (b) ``RunHandle.callback_handler()`` defaulted its ``execution_id`` to
      a FRESH ``fresh_execution_id()`` (id A) — so the LangGraph callback
      stream's own ``execution_started`` + every ``tool_call_observed``
      landed under id A.

The Watchlight lineage service mints one ``lineage.executions`` row
per distinct ``execution_id``, so two root ids ⇒ two root rows ⇒ one
orphan.

Fix: ``callback_handler()`` defaults its ``execution_id`` to the handle's
OWN ``execution_id``, so (a) and (b) agree on ONE canonical root id.

These tests drive the REAL plugin lifecycle (``start_run`` → ``async
with`` → ``callback_handler`` → graph callbacks → ``authorize_action`` →
``flush``) against the shipped ``MockApdpClient``, which records every
published :class:`ExecutionEvent`. They FAIL on the pre-fix code (two
distinct root ids) and PASS after it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

import pytest

from watchlight_core_testing.conformance import check_single_correlated_execution_id
from watchlight_core_testing import ConformanceFailure, MockApdpClient
from watchlight_langgraph import WatchlightLangGraphPlugin

_ORCH_SLUG = "orchestrator"
_ORCH_UUID = "d0000000-0000-4000-8000-0000000000aa"


def _build_plugin() -> WatchlightLangGraphPlugin:
    plugin = WatchlightLangGraphPlugin(
        apdp_url="http://localhost:8081", tenant_id="acme"
    )
    apdp = MockApdpClient()
    apdp.known_agents[_ORCH_SLUG] = _ORCH_UUID
    apdp.default_decision = "Allow"
    plugin.apdp = apdp
    return plugin


def _started_ids(events: List[Dict[str, Any]]) -> List[str]:
    return [e["execution_id"] for e in events if e.get("event_type") == "execution_started"]


def _ids_for(events: List[Dict[str, Any]], event_type: str) -> Set[str]:
    return {e["execution_id"] for e in events if e.get("event_type") == event_type}


@pytest.mark.asyncio
async def test_single_root_execution_id_no_orphan_async():
    """Full ALLOWED run (async callback handler): exactly one distinct
    ``execution_started`` id, equal to ``handle.execution_id``, and every
    ``tool_call_observed`` shares it — no orphaned second root."""
    plugin = _build_plugin()
    apdp: MockApdpClient = plugin.apdp

    async with await plugin.start_run(agent_slug=_ORCH_SLUG) as handle:
        root_id = handle.execution_id  # the SDK's canonical root

        # No explicit execution_id → defaults to handle.execution_id.
        callback = handle.callback_handler(async_handler=True)
        assert callback._execution_id == root_id

        # The top-level chain starts (root; parent_run_id=None → the
        # translator emits execution_started), then a governed tool runs.
        await callback.on_chain_start(
            serialized={"name": "orchestrator"},
            inputs={"input": "quarterly filings"},
            run_id="root",
            parent_run_id=None,
        )
        await callback.on_tool_start(
            serialized={"name": "web_search"},
            input_str="Q3 filings",
            run_id="t1",
            parent_run_id="root",
        )
        await callback.on_tool_end(
            output="ok", run_id="t1", parent_run_id="root", name="web_search"
        )

        # The authoritative Cedar gate — attaches policy_decision_made to
        # the handle's own execution_id (the defensive execution_started
        # mint is idempotent for the id __aenter__ already emitted).
        assert await handle.authorize_action("read", "tool/web_search") is True

        await callback.flush()

    events = apdp.published_events

    # ── The load-bearing invariant: ONE root execution id. ───────────
    started = _started_ids(events)
    distinct_started = set(started)
    assert distinct_started == {root_id}, (
        "expected exactly one root execution_started id (the handle's own "
        f"execution_id={root_id!r}); got distinct ids {distinct_started!r}. "
        "A divergent callback id would materialise a second, orphaned "
        "root row in wl-execution-graph."
    )

    # Every tool observation attaches to that same single root id.
    assert _ids_for(events, "tool_call_observed") <= {root_id}
    assert _ids_for(events, "tool_call_observed"), "no tool_call_observed emitted"

    # The lifecycle terminal (from the async-with exit) is on the same id.
    assert _ids_for(events, "execution_completed") <= {root_id}


@pytest.mark.asyncio
async def test_callback_handler_defaults_to_handle_execution_id():
    """The narrow contract: ``callback_handler()`` with no explicit
    execution_id binds to the handle's OWN canonical execution_id — the
    single change that keeps the framework's execution_started, the SDK's,
    and every tool_call_observed on one root."""
    plugin = _build_plugin()
    async with await plugin.start_run(agent_slug=_ORCH_SLUG) as handle:
        default_handler = handle.callback_handler()
        assert default_handler._execution_id == handle.execution_id

        # An explicit id is still honoured (e.g. a sub-agent's own id —
        # an intentionally distinct execution).
        explicit = handle.callback_handler(execution_id="exec_child-001")
        assert explicit._execution_id == "exec_child-001"


# ─── One correlated execution_id across a spawn tree ──────────────────
#
# Earlier tests proved the ROOT is single. These extend the guarantee to
# the sub-agent lane (the execution-id correlation contract): a spawned
# sub-agent is its OWN execution (distinct id) but its whole spawn tree
# groups under the orchestrator's single root_execution_id, and the
# single-correlated-execution-id conformance check fails loudly on any
# divergent root.

_CHILD_SLUG = "researcher"
_CHILD_UUID = "d0000000-0000-4000-8000-0000000000bb"


def _build_plugin_with_child() -> WatchlightLangGraphPlugin:
    plugin = _build_plugin()
    plugin.apdp.known_agents[_CHILD_SLUG] = _CHILD_UUID
    return plugin


@pytest.mark.asyncio
async def test_spawn_tree_shares_one_root_execution_id():
    """A governed run that spawns a sub-agent yields exactly ONE root
    execution_started id (the orchestrator's) and the sub-agent's
    execution_started carries root_execution_id == that single root — the
    whole tree correlates under one root."""
    plugin = _build_plugin_with_child()
    apdp: MockApdpClient = plugin.apdp

    async with await plugin.start_run(agent_slug=_ORCH_SLUG) as handle:
        root_id = handle.execution_id
        handle.root_execution_id = root_id

        child = await handle.spawn_subagent(
            _CHILD_SLUG,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id=root_id,
            allowed_tools=["web_search"],
            allowed_resources=[],
            allowed_intents=["research"],
            max_depth=0,
            time_budget_seconds=300,
        )
        # The child is its OWN execution, distinct from the root.
        assert child.execution_id != root_id
        # …but rooted at the orchestrator's single root.
        assert child.root_execution_id == root_id
        await child.complete()

    events = apdp.published_events

    # Exactly one ROOT execution_started (no parent_execution_id).
    root_started = [
        e
        for e in events
        if e.get("event_type") == "execution_started"
        and not e.get("parent_execution_id")
    ]
    root_ids = {e["execution_id"] for e in root_started}
    assert root_ids == {root_id}, (
        f"expected one root execution id {root_id!r}; got {root_ids!r}"
    )

    # The sub-agent's execution_started is a distinct id rooted at root_id.
    child_started = [
        e
        for e in events
        if e.get("event_type") == "execution_started"
        and e.get("parent_execution_id")
    ]
    assert child_started, "no sub-agent execution_started emitted"
    for e in child_started:
        assert e["execution_id"] != root_id
        assert e.get("root_execution_id") == root_id, (
            "sub-agent execution_started must carry the orchestrator's "
            f"root_execution_id ({root_id!r}); got "
            f"{e.get('root_execution_id')!r}"
        )

    # The single-correlated-execution-id conformance check passes on the
    # real stream.
    check_single_correlated_execution_id(events)


def test_invariant15_passes_on_correlated_stream():
    """The invariant is satisfied by a well-formed root + sub-agent."""
    root = "exec_root"
    child = "exec_child"
    events = [
        {"event_type": "execution_started", "execution_id": root},
        {
            "event_type": "execution_started",
            "execution_id": child,
            "parent_execution_id": root,
            "root_execution_id": root,
        },
        {"event_type": "tool_call_observed", "execution_id": root},
    ]
    # No raise.
    check_single_correlated_execution_id(events)


def test_invariant15_fails_on_divergent_roots():
    """Two ROOT execution_started ids for one run = the orphaned-root
    bug — the invariant must fail loudly."""
    events = [
        {"event_type": "execution_started", "execution_id": "exec_A"},
        {"event_type": "execution_started", "execution_id": "exec_B"},
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_single_correlated_execution_id(events)
    assert excinfo.value.args[0] == 15
    assert "divergent" in excinfo.value.args[1].lower()


def test_invariant15_fails_on_broken_subagent_root_linkage():
    """A sub-agent whose root_execution_id points away from the run's
    single root breaks correlation — the invariant must fail."""
    events = [
        {"event_type": "execution_started", "execution_id": "exec_root"},
        {
            "event_type": "execution_started",
            "execution_id": "exec_child",
            "parent_execution_id": "exec_root",
            # WRONG: should be exec_root.
            "root_execution_id": "exec_child",
        },
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_single_correlated_execution_id(events)
    assert excinfo.value.args[0] == 15
