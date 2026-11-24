"""Sub-agent lineage continuity regression test.

Locks in the ADK plugin's lineage stitching for nested
`before_agent_callback` invocations (sub-agent transfer / sub-agent
chaining).

When ADK fires `before_agent_callback` for a sub-agent while the
root's run is still in flight, the plugin MUST:

  - Push the root's lifecycle context onto `_lineage_stack`.
  - Set the sub-agent's `parent_execution_id` to the root's
    `execution_id`.
  - Keep `root_execution_id` pinned at the outermost run's id so
    every event in the tree shares the same root.

Without this the sub-agent's lineage events would orphan in
`/lineage` — the dashboard's recursive CTE would walk only the
sub-agent's subtree from a separate "root", and the operator-
visible delegation chain would diverge from the actual call graph.

This is the lineage half of correct sub-agent governance. The
authorization-attribution half (`before_tool_callback` reading the
calling-agent identity from `tool_context`) is tracked separately
because it requires upstream introspection.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_adk.plugin import WatchlightPlugin
from .conftest import stand_in_session, stand_in_spawn, token_of
from ._contexts import non_live_context

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")


# In-process stand-in for unit tests only.
class _StubApdp:
    """Mock ApdpClient that pre-resolves every slug + always trusts.

    Supports the governed ``spawn_subagent`` chokepoint:
    every nested ADK sub-agent transfer now routes its spawn through
    ``POST /v1/spawn_subagent`` rather than opening an independent root
    session, so the mock server-mints a distinct child ``execution_id`` +
    per-child ``sst_`` and grants the requested scope.
    """

    def __init__(self):
        self.published_batches: List[List[Dict[str, Any]]] = []
        self.spawn_requests: List[Dict[str, Any]] = []
        self._spawn_seq = 0
        self.resolved: Dict[str, str] = {
            # Registered slugs, as wl-registry mints them. The plugin
            # asks for the CONFIGURED slug, never one built from
            # ``agent.name``.
            "agent-root-agent": "00000000-0000-0000-0000-000000000001",
            "agent-sub-agent-a": "00000000-0000-0000-0000-0000000000a1",
            "agent-sub-sub-agent-b": "00000000-0000-0000-0000-0000000000b1",
        }

        async def _resolve_agent(slug):
            uuid_ = self.resolved.get(slug)
            return {"id": uuid_} if uuid_ else None

        async def _check_trust(_aid):
            return {"trusted": True, "reason": ""}

        async def _create_session(**_kwargs):
            # Root session carries a per-run token + a server-minted
            # execution id, matching the lineage identity-binding wire shape.
            return stand_in_session(
                "sess_root", "sst_root", execution_id="exec_server_root"
            )

        async def _get_manifest(_aid, **_kw):
            return {}

        async def _publish_events(run, events):
            session_token = token_of(run)
            self.published_batches.append(list(events))
            return True

        async def _spawn_subagent(parent, body):
            self.spawn_requests.append(body)
            self._spawn_seq += 1
            n = self._spawn_seq
            child_rh = f"00000000-0000-0000-0000-0000000000{n:02d}"
            return stand_in_spawn({
                "child_run_handle_id": child_rh,
                "granted_scope": {
                    "allowed_tools": list(
                        (body.get("requested_scope") or {}).get("allowed_tools")
                        or []
                    ),
                    "allowed_resources": [],
                    "allowed_intents": [],
                    "max_depth": 3,
                    "time_budget_seconds": 0,
                },
                "child_execution_id": f"exec_server_child_{n}",
                "root_execution_id": "exec_server_root",
                "child_session_id": f"ses_{child_rh}",
                "child_session_token": f"sst_child_{n}",
            })

        self.resolve_agent = AsyncMock(side_effect=_resolve_agent)
        self.check_agent_trust = AsyncMock(side_effect=_check_trust)
        self.create_session = AsyncMock(side_effect=_create_session)
        self.get_manifest = AsyncMock(side_effect=_get_manifest)
        self.publish_events = AsyncMock(side_effect=_publish_events)
        self.spawn_subagent = AsyncMock(side_effect=_spawn_subagent)
        self.complete_session = AsyncMock(return_value=True)


def _make_plugin() -> tuple[WatchlightPlugin, _StubApdp]:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-root-agent",
        root_agent_name="root_agent",
        subagent_slugs={
            "sub_agent_a": "agent-sub-agent-a",
            "sub_sub_agent_b": "agent-sub-sub-agent-b",
        },
    )
    apdp = _StubApdp()
    # Inject the stub. The plugin's __init__ already constructed an
    # ApdpClient; replace it with our spy. lineage.connect is a no-op
    # but we also point its publish path at the stub.
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin, apdp


def _agent(name: str) -> Any:
    a = MagicMock()
    a.name = name
    a.tools = []
    return a


def _flat_events(apdp: _StubApdp) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for batch in apdp.published_batches:
        out.extend(batch)
    return out


@pytest.mark.asyncio
async def test_lineage_stack_pushes_parent_on_nested_before_agent_callback():
    """When `before_agent_callback` fires for a sub-agent while the
    root is still active, the plugin captures the root's
    execution_id as the sub-agent's parent_execution_id and pins
    root_execution_id to the root's id.
    """
    plugin, _apdp = _make_plugin()

    # Step 1: root agent's before_agent_callback opens the outer run.
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec_id = plugin._current_execution_id
    root_agent_id = plugin._current_agent_id
    assert plugin._root_execution_id == root_exec_id
    assert plugin._current_parent_execution_id is None
    assert len(plugin._lineage_stack) == 0

    # Step 2: sub-agent's before_agent_callback fires WITHOUT root's
    # after_agent_callback having run (nested). The plugin must push
    # the root's context and set parent_execution_id = root_exec_id.
    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    sub_exec_id = plugin._current_execution_id
    assert plugin._current_parent_execution_id == root_exec_id
    # Root stays pinned through the whole tree.
    assert plugin._root_execution_id == root_exec_id
    # Sub-agent's execution_id is distinct from the root's.
    assert sub_exec_id != root_exec_id
    # Stack now holds the root's saved context.
    assert len(plugin._lineage_stack) == 1
    saved = plugin._lineage_stack[0]
    assert saved._current_execution_id == root_exec_id
    assert saved._current_agent_id == root_agent_id


@pytest.mark.asyncio
async def test_lineage_stack_pops_on_after_agent_callback():
    """`after_agent_callback` restores the parent's context so any
    events the parent emits AFTER the sub-agent returns are
    attributed to the parent again.
    """
    plugin, _apdp = _make_plugin()
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec_id = plugin._current_execution_id

    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    sub_exec_id = plugin._current_execution_id
    assert plugin._current_parent_execution_id == root_exec_id

    # Sub-agent finishes — restore the root's context.
    await plugin.after_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    assert plugin._current_execution_id == root_exec_id
    assert plugin._current_parent_execution_id is None
    assert plugin._root_execution_id == root_exec_id
    assert len(plugin._lineage_stack) == 0

    # Root finishes — reset for the next top-level run.
    await plugin.after_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    assert plugin._current_execution_id == ""
    assert plugin._root_execution_id == ""

    # Sanity: the sub-agent's id never leaked into the saved root.
    assert sub_exec_id != root_exec_id


@pytest.mark.asyncio
async def test_emitted_events_carry_root_and_parent_at_depth_two():
    """Three-level chain: root → A → B. Every event B emits MUST
    carry `root_execution_id == root.execution_id` and
    `parent_execution_id == A.execution_id`. This is the linkage
    `/lineage` needs to stitch the full delegation tree.
    """
    plugin, apdp = _make_plugin()

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec_id = plugin._current_execution_id

    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    sub_exec_id = plugin._current_execution_id

    # Grandchild B fires before A returns.
    await plugin.before_agent_callback(
        agent=_agent("sub_sub_agent_b"), callback_context=non_live_context()
    )
    grandchild_exec_id = plugin._current_execution_id

    assert plugin._current_parent_execution_id == sub_exec_id
    assert plugin._root_execution_id == root_exec_id
    assert grandchild_exec_id != root_exec_id
    assert grandchild_exec_id != sub_exec_id

    # Flush so the captures translate to canonical envelopes.
    await plugin.lineage.flush()
    events = _flat_events(apdp)

    # Filter to the grandchild's events.
    grandchild_events = [
        e for e in events if e.get("execution_id") == grandchild_exec_id
    ]
    assert len(grandchild_events) >= 1, "expected execution_started for grandchild"
    for e in grandchild_events:
        # CRITICAL: root_execution_id stays pinned at the original
        # root — NOT at A. wl-execution-graph's recursive tree query
        # walks the full tree from this root row.
        assert (
            e.get("root_execution_id") == root_exec_id
        ), f"grandchild event {e.get('event_type')} root mismatch: {e.get('root_execution_id')}"
        # Parent is the direct spawner — sub-agent A.
        assert (
            e.get("parent_execution_id") == sub_exec_id
        ), f"grandchild event {e.get('event_type')} parent mismatch: {e.get('parent_execution_id')}"


@pytest.mark.asyncio
async def test_execution_started_depth_reflects_spawn_tree_nesting():
    """Regression for the SUB-AGENT · DEPTH 0 dashboard bug.

    ADK fires ``before_agent_callback`` for the root AND every nested
    sub-agent transfer. The emitted ``execution_started`` payload MUST
    carry the real spawn-tree depth (root 0, child 1, grandchild 2) —
    ``len(_lineage_stack)`` at emit time — never the old hardcoded 0.
    wl-execution-graph stores ``payload.depth`` verbatim, so a wrong
    literal here renders every sub-agent as DEPTH 0 on ``/lineage``.
    """
    plugin, apdp = _make_plugin()

    # root → A → B, each nested before the previous returns.
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec_id = plugin._current_execution_id

    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    sub_exec_id = plugin._current_execution_id

    await plugin.before_agent_callback(
        agent=_agent("sub_sub_agent_b"), callback_context=non_live_context()
    )
    grandchild_exec_id = plugin._current_execution_id

    await plugin.lineage.flush()
    events = _flat_events(apdp)

    def _started_depth(exec_id: str) -> int:
        started = [
            e
            for e in events
            if e.get("execution_id") == exec_id
            and e.get("event_type") == "execution_started"
        ]
        assert len(started) == 1, f"expected one execution_started for {exec_id}"
        return int(started[0]["payload"]["depth"])

    # Root is 0 by definition; each nesting level is +1.
    assert _started_depth(root_exec_id) == 0
    assert _started_depth(sub_exec_id) == 1
    assert _started_depth(grandchild_exec_id) == 2


@pytest.mark.asyncio
async def test_top_level_event_has_root_eq_self_and_no_parent():
    """Outermost run's events should carry
    `root_execution_id == execution_id` and no
    `parent_execution_id`. The normalizer in `wl-execution-graph`
    already back-fills the root field, but the plugin emits it
    explicitly so the contract is honest at the source.
    """
    plugin, apdp = _make_plugin()

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec_id = plugin._current_execution_id

    await plugin.lineage.flush()
    events = _flat_events(apdp)
    root_events = [e for e in events if e.get("execution_id") == root_exec_id]
    assert len(root_events) >= 1
    for e in root_events:
        assert e.get("root_execution_id") == root_exec_id
        # parent_execution_id absent for the outermost root.
        assert "parent_execution_id" not in e or e["parent_execution_id"] is None
