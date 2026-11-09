"""Governed native-sub-agent spawn tests.

ADK's native sub-agent transfer used to open a FRESH, INDEPENDENT root
session per sub-agent — so children were neither correlated to the
parent's execution tree NOR attenuated against the parent's granted
scope. These tests lock in the fix: every nested
``before_agent_callback`` routes the child's creation through the
governed ``spawn_subagent`` chokepoint (``POST /v1/spawn_subagent``), so
wl-apdp server-attests the spawn + enforces strict-subset scope
attenuation, and the child's tool calls authorize under the child's OWN
server-minted ``run_handle_id`` + per-child ``sst_``.

Coverage:
  * a nested ``before_agent_callback`` fires a real ``spawn_subagent``
    with the child agent + derived-from-tool-list scope
  * ``before_tool_callback`` authorizes under the child ``run_handle_id``
    (in-scope Allow / out-of-scope Deny)
  * a DENIED spawn → the sub-agent never starts: ``before_agent_callback``
    short-circuits with an instructive refusal (no model turn, no tool
    call, no exception into ADK's orchestration)
  * ``after_agent_callback`` pops to the parent (registry ``on_stop``)
  * the child's lineage events carry the server-minted child
    ``execution_id`` and ride the per-child ``sst_``
  * a ``max_depth == 0`` parent cannot spawn a grandchild (denied)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.tools.base_tool import BaseTool

from watchlight_core import ScopeAttenuationDenied
from watchlight_adk.plugin import WatchlightPlugin
from .conftest import run_for, stand_in_session, stand_in_spawn, token_of
from ._contexts import non_live_context

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")

ROOT_UUID = "00000000-0000-0000-0000-000000000001"
SUB_A_UUID = "00000000-0000-0000-0000-0000000000a1"
SUB_B_UUID = "00000000-0000-0000-0000-0000000000b1"


class _SpawnApdp:
    """Mock ApdpClient exercising the governed ``spawn_subagent`` path.

    ``spawn_subagent`` server-mints a distinct child ``execution_id`` +
    per-child ``sst_`` and records the granted ``allowed_tools`` /
    ``max_depth`` per child ``run_handle_id``. ``authorize`` then simulates
    wl-apdp's ``check_subagent_scope``: a request carrying a child
    ``run_handle_id`` is Allowed only when the action verb is in that
    child's granted tool set.
    """

    def __init__(
        self,
        *,
        deny_child_uuids: Optional[set] = None,
        first_level_max_depth: int = 3,
        unregistered_slugs: Optional[set] = None,
        untrusted_uuids: Optional[set] = None,
    ) -> None:
        self.published: List[Dict[str, Any]] = []  # {"events":..., "token":...}
        self.spawn_bodies: List[Dict[str, Any]] = []
        self.authorize_calls: List[Dict[str, Any]] = []
        self._seq = 0
        self._granted_tools: Dict[str, set] = {}
        self._granted_depth: Dict[str, int] = {}
        self._deny = set(deny_child_uuids or set())
        self._first_level_max_depth = first_level_max_depth
        self._unregistered = set(unregistered_slugs or set())
        self._untrusted = set(untrusted_uuids or set())
        self.resolved = {
            # Registered slugs, as wl-registry mints them. The plugin
            # asks for the CONFIGURED slug, never one built from
            # ``agent.name``.
            "agent-root-agent": ROOT_UUID,
            "agent-sub-agent-a": SUB_A_UUID,
            "agent-sub-sub-agent-b": SUB_B_UUID,
        }

        async def _resolve_agent(slug):
            if slug in self._unregistered:
                return None
            uuid_ = self.resolved.get(slug)
            return {"id": uuid_} if uuid_ else None

        async def _check_trust(_aid):
            if _aid in self._untrusted:
                return {"trusted": False, "reason": "flagged for review"}
            return {"trusted": True, "reason": ""}

        async def _create_session(**_kwargs):
            return stand_in_session(
                "sess_root", "sst_root", execution_id="exec_server_root"
            )

        async def _get_manifest(_aid, **_kw):
            return {}

        async def _publish_events(run, events):
            session_token = token_of(run)
            self.published.append(
                {"events": list(events), "token": session_token}
            )
            return True

        async def _authorize(
            *,
            principal,
            action,
            resource,
            context=None,
            execution_id=None,
            intent=None,
            **_kw,
        ):
            ctx = context or {}
            self.authorize_calls.append(
                {
                    "principal": principal,
                    "action": action,
                    "resource": resource,
                    "run_handle_id": ctx.get("run_handle_id"),
                    "execution_id": execution_id,
                }
            )
            verb = action.split('"')[1] if '"' in action else action
            resource_name = resource.split('"')[1] if '"' in resource else resource
            rh = ctx.get("run_handle_id")
            if rh is not None and rh in self._granted_tools:
                # wl-apdp's membership check accepts either the bare
                # action or the bare resource name against the granted
                # allowed_tools (a tool-name list).
                granted = self._granted_tools[rh]
                if verb in granted or resource_name in granted:
                    return {"decision": "Allow", "reason": ""}
                return {
                    "decision": "Deny",
                    "reason": "subagent_out_of_scope",
                    "details": {},
                }
            # Root (no sub-agent run handle) — governed by Cedar elsewhere.
            return {"decision": "Allow", "reason": ""}

        async def _spawn_subagent(parent, body):
            self.spawn_bodies.append(body)
            child_agent = body["child_agent_id"]
            parent_rh = body["parent_run_handle_id"]
            req = body.get("requested_scope") or {}
            # Depth exhaustion — a parent granted max_depth 0 cannot spawn.
            parent_depth = self._granted_depth.get(parent_rh)
            if parent_depth is not None and parent_depth <= 0:
                raise ScopeAttenuationDenied(
                    reason="scope_attenuation_violation", violations=[]
                )
            if child_agent in self._deny:
                raise ScopeAttenuationDenied(
                    reason="scope_attenuation_violation", violations=[]
                )
            self._seq += 1
            n = self._seq
            child_rh = f"00000000-0000-0000-0000-0000000000{n:02d}"
            granted_tools = list(req.get("allowed_tools") or [])
            self._granted_tools[child_rh] = set(granted_tools)
            child_depth = (
                parent_depth - 1
                if parent_depth is not None
                else self._first_level_max_depth
            )
            self._granted_depth[child_rh] = child_depth
            return stand_in_spawn({
                "child_run_handle_id": child_rh,
                "granted_scope": {
                    "allowed_tools": granted_tools,
                    "allowed_resources": [],
                    "allowed_intents": [],
                    "max_depth": max(0, child_depth),
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
        self.authorize = AsyncMock(side_effect=_authorize)
        self.spawn_subagent = AsyncMock(side_effect=_spawn_subagent)
        self.complete_session = AsyncMock(return_value=True)


def _make_plugin(apdp: _SpawnApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        agent_slug="agent-root-agent",
        root_agent_name="root_agent",
        subagent_slugs={
            "sub_agent_a": "agent-sub-agent-a",
            "sub_sub_agent_b": "agent-sub-sub-agent-b",
        },
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


def _agent(name: str, tools: Optional[List[str]] = None) -> Any:
    a = MagicMock()
    a.name = name
    a.tools = [_tool(t) for t in (tools or [])]
    return a


def _tool(name: str) -> Any:
    # A stand-in for an ADK ``BaseTool`` (``spec=`` makes it one for
    # ``isinstance``), named the way ADK names a declared tool.
    t = MagicMock(spec=BaseTool)
    t.name = name
    t.description = f"tool {name}"
    return t


def _flat_events(apdp: _SpawnApdp) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for batch in apdp.published:
        out.extend(batch["events"])
    return out


async def _enter_root_then_sub(
    plugin: WatchlightPlugin,
    apdp: _SpawnApdp,
    *,
    sub_tools: Optional[List[str]] = None,
) -> None:
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=sub_tools),
        callback_context=non_live_context(),
    )


# ─── 1. nested before_agent_callback fires a real spawn_subagent ─────────


@pytest.mark.asyncio
async def test_nested_before_agent_fires_spawn_with_derived_scope():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)

    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report", "search_web"])

    # Exactly one spawn_subagent round-trip for the one nested sub-agent.
    apdp.spawn_subagent.assert_awaited_once()
    body = apdp.spawn_bodies[0]
    # The child principal is the resolved child agent UUID.
    assert body["child_agent_id"] == SUB_A_UUID
    assert body["parent_agent_id"] == ROOT_UUID
    # Scope was auto-derived from the child's DECLARED tool list as TOOL
    # NAMES — the identifier wl-apdp's strict-subset check compares against
    # the parent's effective allowed_tools (never the action verbs).
    assert set(body["requested_scope"]["allowed_tools"]) == {"get_report", "search_web"}


@pytest.mark.asyncio
async def test_root_agent_does_not_spawn():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    apdp.spawn_subagent.assert_not_called()
    # The root opened a normal ExecutionSession + built the registry.
    apdp.create_session.assert_awaited_once()
    assert plugin._root_handle is not None
    assert plugin._root_handle is not None


# ─── 2. before_tool_callback authorizes under the child run_handle_id ────


@pytest.mark.asyncio
async def test_subagent_tool_in_scope_allow_under_child_handle():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])

    child_rh = plugin._subagent_stack[-1][1].run_handle_id

    # In-scope tool (read) → Allow (before_tool_callback returns None).
    result = await plugin.before_tool_callback(
        tool=_tool("get_report"), tool_args={}
    )
    assert result is None
    last = apdp.authorize_calls[-1]
    # Authorized under the CHILD's server-minted run_handle_id, and the
    # principal is the child agent.
    assert last["run_handle_id"] == child_rh
    assert last["principal"] == f'Agent::"{SUB_A_UUID}"'


@pytest.mark.asyncio
async def test_subagent_tool_out_of_scope_deny_under_child_handle():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])

    child_rh = plugin._subagent_stack[-1][1].run_handle_id

    # Out-of-scope tool (execute) → Deny (block dict returned).
    result = await plugin.before_tool_callback(
        tool=_tool("execute_trade"), tool_args={}
    )
    assert isinstance(result, dict)
    assert "ACTION BLOCKED" in result["result"]
    last = apdp.authorize_calls[-1]
    assert last["run_handle_id"] == child_rh
    assert plugin._denied_count >= 1


# ─── 3. denied spawn → the sub-agent never runs ─────────────────


@pytest.mark.asyncio
async def test_denied_spawn_short_circuits_the_subagent():
    apdp = _SpawnApdp(deny_child_uuids={SUB_A_UUID})
    plugin = _make_plugin(apdp)

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec = plugin._current_execution_id
    root_token = plugin._current_run
    published_before = len(apdp.published)

    # The governed spawn is refused: before_agent_callback does not raise,
    # it returns the refusal Content so ADK never starts the sub-agent.
    refusal = await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    assert refusal is not None
    text = refusal.parts[0].text
    assert "sub_agent_a" in text
    assert "was not started" in text
    assert "strict subset of its parent's granted scope" in text

    # The refused child owns no frame and the parent's context is intact —
    # it does not run under the parent's credential.
    assert plugin._subagent_stack == []
    assert plugin._lineage_stack == []
    assert plugin._current_execution_id == root_exec
    assert plugin._current_agent_id == ROOT_UUID
    assert plugin._current_run == root_token
    # No execution_started for a child that never ran.
    assert len(apdp.published) == published_before


@pytest.mark.asyncio
async def test_refused_subagent_model_turn_never_reaches_authorize():
    """Second line: if a frame for a sub-agent with no handle is live, its
    model turn is refused locally — no /authorize with no credential (the
    observed symptom: a 400 ``missing_run_credential``) and no model."""
    apdp = _SpawnApdp(deny_child_uuids={SUB_A_UUID})
    plugin = _make_plugin(apdp)
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    # A sub-agent frame whose spawn holds no handle (its own frame, in
    # its own context, under the root's).
    from watchlight_adk.plugin import _Frame

    root = plugin._frame_var.get()
    child = _Frame(state=root.state, parent=root, invocation_id=root.invocation_id)
    child.child_key = "sub_agent_a"
    child._current_agent_id = SUB_A_UUID
    child._current_agent_name = "sub_agent_a"
    child._current_execution_id = "exec_sub_a"
    plugin._frame_var.set(child)
    apdp.authorize.reset_mock()

    response = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=None
    )
    assert response is not None  # the model is not called
    assert "was not started" in response.content.parts[0].text
    apdp.authorize.assert_not_called()

    result = await plugin.before_tool_callback(
        tool=_tool("get_report"), tool_args={}
    )
    assert isinstance(result, dict)
    assert "ACTION BLOCKED" in result["result"]
    apdp.authorize.assert_not_called()


@pytest.mark.asyncio
async def test_subagent_never_acts_on_the_parents_credential():
    """A granted child whose live credential is not its own (the parent's
    ``sst_``) is refused locally on both the model and the tool path."""
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])
    plugin._current_run = run_for("sst_root")
    apdp.authorize.reset_mock()

    response = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=None
    )
    assert response is not None
    result = await plugin.before_tool_callback(
        tool=_tool("get_report"), tool_args={}
    )
    assert isinstance(result, dict)
    apdp.authorize.assert_not_called()


@pytest.mark.asyncio
async def test_granted_subagent_model_turn_presents_its_own_handle():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])
    child = plugin._subagent_stack[-1][1]
    apdp.authorize.reset_mock()

    await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=None
    )
    # The stand-in engine decides; what matters is what was presented.
    call = apdp.authorize.call_args
    assert child.run and call.kwargs["run"] == child.run
    assert call.kwargs["context"]["run_handle_id"] == child.run_handle_id
    assert call.kwargs["principal"] == f'Agent::"{SUB_A_UUID}"'


# ─── 4. after_agent_callback pops to the parent (registry.on_stop) ───────


@pytest.mark.asyncio
async def test_after_agent_pops_subagent_to_parent():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec = plugin._current_execution_id
    root_agent_id = plugin._current_agent_id

    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    assert len(plugin._subagent_stack) == 1
    child_handle = plugin._subagent_stack[-1][1]

    await plugin.after_agent_callback(
        agent=_agent("sub_agent_a"), callback_context=non_live_context()
    )
    # Sub-agent frame popped; context restored to the root.
    assert plugin._subagent_stack == []
    assert plugin._current_execution_id == root_exec
    assert plugin._current_agent_id == root_agent_id
    # on_stop completed the child handle's session server-side.
    # Only the run itself may close it: the child's own credential.
    apdp.complete_session.assert_any_await(child_handle.run)


# ─── 5. child events carry the server-minted execution_id + sst_ ─────────


@pytest.mark.asyncio
async def test_child_events_carry_server_execution_id_and_child_token():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])

    child_handle = plugin._subagent_stack[-1][1]
    # The plugin adopted the SERVER-minted child execution_id + per-child
    # sst_ so the sub-agent's lineage binds to the child session.
    assert plugin._current_execution_id == "exec_server_child_1"
    assert child_handle.execution_id == "exec_server_child_1"
    assert token_of(plugin._current_run) == "sst_child_1"

    await plugin.lineage.flush()

    # The child's execution_started is published under the child's token.
    child_batches = [
        b
        for b in apdp.published
        if any(
            e.get("execution_id") == "exec_server_child_1"
            and e.get("event_type") == "execution_started"
            for e in b["events"]
        )
    ]
    assert child_batches, "expected a child execution_started batch"
    for b in child_batches:
        assert b["token"] == "sst_child_1"
    # And the child event carries the parent/root stitch.
    started = next(
        e
        for e in _flat_events(apdp)
        if e.get("execution_id") == "exec_server_child_1"
        and e.get("event_type") == "execution_started"
    )
    assert started["root_execution_id"] == "exec_server_root"
    assert started["parent_execution_id"] == "exec_server_root"


# ─── 6. max_depth == 0 parent cannot spawn a grandchild ──────────────────


@pytest.mark.asyncio
async def test_max_depth_zero_parent_cannot_spawn_grandchild():
    # A (first-level) is GRANTED max_depth 0 → it may not spawn descendants.
    apdp = _SpawnApdp(first_level_max_depth=0)
    plugin = _make_plugin(apdp)

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    # A spawned successfully (granted max_depth 0).
    assert plugin._subagent_stack[-1][1] is not None

    # Grandchild B — the spawn is refused server-side (parent depth
    # exhausted). B is short-circuited: it never starts.
    refusal = await plugin.before_agent_callback(
        agent=_agent("sub_sub_agent_b", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    assert refusal is not None
    assert "was not started" in refusal.parts[0].text
    # A is still the executing sub-agent; B owns no frame.
    assert [k for k, _ in plugin._subagent_stack] == ["sub_agent_a"]


@pytest.mark.asyncio
async def test_grandchild_spawns_under_direct_parent_when_permitted():
    """root → A → B, each a governed spawn. B's spawn round-trips under
    A's handle (explicit parent_key), so B attenuates against A — not the
    root."""
    apdp = _SpawnApdp(first_level_max_depth=3)
    plugin = _make_plugin(apdp)

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    handle_a = plugin._subagent_stack[-1][1]
    await plugin.before_agent_callback(
        agent=_agent("sub_sub_agent_b", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    handle_b = plugin._subagent_stack[-1][1]
    assert handle_b is not None
    # B's spawn presented A's run handle as the parent (not the root's).
    b_body = apdp.spawn_bodies[-1]
    assert b_body["parent_run_handle_id"] == handle_a.run_handle_id
    assert b_body["parent_agent_id"] == SUB_A_UUID
    assert handle_b.parent_execution_id == handle_a.execution_id


# ─── A REFUSED nested sub-agent must not brick later runs ────────────────
#
# ADK SKIPS ``after_agent_callback`` for an agent that short-circuits from
# ``before_agent_callback``. If ``before_agent_callback`` mutated lifecycle
# state (pushed a lineage frame, minted an execution id) BEFORE refusing,
# that state would leak: ``_lineage_stack`` would diverge from
# ``_subagent_stack``, the outermost teardown would be skipped, and the
# next top-level run would misclassify itself as a sub-agent transfer
# against a stale registry — spuriously denying every tool call forever.
# The fix resolves + trust-checks BEFORE any state mutation so a refused
# agent (nested OR root) owns no lifecycle state.


@pytest.mark.asyncio
async def test_unregistered_nested_subagent_leaves_state_clean():
    apdp = _SpawnApdp(unregistered_slugs={"ghost-agent"})
    plugin = _make_plugin(apdp)

    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    root_exec = plugin._current_execution_id
    root_agent_id = plugin._current_agent_id

    # A nested UNREGISTERED sub-agent short-circuits with a refusal Content.
    ghost = _agent("ghost_agent", tools=["get_report"])
    refusal = await plugin.before_agent_callback(
        agent=ghost, callback_context=non_live_context()
    )
    assert refusal is not None  # short-circuit (agent does not proceed)

    # No lineage frame leaked; no sub-agent frame pushed; the PARENT's
    # lifecycle context is fully intact (the refused agent mutated nothing).
    assert plugin._lineage_stack == []
    assert plugin._subagent_stack == []
    assert plugin._current_execution_id == root_exec
    assert plugin._current_agent_id == root_agent_id
    # The refused nested agent never spawned.
    apdp.spawn_subagent.assert_not_called()


@pytest.mark.asyncio
async def test_untrusted_nested_subagent_does_not_brick_next_run():
    # A nested sub-agent that resolves but is UNTRUSTED — the other refusal
    # path that used to leak state (resolve set _current_agent_id, then
    # trust refused).
    apdp = _SpawnApdp(untrusted_uuids={SUB_A_UUID})
    plugin = _make_plugin(apdp)

    # ── Run 1: root → untrusted nested sub-agent (short-circuited) ──
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    refusal = await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]),
        callback_context=non_live_context(),
    )
    assert refusal is not None
    assert plugin._lineage_stack == []
    assert plugin._subagent_stack == []

    # The root finishes normally (ADK fires ITS after_agent_callback; the
    # short-circuited sub-agent's after_agent_callback is skipped).
    await plugin.after_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    # Outermost teardown ran — the run's governed handle + registry are gone
    # and no stale lifecycle identity remains to misclassify the next run.
    assert plugin._root_handle is None
    assert plugin._root_handle is None
    assert plugin._current_execution_id == ""
    assert plugin._current_agent_id == ""
    assert plugin._subagent_stack == []

    # ── Run 2: a FRESH top-level run must open a new session + registry ──
    apdp.create_session.reset_mock()
    apdp.spawn_subagent.reset_mock()
    proceed = await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    assert proceed is None  # governed, proceeds
    # It was classified as a ROOT (not a sub-agent transfer against a stale
    # registry): a fresh session opened and NO spawn was attempted.
    apdp.create_session.assert_awaited_once()
    apdp.spawn_subagent.assert_not_called()
    assert plugin._root_handle is not None
    assert plugin._root_handle is not None

    # And its tool calls are governed normally — NOT all denied.
    result = await plugin.before_tool_callback(
        tool=_tool("get_report"), tool_args={}
    )
    assert result is None  # Allow (root governed by Cedar; not bricked)


@pytest.mark.asyncio
async def test_root_refusal_does_not_brick_next_run():
    # Symmetry check: an UNTRUSTED ROOT also short-circuits, and (because
    # resolve now precedes state mutation) leaves no stale identity to
    # brick the retry.
    apdp = _SpawnApdp(untrusted_uuids={ROOT_UUID})
    plugin = _make_plugin(apdp)

    refusal = await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    assert refusal is not None
    # Opaque deny: the trust check's reason is not shown to the agent.
    assert "flagged for review" not in "".join(p.text or "" for p in refusal.parts)
    assert plugin._current_execution_id == ""
    assert plugin._current_agent_id == ""
    assert plugin._lineage_stack == []
    assert plugin._subagent_stack == []

    # The operator fixes trust; the retry is governed normally.
    apdp._untrusted.clear()
    proceed = await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    assert proceed is None
    assert plugin._root_handle is not None


# ─── The refusal text names the refusal class, never server detail ───────


@pytest.mark.asyncio
async def test_depth_refusal_says_depth_not_strict_subset():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)

    async def _depth(parent, body):
        raise ScopeAttenuationDenied(
            reason="scope_attenuation_violation: tree depth 9 > 8",
            violations=[],
            reason_code="DELEGATION_DEPTH_EXCEEDED",
        )

    apdp.spawn_subagent.side_effect = _depth
    await plugin.before_agent_callback(agent=_agent("root_agent"), callback_context=non_live_context())
    refusal = await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]), callback_context=non_live_context()
    )
    text = refusal.parts[0].text
    assert "depth limit" in text
    assert "strict subset" not in text
    # Opaque: the server's reason string never reaches the agent.
    assert "tree depth 9" not in text


@pytest.mark.asyncio
async def test_transport_failure_refusal_says_unavailable():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    apdp.spawn_subagent.side_effect = RuntimeError("connect ECONNREFUSED 10.0.0.7:8081")
    await plugin.before_agent_callback(agent=_agent("root_agent"), callback_context=non_live_context())
    refusal = await plugin.before_agent_callback(
        agent=_agent("sub_agent_a", tools=["get_report"]), callback_context=non_live_context()
    )
    text = refusal.parts[0].text
    assert "governance is unavailable" in text
    assert "strict subset" not in text
    assert "ECONNREFUSED" not in text


# ─── Child intent ─────────────────────────────────────


@pytest.mark.asyncio
async def test_nested_spawn_declares_the_child_intent_from_its_description():
    """Every spawn declares the child's intent: the objective is the ADK
    sub-agent's ``description``; the category is the plugin's configured
    one (else the default)."""
    from watchlight_core import DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY

    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    await plugin.before_agent_callback(
        agent=_agent("root_agent"), callback_context=non_live_context()
    )
    sub = _agent("sub_agent_a", tools=["get_report"])
    sub.description = "Fetch the quarterly report"
    await plugin.before_agent_callback(agent=sub, callback_context=non_live_context())
    assert apdp.spawn_bodies[0]["child_intent"] == {
        "category": DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
        "objective": "Fetch the quarterly report",
    }


@pytest.mark.asyncio
async def test_nested_spawn_uses_the_configured_category_and_a_fallback_objective():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)
    plugin.child_intent_category = "research"
    await _enter_root_then_sub(plugin, apdp, sub_tools=["get_report"])
    sent = apdp.spawn_bodies[0]["child_intent"]
    assert sent["category"] == "research"
    assert sent["objective"].startswith("Delegated task for sub-agent")
