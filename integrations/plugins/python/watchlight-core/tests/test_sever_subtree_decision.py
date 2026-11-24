"""Enforcement-effect SeverSubtree — tests for the Python lane.

These tests pin down the SeverSubtree enforcement effect
(A · Halt/contain) as it wires through the decision parser and
``BaseRunHandle``:

- The wl-apdp SeverSubtree wire shape (``decision: "SeverSubtree"`` +
  ``details.enforcement`` with ``effect == "sever_subtree"``)
  deserialises into a typed :class:`SeverSubtreeDecision` carrying the
  ``policy_id``.
- A SeverSubtree response collapses the sub-agent spawn TREE rooted
  at the handle (multi-agent containment): ``authorize_action`` raises
  :class:`SubtreeSeveredError`, drives the current handle AND every
  descendant to the terminal :class:`RunHandleState.SEVERED` state, and
  fires each handle's kill signal with ``reason=sever_subtree``.
- Fail-closed containment: a descendant that cannot be enumerated (a
  dead weak-ref) is counted on ``unreachable_descendants`` and surfaced
  loudly — the walk NEVER silently under-collapses.
- Severing does NOT bag the agent: a fresh ``start_run`` re-spawns a
  clean tree (SEVERED is terminal but ephemeral, NOT a durable bag).
- :class:`SubtreeSeveredError` is catchable by the same generic
  ``except Exception`` handler pattern the deny / quarantine / terminate
  paths use, while an effect-aware handler can match the specific type.

SeverSubtree is the THIRD rung of the halt/contain severity ladder
(ordinal 3 — above Quarantine). It contrasts with Terminate (which
scopes to one run and walks nothing) by walking DOWN to every
descendant, so these mirror ``test_terminate_decision.py`` but assert
the *tree-collapse* differences.
"""

from __future__ import annotations

import asyncio
import gc
import weakref
from dataclasses import dataclass, field
from typing import List, Optional

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    BaseRunHandle,
    ExecutionTerminatedError,
    LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE,
    RunHandleState,
    SeverSubtreeDecision,
    SubtreeSeveredError,
    parse_authorization_decision,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Stub kill-signal registry (mirrors test_terminate_decision) ─────


@dataclass
class _CountingKillRegistry:
    """Counts ``cancel`` calls so tests assert on invocation shape."""

    cancel_calls: List[str] = field(default_factory=list)

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# ─── Plugin + handle fixtures ────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal plugin satisfying the GovernedPlugin Protocol + the
    optional ``kill_signal_registry`` attribute.
    """

    def __init__(
        self,
        kill_signal_registry: Optional[_CountingKillRegistry] = None,
    ) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.apdp.known_agents["agent-x"] = "uuid-x"
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = kill_signal_registry


@pytest.fixture
def registry() -> _CountingKillRegistry:
    return _CountingKillRegistry()


@pytest.fixture
def plugin(registry: _CountingKillRegistry) -> _Plugin:
    return _Plugin(kill_signal_registry=registry)


@pytest_asyncio.fixture
async def handle(plugin: _Plugin) -> BaseRunHandle:
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    # Synthetic test handle bypasses the production ``async with`` entry
    # path; flip the fail-closed flag so the contract guard accepts the
    # test's direct authorize calls.
    h._aentered = True
    return h


def _sever_wire_payload() -> dict:
    """The exact wire shape wl-apdp emits on a policy-driven SeverSubtree.

    Mirrors the enforcement-effects wire contract.
    """
    return {
        "decision": "SeverSubtree",
        "reason": "Sub-agent spawn tree severed by policy forbid-sever-compromised-subtree",
        "details": {
            "enforcement": {
                "effect": "sever_subtree",
                "severity": 3,
                "reason": "sever_subtree",
                "lift_required": False,
                "policy_id": "forbid-sever-compromised-subtree",
            }
        },
    }


def _make_handle(
    plugin: _Plugin,
    *,
    agent_uuid: str,
    session_id: str,
    parent: Optional[BaseRunHandle] = None,
) -> BaseRunHandle:
    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid=agent_uuid,
        session_id=session_id,
        parent_handle=parent,
    )
    h._aentered = True
    return h


# ─── Test (a) — parser returns a SeverSubtreeDecision ────────────────


def test_parse_sever_wire_returns_sever_decision() -> None:
    """The SeverSubtree wire shape deserialises into a typed
    :class:`SeverSubtreeDecision` carrying the enforcement-block
    ``policy_id`` and the top-level ``reason``.
    """
    typed = parse_authorization_decision(_sever_wire_payload())
    assert isinstance(typed, SeverSubtreeDecision)
    assert typed.kind == "sever_subtree"
    assert typed.policy_id == "forbid-sever-compromised-subtree"
    assert "severed" in typed.reason.lower()


def test_parse_sever_falls_back_to_determining_policy_id() -> None:
    """When the enforcement block omits ``policy_id`` (or carries a
    different effect), the parser falls back to the top-level
    ``determining_policy_id`` rather than mis-attributing another
    effect's id.
    """
    payload = {
        "decision": "SeverSubtree",
        "reason": "severed",
        "determining_policy_id": "top-level-pid",
        "details": {"enforcement": {"effect": "terminate", "policy_id": "wrong"}},
    }
    typed = parse_authorization_decision(payload)
    assert isinstance(typed, SeverSubtreeDecision)
    # ``effect != "sever_subtree"`` so we do NOT trust the block's id.
    assert typed.policy_id == "top-level-pid"


def test_parse_sever_default_reason_when_missing() -> None:
    """A SeverSubtree with no top-level reason gets the default."""
    typed = parse_authorization_decision(
        {"decision": "SeverSubtree", "details": {}}
    )
    assert isinstance(typed, SeverSubtreeDecision)
    assert typed.reason == "Subtree severed"


# ─── Test (b) — authorize collapses a multi-level tree ───────────────


@pytest.mark.asyncio
async def test_sever_collapses_multi_level_tree() -> None:
    """A SeverSubtree response on the ROOT severs the root AND every
    descendant (child + grandchild) depth-first — each to the terminal
    ``SEVERED`` state — and fires each handle's kill signal with
    ``reason=sever_subtree``. The agent is NOT bagged.
    """
    root_registry = _CountingKillRegistry()
    child_registry = _CountingKillRegistry()
    grand_registry = _CountingKillRegistry()

    root_plugin = _Plugin(kill_signal_registry=root_registry)
    child_plugin = _Plugin(kill_signal_registry=child_registry)
    grand_plugin = _Plugin(kill_signal_registry=grand_registry)

    root = _make_handle(root_plugin, agent_uuid="uuid-root", session_id="ses_root")
    child = _make_handle(
        child_plugin, agent_uuid="uuid-child", session_id="ses_child", parent=root
    )
    grandchild = _make_handle(
        grand_plugin,
        agent_uuid="uuid-grand",
        session_id="ses_grand",
        parent=child,
    )

    root_plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError) as exc_info:
        await root.authorize_action("execute", "Tool::scanner")
    # Yield so any scheduled descendant-lifecycle tasks run.
    await asyncio.sleep(0)

    # Root + both descendants are SEVERED (terminal, NOT quarantined).
    assert root.state == RunHandleState.SEVERED
    assert child.state == RunHandleState.SEVERED
    assert grandchild.state == RunHandleState.SEVERED
    assert root.is_severed is True
    assert child.is_severed is True
    assert grandchild.is_severed is True
    # Not bagged — no quarantine state anywhere.
    assert root.is_quarantined is False
    assert child.is_quarantined is False
    assert grandchild.is_quarantined is False

    # Every handle's kill signal fired with the sever_subtree reason.
    assert root_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE]
    assert child_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE]
    assert grand_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE]

    # The error reports the blast radius: 2 descendants (child +
    # grandchild), 0 unreachable, and the determining policy id.
    assert exc_info.value.descendants_severed == 2
    assert exc_info.value.unreachable_descendants == 0
    assert exc_info.value.policy_id == "synthetic.sever_subtree"


@pytest.mark.asyncio
async def test_sever_collapses_depth_three_tree() -> None:
    """Depth coverage beyond the 2-deep case: a FOUR-level tree
    (root → child → grandchild → great-grandchild) collapses entirely.

    The walk is transitive, so the blast radius is every node below the
    offender regardless of depth: 3 descendants here.
    """
    plugins = [_Plugin(kill_signal_registry=_CountingKillRegistry()) for _ in range(4)]
    root = _make_handle(plugins[0], agent_uuid="uuid-root", session_id="ses_root")
    child = _make_handle(
        plugins[1], agent_uuid="uuid-c1", session_id="ses_c1", parent=root
    )
    grand = _make_handle(
        plugins[2], agent_uuid="uuid-c2", session_id="ses_c2", parent=child
    )
    great = _make_handle(
        plugins[3], agent_uuid="uuid-c3", session_id="ses_c3", parent=grand
    )

    plugins[0].apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError) as exc_info:
        await root.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    for handle in (root, child, grand, great):
        assert handle.state == RunHandleState.SEVERED
        assert handle.is_quarantined is False
    # Every level fired its own kill signal with the sever reason.
    for plugin_ in plugins:
        assert plugin_.kill_signal_registry.cancel_calls == [
            LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE
        ]
    # 3 descendants below the root, transitively.
    assert exc_info.value.descendants_severed == 3
    assert exc_info.value.unreachable_descendants == 0


@pytest.mark.asyncio
async def test_sever_from_mid_tree_collapses_below_and_spares_ancestor() -> None:
    """A sever fired on a MID-TREE node collapses everything BENEATH it
    and leaves the ANCESTOR ACTIVE.

    This is the documented down-walk-only boundary
    (:meth:`BaseRunHandle._sever_subtree_descendants` is the explicit
    dual of :meth:`_propagate_quarantine_to_parents`, which walks UP).
    An operator who needs the ancestor contained too must reach for
    Quarantine (severity 2) — SeverSubtree deliberately does NOT blast
    upward, and this test pins that semantic so neither the SDK nor the
    demo can drift into implying more containment than exists.

    It is also the shape the demo scenario now exercises: firing on a
    LEAF makes ``descendants_severed`` structurally 0, which proves no
    more than a Terminate would.
    """
    root_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    mid_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    leaf_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())

    root = _make_handle(root_plugin, agent_uuid="uuid-root", session_id="ses_root")
    mid = _make_handle(
        mid_plugin, agent_uuid="uuid-mid", session_id="ses_mid", parent=root
    )
    leaf = _make_handle(
        leaf_plugin, agent_uuid="uuid-leaf", session_id="ses_leaf", parent=mid
    )

    # Only the MID node's APDP severs — it is the offender.
    mid_plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError) as exc_info:
        await mid.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    # Offender + everything beneath it: SEVERED.
    assert mid.state == RunHandleState.SEVERED
    assert leaf.state == RunHandleState.SEVERED
    assert mid.is_severed is True
    assert leaf.is_severed is True
    # A REAL subtree collapsed — this is the assertion a leaf-rooted
    # sever can never make.
    assert exc_info.value.descendants_severed == 1
    assert exc_info.value.unreachable_descendants == 0

    # DOWN-WALK BOUNDARY: the ancestor is untouched — still ACTIVE, not
    # severed, not bagged, and its kill signal never fired.
    assert root.state == RunHandleState.ACTIVE
    assert root.is_severed is False
    assert root.is_quarantined is False
    assert root_plugin.kill_signal_registry.cancel_calls == []

    # ... and the ancestor can still authorize: sever contained the
    # subtree, it did not halt the delegating parent.
    root_plugin.apdp.default_decision = "Allow"
    assert await root.authorize_action("execute", "Tool::scanner") is True


@pytest.mark.asyncio
async def test_descendants_severed_counts_only_active_transitions() -> None:
    """``descendants_severed`` counts ACTIVE → SEVERED TRANSITIONS, not
    the total size of the subtree.

    Documented, deliberately-unchanged semantics (see
    :meth:`BaseRunHandle._sever_subtree_descendants`: it increments only
    when ``node._state == RunHandleState.ACTIVE``):

    1. A descendant that is ALREADY terminal (COMPLETED here) is left
       untouched and is NOT counted — so the reported number can be
       LOWER than the number of nodes in the subtree.
    2. Consequently a REPLAYED sever over an already-collapsed tree
       reports 0 descendants while the tree stays fully severed. The
       count is a transition counter, NOT a durable blast-radius total;
       audit consumers must not read it as "subtree size".

    This under-reporting is real but benign: containment is driven by
    STATE (every reachable node ends terminal), never by the count.
    Fixing the reporting would change core SDK semantics and is
    deliberately out of scope here.
    """
    root_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    active_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    done_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())

    root = _make_handle(root_plugin, agent_uuid="uuid-root", session_id="ses_root")
    still_active = _make_handle(
        active_plugin, agent_uuid="uuid-a", session_id="ses_a", parent=root
    )
    already_done = _make_handle(
        done_plugin, agent_uuid="uuid-d", session_id="ses_d", parent=root
    )
    # This child finished normally BEFORE the sever fired.
    already_done._state = RunHandleState.COMPLETED

    root_plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError) as exc_info:
        await root.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    # TWO children in the subtree, but only ONE transitioned.
    assert len(root._child_handle_refs) == 2
    assert exc_info.value.descendants_severed == 1
    assert still_active.state == RunHandleState.SEVERED
    # The already-terminal child keeps its own terminal attribution.
    assert already_done.state == RunHandleState.COMPLETED

    # Replay the walk over the now-collapsed tree: idempotent in STATE
    # (nothing regresses, nothing re-fires) but it reports 0 because
    # there is nothing left to transition.
    decision = SeverSubtreeDecision(
        reason="replayed sever", policy_id="forbid-sever-compromised-subtree"
    )
    replay_severed, replay_unreachable = root._sever_subtree_descendants(decision)
    assert replay_severed == 0, (
        "a replayed sever reports 0 descendants — the counter tracks "
        "ACTIVE→SEVERED transitions, not subtree size"
    )
    assert replay_unreachable == 0
    # State is unchanged and the descendant's kill signal did NOT fire a
    # second time — the walk is genuinely idempotent.
    assert still_active.state == RunHandleState.SEVERED
    assert root.state == RunHandleState.SEVERED
    assert active_plugin.kill_signal_registry.cancel_calls == [
        LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE
    ]


@pytest.mark.asyncio
async def test_severed_descendant_short_circuits_further_calls() -> None:
    """A descendant severed transitively MUST fail closed on any further
    ``authorize_action`` — it short-circuits with
    :class:`SubtreeSeveredError` WITHOUT round-tripping to wl-apdp.
    """
    root_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    child_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())

    root = _make_handle(root_plugin, agent_uuid="uuid-root", session_id="ses_root")
    child = _make_handle(
        child_plugin, agent_uuid="uuid-child", session_id="ses_child", parent=root
    )
    root_plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError):
        await root.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert child.state == RunHandleState.SEVERED

    # The child now short-circuits — even if wl-apdp would Allow, the
    # severed handle never round-trips. Prove it by making the child's
    # mock Allow: the call MUST still raise.
    child_plugin.apdp.default_decision = "Allow"
    calls_before = len(child_plugin.apdp.authorize_calls)
    with pytest.raises(SubtreeSeveredError):
        await child.authorize_action("execute", "Tool::scanner")
    # No new round-trip to wl-apdp — the short-circuit came first.
    assert len(child_plugin.apdp.authorize_calls) == calls_before


# ─── Test (c) — fail-closed on a partially-enumerable tree ───────────


@pytest.mark.asyncio
async def test_sever_fail_loud_on_unreachable_descendant() -> None:
    """If a descendant child ref is dead (GC'd), the walk COUNTS it as
    unreachable and surfaces the gap on
    ``SubtreeSeveredError.unreachable_descendants`` — it MUST NEVER
    silently under-collapse. Reachable descendants are still severed.
    """
    root_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())
    live_plugin = _Plugin(kill_signal_registry=_CountingKillRegistry())

    root = _make_handle(root_plugin, agent_uuid="uuid-root", session_id="ses_root")
    live_child = _make_handle(
        live_plugin, agent_uuid="uuid-live", session_id="ses_live", parent=root
    )

    # Register a SECOND child, then drop every strong reference to it so
    # its weak ref in the parent registry goes dead — simulating a
    # GC'd descendant the walk cannot enumerate. We inject a dead
    # weakref directly to make the "unreachable" branch deterministic
    # (GC timing is otherwise non-deterministic).
    class _Ghost:
        pass

    ghost = _Ghost()
    dead_ref = weakref.ref(ghost)
    root._child_handle_refs.append(dead_ref)  # type: ignore[arg-type]
    del ghost
    gc.collect()
    assert dead_ref() is None, "ghost ref must be dead for the test"

    root_plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError) as exc_info:
        await root.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    # The live descendant is severed; the dead one is COUNTED loudly.
    assert live_child.state == RunHandleState.SEVERED
    assert exc_info.value.descendants_severed == 1
    assert exc_info.value.unreachable_descendants == 1
    # The detail is on the attributes; the message stays opaque.
    assert "unreachable" not in str(exc_info.value)


# ─── Test (d) — a fresh run after a sever is clean ───────────────────


@pytest.mark.asyncio
async def test_fresh_run_after_sever_is_clean(plugin: _Plugin) -> None:
    """SeverSubtree does NOT bag the agent — a brand-new handle
    (representing a fresh ``start_run``) authorizes normally, proving
    there is no durable contained state leaking across executions.
    """
    plugin.apdp.default_decision = "SeverSubtree"

    h1 = _make_handle(plugin, agent_uuid="uuid-x", session_id="ses_1")
    with pytest.raises(SubtreeSeveredError):
        await h1.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert h1.state == RunHandleState.SEVERED
    assert h1.is_quarantined is False

    # Fresh run — now the policy no longer severs (clean).
    plugin.apdp.default_decision = "Allow"
    h2 = _make_handle(plugin, agent_uuid="uuid-x", session_id="ses_2")
    allowed = await h2.authorize_action("execute", "Tool::scanner")
    assert allowed is True
    assert h2.state == RunHandleState.ACTIVE
    assert h2.is_severed is False


# ─── Test (e) — generic + effect-aware handlers both catch it ────────


@pytest.mark.asyncio
async def test_sever_error_caught_by_generic_handler(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """:class:`SubtreeSeveredError` is catchable by the same generic
    ``except Exception`` handler pattern customer agent code uses — while
    still being a distinct, effect-aware type siblings-with (not a
    subclass of) the other effect errors.
    """
    plugin.apdp.default_decision = "SeverSubtree"

    caught_generic = False
    try:
        await handle.authorize_action("execute", "Tool::scanner")
    except Exception as exc:  # noqa: BLE001 — intentional generic catch
        caught_generic = True
        assert isinstance(exc, SubtreeSeveredError)
    assert caught_generic

    # Effect-aware handlers distinguish SeverSubtree from Terminate /
    # Quarantine — none is a subclass of another, so agent code can
    # branch precisely.
    assert not issubclass(SubtreeSeveredError, ExecutionTerminatedError)
    assert not issubclass(SubtreeSeveredError, AgentQuarantinedError)
    assert not issubclass(ExecutionTerminatedError, SubtreeSeveredError)
    assert not issubclass(AgentQuarantinedError, SubtreeSeveredError)


@pytest.mark.asyncio
async def test_sever_marks_run_terminal_idempotently(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """After a sever the run is already terminal — a subsequent
    ``terminate()`` / ``complete()`` is an idempotent no-op that does
    not round-trip to wl-apdp for a fresh session-close.
    """
    plugin.apdp.default_decision = "SeverSubtree"

    with pytest.raises(SubtreeSeveredError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    closed_before = list(plugin.apdp._closed_sessions)
    terminated_before = list(plugin.apdp._terminated_sessions)

    await handle.terminate("late")
    await handle.complete()

    assert plugin.apdp._closed_sessions == closed_before
    assert plugin.apdp._terminated_sessions == terminated_before
    assert handle.state == RunHandleState.SEVERED
