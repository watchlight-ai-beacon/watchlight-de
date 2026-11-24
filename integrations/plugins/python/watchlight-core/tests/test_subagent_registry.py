"""SubagentRegistry — uniform governed-spawn routing primitive.

Order-independent unit tests for the Python lane of
:class:`watchlight_core.SubagentRegistry`. Wire-identical to the TS
lane's ``tests/subagent-registry.test.ts``.

Coverage:

* parent-resolution ladder — explicit ``parent_key`` vs stack-top vs
  root;
* a server-denied spawn (mock ``spawn_subagent`` raising
  :class:`ScopeAttenuationDenied`) → :meth:`resolve` returns ``None``
  (fail-closed); same for :class:`RunHandleInvalidated`;
* nested spawn — a grandchild attenuates against the DIRECT parent
  handle, not the root;
* :meth:`on_stop` closes + removes the child and the stack pops back to
  the parent;
* ``default_subagent_scope`` used when ``requested_scope`` is ``None``;
* an EMPTY default still registers the child (the registry returns the
  handle; authorizing the child's tool calls is the caller's job).
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

import pytest

from watchlight_core import (
    BaseRunHandle,
    GovernanceUnavailable,
    RunHandleInvalidated,
    ScopeAttenuationDenied,
    ScopeViolationDimension,
    SubagentRegistry,
)
from watchlight_core.subagent_registry import (
    DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
    default_subagent_scope_from_env,
)
from watchlight_core_testing import MockApdpClient


# ─── Test scaffold ───────────────────────────────────────────────


class _Plugin:
    """Minimal ``GovernedPlugin`` for driving a bare
    :class:`BaseRunHandle` against a :class:`MockApdpClient`."""

    def __init__(self, apdp: MockApdpClient, tenant_id: str = "tenant-a") -> None:
        self.apdp = apdp
        self.tenant_id = tenant_id
        self.log_decisions = False
        self.last_governance_mode = "unmeasured"
        self.last_session_id: Optional[str] = None
        self.last_manifest: Optional[Dict[str, Any]] = None
        self.last_plan_validation: Optional[Dict[str, Any]] = None
        self.last_proposed_plan: Optional[Any] = None
        self.last_actions_allowed = 0
        self.last_actions_denied = 0
        self.kill_signal_registry = None


def _make_root(apdp: MockApdpClient) -> BaseRunHandle:
    """A synthetic root handle whose ids are valid UUIDs so the
    spawn wire-shape serialisation round-trips cleanly."""
    handle = BaseRunHandle(
        plugin=_Plugin(apdp),
        agent_uuid="00000000-0000-0000-0000-000000000001",
        session_id=f"ses_{uuid.uuid4()}",
        run_handle_id=str(uuid.uuid4()),
    )
    handle._aentered = True
    return handle


def _child_uuid() -> str:
    return str(uuid.uuid4())


def _last_parent_handle_id(apdp: MockApdpClient) -> str:
    """The ``parent_run_handle_id`` on the most recent spawn call —
    identifies which handle the registry routed the spawn through."""
    return apdp.spawn_subagent_calls[-1]["parent_run_handle_id"]


# ─── Parent-resolution ladder ────────────────────────────────────


class TestParentResolutionLadder:
    @pytest.mark.asyncio
    async def test_root_when_stack_empty_and_no_parent_key(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        child = await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        assert child is not None
        assert _last_parent_handle_id(apdp) == root.run_handle_id

    @pytest.mark.asyncio
    async def test_stack_top_when_no_parent_key(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        b = await reg.on_spawn(child_key="b", child_slug=_child_uuid())
        assert a is not None and b is not None

        # A third spawn with no explicit parent attributes to the TOP
        # of the stack (b), not the root and not a.
        await reg.on_spawn(child_key="c", child_slug=_child_uuid())
        assert _last_parent_handle_id(apdp) == b.run_handle_id

    @pytest.mark.asyncio
    async def test_explicit_parent_key_overrides_stack_top(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        b = await reg.on_spawn(child_key="b", child_slug=_child_uuid())
        assert a is not None and b is not None

        # Explicit parent_key="a" must win over the stack top (b).
        await reg.on_spawn(
            child_key="c", child_slug=_child_uuid(), parent_key="a"
        )
        assert _last_parent_handle_id(apdp) == a.run_handle_id

    @pytest.mark.asyncio
    async def test_unknown_explicit_parent_key_fails_closed(self) -> None:
        # F1 — an EXPLICIT parent_key that names a parent the registry
        # has never spawned must NOT silently fall through to the
        # stack-top sibling / root (that would spawn the child under a
        # laxer ancestor). It fails CLOSED.
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert a is not None
        spawns_before = len(apdp.spawn_subagent_calls)

        child = await reg.on_spawn(
            child_key="b", child_slug=_child_uuid(), parent_key="ghost"
        )
        # Denied: no handle, marked fail-closed, and NO spawn round-trip
        # was made (we refuse before contacting APDP).
        assert child is None
        assert reg.resolve("b") is None
        assert len(apdp.spawn_subagent_calls) == spawns_before


# ─── Nested spawn / grandchild ───────────────────────────────────


class TestNestedSpawn:
    @pytest.mark.asyncio
    async def test_grandchild_attenuates_against_direct_parent(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        parent = await reg.on_spawn(child_key="p", child_slug=_child_uuid())
        assert parent is not None

        grandchild = await reg.on_spawn(child_key="g", child_slug=_child_uuid())
        assert grandchild is not None

        # The grandchild's spawn routed through the DIRECT parent's
        # handle — so the server bounds it by the parent's granted
        # scope, never the root's full scope.
        assert _last_parent_handle_id(apdp) == parent.run_handle_id
        assert _last_parent_handle_id(apdp) != root.run_handle_id


# ─── Fail-closed on server denial ────────────────────────────────


class TestFailClosed:
    @pytest.mark.asyncio
    async def test_scope_attenuation_denied_registers_fail_closed(self) -> None:
        apdp = MockApdpClient()
        apdp.spawn_error_override = ScopeAttenuationDenied(
            "tool 'wire_funds' not in parent.allowed_tools",
            [ScopeViolationDimension.ALLOWED_TOOLS],
        )
        reg = SubagentRegistry(_make_root(apdp))

        result = await reg.on_spawn(
            child_key="denied",
            child_slug=_child_uuid(),
            requested_scope={"allowed_tools": ["wire_funds"]},
        )

        # on_spawn returns None AND resolve returns None — the caller
        # MUST deny the child's tool calls (ungoverned-gate default).
        assert result is None
        assert reg.resolve("denied") is None

    @pytest.mark.asyncio
    async def test_run_handle_invalidated_registers_fail_closed(self) -> None:
        apdp = MockApdpClient()
        apdp.spawn_error_override = RunHandleInvalidated(
            "parent run handle revoked"
        )
        reg = SubagentRegistry(_make_root(apdp))

        result = await reg.on_spawn(child_key="dead", child_slug=_child_uuid())

        assert result is None
        assert reg.resolve("dead") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error, expected",
        [
            (ScopeAttenuationDenied("nope", [ScopeViolationDimension.ALLOWED_TOOLS]), "scope_attenuation"),
            (
                ScopeAttenuationDenied("nope", [], reason_code="DELEGATION_DEPTH_EXCEEDED"),
                "delegation_depth",
            ),
            (ScopeAttenuationDenied("nope", [], reason_code="UNSATISFIABLE_SCOPE"), "unsatisfiable_scope"),
            (RunHandleInvalidated("revoked"), "parent_invalidated"),
        ],
    )
    async def test_refusal_class_names_why_the_spawn_failed_closed(self, error, expected) -> None:
        # A framework turns the class into an instructive message
        # without repeating the server's decision detail.
        apdp = MockApdpClient()
        apdp.spawn_error_override = error
        reg = SubagentRegistry(_make_root(apdp))
        assert await reg.on_spawn(child_key="c", child_slug=_child_uuid()) is None
        assert reg.refusal_class("c") == expected
        # A child under the refused one is refused as such.
        assert await reg.on_spawn(child_key="gc", child_slug=_child_uuid(), parent_key="c") is None
        assert reg.refusal_class("gc") == "parent_refused"
        assert await reg.on_spawn(child_key="x", child_slug=_child_uuid(), parent_key="nobody") is None
        assert reg.refusal_class("x") == "parent_unknown"
        # Cleared with the marker.
        await reg.on_stop("c")
        assert reg.refusal_class("c") is None

    @pytest.mark.asyncio
    async def test_implicit_spawn_while_refused_child_is_open_fails_closed(
        self,
    ) -> None:
        # This test used to assert that the next implicit spawn
        # re-parents onto the stack-top sibling `good`, skipping the
        # refused `bad`. An implicit spawn while a refused child is still
        # open may BE that child's grandchild; it must fail closed, not run
        # under a sibling's or the root's authority.
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        good = await reg.on_spawn(child_key="good", child_slug=_child_uuid())
        assert good is not None

        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        denied = await reg.on_spawn(child_key="bad", child_slug=_child_uuid())
        assert denied is None

        apdp.spawn_error_override = None
        spawns_before = len(apdp.spawn_subagent_calls)
        nxt = await reg.on_spawn(child_key="next", child_slug=_child_uuid())
        assert nxt is None
        assert reg.refusal_class("next") == "parent_refused"
        assert len(apdp.spawn_subagent_calls) == spawns_before

        # Once the refused child is stopped, implicit spawns resolve to
        # the live stack-top again.
        await reg.on_stop("bad")
        await reg.on_spawn(child_key="next2", child_slug=_child_uuid())
        assert _last_parent_handle_id(apdp) == good.run_handle_id

    @pytest.mark.asyncio
    async def test_implicit_grandchild_of_refused_child_never_reaches_root(
        self,
    ) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))
        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        assert await reg.on_spawn(child_key="p", child_slug=_child_uuid()) is None
        apdp.spawn_error_override = None
        spawns_before = len(apdp.spawn_subagent_calls)
        assert await reg.on_spawn(child_key="gc", child_slug=_child_uuid()) is None
        assert len(apdp.spawn_subagent_calls) == spawns_before

    @pytest.mark.asyncio
    async def test_explicit_denied_parent_key_fails_closed(self) -> None:
        # F1 — an EXPLICIT parent_key that is itself fail-closed (its own
        # spawn was denied) must NOT re-parent the child onto root. The
        # denied parent's subtree must not execute.
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        # Parent's own spawn is denied → "p" is marked fail-closed.
        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        p = await reg.on_spawn(child_key="p", child_slug=_child_uuid())
        assert p is None
        assert reg.resolve("p") is None

        # A child naming that denied parent explicitly must fail closed —
        # NOT fall through to the root (which is laxer).
        apdp.spawn_error_override = None
        spawns_before = len(apdp.spawn_subagent_calls)
        child = await reg.on_spawn(
            child_key="c", child_slug=_child_uuid(), parent_key="p"
        )
        assert child is None
        assert reg.resolve("c") is None
        # No spawn round-trip was made under root's authority.
        assert len(apdp.spawn_subagent_calls) == spawns_before

    @pytest.mark.asyncio
    async def test_non_governance_exception_propagates(self) -> None:
        # F4a — a NON-governance exception from the backend's
        # spawn_subagent is a typed refusal (GovernanceUnavailable) that
        # carries the real fault as its cause, so the caller sees both
        # (it ALSO leaves a fail-closed marker, see
        # test_unexpected_spawn_error_registers_fail_closed_marker).
        apdp = MockApdpClient()
        apdp.spawn_error_override = RuntimeError("APDP transport exploded")
        reg = SubagentRegistry(_make_root(apdp))

        with pytest.raises(GovernanceUnavailable, match="refusing to run the sub-agent") as info:
            await reg.on_spawn(child_key="x", child_slug=_child_uuid())
        assert isinstance(info.value.__cause__, RuntimeError)
        assert "transport exploded" in str(info.value.__cause__)

        assert reg.resolve("x") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "error",
        [RuntimeError("transport exploded"), GovernanceUnavailable("no child token")],
        ids=["runtime_error", "governance_unavailable"],
    )
    async def test_unexpected_spawn_error_registers_fail_closed_marker(
        self, error
    ) -> None:
        # Every failed spawn leaves a fail-closed marker, not just
        # the two governance denials, so the child's subtree cannot be
        # re-parented onto a laxer ancestor.
        apdp = MockApdpClient()
        apdp.spawn_error_override = error
        reg = SubagentRegistry(_make_root(apdp))
        # A raw backend fault surfaces as a typed refusal.
        with pytest.raises(GovernanceUnavailable):
            await reg.on_spawn(child_key="x", child_slug=_child_uuid())
        assert reg.refusal_class("x") == "spawn_failed"
        apdp.spawn_error_override = None
        assert (
            await reg.on_spawn(child_key="y", child_slug=_child_uuid(), parent_key="x")
            is None
        )
        assert await reg.on_spawn(child_key="z", child_slug=_child_uuid()) is None

    @pytest.mark.asyncio
    async def test_denied_then_respawn_clears_marker(self) -> None:
        # F4b — a child_key denied once, then re-spawned successfully,
        # clears its fail-closed marker and becomes resolvable.
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))

        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        first = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert first is None
        assert reg.resolve("a") is None

        # Retry the same child_key now that the server would accept it.
        apdp.spawn_error_override = None
        second = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert second is not None
        assert reg.resolve("a") is second


# ─── F3 — duplicate live child_key guard ─────────────────────────


class TestDuplicateGuard:
    @pytest.mark.asyncio
    async def test_duplicate_live_key_returns_existing_without_respawn(
        self,
    ) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))

        first = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert first is not None
        spawns_after_first = len(apdp.spawn_subagent_calls)

        # Second on_spawn for the SAME live key returns the existing
        # handle and does NOT issue another spawn round-trip (no leaked
        # handle, no duplicate attestation).
        second = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert second is first
        assert len(apdp.spawn_subagent_calls) == spawns_after_first

    @pytest.mark.asyncio
    async def test_duplicate_live_key_does_not_double_push_stack(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert a is not None
        # Duplicate — must not push "a" onto the stack a second time.
        await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        # A SINGLE on_stop("a") must fully drain the stack. If the
        # duplicate had double-pushed, one "a" would dangle and the next
        # implicit spawn would still attribute to "a" instead of root.
        await reg.on_stop("a")
        await reg.on_spawn(child_key="c", child_slug=_child_uuid())
        assert _last_parent_handle_id(apdp) == root.run_handle_id


# ─── resolve ─────────────────────────────────────────────────────


class TestResolve:
    @pytest.mark.asyncio
    async def test_resolve_returns_registered_child(self) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))

        child = await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        assert reg.resolve("a") is child

    def test_resolve_unknown_key_returns_none(self) -> None:
        reg = SubagentRegistry(_make_root(MockApdpClient()))
        assert reg.resolve("never-spawned") is None


# ─── on_stop ─────────────────────────────────────────────────────


class TestOnStop:
    @pytest.mark.asyncio
    async def test_on_stop_closes_and_removes_child(self) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))

        child = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        assert child is not None

        await reg.on_stop("a")

        # Child handle was completed (its session closed server-side)
        # and the entry dropped.
        assert child.session_id in apdp._closed_sessions
        assert reg.resolve("a") is None

    @pytest.mark.asyncio
    async def test_on_stop_pops_stack_back_to_parent(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        b = await reg.on_spawn(child_key="b", child_slug=_child_uuid())
        assert a is not None and b is not None

        await reg.on_stop("b")

        # After b stops, the stack top is a again — a subsequent
        # no-parent spawn attributes to a, not the (gone) b.
        await reg.on_spawn(child_key="c", child_slug=_child_uuid())
        assert _last_parent_handle_id(apdp) == a.run_handle_id

    @pytest.mark.asyncio
    async def test_on_stop_out_of_order_is_safe(self) -> None:
        apdp = MockApdpClient()
        root = _make_root(apdp)
        reg = SubagentRegistry(root)

        a = await reg.on_spawn(child_key="a", child_slug=_child_uuid())
        b = await reg.on_spawn(child_key="b", child_slug=_child_uuid())
        assert a is not None and b is not None

        # Stop the OUTER sub-agent (a) first — b is still on the stack.
        await reg.on_stop("a")

        await reg.on_spawn(child_key="c", child_slug=_child_uuid())
        assert _last_parent_handle_id(apdp) == b.run_handle_id

    @pytest.mark.asyncio
    async def test_on_stop_unknown_key_is_noop(self) -> None:
        reg = SubagentRegistry(_make_root(MockApdpClient()))
        # Must not raise.
        await reg.on_stop("never-registered")


# ─── default_subagent_scope ──────────────────────────────────────


class TestDefaultScope:
    @pytest.mark.asyncio
    async def test_default_scope_used_when_requested_none(self) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(
            _make_root(apdp),
            default_subagent_scope={
                "allowed_tools": ["search.web"],
                "max_depth": 1,
            },
        )

        await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        req = apdp.spawn_subagent_calls[-1]["requested_scope"]
        assert req["allowed_tools"] == ["search.web"]
        assert req["max_depth"] == 1

    @pytest.mark.asyncio
    async def test_explicit_requested_scope_overrides_default(self) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(
            _make_root(apdp),
            default_subagent_scope={"allowed_tools": ["search.web"]},
        )

        await reg.on_spawn(
            child_key="a",
            child_slug=_child_uuid(),
            requested_scope={"allowed_tools": ["summarize.text"]},
        )

        req = apdp.spawn_subagent_calls[-1]["requested_scope"]
        assert req["allowed_tools"] == ["summarize.text"]

    @pytest.mark.asyncio
    async def test_empty_default_still_registers_child(self) -> None:
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))  # empty default

        child = await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        # Empty scope is the deliberate fail-closed default: the child
        # is registered and the handle IS returned — authorizing its
        # tool calls (which will be denied by the empty scope) is the
        # caller's responsibility, not the registry's.
        assert child is not None
        assert reg.resolve("a") is child
        req = apdp.spawn_subagent_calls[-1]["requested_scope"]
        assert req["allowed_tools"] == []
        assert req["max_depth"] == 0


# ─── env-var default resolution ──────────────────────────────────


class TestEnvDefaultScope:
    def test_env_json_parsed_into_kwargs(self, monkeypatch: Any) -> None:
        monkeypatch.setenv(
            DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
            '{"allowed_tools": ["a"], "max_depth": 2}',
        )
        scope = default_subagent_scope_from_env()
        assert scope == {"allowed_tools": ["a"], "max_depth": 2}

    def test_env_camelcase_tolerated(self, monkeypatch: Any) -> None:
        # A blob copy-pasted from the TS lane (camelCase) still resolves.
        monkeypatch.setenv(
            DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
            '{"allowedTools": ["a"], "maxDepth": 2}',
        )
        scope = default_subagent_scope_from_env()
        assert scope == {"allowed_tools": ["a"], "max_depth": 2}

    def test_env_unset_is_empty_fail_closed(self, monkeypatch: Any) -> None:
        monkeypatch.delenv(DEFAULT_SUBAGENT_SCOPE_ENV_VAR, raising=False)
        assert default_subagent_scope_from_env() == {}

    def test_env_malformed_json_is_empty_fail_closed(
        self, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(DEFAULT_SUBAGENT_SCOPE_ENV_VAR, "{not json")
        assert default_subagent_scope_from_env() == {}

    def test_env_non_object_is_empty_fail_closed(
        self, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(DEFAULT_SUBAGENT_SCOPE_ENV_VAR, "[1, 2, 3]")
        assert default_subagent_scope_from_env() == {}

    @pytest.mark.asyncio
    async def test_constructor_reads_env_when_param_omitted(
        self, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(
            DEFAULT_SUBAGENT_SCOPE_ENV_VAR, '{"allowed_tools": ["envtool"]}'
        )
        apdp = MockApdpClient()
        reg = SubagentRegistry(_make_root(apdp))  # no explicit default

        await reg.on_spawn(child_key="a", child_slug=_child_uuid())

        req = apdp.spawn_subagent_calls[-1]["requested_scope"]
        assert req["allowed_tools"] == ["envtool"]
