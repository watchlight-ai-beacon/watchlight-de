"""BaseRunHandle.spawn_subagent.

Wire-level + ergonomics + fail-closed tests for the SDK's
``POST /v1/spawn_subagent`` integration. These tests pin the
contract the Python plugin propagation work (LangGraph,
Pydantic AI, etc.) builds on top of.

Scope:

- Explicit scope kwargs marshalled to the canonical wire shape.
- Bare-string ``allowed_resources`` coerced to
  :class:`ResourceMatcher` for ergonomic call sites.
- Fail-closed defaults: omitted kwargs marshal as empty lists +
  zero numerics (locked invariant #2 — sub-agent scope attenuation).
- 200 OK → sub-handle carries ``granted_scope``.
- 403 ``scope_attenuation_violation`` → :class:`ScopeAttenuationDenied`
  with the typed dimension list.
- 404 ``run_handle_invalidated`` → :class:`RunHandleInvalidated`.
- Sub-agent ``authorize_action`` uses the sub-agent's
  ``run_handle_id``, not the parent's (per
  ``feedback_subagents_must_be_governed``).
- Concurrent spawn doesn't bleed scope between sibling sub-agents via
  the contextvar.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core_testing import register_test_run

from watchlight_core import (
    BaseRunHandle,
    GrantedScope,
    InterceptorKillRegistry,
    ResourceMatcher,
    RunHandleInvalidated,
    ScopeAttenuationDenied,
    ScopeViolationDimension,
    current_subagent_handle,
)
from watchlight_core_testing import MockApdpClient


# ─── Test plugin scaffold ────────────────────────────────────────


class _Plugin:
    """Bare minimum :class:`GovernedPlugin` for these tests.

    Mirrors the ``GovernedPlugin`` Protocol so :class:`BaseRunHandle`
    can run against it without dragging in a full framework plugin.
    """

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
        self.kill_signal_registry: Optional[InterceptorKillRegistry] = None


def _make_handle(
    *,
    apdp: Optional[MockApdpClient] = None,
    agent_uuid: str = "00000000-0000-0000-0000-000000000001",
    run_handle_id: Optional[str] = None,
) -> BaseRunHandle:
    """Construct a synthetic root :class:`BaseRunHandle` whose
    ``agent_uuid`` and ``run_handle_id`` are valid UUIDs so the
    wire-shape serialisation can round-trip cleanly."""
    apdp = apdp or MockApdpClient()
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid=agent_uuid,
        session_id=f"ses_{uuid.uuid4()}",
        run_handle_id=run_handle_id or str(uuid.uuid4()),
    )
    # synthetic test handle bypasses the production
    # ``async with`` entry path; flip the fail-closed flag so the
    # lineage contract guard accepts direct authorize / publish calls.
    handle._aentered = True
    return handle


CHILD_UUID = "22222222-2222-2222-2222-222222222222"


# ─── Wire shape ──────────────────────────────────────────────────


class TestWireShape:
    """Asserts the SDK marshals the kwargs into the canonical
    request body."""

    @pytest.mark.asyncio
    async def test_explicit_scope_marshalled_to_wire(self) -> None:
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp)
        await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "audit q3 invoices", "objective": "Delegated sub-task"},
            allowed_tools=["search.web", "summarize.text"],
            allowed_resources=[ResourceMatcher(matcher="doc::*")],
            allowed_intents=["audit q3 invoices"],
            max_depth=2,
            time_budget_seconds=300,
        )
        assert len(apdp.spawn_subagent_calls) == 1
        body = apdp.spawn_subagent_calls[0]
        # Envelope identifiers
        assert body["parent_agent_id"] == handle.agent_uuid
        assert body["child_agent_id"] == CHILD_UUID
        assert body["parent_run_handle_id"] == handle.run_handle_id
        # Canonical snake_case requested_scope
        scope = body["requested_scope"]
        assert scope["allowed_tools"] == ["search.web", "summarize.text"]
        assert scope["allowed_resources"] == [{"matcher": "doc::*"}]
        assert scope["allowed_intents"] == ["audit q3 invoices"]
        assert scope["max_depth"] == 2
        assert scope["time_budget_seconds"] == 300

    @pytest.mark.asyncio
    async def test_string_resources_coerced_to_resource_matcher(self) -> None:
        """Bare-string ergonomic form is wrapped into the canonical
        ``{"matcher": "..."}`` shape on the wire."""
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp)
        await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["search.web"],
            allowed_resources=["doc:foo", "url::https://*"],
        )
        body = apdp.spawn_subagent_calls[0]
        assert body["requested_scope"]["allowed_resources"] == [
            {"matcher": "doc:foo"},
            {"matcher": "url::https://*"},
        ]


# ─── Fail-closed defaults ────────────────────────────────────────


class TestFailClosedDefaults:
    """Invariant #2 — omitted kwargs = zero privileges. Empty lists +
    ``max_depth=0``; no time budget is sent, so the child inherits the
    parent's remaining time."""

    @pytest.mark.asyncio
    async def test_fail_closed_default_when_kwargs_omitted(self) -> None:
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp)
        await handle.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"})
        body = apdp.spawn_subagent_calls[0]
        scope = body["requested_scope"]
        assert scope["allowed_tools"] == []
        assert scope["allowed_resources"] == []
        assert scope["allowed_intents"] == []
        assert scope["max_depth"] == 0
        # No budget named: none is sent (never 0), so the server resolves
        # it to the parent's remaining time. Every other canonical field is
        # present even when defaulted.
        assert set(scope.keys()) == {
            "allowed_tools",
            "allowed_resources",
            "allowed_intents",
            "max_depth",
        }


# ─── 200 OK path ─────────────────────────────────────────────────


class TestSuccessfulSpawn:
    """200 OK → mint a new sub-agent handle with the server-attested
    grant attached."""

    @pytest.mark.asyncio
    async def test_200_response_returns_sub_handle_with_granted_scope(
        self,
    ) -> None:
        apdp = MockApdpClient()
        # Custom 200 response so we can assert the grant flows through.
        apdp.spawn_response_override = {
            "child_run_handle_id": "33333333-3333-3333-3333-333333333333",
            # The real server always mints the child run credential.
            "child_session_token": "sst_child_fixture",
            "granted_scope": {
                "allowed_tools": ["search.web"],
                "allowed_resources": [{"matcher": "doc::*"}],
                "allowed_intents": [],
                "max_depth": 1,
                "time_budget_seconds": 60,
                "depth": 1,
                "parent_run_handle_id": (
                    "00000000-0000-0000-0000-000000000010"
                ),
            },
            "lineage_event_id": None,
        }
        handle = _make_handle(apdp=apdp)
        child = await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["search.web"],
            allowed_resources=[ResourceMatcher(matcher="doc::*")],
            max_depth=1,
            time_budget_seconds=60,
        )
        assert isinstance(child, BaseRunHandle)
        assert child.run_handle_id == (
            "33333333-3333-3333-3333-333333333333"
        )
        assert child.agent_uuid == CHILD_UUID
        # Sub-agent carries the server-attested grant; root does not.
        assert child.granted_scope is not None
        assert isinstance(child.granted_scope, GrantedScope)
        assert child.granted_scope.allowed_tools == ["search.web"]
        assert child.granted_scope.allowed_resources == [
            ResourceMatcher(matcher="doc::*")
        ]
        assert child.granted_scope.max_depth == 1
        assert child.granted_scope.time_budget_seconds == 60
        assert child.granted_scope.depth == 1
        # Root handle never has a granted_scope (it carries the
        # agent's full registered scope; no attenuation declared).
        assert handle.granted_scope is None


# ─── 403 + 404 typed errors ──────────────────────────────────────


class TestDenialPaths:
    """APDP wire denials surface as typed exceptions, not strings —
    ``feedback_production_grade_for_non_demo_code`` bars stringly
    typed errors on the customer-facing API."""

    @pytest.mark.asyncio
    async def test_403_scope_attenuation_raises_typed_exception(
        self,
    ) -> None:
        apdp = MockApdpClient()
        apdp.spawn_error_override = ScopeAttenuationDenied(
            reason="scope_attenuation_violation",
            violations=[
                ScopeViolationDimension.ALLOWED_TOOLS,
                ScopeViolationDimension.MAX_DEPTH,
            ],
        )
        handle = _make_handle(apdp=apdp)
        with pytest.raises(ScopeAttenuationDenied) as exc_info:
            await handle.spawn_subagent(
                CHILD_UUID,
                child_intent={"category": "research", "objective": "Delegated sub-task"},
                allowed_tools=["search.web", "delete.everything"],
                max_depth=5,
            )
        err = exc_info.value
        assert err.reason == "scope_attenuation_violation"
        # The typed dimension list is the canonical data carrier.
        assert ScopeViolationDimension.ALLOWED_TOOLS in err.violations
        assert ScopeViolationDimension.MAX_DEPTH in err.violations
        assert len(err.violations) == 2

    @pytest.mark.asyncio
    async def test_404_run_handle_invalidated_raises_typed_exception(
        self,
    ) -> None:
        apdp = MockApdpClient()
        apdp.spawn_error_override = RunHandleInvalidated(
            reason="run_handle_invalidated",
        )
        handle = _make_handle(apdp=apdp)
        with pytest.raises(RunHandleInvalidated) as exc_info:
            await handle.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"})
        assert exc_info.value.reason == "run_handle_invalidated"

    @pytest.mark.asyncio
    async def test_apdp_client_decodes_403_violations_from_wire(self) -> None:
        """End-to-end decode — when the SDK hits a real wire-shape 403,
        the typed exception is raised with the dimension list. This
        exercises the ApdpClient decoder rather than the mock's
        override path, so a regression in the decoder shows up here."""
        import httpx

        from watchlight_core.apdp_client import ApdpClient

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/health":
                return httpx.Response(
                    200,
                    json={"auth": "ok", "kind": "plugin"},
                )
            assert request.url.path == "/v1/spawn_subagent"
            return httpx.Response(
                403,
                json={
                    "reason": "scope_attenuation_violation",
                    "violations": [
                        "allowed_tools",
                        "time_budget_seconds",
                    ],
                },
            )

        transport = httpx.MockTransport(handler)
        client = ApdpClient(
            "http://localhost",
            auto_probe=False,
        )
        # Swap the transport on the lazy client.
        _ = client.client  # force construction
        await client._client.aclose()  # type: ignore[union-attr]
        client._client = httpx.AsyncClient(
            base_url="http://localhost",
            transport=transport,
        )
        with pytest.raises(ScopeAttenuationDenied) as exc_info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"),
                {
                    "parent_agent_id": (
                        "00000000-0000-0000-0000-000000000001"
                    ),
                    "child_agent_id": (
                        "00000000-0000-0000-0000-000000000002"
                    ),
                    "parent_run_handle_id": (
                        "00000000-0000-0000-0000-000000000003"
                    ),
                    "requested_scope": {},
                }
            )
        await client.close()
        assert exc_info.value.violations == [
            ScopeViolationDimension.ALLOWED_TOOLS,
            ScopeViolationDimension.TIME_BUDGET_SECONDS,
        ]
        # A strict-subset refusal carries no delegation-depth code.
        assert exc_info.value.reason_code is None

    @pytest.mark.asyncio
    async def test_apdp_client_decodes_the_delegation_depth_code(self) -> None:
        """A spawn past the tree's depth limit keeps the
        ``scope_attenuation_violation`` discriminator and adds the
        DELEGATION_DEPTH_EXCEEDED code with the observed depth and the limit."""
        import httpx

        from watchlight_core.apdp_client import ApdpClient

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/health":
                return httpx.Response(200, json={"auth": "ok", "kind": "plugin"})
            return httpx.Response(
                403,
                json={
                    "reason": "scope_attenuation_violation",
                    "violations": ["max_depth"],
                    "reason_code": "DELEGATION_DEPTH_EXCEEDED",
                    "observed_depth": 9,
                    "max_delegation_depth": 8,
                },
            )

        client = ApdpClient("http://localhost", auto_probe=False)
        _ = client.client
        await client._client.aclose()  # type: ignore[union-attr]
        client._client = httpx.AsyncClient(
            base_url="http://localhost", transport=httpx.MockTransport(handler)
        )
        with pytest.raises(ScopeAttenuationDenied) as exc_info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"),
                {
                    "parent_agent_id": "00000000-0000-0000-0000-000000000001",
                    "child_agent_id": "00000000-0000-0000-0000-000000000002",
                    "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
                    "requested_scope": {},
                }
            )
        await client.close()
        err = exc_info.value
        assert err.reason == "scope_attenuation_violation"
        assert err.reason_code == "DELEGATION_DEPTH_EXCEEDED"
        assert (err.observed_depth, err.max_delegation_depth) == (9, 8)


# ─── Sub-agent governance attribution ────────────────────────────


class TestSubagentAttribution:
    """``feedback_subagents_must_be_governed`` — the sub-agent's
    authorize calls MUST carry the sub-agent's identity, not the
    parent's."""

    @pytest.mark.asyncio
    async def test_sub_handle_authorize_action_carries_run_handle_id(
        self,
    ) -> None:
        apdp = MockApdpClient()
        apdp.spawn_response_override = {
            "child_run_handle_id": "44444444-4444-4444-4444-444444444444",
            # The real server always mints the child run credential.
            "child_session_token": "sst_child_fixture",
            "granted_scope": {
                "allowed_tools": ["search.web"],
                "allowed_resources": [],
                "allowed_intents": [],
                "max_depth": 0,
                "time_budget_seconds": 60,
                "depth": 1,
            },
        }
        handle = _make_handle(apdp=apdp)
        parent_principal = handle.agent_uuid
        child = await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["search.web"],
            time_budget_seconds=60,
        )
        # Clear the authorize_calls log so the only entry comes from
        # the sub-agent's call below.
        apdp.authorize_calls.clear()
        await child.authorize_action("execute", "search.web")
        # Exactly one authorize call, and it carries the sub-agent's
        # identity in the Cedar principal AND the sub-agent's
        # session_id. Post-v0.9.12 the child session id is the SERVER-derived
        # ``ses_<child-run-handle>`` (here via the SDK fallback, since this
        # override omits ``child_session_id``) — distinct from the raw
        # run_handle_id but deterministically derived from it.
        assert len(apdp.authorize_calls) == 1
        call = apdp.authorize_calls[0]
        assert CHILD_UUID in call["principal"]
        assert parent_principal not in call["principal"]
        assert call["session_id"] == child.session_id == f"ses_{child.run_handle_id}"


# ─── Concurrent-spawn isolation ──────────────────────────────────


class TestContextvarIsolation:
    """Concurrent ``asyncio.gather`` of spawns from a single parent
    MUST keep each spawned handle's contextvar binding isolated.
    Otherwise sibling sub-agents would see each other's scope —
    the privilege-escalation shape ``feedback_subagents_must_be_governed``
    forbids."""

    @pytest.mark.asyncio
    async def test_contextvar_sub_handle_isolated_from_parent(self) -> None:
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp)
        # Root context — no sub-handle is active.
        assert current_subagent_handle() is None

        observed: List[Optional[str]] = []

        async def spawn_and_observe(child_uuid: str) -> Optional[str]:
            child = await handle.spawn_subagent(
                child_uuid,
                child_intent={"category": "research", "objective": "Delegated sub-task"},
                allowed_tools=["search.web"],
            )
            # Yield to ensure the sibling task interleaves; the
            # contextvar binding must remain stable across the await.
            await asyncio.sleep(0)
            active = current_subagent_handle()
            observed.append(active.run_handle_id if active else None)
            return child.run_handle_id

        a, b = await asyncio.gather(
            spawn_and_observe("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            spawn_and_observe("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        )
        # Each task observed ITS OWN sub-handle, not the sibling's.
        # That's the load-bearing invariant — concurrent spawns must
        # NOT bleed scope into each other.
        assert a in observed
        assert b in observed
        assert a != b
        # The PARENT task's contextvar binding is untouched by the
        # spawned tasks' bindings (contextvars are per-task copies).
        assert current_subagent_handle() is None


# ─── sub-agent run_handle_id authorize binding ──────────


_CHILD_HANDLE_ID = "33333333-3333-3333-3333-333333333333"


def _spawn_override(handle_id: str = _CHILD_HANDLE_ID) -> Dict[str, Any]:
    return {
        "child_run_handle_id": handle_id,
        # The real server always mints the child run credential.
        "child_session_token": "sst_child_fixture",
        "granted_scope": {
            "allowed_tools": ["web_search"],
            "allowed_resources": [],
            "allowed_intents": [],
            "max_depth": 1,
            "time_budget_seconds": 60,
            "depth": 1,
            "parent_run_handle_id": "00000000-0000-0000-0000-000000000010",
        },
        "lineage_event_id": None,
    }


class TestSubAgentRunHandleBinding:
    """A spawned sub-agent MUST present its APDP-minted ``run_handle_id``
    in the Cedar context on every authorize, so wl-apdp's
    ``check_subagent_scope`` can validate the child's attenuated scope.
    A sub-agent presenting NO handle is denied server-side
    (``subagent_run_handle_required``) instead of silently escalating to
    the root's full scope — so this binding is what makes sub-agent
    scope attenuation real. A ROOT handle carries a client-minted id
    the server store does not know and MUST NOT present it."""

    @pytest.mark.asyncio
    async def test_subagent_authorize_injects_its_run_handle_id(self) -> None:
        apdp = MockApdpClient()
        apdp.spawn_response_override = _spawn_override()
        handle = _make_handle(apdp=apdp)
        child = await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["web_search"],
            max_depth=1,
            time_budget_seconds=60,
        )
        # allow_no_run_handle bypasses the orthogonal lineage guard;
        # the run_handle_id injection under test is independent of it.
        await child.authorize_action(
            "execute", "web_search", allow_no_run_handle=True
        )
        ctx = apdp.authorize_calls[-1]["context"]
        assert ctx["run_handle_id"] == _CHILD_HANDLE_ID
        assert ctx["run_handle_id"] == child.run_handle_id

    @pytest.mark.asyncio
    async def test_root_authorize_omits_run_handle_id(self) -> None:
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp)  # root — parent_handle is None
        await handle.authorize_action("execute", "web_search")
        ctx = apdp.authorize_calls[-1]["context"]
        assert "run_handle_id" not in ctx

    @pytest.mark.asyncio
    async def test_caller_supplied_run_handle_id_wins(self) -> None:
        apdp = MockApdpClient()
        apdp.spawn_response_override = _spawn_override()
        handle = _make_handle(apdp=apdp)
        child = await handle.spawn_subagent(
            CHILD_UUID,
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            allowed_tools=["web_search"],
            max_depth=1,
            time_budget_seconds=60,
        )
        await child.authorize_action(
            "execute",
            "web_search",
            context={"run_handle_id": "caller-override"},
            allow_no_run_handle=True,
        )
        ctx = apdp.authorize_calls[-1]["context"]
        assert ctx["run_handle_id"] == "caller-override"


# ─── option b — server-minted ROOT run-handle binding ───────────


class TestServerMintedRootRunHandle:
    """Option b — when wl-apdp mints a first-class run handle for the
    ROOT run (returned as ``root_run_handle_id`` on ``POST /sessions``),
    the SDK presents that server-KNOWN id on every root authorize so
    runtime Attenuate applies to the root run. A root WITHOUT a
    server-minted handle (older wl-apdp / no run-handle store) keeps the
    prior behaviour: client-minted id, never presented."""

    @pytest.mark.asyncio
    async def test_server_root_authorize_injects_run_handle_id(self) -> None:
        apdp = MockApdpClient()
        server_id = "55555555-5555-5555-5555-555555555555"
        handle = _make_handle(apdp=apdp, run_handle_id=server_id)
        # Simulate start_run having received root_run_handle_id from the
        # session response and flagged the handle as server-minted.
        handle._server_run_handle = True
        await handle.authorize_action("execute", "web_search")
        ctx = apdp.authorize_calls[-1]["context"]
        assert ctx["run_handle_id"] == server_id
        assert ctx["run_handle_id"] == handle.run_handle_id

    @pytest.mark.asyncio
    async def test_server_root_caller_override_still_wins(self) -> None:
        apdp = MockApdpClient()
        handle = _make_handle(apdp=apdp, run_handle_id="server-root-id")
        handle._server_run_handle = True
        await handle.authorize_action(
            "execute", "web_search", context={"run_handle_id": "caller-override"}
        )
        ctx = apdp.authorize_calls[-1]["context"]
        assert ctx["run_handle_id"] == "caller-override"

    def test_parse_root_run_handle_id_present(self) -> None:
        session = {
            "session": {"id": "ses_x"},
            "root_run_handle_id": "66666666-6666-6666-6666-666666666666",
        }
        assert (
            BaseRunHandle.parse_root_run_handle_id(session)
            == "66666666-6666-6666-6666-666666666666"
        )

    def test_parse_root_run_handle_id_absent_or_malformed(self) -> None:
        # Absent → None (older wl-apdp / no run-handle store).
        assert BaseRunHandle.parse_root_run_handle_id({"session": {"id": "x"}}) is None
        # Empty string → None (never present a blank id).
        assert (
            BaseRunHandle.parse_root_run_handle_id({"root_run_handle_id": ""}) is None
        )
        # Non-dict → None (fail-soft, never raise).
        assert BaseRunHandle.parse_root_run_handle_id(None) is None  # type: ignore[arg-type]

    def test_server_run_handle_flag_false_when_also_subagent(self) -> None:
        # Defense in depth: a handle constructed with BOTH a parent (making
        # it a sub-agent) and server_run_handle=True is NOT treated as a
        # server root — a handle is either a root or a sub-agent, never both.
        parent = _make_handle()
        child = BaseRunHandle(
            plugin=parent._plugin,
            agent_uuid="00000000-0000-0000-0000-000000000002",
            session_id="ses_child",
            parent_handle=parent,
            run_handle_id="77777777-7777-7777-7777-777777777777",
            server_run_handle=True,
        )
        assert child._is_subagent is True
        assert child._server_run_handle is False


# ─── Spawn-tree depth is AUTO-CALCULATED (regression: #lineage-depth) ──


class TestSubagentDepthAutoCalc:
    """Every handle's ``depth`` is auto-calculated, never a literal:
    server-authoritative (``granted_scope.depth``) first, else derived
    from the parent chain (``parent.depth + 1``); a root is 0.

    Regression guard for the dashboard rendering every SUB-AGENT as
    ``DEPTH 0`` — the SDK used to hardcode ``payload["depth"] = 0`` on the
    ``execution_started`` event and never tracked a per-handle depth.
    """

    def test_root_handle_is_depth_zero(self) -> None:
        assert _make_handle().depth == 0

    @pytest.mark.asyncio
    async def test_child_and_grandchild_depth_from_parent_chain(self) -> None:
        # The default MockApdpClient spawn response carries depth 0, so this
        # exercises the PARENT-CHAIN fallback (the path that fixes deepagents,
        # whose base-minted children never had a server depth wired through).
        root = _make_handle()
        child = await root.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        assert child.depth == 1, "first-level sub-agent must be depth 1, not 0"

        grandchild = await child.spawn_subagent(
            "33333333-3333-3333-3333-333333333333", child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"]
        )
        assert grandchild.depth == 2, "second-level sub-agent must be depth 2"

    @pytest.mark.asyncio
    async def test_server_authoritative_depth_wins(self) -> None:
        apdp = MockApdpClient()
        apdp.spawn_response_override = {
            "child_run_handle_id": str(uuid.uuid4()),
            # The real server always mints the child run credential.
            "child_session_token": "sst_child_fixture",
            "granted_scope": {
                "allowed_tools": ["search.web"],
                "allowed_resources": [],
                "allowed_intents": [],
                "max_depth": 1,
                "time_budget_seconds": 60,
                "depth": 3,  # server-attested spawn-tree depth
            },
            "lineage_event_id": None,
        }
        root = _make_handle(apdp=apdp)
        child = await root.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        assert child.depth == 3, "the wl-apdp-attested granted_scope.depth must win"

    @pytest.mark.asyncio
    async def test_child_inherits_the_parent_goal_on_execution_started(self) -> None:
        """A sub-agent runs under the SAME goal as its parent: the child's
        ``execution_started`` carries the parent's ``goal_id`` so the whole
        tree renders under one goal in lineage."""
        root = _make_handle()
        root._goal_id = "11111111-1111-4111-8111-111111111101"
        child = await root.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        captured: List[Dict[str, Any]] = []

        async def _capture(
            run: Any, events: List[Dict[str, Any]]
        ) -> Dict[str, Any]:
            captured.extend(events)
            return {"accepted": len(events)}

        child._plugin.apdp.publish_events = _capture  # type: ignore[assignment]
        await child._emit_execution_started(child.execution_id)
        started = [e for e in captured if e["event_type"] == "execution_started"]
        assert started, "child must emit an execution_started"
        assert started[-1]["payload"]["goal_id"] == "11111111-1111-4111-8111-111111111101"

    @pytest.mark.asyncio
    async def test_execution_started_payload_carries_real_depth(self) -> None:
        root = _make_handle()
        child = await root.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        captured: List[Dict[str, Any]] = []

        async def _capture(
            run: Any, events: List[Dict[str, Any]]
        ) -> Dict[str, Any]:
            captured.extend(events)
            return {"accepted": len(events)}

        child._plugin.apdp.publish_events = _capture  # type: ignore[assignment]
        await child._emit_execution_started(child.execution_id)

        started = [e for e in captured if e["event_type"] == "execution_started"]
        assert started, "child must emit an execution_started"
        assert started[-1]["payload"]["depth"] == 1, (
            "the emitted execution_started depth must be the auto-calculated "
            "handle depth, never a hardcoded 0"
        )
