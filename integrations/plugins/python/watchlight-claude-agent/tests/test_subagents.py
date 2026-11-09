"""Native Task sub-agent governed-spawn wiring tests.

Order-independent tests for routing the Claude Agent SDK's native Task
sub-agents through the governed ``spawn_subagent`` chokepoint via the
shared :class:`watchlight_core.SubagentRegistry` primitive.

Each test constructs its OWN plugin + :class:`MockApdpClient` — no
shared module-level state, no ordering dependency.

Coverage:

* a real ``spawn_subagent`` round-trip fires on ``SubagentStart`` — the
  mock APDP records ``POST /v1/spawn_subagent`` with the RESOLVED child
  slug (agent-type → UUID) + the DERIVED scope (from the Task tool's
  ``allowed-tools``);
* the child authorizes under the ATTENUATED granted scope — a tool
  in-scope → Allow under the CHILD handle (its own ``run_handle_id``),
  a tool out-of-scope → Deny;
* a ``SubagentStart`` whose spawn is DENIED
  (``ScopeAttenuationDenied``) → the sub-agent's ``PreToolUse`` has NO
  handle → the caller DENIES;
* the plugin never emits a client ``agent_spawn_observed``;
* scope derivation: ``allowed-tools`` surfaced → derived; absent →
  falls back to the operator ``default_subagent_scope``;
* the child's own ``execution_started`` adopts the child handle's
  server-minted ``execution_id`` + per-child ``sst_`` credential.
"""

from __future__ import annotations

import uuid

import pytest

from watchlight_claude_agent import (
    WatchlightClaudeAgentSDKPlugin,
    derive_requested_scope,
    parent_key_from_capture,
    subagent_id_from_capture,
    subagent_slug_from_capture,
)
from watchlight_core import ScopeAttenuationDenied, ScopeViolationDimension
from watchlight_core_testing import MockApdpClient

ROOT_AGENT_SLUG = "root-agent"
ROOT_AGENT_UUID = "00000000-0000-0000-0000-000000000001"
CHILD_AGENT_SLUG = "researcher"
CHILD_AGENT_UUID = "00000000-0000-0000-0000-0000000000a1"


def _make_plugin(*, default_subagent_scope=None):
    """Fresh plugin wired to a fresh MockApdpClient. The root agent and
    the ``researcher`` sub-agent are registered so slug→UUID resolution
    succeeds; both ids are real UUIDs so the spawn wire-shape
    serialises cleanly."""
    apdp = MockApdpClient()
    apdp.known_agents[ROOT_AGENT_SLUG] = ROOT_AGENT_UUID
    apdp.known_agents[CHILD_AGENT_SLUG] = CHILD_AGENT_UUID
    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="tenant-a",
        default_subagent_scope=default_subagent_scope,
    )
    plugin.apdp = apdp
    return plugin, apdp


async def _root(plugin):
    handle = await plugin.start_run(ROOT_AGENT_SLUG)
    handle._aentered = True
    return handle


def _subagent_start(
    *, subagent_id="sub-1", agent_type=CHILD_AGENT_SLUG, allowed_tools=None
):
    capture = {
        "hook": "SubagentStart",
        "subagent_id": subagent_id,
        "agent_type": agent_type,
    }
    if allowed_tools is not None:
        capture["allowed_tools"] = allowed_tools
    return capture


# ─── SubagentStart routes through spawn_subagent ─────────────────────


class TestSpawnRoundTrip:
    @pytest.mark.asyncio
    async def test_subagent_start_fires_spawn_with_resolved_slug_and_scope(
        self,
    ):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root,
            _subagent_start(allowed_tools=["search.web", "summarize.text"]),
        )

        assert child is not None
        # A real POST /v1/spawn_subagent round-trip fired.
        assert len(apdp.spawn_subagent_calls) == 1
        call = apdp.spawn_subagent_calls[-1]
        # RESOLVED child slug: agent-type "researcher" → its UUID.
        assert call["child_agent_id"] == CHILD_AGENT_UUID
        # DERIVED scope from the Task tool's allowed-tools.
        assert call["requested_scope"]["allowed_tools"] == [
            "search.web",
            "summarize.text",
        ]
        # Routed through the ROOT handle (depth-1 spawn).
        assert call["parent_run_handle_id"] == root.run_handle_id
        # The child handle is now resolvable by its SDK id.
        assert plugin.resolve_subagent(root, "sub-1") is child

    @pytest.mark.asyncio
    async def test_spawn_authenticated_with_parent_run_credential(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )

        # The PARENT's per-run sst_ credential authenticated the spawn —
        # never the shared tenant bearer.
        assert apdp.spawn_subagent_tokens[-1] == apdp.token_for(root.run)
        assert apdp.spawn_subagent_tokens[-1] is not None

    @pytest.mark.asyncio
    async def test_grandchild_attenuates_against_direct_parent(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        parent = await plugin.on_subagent_start(
            root,
            _subagent_start(
                subagent_id="p", allowed_tools=["search.web", "summarize.text"]
            ),
        )
        assert parent is not None

        # A grandchild spawned with an explicit parent_key routes through
        # the DIRECT parent's handle — the server bounds it by the
        # parent's granted scope, not the root's.
        capture = _subagent_start(
            subagent_id="g", allowed_tools=["summarize.text"]
        )
        capture["parent_agent_id"] = "p"
        grandchild = await plugin.on_subagent_start(root, capture)

        assert grandchild is not None
        assert apdp.spawn_subagent_calls[-1]["parent_run_handle_id"] == (
            parent.run_handle_id
        )
        assert apdp.spawn_subagent_calls[-1]["parent_run_handle_id"] != (
            root.run_handle_id
        )


# ─── Child authorizes under the attenuated child handle ──────────────


class TestChildAuthorizesAttenuated:
    @pytest.mark.asyncio
    async def test_in_scope_tool_allowed_under_child_handle(self):
        plugin, apdp = _make_plugin()
        apdp.decisions[("execute", "search.web")] = "Allow"
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        child = plugin.resolve_subagent(root, "sub-1")
        assert child is not None

        allowed = await child.authorize_action("execute", "search.web")

        assert allowed is True
        # The authorize round-trip was made under the CHILD's own
        # run_handle_id — never the root's (the privilege-escalation
        # guard).
        ctx = apdp.authorize_calls[-1]["context"]
        assert ctx["run_handle_id"] == child.run_handle_id
        assert ctx["run_handle_id"] != root.run_handle_id

    @pytest.mark.asyncio
    async def test_out_of_scope_tool_denied(self):
        plugin, apdp = _make_plugin()
        apdp.decisions[("execute", "wire.funds")] = "Deny"
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        child = plugin.resolve_subagent(root, "sub-1")
        assert child is not None

        allowed = await child.authorize_action("execute", "wire.funds")

        assert allowed is False
        assert apdp.authorize_calls[-1]["context"]["run_handle_id"] == (
            child.run_handle_id
        )


# ─── Denied spawn → PreToolUse denies (no handle) ────────────────────


class TestDeniedSpawnFailsClosed:
    @pytest.mark.asyncio
    async def test_scope_attenuation_denied_yields_no_handle(self):
        plugin, apdp = _make_plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied(
            "tool 'wire.funds' not in parent.allowed_tools",
            [ScopeViolationDimension.ALLOWED_TOOLS],
        )
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["wire.funds"])
        )

        # on_subagent_start returns None AND the sub-agent's PreToolUse
        # resolve returns None — the caller MUST deny the tool call.
        assert child is None
        assert plugin.resolve_subagent(root, "sub-1") is None

    @pytest.mark.asyncio
    async def test_pretooluse_denies_when_spawn_denied(self):
        """End-to-end: a denied spawn means the sub-agent's PreToolUse
        has no governed handle, so the customer's loop denies the tool
        call (ungoverned-request gate). No authorize round-trip fires."""
        plugin, apdp = _make_plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        root = await _root(plugin)
        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["wire.funds"])
        )

        handle = plugin.resolve_subagent(root, "sub-1")

        # The customer's PreToolUse loop: no handle ⇒ DENY, never
        # authorize.
        denied = handle is None
        assert denied is True
        assert apdp.authorize_calls == []

    @pytest.mark.asyncio
    async def test_unregistered_subagent_fails_closed(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, _subagent_start(agent_type="not-registered")
        )

        # Unresolvable principal → refuse to spawn, no round-trip, deny.
        assert child is None
        assert plugin.resolve_subagent(root, "sub-1") is None
        assert apdp.spawn_subagent_calls == []

    @pytest.mark.asyncio
    async def test_missing_subagent_id_fails_closed(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, {"hook": "SubagentStart", "agent_type": CHILD_AGENT_SLUG}
        )

        assert child is None
        assert apdp.spawn_subagent_calls == []


# ─── No client-side agent_spawn_observed emitted ─────────────────────


class TestNoClientSpawnObserved:
    @pytest.mark.asyncio
    async def test_lifecycle_emits_no_agent_spawn_observed(self):
        """A full sub-agent lifecycle (spawn → child execution_started +
        tool call → stop) publishes NO client ``agent_spawn_observed``.
        Spawn attestation is SERVER-emitted only; the translator
        drops ``SubagentStart``."""
        plugin, apdp = _make_plugin()
        apdp.decisions[("execute", "search.web")] = "Allow"
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        child = plugin.resolve_subagent(root, "sub-1")
        assert child is not None

        # Emit the child's own hook stream (its UserPromptSubmit +
        # PreToolUse) under the child handle.
        await plugin.publish_subagent_events(
            root,
            "sub-1",
            [
                {"hook": "UserPromptSubmit", "depth": 1},
                {
                    "hook": "PreToolUse",
                    "tool_name": "search.web",
                    "tool_input": {"q": "x"},
                    "decision": "Allow",
                },
            ],
        )
        await plugin.on_subagent_stop(root, "sub-1")

        emitted_types = [e["event_type"] for e in apdp.published_events]
        assert "agent_spawn_observed" not in emitted_types
        # The child's execution_started DID ride the wire.
        assert "execution_started" in emitted_types


# ─── Child execution_started adopts the child lineage ────────────────


class TestChildLineageEmission:
    @pytest.mark.asyncio
    async def test_child_execution_started_uses_child_execution_id(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        assert child is not None

        ok = await plugin.publish_subagent_events(
            root, "sub-1", [{"hook": "UserPromptSubmit", "depth": 1}]
        )
        assert ok is True

        started = [
            e
            for e in apdp.published_events
            if e["event_type"] == "execution_started"
        ]
        assert len(started) == 1
        ev = started[0]
        # Adopts the SERVER-minted child execution_id + child agent id +
        # the root/parent lineage — NOT the root's execution_id.
        assert ev["execution_id"] == child.execution_id
        assert ev["execution_id"] != root.execution_id
        assert ev["agent_id"] == CHILD_AGENT_UUID
        assert ev["root_execution_id"] == child.root_execution_id
        assert ev["parent_execution_id"] == child.parent_execution_id

    @pytest.mark.asyncio
    async def test_child_events_published_under_child_credential(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        assert child is not None

        await plugin.publish_subagent_events(
            root, "sub-1", [{"hook": "UserPromptSubmit", "depth": 1}]
        )

        # The emission carried the PER-CHILD sst_ credential — not the
        # root's, not the shared bearer.
        token, _events = apdp.published_event_batches[-1]
        assert token == apdp.token_for(child.run)
        assert token != apdp.token_for(root.run)
        assert token is not None

    @pytest.mark.asyncio
    async def test_publish_refused_for_ungoverned_subagent(self):
        plugin, apdp = _make_plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
        root = await _root(plugin)
        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["wire.funds"])
        )

        ok = await plugin.publish_subagent_events(
            root, "sub-1", [{"hook": "UserPromptSubmit", "depth": 1}]
        )

        assert ok is False
        assert apdp.published_events == []


# ─── on_subagent_stop closes the child ───────────────────────────────


class TestSubagentStop:
    @pytest.mark.asyncio
    async def test_stop_closes_and_removes_child(self):
        plugin, apdp = _make_plugin()
        root = await _root(plugin)

        child = await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["search.web"])
        )
        assert child is not None

        await plugin.on_subagent_stop(root, "sub-1")

        assert child.session_id in apdp._closed_sessions
        assert plugin.resolve_subagent(root, "sub-1") is None

    @pytest.mark.asyncio
    async def test_stop_unknown_id_is_noop(self):
        plugin, _apdp = _make_plugin()
        root = await _root(plugin)
        # Must not raise.
        await plugin.on_subagent_stop(root, "never-spawned")


# ─── Operator default_subagent_scope knob ────────────────────────────


class TestDefaultScopeFallback:
    @pytest.mark.asyncio
    async def test_default_scope_applied_when_no_allowed_tools(self):
        plugin, apdp = _make_plugin(
            default_subagent_scope={"allowed_tools": ["search.web"]}
        )
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=None)
        )

        assert apdp.spawn_subagent_calls[-1]["requested_scope"][
            "allowed_tools"
        ] == ["search.web"]

    @pytest.mark.asyncio
    async def test_empty_default_spawns_zero_tool_child(self, caplog):
        plugin, apdp = _make_plugin()  # empty default → fail-closed
        root = await _root(plugin)

        with caplog.at_level("WARNING"):
            child = await plugin.on_subagent_start(
                root, _subagent_start(allowed_tools=None)
            )

        # Child IS registered (server attested the spawn), but with zero
        # tools — its first tool call will be denied at the server.
        assert child is not None
        assert apdp.spawn_subagent_calls[-1]["requested_scope"][
            "allowed_tools"
        ] == []
        # Loud fail-closed warning — and it carries no token/credential.
        assert any(
            "FAIL-CLOSED" in rec.message for rec in caplog.records
        )

    @pytest.mark.asyncio
    async def test_env_default_scope_read_when_param_omitted(
        self, monkeypatch
    ):
        monkeypatch.setenv(
            "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE",
            '{"allowed_tools": ["envtool"]}',
        )
        plugin, apdp = _make_plugin()  # no explicit default
        assert plugin.default_subagent_scope["allowed_tools"] == ["envtool"]
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=None)
        )

        assert apdp.spawn_subagent_calls[-1]["requested_scope"][
            "allowed_tools"
        ] == ["envtool"]

    @pytest.mark.asyncio
    async def test_surfaced_allowed_tools_overrides_default(self):
        plugin, apdp = _make_plugin(
            default_subagent_scope={"allowed_tools": ["search.web"]}
        )
        root = await _root(plugin)

        await plugin.on_subagent_start(
            root, _subagent_start(allowed_tools=["summarize.text"])
        )

        # Surfaced per-spawn allowed-tools wins over the operator default.
        assert apdp.spawn_subagent_calls[-1]["requested_scope"][
            "allowed_tools"
        ] == ["summarize.text"]


# ─── Pure capture-parsing helpers ────────────────────────────────────


class TestCaptureHelpers:
    def test_subagent_id_extraction_spellings(self):
        assert subagent_id_from_capture({"subagent_id": "a"}) == "a"
        assert subagent_id_from_capture({"agent_id": "b"}) == "b"
        assert subagent_id_from_capture({"agentId": "c"}) == "c"
        assert subagent_id_from_capture({}) is None
        assert subagent_id_from_capture({"subagent_id": "  "}) is None

    def test_slug_extraction_spellings(self):
        assert subagent_slug_from_capture({"agent_type": "r"}) == "r"
        assert subagent_slug_from_capture({"subagentType": "r2"}) == "r2"
        assert subagent_slug_from_capture({}) is None

    def test_parent_key_extraction(self):
        assert parent_key_from_capture({"parent_agent_id": "p"}) == "p"
        assert parent_key_from_capture({"parentAgentId": "p2"}) == "p2"
        assert parent_key_from_capture({}) is None

    def test_derive_scope_from_top_level_allowed_tools(self):
        scope = derive_requested_scope({"allowed_tools": ["a", "b"]})
        assert scope == {"allowed_tools": ["a", "b"]}

    def test_derive_scope_from_hyphenated_key(self):
        scope = derive_requested_scope({"allowed-tools": ["a"]})
        assert scope == {"allowed_tools": ["a"]}

    def test_derive_scope_from_tool_input(self):
        scope = derive_requested_scope(
            {"tool_input": {"allowed-tools": ["x", "y"]}}
        )
        assert scope == {"allowed_tools": ["x", "y"]}

    def test_derive_scope_comma_separated_string(self):
        scope = derive_requested_scope({"allowed_tools": "a, b ,c"})
        assert scope == {"allowed_tools": ["a", "b", "c"]}

    def test_derive_scope_absent_returns_none(self):
        # No allowed-tools ⇒ None so the caller falls back to the
        # operator default.
        assert derive_requested_scope({"agent_type": "r"}) is None

    def test_derive_scope_explicit_empty_is_zero_tools(self):
        # An explicit empty list is a deliberate zero-tool child — NOT
        # the "fall back to default" signal.
        assert derive_requested_scope({"allowed_tools": []}) == {
            "allowed_tools": []
        }


# ─── No spawn_subagent override on the plugin RunHandle ──────────────


def test_no_registry_on_ad_hoc_handle_fails_closed():
    """A handle NOT minted by start_run (no attached registry) fails
    closed: resolve returns None, so the caller denies."""
    plugin, _apdp = _make_plugin()
    bogus = uuid.uuid4()  # not a handle at all
    assert plugin.resolve_subagent(bogus, "sub-1") is None  # type: ignore[arg-type]
