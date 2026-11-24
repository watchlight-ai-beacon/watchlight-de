"""The shipped enforcement hooks (``governance_hooks``).

A refused sub-agent must never start: the ``Task``/``Agent``
``PreToolUse`` gate performs the governed spawn and denies the tool
call when the spawn is refused or uncertain. Every other tool call is
authorized on the acting agent's own handle and denied on a deny,
a needs-approval decision, or any error.

Hook inputs use the Claude Agent SDK's dict shapes
(``tool_name`` / ``tool_input`` / ``agent_id`` / ``agent_type``) and the
callbacks use its ``(input_data, tool_use_id, context)`` signature.
"""

from __future__ import annotations

import warnings

import pytest

from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin
from watchlight_claude_agent.hooks import is_deny_output
from watchlight_core import ScopeAttenuationDenied, ScopeViolationDimension
from watchlight_core_testing import MockApdpClient

ROOT_SLUG = "root-agent"
ROOT_UUID = "00000000-0000-0000-0000-000000000001"
CHILD_SLUG = "researcher"
CHILD_UUID = "00000000-0000-0000-0000-0000000000a1"


def _plugin(*, default_subagent_scope=None):
    apdp = MockApdpClient(default_decision="Allow")
    apdp.known_agents[ROOT_SLUG] = ROOT_UUID
    apdp.known_agents[CHILD_SLUG] = CHILD_UUID
    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="tenant-a",
        default_subagent_scope=default_subagent_scope
        if default_subagent_scope is not None
        else {"allowed_tools": ["WebSearch"]},
    )
    plugin.apdp = apdp
    return plugin, apdp


async def _root(plugin):
    handle = await plugin.start_run(ROOT_SLUG)
    handle._aentered = True
    return handle


def _callbacks(hooks, event):
    out = []
    for matcher in hooks[event]:
        out.extend(matcher.hooks)
    return out


async def _fire(hooks, event, data, tool_use_id=None):
    """Run every callback for ``event`` like the SDK does; return outputs."""
    return [await cb(data, tool_use_id, None) for cb in _callbacks(hooks, event)]


def _denied(outputs):
    return any(is_deny_output(o) for o in outputs)


def _task(subagent_type=CHILD_SLUG, *, agent_id=None, tool_name="Task"):
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {
            "description": "research",
            "prompt": "look it up",
            "subagent_type": subagent_type,
        },
    }
    if agent_id is not None:
        data["agent_id"] = agent_id
    return data


def _tool(name, tool_input=None, *, agent_id=None):
    data = {
        "hook_event_name": "PreToolUse",
        "tool_name": name,
        "tool_input": tool_input or {},
    }
    if agent_id is not None:
        data["agent_id"] = agent_id
    return data


class TestShape:
    @pytest.mark.asyncio
    async def test_hooks_cover_every_tool_and_subagent_lifecycle(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        assert set(hooks) >= {"PreToolUse", "SubagentStart", "SubagentStop"}
        # The PreToolUse gate matches every tool (no matcher filter).
        assert any(m.matcher is None for m in hooks["PreToolUse"])

    @pytest.mark.asyncio
    async def test_customer_hooks_are_kept_after_watchlight(self):
        plugin, _ = _plugin()
        root = await _root(plugin)

        async def mine(data, tool_use_id, ctx):
            return {}

        class M:
            matcher = "Bash"
            hooks = [mine]

        hooks = plugin.governance_hooks(root, {"PreToolUse": [M()]})
        assert hooks["PreToolUse"][-1].hooks == [mine]
        assert hooks["PreToolUse"][0].matcher is None

    @pytest.mark.asyncio
    async def test_governed_options_merges_into_a_dict(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        opts = plugin.governed_options(root, {"model": "x"})
        assert opts["model"] == "x"
        assert "PreToolUse" in opts["hooks"]


class TestSubagentSpawnGate:
    @pytest.mark.asyncio
    async def test_refused_spawn_denies_task_before_subagent_starts(self):
        plugin, apdp = _plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied(
            "tool not in parent scope", [ScopeViolationDimension.ALLOWED_TOOLS]
        )
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)

        out = await _fire(hooks, "PreToolUse", _task(), "toolu_1")

        assert _denied(out)
        # The governed spawn was attempted before the tool ran.
        assert len(apdp.spawn_subagent_calls) == 1

    @pytest.mark.asyncio
    async def test_agent_tool_name_is_gated_too(self):
        plugin, apdp = _plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied("no", [])
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _task(tool_name="Agent"), "toolu_1")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_unregistered_subagent_type_is_denied(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _task("not-registered"), "toolu_1")
        assert _denied(out)
        assert apdp.spawn_subagent_calls == []

    @pytest.mark.asyncio
    async def test_spawn_transport_error_is_denied(self):
        plugin, apdp = _plugin()
        apdp.spawn_error_override = RuntimeError("connection reset")
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _task(), "toolu_1")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_allowed_spawn_child_tools_authorize_on_child_handle(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)

        out = await _fire(hooks, "PreToolUse", _task(), "toolu_1")
        assert not _denied(out)
        await _fire(
            hooks,
            "SubagentStart",
            {"hook_event_name": "SubagentStart", "agent_id": "a1",
             "agent_type": CHILD_SLUG},
        )
        child = plugin.resolve_subagent(root, "a1")
        assert child is not None and child is not root
        child._aentered = True

        out = await _fire(
            hooks, "PreToolUse", _tool("WebSearch", agent_id="a1"), "toolu_2"
        )
        assert not _denied(out)
        call = apdp.authorize_calls[-1]
        assert call["session_id"] == child.session_id
        assert call["session_id"] != root.session_id

        # Stop closes the child; later calls from it are denied.
        await _fire(
            hooks, "SubagentStop",
            {"hook_event_name": "SubagentStop", "agent_id": "a1"},
        )
        out = await _fire(
            hooks, "PreToolUse", _tool("WebSearch", agent_id="a1"), "toolu_3"
        )
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_subagent_without_governed_spawn_is_denied(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(
            hooks,
            "SubagentStart",
            {"hook_event_name": "SubagentStart", "agent_id": "rogue",
             "agent_type": CHILD_SLUG},
        )
        out = await _fire(
            hooks, "PreToolUse", _tool("WebSearch", agent_id="rogue"), "t"
        )
        assert _denied(out)
        assert apdp.authorize_calls == []

    @pytest.mark.asyncio
    async def test_call_with_unknown_agent_id_is_denied(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(
            hooks, "PreToolUse", _tool("Bash", agent_id="who-knows"), "t"
        )
        assert _denied(out)
        assert apdp.authorize_calls == []

    @pytest.mark.asyncio
    async def test_unattributed_call_while_subagent_live_is_denied(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_1")
        await _fire(
            hooks,
            "SubagentStart",
            {"hook_event_name": "SubagentStart", "agent_id": "a1",
             "agent_type": CHILD_SLUG},
        )
        # No agent_id: cannot tell root from child, so never run it on
        # the root's credential.
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "toolu_2")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_on_subagent_start_is_deprecated(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            await plugin.on_subagent_start(
                root,
                {"hook": "SubagentStart", "subagent_id": "s",
                 "agent_type": CHILD_SLUG},
            )
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)


class TestEveryToolGate:
    @pytest.mark.asyncio
    async def test_root_tool_allowed(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Read"), "t")
        assert not _denied(out)
        assert apdp.authorize_calls[-1]["session_id"] == root.session_id

    @pytest.mark.asyncio
    async def test_policy_deny_denies_tool(self):
        plugin, apdp = _plugin()
        apdp.decisions[("execute", "Bash")] = "Deny"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_needs_approval_denies_tool(self):
        plugin, apdp = _plugin()
        apdp.decisions[("execute", "Bash")] = "needs_approval"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_backend_error_denies_tool(self):
        plugin, apdp = _plugin()

        async def boom(*a, **k):
            raise RuntimeError("APDP unreachable")

        apdp.authorize = boom  # type: ignore[method-assign]
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_unentered_handle_denies_tool(self):
        plugin, _ = _plugin()
        root = await plugin.start_run(ROOT_SLUG)  # not entered
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_raw_argument_values_are_not_sent(self):
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        secret = "sk-live-DO-NOT-SEND"
        await _fire(
            hooks, "PreToolUse", _tool("Bash", {"command": secret}), "t"
        )
        call = apdp.authorize_calls[-1]
        assert secret not in repr(call["context"])
        assert secret not in repr(call["intent"])


def _start(agent_id, agent_type=CHILD_SLUG):
    return {"hook_event_name": "SubagentStart", "agent_id": agent_id,
            "agent_type": agent_type}


def _post(tool_use_id, *, event="PostToolUse", tool_name="Task"):
    return {"hook_event_name": event, "tool_name": tool_name,
            "tool_input": {"subagent_type": CHILD_SLUG},
            "tool_use_id": tool_use_id}


class TestPendingSpawnBinding:
    @pytest.mark.asyncio
    async def test_hook_matchers_set_an_explicit_timeout(self):
        from watchlight_claude_agent.hooks import HOOK_TIMEOUT_SECONDS

        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        for matchers in hooks.values():
            for m in matchers:
                assert m.timeout == HOOK_TIMEOUT_SECONDS

    @pytest.mark.asyncio
    async def test_parallel_same_type_spawn_is_refused(self):
        """SubagentStart carries no tool-use id, so a second pending spawn
        of the same type could bind to the first one's handle."""
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)

        assert not _denied(await _fire(hooks, "PreToolUse", _task(), "toolu_A"))
        out = await _fire(hooks, "PreToolUse", _task(), "toolu_B")
        assert _denied(out)
        assert len(apdp.spawn_subagent_calls) == 1

        # Once the first has started and stopped, another may launch.
        await _fire(hooks, "SubagentStart", _start("a1"))
        await _fire(hooks, "SubagentStop", {"hook_event_name": "SubagentStop",
                                            "agent_id": "a1"})
        assert not _denied(await _fire(hooks, "PreToolUse", _task(), "toolu_C"))

    @pytest.mark.asyncio
    async def test_same_type_spawn_is_refused_while_one_is_pending(self):
        """The type rule on its own: a spawn from a governed sub-agent
        while a same-type spawn is still pending is refused."""
        plugin, apdp = _plugin(
            default_subagent_scope={"allowed_tools": ["WebSearch"], "max_depth": 2}
        )
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        await _fire(hooks, "SubagentStart", _start("a1"))
        plugin.resolve_subagent(root, "a1")._aentered = True
        assert not _denied(
            await _fire(hooks, "PreToolUse", _task(agent_id="a1"), "toolu_B")
        )
        assert "toolu_B" in gate._pending
        out = await _fire(hooks, "PreToolUse", _task(agent_id="a1"), "toolu_C")
        assert _denied(out)
        assert "still starting" in out[0]["hookSpecificOutput"]["permissionDecisionReason"]

    @pytest.mark.asyncio
    async def test_explicit_tool_use_id_binds_its_own_spawn(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        gate_child = None
        for cb in _callbacks(hooks, "SubagentStart"):
            gate_child = cb.__self__._pending["toolu_A"].child
        data = _start("a1")
        data["tool_use_id"] = "toolu_other"
        await _fire(hooks, "SubagentStart", data)
        # A non-matching id claims nothing: the sub-agent stays unbound.
        assert plugin.resolve_subagent(root, "a1") is None
        data = _start("a2")
        data["tool_use_id"] = "toolu_A"
        await _fire(hooks, "SubagentStart", data)
        assert plugin.resolve_subagent(root, "a2") is gate_child

    @pytest.mark.asyncio
    async def test_ambiguous_type_match_leaves_the_subagent_unbound(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        # Force two pending spawns of one type (the gate itself refuses
        # this; the claim must still never guess).
        gate._pending["toolu_B"] = gate._pending["toolu_A"].__class__(
            agent_type=CHILD_SLUG, child=gate._pending["toolu_A"].child,
            created_at=0.0 + gate._pending["toolu_A"].created_at,
        )
        await _fire(hooks, "SubagentStart", _start("a1"))
        assert plugin.resolve_subagent(root, "a1") is None
        out = await _fire(
            hooks, "PreToolUse", _tool("WebSearch", agent_id="a1"), "t"
        )
        assert _denied(out)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("event", ["PostToolUse", "PostToolUseFailure"])
    async def test_spawn_that_never_starts_is_closed_and_unblocks_the_root(self, event):
        """A Task the gate allowed but that never started (a later hook or
        a permission prompt refused it) is closed: it does not keep the
        root's calls denied, and a later same-type sub-agent cannot claim
        its handle."""
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        child = gate._pending["toolu_A"].child

        # While it is pending, unattributed calls are refused.
        assert _denied(await _fire(hooks, "PreToolUse", _tool("Read"), "t1"))

        await _fire(hooks, event, _post("toolu_A", event=event), "toolu_A")

        assert gate._pending == {}
        assert child._completed
        assert not _denied(await _fire(hooks, "PreToolUse", _tool("Read"), "t2"))
        # A sub-agent that starts now has no governed spawn to claim.
        await _fire(hooks, "SubagentStart", _start("late"))
        assert plugin.resolve_subagent(root, "late") is None

    @pytest.mark.asyncio
    async def test_stop_closes_every_pending_spawn(self):
        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        child = gate._pending["toolu_A"].child
        await _fire(hooks, "Stop", {"hook_event_name": "Stop"})
        assert gate._pending == {} and child._completed

    @pytest.mark.asyncio
    async def test_stale_pending_spawn_expires(self, monkeypatch):
        import watchlight_claude_agent.hooks as hooks_mod

        plugin, _ = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        gate._pending["toolu_A"].created_at -= hooks_mod.PENDING_SPAWN_TTL_SECONDS + 1
        assert not _denied(await _fire(hooks, "PreToolUse", _tool("Read"), "t"))
        assert gate._pending == {}


class TestGateDeadline:
    @pytest.mark.asyncio
    async def test_a_gate_that_does_not_decide_in_time_denies(self, monkeypatch):
        import asyncio

        import watchlight_claude_agent.hooks as hooks_mod

        monkeypatch.setattr(hooks_mod, "GATE_DEADLINE_SECONDS", 0.05)
        plugin, apdp = _plugin()

        async def slow(*a, **k):
            await asyncio.sleep(5)
            return {"decision": "Allow"}

        apdp.authorize = slow  # type: ignore[method-assign]
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)
        assert hooks_mod.GATE_DEADLINE_SECONDS < hooks_mod.HOOK_TIMEOUT_SECONDS


class TestDeclareIntentShortcut:
    @pytest.mark.asyncio
    async def test_look_alike_name_is_refused_in_brownfield(self):
        plugin, apdp = _plugin()
        plugin.intent_enforcement_mode = "brownfield"
        apdp.decisions[("execute", "watchlight.declare_intent")] = "Deny"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(
            hooks, "PreToolUse",
            _tool("watchlight.declare_intent", {"objective": "x"}), "t",
        )
        # Not the plugin's own tool here, and not a tool the plugin has
        # classified: refused before any decision.
        assert _denied(out)
        assert apdp.authorize_calls == []

    @pytest.mark.asyncio
    async def test_case_variant_is_not_the_synthetic_tool(self):
        plugin, apdp = _plugin()
        plugin.intent_enforcement_mode = "greenfield"
        apdp.decisions[("execute", "Watchlight.Declare_Intent")] = "Deny"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(
            hooks, "PreToolUse",
            _tool("Watchlight.Declare_Intent", {"objective": "x"}), "t",
        )
        assert _denied(out)

    @pytest.mark.asyncio
    async def test_the_plugins_own_tool_records_intent_in_greenfield(self):
        plugin, apdp = _plugin()
        plugin.intent_enforcement_mode = "greenfield"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(
            hooks, "PreToolUse",
            _tool("watchlight.declare_intent", {"objective": "summarise"}), "t",
        )
        assert not _denied(out)
        assert apdp.authorize_calls == []


class TestOpaqueDeny:
    @pytest.mark.asyncio
    async def test_deny_reason_from_the_server_is_not_shown_to_the_agent(self):
        plugin, apdp = _plugin()
        real = apdp.authorize

        async def deny_with_reason(*a, **k):
            response = await real(*a, **k)
            response.update({"decision": "Deny", "reason": "policy secret-policy-7 matched"})
            return response

        apdp.authorize = deny_with_reason  # type: ignore[method-assign]
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _tool("Bash"), "t")
        assert _denied(out)
        text = out[0]["hookSpecificOutput"]["permissionDecisionReason"]
        assert "secret-policy-7" not in text
        assert text == "Denied by Watchlight policy."


class TestParallelSameTypeRace:
    @pytest.mark.asyncio
    async def test_concurrent_same_type_launches_admit_exactly_one(self):
        """Both gates run concurrently; the slot is reserved before the
        first await, so the second sees it and is refused."""
        import asyncio

        plugin, apdp = _plugin(
            default_subagent_scope={"allowed_tools": ["WebSearch"], "max_depth": 2}
        )
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        await _fire(hooks, "SubagentStart", _start("a1"))
        plugin.resolve_subagent(root, "a1")._aentered = True

        real_resolve = plugin._resolve_subagent_principal

        async def slow_resolve(agent_type):
            await asyncio.sleep(0.01)  # both gates are past their checks here
            return await real_resolve(agent_type)

        plugin._resolve_subagent_principal = slow_resolve  # type: ignore[method-assign]
        before = len(apdp.spawn_subagent_calls)
        outs = await asyncio.gather(
            _fire(hooks, "PreToolUse", _task(agent_id="a1"), "toolu_B"),
            _fire(hooks, "PreToolUse", _task(agent_id="a1"), "toolu_C"),
        )
        denied = [_denied(o) for o in outs]
        assert sorted(denied) == [False, True]
        assert len(apdp.spawn_subagent_calls) - before == 1
        assert len([k for k in gate._pending if gate._pending[k].child is not None]) == 1

    @pytest.mark.asyncio
    async def test_a_refused_launch_releases_its_reservation(self):
        plugin, apdp = _plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied("no", [])
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        gate = _callbacks(hooks, "SubagentStart")[0].__self__
        assert _denied(await _fire(hooks, "PreToolUse", _task(), "toolu_A"))
        assert gate._pending == {}


class TestDeadlineDuringSpawn:
    @pytest.mark.asyncio
    async def test_child_minted_after_the_deadline_is_ended(self, monkeypatch):
        import asyncio

        import watchlight_claude_agent.hooks as hooks_mod

        monkeypatch.setattr(hooks_mod, "GATE_DEADLINE_SECONDS", 0.05)
        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        gate = _callbacks(hooks, "SubagentStart")[0].__self__

        minted = []
        real_spawn = root.spawn_subagent

        async def slow_spawn(*a, **k):
            await asyncio.sleep(0.15)  # the server mints after the deadline
            child = await real_spawn(*a, **k)
            minted.append(child)
            return child

        root.spawn_subagent = slow_spawn  # type: ignore[method-assign]
        out = await _fire(hooks, "PreToolUse", _task(), "toolu_A")
        assert _denied(out)
        assert gate._pending == {}

        await asyncio.sleep(0.3)
        assert len(minted) == 1
        child = minted[0]
        assert child._completed
        assert gate._orphan_closes == set()


class TestChildIntent:
    """Every Task spawn declares the child's intent:
    the objective is the Task tool's description (else its prompt)."""

    @pytest.mark.asyncio
    async def test_task_spawn_sends_the_task_description_as_the_objective(self):
        from watchlight_core import DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY

        plugin, apdp = _plugin()
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _task(), "toolu_1")
        assert not _denied(out)
        sent = apdp.spawn_subagent_calls[-1]["child_intent"]
        assert sent == {
            "category": DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
            "objective": "research",
        }

    @pytest.mark.asyncio
    async def test_configured_category_and_prompt_fallback(self):
        plugin, apdp = _plugin()
        plugin.child_intent_category = "research"
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        data = _task()
        data["tool_input"].pop("description")
        out = await _fire(hooks, "PreToolUse", data, "toolu_1")
        assert not _denied(out)
        assert apdp.spawn_subagent_calls[-1]["child_intent"] == {
            "category": "research",
            "objective": "look it up",
        }

    @pytest.mark.asyncio
    async def test_a_refused_derivation_denies_the_task(self):
        from watchlight_core import ScopeAttenuationDenied

        plugin, apdp = _plugin()
        apdp.spawn_error_override = ScopeAttenuationDenied(
            "scope_attenuation_violation", [], reason_code="INTENT_NOT_DERIVED"
        )
        root = await _root(plugin)
        hooks = plugin.governance_hooks(root)
        out = await _fire(hooks, "PreToolUse", _task(), "toolu_1")
        assert _denied(out)
