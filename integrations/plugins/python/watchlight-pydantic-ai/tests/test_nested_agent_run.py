"""Tests for the contextvar-based nested ``Agent.run()`` instrumentation.

These tests are the spec for Pydantic AI's
"agent as composable callable" multi-agent pattern, which must stitch
into ONE lineage tree under one workflow root, with sub-agent
authorization correctly attributed, all with **zero customer code
changes**.

Coverage matrix:

| Case | What it asserts |
|------|-----------------|
| ``two_agent_flow`` | parent → specialist linkage + per-agent authz |
| ``three_deep_flow`` | researcher's root === parent.execution_id (not specialist.execution_id) |
| ``concurrent_runs`` | asyncio.gather doesn't cross-pollinate contextvar |
| ``sync_entry_point`` | ``agent.run_sync`` produces equivalent linkage |
| ``exception_path`` | inner failure → child terminates + parent recovers |
| ``idempotency`` | constructing plugin twice doesn't double-emit |
| ``uninstall`` | ``uninstall_instrumentation`` restores original methods |
| ``run_stream_entry_point`` | streaming entry-point also stitches |

Each test uses the ``MockApdpClient`` so the lifecycle exercises
real plugin code paths without touching a live APDP.
"""

from __future__ import annotations

import asyncio
import pytest

# Skip the whole module if pydantic-ai isn't importable. The plugin
# declares pydantic-ai as a required dep; this fence is for
# environments where the install is broken.
pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    RunHandle,
    WatchlightPydanticAIPlugin,
    current_handle,
    is_instrumented,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    """Each test starts with a clean Agent class and a reset
    contextvar. Tests that need instrumentation construct a plugin
    inside the test body; the fixture tears down after.
    """
    # Ensure prior tests' instrumentation is gone before this one.
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


def _make_plugin(
    known_agents: dict,
    decisions: dict | None = None,
) -> tuple[WatchlightPydanticAIPlugin, MockApdpClient]:
    """Build a plugin wired to a MockApdpClient with the given
    agent registrations.

    Returns ``(plugin, mock)`` so tests can assert on the mock's
    captured authorize_calls + published_events.
    """
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    mock = MockApdpClient()
    for slug, uuid in known_agents.items():
        mock.known_agents[slug] = uuid
    if decisions:
        mock.decisions.update(decisions)
    plugin.apdp = mock
    return plugin, mock


# ─── 1. Two-agent flow ───────────────────────────────────────────────


def test_two_agent_flow_parent_tool_calls_specialist_run() -> None:
    """A parent agent's tool calls ``await specialist.run(...)``.
    The plugin's runtime instrumentation should:

    - Open a root handle for ``parent.run()``.
    - Open a child handle for the nested ``specialist.run()``.
    - Authorize ``specialist.run`` against the SPECIALIST's
      principal (not the parent's).
    - Emit ``execution_started`` for both agents.
    - The specialist's events carry
      ``root_execution_id == parent.execution_id`` and
      ``parent_execution_id == parent.execution_id``.
    """

    async def _run():
        plugin, mock = _make_plugin(
            {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
        )

        # Build the agents — vanilla pydantic-ai with no Watchlight
        # imports in the agent code (zero agent-code touches is a
        # plugin design principle).
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist looked up {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult_specialist(prompt: str) -> str:
            result = await specialist.run(prompt)
            return str(result.output)

        # Run the parent. Inside, the parent's tool body will
        # invoke specialist.run() — instrumentation must stitch.
        result = await parent.run("please help")
        assert result.output is not None  # sanity: pydantic-ai ran

        # The plugin does not emit ``agent_spawn_observed``:
        # spawn attestation is SERVER-emitted by wl-apdp's ``spawn_handler``
        # (the class is rejected at ``/v1/events`` ingest). The spawn
        # linkage is captured on-wire via the child's ``execution_started``
        # (asserted below), whose ``agent_id`` / ``parent_execution_id``
        # tell us which handle was opened.
        assert not [
            e
            for e in mock.published_events
            if e.get("event_type") == "agent_spawn_observed"
        ]

        # ``execution_started`` for the child is emitted by the
        # instrumentation (the PARENT's is the top-level run's own).
        started_events = [
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
        ]
        assert any(
            e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb" for e in started_events
        ), "specialist's execution_started was not emitted"

        # The specialist's started event must carry the parent's
        # execution_id as ``parent_execution_id`` AND ``root_execution_id``
        # (since the parent IS the workflow root in a two-agent flow).
        spec_started = next(
            e for e in started_events if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        assert spec_started["parent_execution_id"] is not None
        assert spec_started["root_execution_id"] is not None
        # The root and parent should match for a one-level deep spawn.
        assert (
            spec_started["root_execution_id"]
            == spec_started["parent_execution_id"]
        ), (
            "for a one-deep spawn, root_execution_id should equal "
            "parent_execution_id (the parent IS the workflow root)"
        )

    asyncio.run(_run())


# ─── 2. Three-deep flow ──────────────────────────────────────────────


def test_three_deep_flow_root_propagates_through_chain() -> None:
    """parent → specialist → researcher.

    Researcher's ``root_execution_id`` MUST equal parent's
    execution_id (NOT specialist's). Researcher's
    ``parent_execution_id`` MUST equal specialist's execution_id.

    This is the load-bearing invariant for the dashboard's
    /lineage view — without it, the deeper sub-agent renders as
    its own root.
    """

    async def _run():
        plugin, mock = _make_plugin(
            {
                "parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa",
                "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb",
                "researcher": "11111111-1111-4111-8111-cccccccccccc",
            }
        )

        researcher = Agent(TestModel(), name="researcher")

        @researcher.tool_plain
        async def deep_lookup(q: str) -> str:
            return f"researcher: {q}"

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def consult_researcher(prompt: str) -> str:
            result = await researcher.run(prompt)
            return str(result.output)

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult_specialist(prompt: str) -> str:
            result = await specialist.run(prompt)
            return str(result.output)

        await parent.run("trigger the chain")

        started_events = [
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
        ]
        spec_started = next(
            e for e in started_events if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        rsch_started = next(
            e for e in started_events if e["agent_id"] == "11111111-1111-4111-8111-cccccccccccc"
        )

        # Specialist's parent_execution_id should equal a parent's
        # execution_id; root and parent equal at depth 1.
        assert (
            spec_started["parent_execution_id"]
            == spec_started["root_execution_id"]
        )

        # Researcher's root should equal specialist's root (which
        # is the parent's execution_id). Researcher's
        # parent_execution_id should equal specialist's
        # execution_id (the spec's child_execution_id, which is
        # the specialist's own execution_id).
        assert (
            rsch_started["root_execution_id"]
            == spec_started["root_execution_id"]
        ), (
            "researcher's root_execution_id must propagate UP to "
            "the parent's, NOT take on the specialist's"
        )
        assert (
            rsch_started["parent_execution_id"] == spec_started["execution_id"]
        ), (
            "researcher's parent_execution_id should be the "
            "specialist's execution_id (the immediate parent)"
        )

    asyncio.run(_run())


# ─── 3. Concurrent runs ──────────────────────────────────────────────


def test_concurrent_runs_do_not_cross_pollinate_contextvar() -> None:
    """Two independent roots run at once through
    ``asyncio.gather``, each declared with ``root_run()``,
    each get their own root execution_id. The contextvar must NOT
    leak across them.

    Python's contextvars guarantee per-task isolation; this test
    locks in the behaviour against any future refactor that
    accidentally swaps the contextvar for a module-global.
    """
    from watchlight_pydantic_ai import root_run

    async def _run():
        plugin, mock = _make_plugin(
            {"agent-a": "33333333-3333-4333-8333-aaaaaaaaaaaa", "agent-b": "33333333-3333-4333-8333-bbbbbbbbbbbb"}
        )

        agent_a = Agent(TestModel(), name="agent-a")
        agent_b = Agent(TestModel(), name="agent-b")

        async def _declared(agent, prompt):
            async with root_run():
                return await agent.run(prompt)

        results = await asyncio.gather(
            _declared(agent_a, "a-prompt"),
            _declared(agent_b, "b-prompt"),
        )
        assert len(results) == 2
        # Both opened as declared roots.
        assert len(mock.declared_root_calls) == 2
        assert all(r.output is not None for r in results)

        # No spawn events should have fired — neither agent
        # called the other. If the contextvar leaked, one of
        # these would have been treated as a child of the other
        # and spawn events would appear.
        spawn_events = [
            e
            for e in mock.published_events
            if e.get("event_type") == "agent_spawn_observed"
        ]
        assert not spawn_events, (
            f"concurrent gather() leaked contextvar — saw "
            f"{len(spawn_events)} spawn events when none expected"
        )

        # And the contextvar must be back to None now.
        assert current_handle() is None

    asyncio.run(_run())


# ─── 4. Sync entry point ─────────────────────────────────────────────


def test_run_sync_produces_equivalent_linkage() -> None:
    """``agent.run_sync(...)`` is the sync API surface. The
    instrumentation must wrap it the same way so customers using
    the sync convenience get governance.
    """

    plugin, mock = _make_plugin({"sync-agent": "33333333-3333-4333-8333-cccccccccccc"})
    agent = Agent(TestModel(), name="sync-agent")

    @agent.tool_plain
    async def hello(q: str) -> str:
        return f"sync said {q}"

    # Call the sync entry point.
    result = agent.run_sync("hello")
    assert result.output is not None

    # The plugin should have opened a root run and closed it.
    # Look for the session in mock._closed_sessions to confirm
    # complete() was called.
    assert mock._closed_sessions, (
        "run_sync did not trigger handle.complete() — session "
        "was never closed"
    )


# ─── 5. Exception path ──────────────────────────────────────────────


def test_inner_exception_terminates_child_and_propagates() -> None:
    """If the inner ``specialist.run()`` raises, the child handle
    must call ``terminate()`` (not ``complete()``), the contextvar
    must reset to the parent's, and the exception must propagate
    so the parent's tool body can react.
    """

    async def _run():
        plugin, mock = _make_plugin(
            {"parent": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
        )

        specialist = Agent(TestModel(), name="specialist")

        # Inject a failure in the specialist's tool path.
        @specialist.tool_plain
        async def doomed(q: str) -> str:
            raise RuntimeError("simulated specialist failure")

        parent = Agent(TestModel(), name="parent")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            try:
                result = await specialist.run(prompt)
                return str(result.output)
            except RuntimeError as exc:
                # Parent recovers — this is the realistic shape.
                return f"parent recovered from: {exc}"

        # The whole flow returns successfully because parent recovers.
        result = await parent.run("trigger")
        assert result.output is not None

        # The specialist's session should have been terminated
        # (not cleanly completed). Look at the mock's terminated
        # sessions list.
        assert mock._terminated_sessions, (
            "specialist's child handle should have been terminated "
            "after the inner exception, but no terminate was recorded"
        )

        # And the contextvar must be back to None after the parent
        # run completes.
        assert current_handle() is None

    asyncio.run(_run())


# ─── 6. Idempotency ────────────────────────────────────────────────


def test_double_install_does_not_double_emit() -> None:
    """Constructing the plugin twice in the same process must
    not double-wrap Agent.run. We detect by checking that a
    single nested call produces ONE spawn event, not two.
    """

    async def _run():
        # First install — happens implicitly in __init__.
        plugin_a, mock = _make_plugin(
            {"parent": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
        )

        # Second install — should be a no-op for the entry-point
        # patching. We share the mock client by re-pointing it.
        plugin_b = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        plugin_b.apdp = mock

        assert is_instrumented(), "first install should leave methods patched"

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"got {q}"

        parent = Agent(TestModel(), name="parent")

        @parent.tool_plain
        async def consult(p: str) -> str:
            r = await specialist.run(p)
            return str(r.output)

        # NOTE: plugin_a is the first-installed instance, so its
        # contextvar capture is the active one. plugin_b's
        # construction was a no-op (idempotency). Run against the
        # plugin_a-instrumented graph; assert ONE spawn event.
        await parent.run("trigger")

        # The spawn is signalled on-wire by the CHILD's own
        # ``execution_started`` (agent_spawn_observed is server-attested
        # only). Exactly one parent->specialist spawn ⇒ exactly one
        # child execution_started. Double-install would have produced two
        # wrappers stacked on Agent.run and we'd see double emission.
        child_started = [
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("parent_execution_id") is not None
        ]
        assert len(child_started) == 1, (
            f"expected 1 child execution_started from a single nested "
            f"call, got {len(child_started)}. Double-install likely "
            f"double-wrapped Agent.run."
        )
        # And no plugin-emitted spawn attestation (server-attested only).
        assert not [
            e
            for e in mock.published_events
            if e.get("event_type") == "agent_spawn_observed"
        ]

    asyncio.run(_run())


# ─── 7. Uninstall ──────────────────────────────────────────────────


def test_uninstall_restores_original_run() -> None:
    """``uninstall_instrumentation()`` restores the original
    ``Agent.run`` bound method. After uninstall, calling
    ``agent.run()`` directly does NOT open any Watchlight handle.
    """

    original_run = Agent.run

    # Install via plugin construction.
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    assert is_instrumented()
    # The patched Agent.run must NOT be the same object as the
    # original — that's how we know the patch landed.
    assert Agent.run is not original_run

    # Now uninstall.
    uninstall_instrumentation()
    assert not is_instrumented()
    # And the original bound method should be back.
    assert Agent.run is original_run


# ─── 8. Streaming entry point ────────────────────────────────────


def test_run_stream_entry_point_also_stitches() -> None:
    """``agent.run_stream(...)`` is the streaming counterpart.
    The instrumentation must wrap it too so a nested
    ``async with specialist.run_stream(...) as s:`` inside a
    parent tool body opens a child handle.

    We don't actually consume the stream here — we just enter
    the async-context-manager, exit it, and verify the child's
    execution_started was emitted (the spawn signal on the wire; the
    agent_spawn_observed attestation is server-emitted).
    """

    async def _run():
        plugin, mock = _make_plugin(
            {"parent": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
        )

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"streamed: {q}"

        parent = Agent(TestModel(), name="parent")

        @parent.tool_plain
        async def stream_consult(prompt: str) -> str:
            async with specialist.run_stream(prompt) as stream:
                # Just consume the output minimally so the inner
                # generator runs to completion.
                out = await stream.get_output()
                return str(out)

        await parent.run("trigger streaming")

        child_started = [
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("parent_execution_id") is not None
        ]
        assert child_started, (
            "expected a child execution_started from the nested "
            "run_stream call, got none"
        )
        assert not [
            e
            for e in mock.published_events
            if e.get("event_type") == "agent_spawn_observed"
        ]

    asyncio.run(_run())


# ─── 9. current_handle is None outside a run ────────────────────


def test_current_handle_returns_none_outside_a_run() -> None:
    """Sanity — the contextvar is unset before any instrumentation
    fires, and reset cleanly after each run."""
    plugin, _ = _make_plugin({"agent-x": "33333333-3333-4333-8333-dddddddddddd"})
    assert current_handle() is None


# ─── 10. Authorization correctly scoped to sub-agent ────────────


def test_subagent_authorize_action_uses_subagent_principal() -> None:
    """The sub-agent governance invariant: authorization for tool
    calls made inside the sub-agent's body MUST carry the
    sub-agent's principal, not the parent's.

    To exercise this end-to-end, we wire the specialist's tool
    with @handle.guarded_tool — which uses the handle the tool
    was decorated with. The tool is decorated INSIDE the
    instrumentation wrapper using ``current_handle()``, so the
    authz call must come from the child handle's principal.

    This test confirms the patching gives the customer's
    ``current_handle()`` accessor the right handle when running
    inside the specialist's body.
    """

    async def _run():
        plugin, mock = _make_plugin(
            {"parent": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"},
            decisions={("execute", "secret_query"): "Allow"},
        )

        observed_handles: list[RunHandle | None] = []

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def secret_query(q: str) -> str:
            # Read the active handle. Should be the specialist's.
            h = current_handle()
            observed_handles.append(h)
            if h is not None:
                await h.authorize_action("execute", "secret_query")
            return f"answered: {q}"

        parent = Agent(TestModel(), name="parent")

        @parent.tool_plain
        async def consult(p: str) -> str:
            r = await specialist.run(p)
            return str(r.output)

        await parent.run("trigger")

        # Did we see the specialist's handle?
        assert observed_handles, "specialist's tool body never ran"
        assert observed_handles[0] is not None
        # The handle's agent_uuid must be the SPECIALIST's UUID.
        assert observed_handles[0].agent_uuid == "11111111-1111-4111-8111-bbbbbbbbbbbb", (
            "the handle active inside specialist.run's tool body "
            "must be bound to the specialist's UUID, not the "
            "parent's — this is the invariant from "
            "feedback_subagents_must_be_governed"
        )

        # And the authorize_action call must have carried the
        # specialist's principal — verify via the mock's
        # authorize_calls log.
        sub_calls = [
            c
            for c in mock.authorize_calls
            if "11111111-1111-4111-8111-bbbbbbbbbbbb" in c.get("principal", "")
        ]
        assert sub_calls, (
            "authorize() for the sub-agent's tool was not called "
            "against the sub-agent's principal — sub-agent "
            "governance regression"
        )

        # And the root's principal must NOT have been used for
        # this tool — that's the sub-agent privilege-escalation
        # bug shape.
        for call in mock.authorize_calls:
            if "secret_query" in call.get("resource", ""):
                assert "11111111-1111-4111-8111-aaaaaaaaaaaa" not in call.get("principal", ""), (
                    "Sub-agent privilege-escalation shape: "
                    "the sub-agent's tool was authorized against the "
                    "root's principal"
                )

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])


# ─── Refused spawn: the sub-agent never runs ─────────────────


def test_refused_subagent_spawn_does_not_run_the_subagent() -> None:
    """A nested ``specialist.run()`` whose governed spawn wl-apdp refuses
    must not run: no model turn and no tool body, and nothing authorized
    under the PARENT's handle on the specialist's behalf. The refusal
    reaches the caller (the parent's tool body) as the typed error."""
    from watchlight_core import ScopeAttenuationDenied

    async def _run():
        plugin, mock = _make_plugin(
            {
                "parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa",
                "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb",
            }
        )
        mock.spawn_error_override = ScopeAttenuationDenied(
            reason="scope_attenuation_violation", violations=[]
        )
        ran: list = []
        seen: list = []

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            ran.append(q)
            return q

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult_specialist(prompt: str) -> str:
            try:
                await specialist.run(prompt)
            except ScopeAttenuationDenied as exc:
                seen.append(exc)
                return "specialist refused"
            return "specialist ran"

        await parent.run("please help")

        assert len(mock.spawn_subagent_calls) >= 1
        assert seen, "the refusal did not reach the caller"
        assert ran == [], "the refused specialist's tool body ran"
        started = [
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("agent_id") == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        ]
        assert started == []

    asyncio.run(_run())


# ─── A failed ROOT open fails closed too ─────────────────────


def test_root_run_that_cannot_open_governance_does_not_run() -> None:
    """``start_run`` failing with a transport error used to run the whole
    agent ungoverned. It now raises ``GovernanceUnavailable`` with an
    instructive message — never the transport's raw text — and the
    agent's tools never run."""
    from watchlight_core import GovernanceUnavailable

    async def _run():
        plugin, mock = _make_plugin({"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa"})
        ran: list = []

        async def _unreachable(*_args, **_kwargs):
            raise ConnectionError("connect ECONNREFUSED 10.0.0.7:8081 token=abc")

        plugin.start_run = _unreachable  # type: ignore[method-assign]

        agent = Agent(TestModel(), name="parent-coordinator")

        @agent.tool_plain
        async def lookup(q: str) -> str:
            ran.append(q)
            return q

        with pytest.raises(GovernanceUnavailable) as excinfo:
            await agent.run("please help")
        message = str(excinfo.value)
        assert "was not started" in message
        assert "parent-coordinator" in message
        assert "ECONNREFUSED" not in message and "token=abc" not in message
        assert ran == []
        assert mock.authorize_calls == []

    asyncio.run(_run())


def test_root_run_refused_by_watchlight_propagates_the_typed_error() -> None:
    """A typed refusal (here an unregistered agent) propagates unchanged
    and the agent does not run."""
    from watchlight_core import WatchlightError

    async def _run():
        plugin, mock = _make_plugin({})
        ran: list = []
        agent = Agent(TestModel(), name="not-registered")

        @agent.tool_plain
        async def lookup(q: str) -> str:
            ran.append(q)
            return q

        with pytest.raises(WatchlightError):
            await agent.run("please help")
        assert ran == []

    asyncio.run(_run())


# ─── Child intent ─────────────────────────────────


@pytest.mark.parametrize("category", [None, "research"])
def test_nested_run_declares_the_child_intent_from_the_prompt(category) -> None:
    """A nested ``Agent.run(prompt)`` spawns its child with a plugin-derived
    intent: the prompt is the objective; the category is the plugin's
    configured one (else the default)."""
    from watchlight_core import DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY

    plugin, mock = _make_plugin(
        {
            "parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa",
            "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb",
        }
    )
    plugin.child_intent_category = category

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return q

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            result = await specialist.run("Summarise the Q3 filings")
            return str(result.output)

        await parent.run("trigger")

    asyncio.run(_run())
    assert mock.spawn_subagent_calls, "the nested run did not spawn"
    assert mock.spawn_subagent_calls[-1]["child_intent"] == {
        "category": category or DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
        "objective": "Summarise the Q3 filings",
    }


def test_child_provenance_is_capped_at_the_derived_one() -> None:
    from watchlight_pydantic_ai.plugin import _cap_to_derived_provenance as cap

    derived = {"intent_category": "research", "objective": "o", "provenance": "plugin_derived"}
    # A child's own "declared" never rises above the derived provenance.
    assert cap("mine", "declared", derived) == ("mine", "plugin_derived")
    assert cap("mine", "plugin_derived", derived) == ("mine", "plugin_derived")
    assert cap("mine", "proxy_inferred", derived) == ("mine", "proxy_inferred")
    # An absent (or unknown, or "declared") derived provenance drops the objective.
    for bad in ("absent", "declared", None, "bogus"):
        d = dict(derived, provenance=bad)
        assert cap("mine", "plugin_derived", d) == (None, "absent")
    # No objective of its own: none is reported.
    assert cap(None, "absent", derived) == (None, "absent")
    assert cap(None, None, derived) == (None, None)
    # No derivation (an older server): capped at plugin_derived.
    assert cap("mine", "declared", None) == ("mine", "plugin_derived")
