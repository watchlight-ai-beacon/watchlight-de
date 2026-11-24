"""Plugin-specific conformance test for the nested-run lineage
contract.

Why this lives in the plugin's own tests rather than the
``watchlight_core_testing.conformance`` harness: the harness's sub-agent
attribution invariant is framework-agnostic — every plugin
exercising ``handle.spawn_subagent`` (or the equivalent) passes
it the same way. The lineage-continuity invariant (root_execution_id
+ parent_execution_id propagation across a runtime-instrumented
nested call) is specific to pydantic-ai's "agent as composable
callable" pattern; the cross-plugin harness asserts the explicit-
primitive shape, but the runtime-instrumented shape is what THIS
plugin uniquely supports.

The cross-plugin conformance harness extension for the
runtime-instrumented shape is deferred to the watchlight-core lane;
this file is the plugin-specific equivalent that fires today.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    WatchlightPydanticAIPlugin,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


def test_synthetic_nested_lifecycle_propagates_root_execution_id() -> None:
    """End-to-end synthetic lifecycle exercise of the nested
    ``Agent.run()`` path. Drives a parent → specialist nested
    flow through the live patched ``Agent.run`` and asserts the
    on-the-wire events carry the lineage-continuity envelope
    fields of the lineage-continuity contract.

    What we assert:

    - The ``execution_started`` events emitted by the runtime
      instrumentation carry ``root_execution_id`` and
      ``parent_execution_id``.
    - The specialist's ``root_execution_id`` matches the
      parent's execution id (the workflow root), NOT the
      specialist's own execution id.
    - No ``agent_spawn_observed`` is plugin-emitted (spawn
      attestation is server-emitted only); the child's
      ``execution_started`` names the right spawner via
      ``parent_execution_id``.
    """

    async def _run():
        plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        mock = MockApdpClient()
        # The canonical spawn_subagent flow requires child_agent_ids
        # to parse as UUIDs (the strict-subset validator at APDP
        # enforces the canonical wire shape).
        mock.known_agents["parent-coordinator"] = (
            "11111111-1111-4111-8111-aaaaaaaaaaaa"
        )
        mock.known_agents["specialist"] = (
            "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        plugin.apdp = mock

        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist data for {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult_specialist(prompt: str) -> str:
            r = await specialist.run(prompt)
            return str(r.output)

        await parent.run("trigger")

        # No plugin-emitted spawn attestation (server-attested
        # only). The child's execution_started names the spawner.
        assert not [
            e
            for e in mock.published_events
            if e.get("event_type") == "agent_spawn_observed"
        ]
        spec_started = next(
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("agent_id") == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )

        # Lineage continuity — specialist's events carry both
        # root_execution_id and parent_execution_id. At depth 1
        # they coincide (parent IS the workflow root).
        assert spec_started["parent_execution_id"] is not None
        assert spec_started["root_execution_id"] is not None
        assert (
            spec_started["root_execution_id"]
            == spec_started["parent_execution_id"]
        ), (
            "at depth 1, root_execution_id should equal "
            "parent_execution_id (the parent is the workflow root)"
        )

    asyncio.run(_run())


def test_three_deep_lineage_root_pins_to_outermost() -> None:
    """Three-deep variant of the lifecycle assertion. The deepest
    agent's events MUST carry the OUTERMOST agent's execution id
    as ``root_execution_id``. This is the load-bearing invariant
    for the dashboard's /lineage view's recent-executions list.

    Mirrors the LangGraph reference implementation's behaviour —
    ``RunHandle.root_execution_id`` propagates verbatim down the
    spawn chain.
    """

    async def _run():
        plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        mock = MockApdpClient()
        # UUIDs required for the canonical spawn path.
        mock.known_agents["coord"] = (
            "22222222-2222-4222-8222-aaaaaaaaaaaa"
        )
        mock.known_agents["spec"] = (
            "22222222-2222-4222-8222-bbbbbbbbbbbb"
        )
        mock.known_agents["rsch"] = (
            "22222222-2222-4222-8222-cccccccccccc"
        )
        plugin.apdp = mock

        rsch = Agent(TestModel(), name="rsch")

        @rsch.tool_plain
        async def deep(q: str) -> str:
            return f"rsch: {q}"

        spec = Agent(TestModel(), name="spec")

        @spec.tool_plain
        async def consult_rsch(p: str) -> str:
            r = await rsch.run(p)
            return str(r.output)

        coord = Agent(TestModel(), name="coord")

        @coord.tool_plain
        async def consult_spec(p: str) -> str:
            r = await spec.run(p)
            return str(r.output)

        await coord.run("kickoff")

        # Get the spec's execution_started + the rsch's started.
        spec_started = next(
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("agent_id") == "22222222-2222-4222-8222-bbbbbbbbbbbb"
        )
        rsch_started = next(
            e
            for e in mock.published_events
            if e.get("event_type") == "execution_started"
            and e.get("agent_id") == "22222222-2222-4222-8222-cccccccccccc"
        )

        # The researcher's root must equal the specialist's root
        # (which is the coord's execution_id).
        assert (
            rsch_started["root_execution_id"]
            == spec_started["root_execution_id"]
        )
        # The researcher's parent must be the specialist's
        # execution_id.
        assert (
            rsch_started["parent_execution_id"]
            == spec_started["execution_id"]
        )

    asyncio.run(_run())


def test_supports_nested_runtime_instrumentation_signal() -> None:
    """Plugins that auto-instrument nested runs declare the
    capability via a simple class method. The watchlight-core
    conformance harness reads this to opt the plugin into
    nested-aware lifecycle exercises in a future PR (currently
    the harness's nested exercise is invoked via the LangGraph
    ``spawn_subagent`` path, which is sufficient for invariant
    #8 attribution).

    The signal is a static method returning ``True`` for
    plugins like ours that have the capability.
    """
    assert (
        WatchlightPydanticAIPlugin.supports_nested_runtime_instrumentation()
        is True
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
