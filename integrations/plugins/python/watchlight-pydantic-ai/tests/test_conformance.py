"""Pydantic AI plugin conformance + translator tests."""

from __future__ import annotations

import asyncio

import pytest

from watchlight_core_testing.conformance import (
    discover_plugin_class,
    discover_translator,
    load_plugin_module,
    run_conformance,
)
from watchlight_core_testing import (
    MockApdpClient,
    assert_canonical_event,
    capture_events,
)


def test_module_is_discoverable() -> None:
    """Plugin class + translator are discoverable by the SDK
    conformance runner."""
    module = load_plugin_module("watchlight_pydantic_ai")
    plugin_cls = discover_plugin_class(module)
    translator = discover_translator(module)
    assert plugin_cls.__name__ == "WatchlightPydanticAIPlugin"
    assert translator is not None


def test_translator_tool_call_canonical_shape() -> None:
    """A Pydantic AI tool-call capture maps to a canonical
    tool_call_observed event with the pydantic-ai:// URI scheme."""
    from watchlight_pydantic_ai.traces import (
        SOURCE_TAG,
        URI_SCHEME,
        translate_pydantic_ai_event,
    )

    event = translate_pydantic_ai_event(
        {
            "hook": "tool_call",
            "tool_name": "web_search",
            "args": {"query": "Q3 revenue figures"},
            "decision": "Allow",
            "duration_ms": 42,
        },
        execution_id="exec_abc",
        agent_id="agent-1",
        session_id="ses_xyz",
        tenant_id="tenant-1",
    )
    assert event is not None
    assert_canonical_event(
        event,
        expected_source=SOURCE_TAG,
        expected_uri_prefix=f"{URI_SCHEME}://",
    )
    assert event["payload"]["tool"]["identifier"] == "web_search"
    assert event["payload"]["decision"] == "Allow"
    assert event["payload"]["duration_ms"] == 42


def test_translator_plan_observed_canonical_shape() -> None:
    """A Pydantic AI plan capture maps to plan_observed with
    bounded rationale."""
    from watchlight_pydantic_ai.traces import (
        SOURCE_TAG,
        translate_pydantic_ai_event,
    )

    event = translate_pydantic_ai_event(
        {
            "hook": "tool_planned",
            "intended_tools": ["fetch_data", "summarize", "score"],
            "plan_kind": "upfront",
            "rationale": "User asked for a quarterly summary",
        },
        execution_id="exec_abc",
        agent_id="agent-1",
    )
    assert event is not None
    assert event["event_type"] == "plan_observed"
    assert event["payload"]["plan_kind"] == "upfront"
    assert_canonical_event(event, expected_source=SOURCE_TAG)


def test_translator_drops_unknown_hook() -> None:
    from watchlight_pydantic_ai.traces import translate_pydantic_ai_event

    out = translate_pydantic_ai_event(
        {"hook": "something_unknown", "data": "irrelevant"},
        execution_id="exec_abc",
        agent_id="agent-1",
    )
    assert out is None


def test_guarded_tool_calls_authorize_action() -> None:
    """The ``guarded_tool`` decorator calls authorize_action
    before invoking the wrapped function, and raises
    PermissionError on Deny."""
    from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

    async def _run() -> None:
        plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        plugin.apdp = MockApdpClient()
        plugin.apdp.known_agents["agent-1"] = "uuid-1"
        plugin.apdp.decisions[("execute", "fetch_data")] = "Allow"
        plugin.apdp.decisions[("execute", "forbidden_op")] = "Deny"

        handle = await plugin.start_run("agent-1")
        handle._aentered = True  # synthetic test handle bypasses ``async with``

        # Allow path
        @handle.guarded_tool()
        async def fetch_data(query: str) -> str:
            return f"results for {query}"

        assert await fetch_data("Q3") == "results for Q3"

        # Deny path
        @handle.guarded_tool()
        async def forbidden_op(payload: str) -> str:
            return "secret"

        with pytest.raises(PermissionError):
            await forbidden_op("evil")

        await handle.complete()

    asyncio.run(_run())


def test_synthetic_lifecycle_passes_all_invariants() -> None:
    """The SDK conformance runner exits 0 against the plugin.

    Originally named ``test_synthetic_lifecycle_passes_seven_invariants``
    when the canonical set was 1-7; renamed since the runner now
    exercises invariants 1-9 + 11 + 12 + 13.
    """

    async def _run() -> bool:
        passed, report = await run_conformance("watchlight_pydantic_ai")
        if not passed:
            for line in report:
                print(line)
        return passed

    assert asyncio.run(_run()), "watchlight_pydantic_ai failed conformance"


def test_spawn_emits_child_started_not_agent_spawn_observed() -> None:
    """The Pydantic AI ``spawn_subagent`` override does not emit
    ``agent_spawn_observed``. Spawn attestation (with the server-validated
    granted scope) is SERVER-emitted by wl-apdp's ``spawn_handler`` while
    it processes the ``POST /v1/spawn_subagent`` round-trip, and the class
    is REJECTED at ``/v1/events`` ingest. The plugin's on-wire spawn signal
    is now ONLY the child's own ``execution_started``, so invariant #13
    passes VACUOUSLY — which the core check confirms.
    """
    from watchlight_core_testing.conformance import (
        check_scope_attenuation_propagation,
    )

    async def _run() -> list[dict]:
        from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

        plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        plugin.apdp = MockApdpClient()
        parent_uuid = "11111111-1111-4111-8111-aaaaaaaaaaaa"
        child_uuid = "11111111-1111-4111-8111-bbbbbbbbbbbb"
        plugin.apdp.known_agents["parent"] = parent_uuid
        plugin.apdp.known_agents["child"] = child_uuid

        handle = await plugin.start_run("parent")
        await handle.spawn_subagent(
            "child",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id=handle.execution_id,
            allowed_tools=["web_search"],
            allowed_intents=["research"],
            max_depth=1,
            time_budget_seconds=60,
        )
        return list(plugin.apdp.published_events)

    events = asyncio.run(_run())

    # No plugin-emitted spawn attestation (server-attested only).
    assert not [
        e for e in events if e.get("event_type") == "agent_spawn_observed"
    ]

    # The child's own execution_started IS emitted with parent linkage.
    child_started = [
        e
        for e in events
        if e.get("event_type") == "execution_started"
        and e.get("parent_execution_id") is not None
    ]
    assert child_started, (
        "the child's execution_started must still be emitted so the "
        "lineage tree renders the child node"
    )

    # Invariant #13 passes vacuously on the captured stream.
    check_scope_attenuation_propagation(events)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
