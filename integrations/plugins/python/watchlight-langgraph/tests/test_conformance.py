"""LangGraph plugin conformance tests.

This file holds the cross-plugin conformance assertions for the
LangGraph plugin — the same shape exercised by the
:mod:`watchlight_core_testing.conformance` runner, asserted here as
pytest tests so failures land on the LangGraph plugin's own CI lane
(not just the runner's CLI).

Includes the scope-attenuation propagation assertion: the
``spawn_subagent`` override emits an ``agent_spawn_observed`` event
with a populated ``delegation_scope`` payload field, so a spawn is
audited at every depth.
"""

from __future__ import annotations

import asyncio

import pytest

from watchlight_core_testing.conformance import (
    check_scope_attenuation_propagation,
    discover_plugin_class,
    discover_translator,
    load_plugin_module,
    run_conformance,
)
from watchlight_core_testing import MockApdpClient


# Canonical test UUIDs — the spawn handler enforces the canonical
# UUID wire shape, so synthetic non-UUID slugs are rejected.
_PARENT_UUID = "11111111-1111-4111-8111-aaaaaaaaaaaa"
_CHILD_UUID = "11111111-1111-4111-8111-bbbbbbbbbbbb"


def test_module_is_discoverable() -> None:
    """Plugin class + translator are discoverable by the SDK
    conformance runner."""
    module = load_plugin_module("watchlight_langgraph")
    plugin_cls = discover_plugin_class(module)
    translator = discover_translator(module)
    assert plugin_cls.__name__ == "WatchlightLangGraphPlugin"
    assert translator is not None


def test_synthetic_lifecycle_passes_all_invariants() -> None:
    """The SDK conformance runner exits 0 against the plugin."""

    async def _run() -> bool:
        passed, report = await run_conformance("watchlight_langgraph")
        if not passed:
            for line in report:
                print(line)
        return passed

    assert asyncio.run(_run()), "watchlight_langgraph failed conformance"


def test_spawn_emits_child_started_not_agent_spawn_observed() -> None:
    """The LangGraph ``spawn_subagent`` override no longer emits
    ``agent_spawn_observed``. Spawn attestation (carrying the
    server-validated ``granted_scope``) is SERVER-emitted by wl-apdp's
    spawn handler as it processes the ``POST /v1/spawn_subagent``
    round-trip, and the class is REJECTED at ``/v1/events`` ingest. The
    plugin's on-wire signal for the spawn is now ONLY the child's own
    ``execution_started`` (server child execution_id + parent linkage),
    so the scope-attenuation propagation check passes VACUOUSLY — which
    the core check confirms.
    """
    from watchlight_langgraph import WatchlightLangGraphPlugin

    async def _run() -> list[dict]:
        plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost")
        plugin.apdp = MockApdpClient()
        plugin.apdp.known_agents["parent-agent"] = _PARENT_UUID
        plugin.apdp.known_agents["child-agent"] = _CHILD_UUID

        parent_handle = await plugin.start_run("parent-agent")
        await parent_handle.spawn_subagent(
            "child-agent",
            child_intent={"category": "research", "objective": "Delegated sub-task"},
            parent_execution_id="exec_parent",
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

    # The child's own execution_started IS emitted, with parent linkage.
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

    # The scope-attenuation propagation check passes vacuously on the
    # captured stream.
    check_scope_attenuation_propagation(events)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
