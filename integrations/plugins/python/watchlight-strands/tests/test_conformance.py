"""Conformance: the watchlight-core harness, plus the same invariants on
the events a real Strands run emits through the plugin."""

from __future__ import annotations

import asyncio

from conftest import SECRET, ScriptedModel, text, tool_call
from strands import Agent, tool
from watchlight_core_testing.conformance import (
    HOSTED_TOOL_PLUGINS_PENDING,
    HOSTED_TOOL_PLUGINS_REQUIRED,
    check_execution_started_precedes_non_lifecycle_events,
    check_required_hosted_tool_plugin,
    check_single_correlated_execution_id,
    discover_plugin_class,
    discover_translator,
    load_plugin_module,
    run_conformance,
)
from watchlight_core_testing import (
    MockApdpClient,
    assert_canonical_event,
    assert_payload_matches_schema,
)
from watchlight_strands.traces import SOURCE_TAG, URI_SCHEME, translate_strands_event


@tool
def lookup(q: str) -> str:
    """Look something up."""
    return "found"


def test_module_exports_the_sdk_surface() -> None:
    module = load_plugin_module("watchlight_strands")
    assert discover_plugin_class(module).__name__ == "WatchlightStrandsPlugin"
    assert discover_translator(module) is not None


def test_hosted_tool_invariant_19_passes_and_is_not_pending() -> None:
    """The real plugin's gate decides every hosted tool before the model
    call, and makes no call when they are denied."""
    assert "watchlight-strands" in HOSTED_TOOL_PLUGINS_REQUIRED
    assert "watchlight-strands" not in HOSTED_TOOL_PLUGINS_PENDING
    assert asyncio.run(check_required_hosted_tool_plugin("watchlight_strands")) == "ok"


def test_conformance_runner_passes() -> None:
    passed, report = asyncio.run(run_conformance("watchlight_strands"))
    assert passed, "\n".join(report)


def test_translator_events_are_canonical() -> None:
    for hook in (
        {"hook": "after_tool_call", "tool_name": "lookup", "input": {"q": SECRET}, "duration_ms": 3},
        {"hook": "before_tool_call", "tool_name": "fs", "tool_type": "mcp", "input": {"p": 1}, "decision": "Deny"},
        {"hook": "before_invocation", "depth": 1},
    ):
        event = translate_strands_event(
            hook,
            execution_id="exec_00000000-0000-4000-8000-000000000000",
            agent_id="11111111-1111-4111-8111-111111111111",
            session_id="ses_x",
        )
        assert event is not None
        assert_canonical_event(event, expected_source=SOURCE_TAG, expected_uri_prefix=f"{URI_SCHEME}://")
        assert_payload_matches_schema(event)
        assert SECRET not in repr(event)
    assert translate_strands_event({"hook": "unknown"}, execution_id="e", agent_id="a") is None


def test_events_of_a_real_run_satisfy_the_invariants(make_plugin, mock_apdp: MockApdpClient) -> None:
    mock_apdp.decisions[("execute", "lookup")] = "Allow"
    child = Agent(
        name="researcher",
        model=ScriptedModel([[tool_call("lookup", {"q": SECRET})], [text("child")]]),
        tools=[lookup],
        callback_handler=None,
    )
    parent = Agent(
        model=ScriptedModel([[tool_call("lookup", {"q": "a"}), tool_call("researcher", {"input": "x"})], [text("ok")]]),
        tools=[lookup, child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    events = mock_apdp.published_events
    assert events
    for event in events:
        assert event["metadata"]["source"].startswith("strands.")
        assert_payload_matches_schema(event)
        if event["event_type"] == "tool_call_observed":
            assert_canonical_event(event, expected_uri_prefix=f"{URI_SCHEME}://")
    check_execution_started_precedes_non_lifecycle_events(events)
    check_single_correlated_execution_id(events)
    assert SECRET not in repr(events)
