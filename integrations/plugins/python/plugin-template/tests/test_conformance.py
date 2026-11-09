"""Template plugin's own conformance test.

This test stays passing when the template ships — the
synthetic-lifecycle harness only exercises ``start_run`` →
``authorize_action`` → ``complete``, none of which require the
TODOs to be filled in. Translator-shape invariants are validated
on a hand-built event below.

When you fork: add framework-specific tests for your
callback-translation paths. The reference plugins each ship
~30-50 tests covering their specific lifecycle.
"""

from __future__ import annotations

import asyncio

import pytest

from watchlight_core_testing.conformance import (
    discover_plugin_class,
    discover_translator,
    load_plugin_module,
    run_conformance,
)
from watchlight_core_testing import assert_canonical_event


def test_template_module_is_discoverable() -> None:
    """The template's package exports the canonical SDK surface
    (plugin class + translator) so the conformance runner can
    discover it by name."""
    module = load_plugin_module("watchlight_template")
    plugin_cls = discover_plugin_class(module)
    translator = discover_translator(module)

    assert plugin_cls.__name__ == "WatchlightTemplatePlugin"
    assert translator is not None, "template should export translate_template_event(s)"
    assert translator.__name__ in (
        "translate_template_event",
        "translate_template_events",
    )


def test_translator_emits_canonical_tool_call_event() -> None:
    """Hand-builds a synthetic hook dict the translator should
    map to a canonical ``tool_call_observed``. Asserts the seven
    invariants on the output.
    """
    from watchlight_template.traces import (
        SOURCE_TAG,
        URI_SCHEME,
        translate_template_event,
    )

    event = translate_template_event(
        {
            "hook": "tool_start",
            "tool_name": "fetch_data",
            "action_verb": "execute",
            "input": "find Q3 revenue figures",
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


def test_translator_emits_canonical_plan_observed_event() -> None:
    """Plan-observed shape: bounded by 64 tools + 1024-byte rationale."""
    from watchlight_template.traces import SOURCE_TAG, translate_template_event

    event = translate_template_event(
        {
            "hook": "plan_declared",
            "intended_tools": ["fetch_data", "summarize", "score"],
            "plan_kind": "upfront",
            "rationale": "User asked for a Q3 revenue summary",
        },
        execution_id="exec_abc",
        agent_id="agent-1",
    )

    assert event is not None
    assert event["event_type"] == "plan_observed"
    assert event["payload"]["intended_tools"] == ["fetch_data", "summarize", "score"]
    assert_canonical_event(event, expected_source=SOURCE_TAG)


def test_translator_drops_unknown_hooks() -> None:
    """Translator MUST return None for unrecognized hooks rather
    than emitting a malformed event."""
    from watchlight_template.traces import translate_template_event

    out = translate_template_event(
        {"hook": "something_unrecognised", "data": "irrelevant"},
        execution_id="exec_abc",
        agent_id="agent-1",
    )
    assert out is None


def test_synthetic_lifecycle_passes_seven_invariants() -> None:
    """The conformance runner drives a synthetic
    plan → authorize → tool-call → complete lifecycle through the
    plugin and asserts the seven invariants on every event the
    plugin emits. The template plugin passes out of the box; the
    customer's fork keeps it passing as they fill in the TODOs.
    """

    async def _run() -> bool:
        passed, report = await run_conformance("watchlight_template")
        if not passed:
            # Surface the report so failures are debuggable.
            for line in report:
                print(line)
        return passed

    assert asyncio.run(_run()), "watchlight_template failed conformance"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
