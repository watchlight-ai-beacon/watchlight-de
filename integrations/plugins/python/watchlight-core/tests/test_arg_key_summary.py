"""Tests for the ``arg_key_summary`` behavioural feature — the
sorted, comma-joined argument KEYS (never values) of a tool call.

This is the privacy-safe feature wl-drift's arg-shape scorer consumes.
The wire contract spans three ends that MUST agree:

* Rust canonical (``wl-lineage::events::ToolCallObservedPayload``)
* this Pydantic mirror (``watchlight_core.events_schema``)
* ``wl-proxy``'s MCP translator + every SDK plugin emitter

If these tests fail, the emitters and wl-drift have drifted on how the
arg-shape distribution is keyed, and drift scoring will be inconsistent
across the SDK and proxy vantages.
"""

from __future__ import annotations

from watchlight_core import INPUT_SUMMARY_MAX_CHARS, summarize_arg_keys
from watchlight_core.events_schema import ToolCallObservedPayload


class TestSummarizeArgKeys:
    def test_sorted_comma_joined_keys(self) -> None:
        # Order-independent: whatever kwarg order the framework used,
        # the same call shape yields the same summary.
        assert summarize_arg_keys({"text": "a", "format": "b"}) == "format,text"
        assert summarize_arg_keys({"format": "b", "text": "a"}) == "format,text"

    def test_single_key(self) -> None:
        assert summarize_arg_keys({"query": "anything"}) == "query"

    def test_values_never_appear(self) -> None:
        out = summarize_arg_keys({"path": "/etc/passwd", "mode": "r"})
        assert out == "mode,path"
        assert "/etc/passwd" not in out
        assert "r" not in out.split(",")

    def test_empty_mapping_is_none(self) -> None:
        # A no-argument call contributes no shape.
        assert summarize_arg_keys({}) is None

    def test_non_mapping_is_none(self) -> None:
        # Only structured mappings carry keys; a flat string rendering
        # (e.g. langchain's input_str) must NOT be treated as keys.
        assert summarize_arg_keys(None) is None
        assert summarize_arg_keys("query=hello") is None
        assert summarize_arg_keys(42) is None
        # A raw list (e.g. Bedrock's parameter dicts) is NOT a mapping;
        # the bedrock emitter projects names into a mapping first.
        assert summarize_arg_keys([{"name": "a"}]) is None

    def test_non_string_keys_are_stringified(self) -> None:
        assert summarize_arg_keys({1: "x", 2: "y"}) == "1,2"

    def test_bounded_to_input_summary_max(self) -> None:
        big = {f"key_{i:04d}": None for i in range(200)}
        out = summarize_arg_keys(big)
        assert out is not None
        assert len(out) <= INPUT_SUMMARY_MAX_CHARS


class TestToolCallObservedPayloadField:
    def test_field_round_trips(self) -> None:
        p = ToolCallObservedPayload.model_validate(
            {
                "tool": {"resource_type": "tool", "identifier": "web_search"},
                "action": {"action": "invoke"},
                "arg_key_summary": "max_results,query",
            }
        )
        assert p.arg_key_summary == "max_results,query"
        assert p.model_dump(exclude_none=True)["arg_key_summary"] == "max_results,query"

    def test_field_is_optional(self) -> None:
        # Absent on the wire (older emitters / no structured args) →
        # no arg-shape contribution, never a validation error.
        p = ToolCallObservedPayload.model_validate(
            {
                "tool": {"resource_type": "tool", "identifier": "t"},
                "action": {"action": "invoke"},
            }
        )
        assert p.arg_key_summary is None
        assert "arg_key_summary" not in p.model_dump(exclude_none=True)
