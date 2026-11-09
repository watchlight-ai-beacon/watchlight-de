"""Lineage tool-call events never carry an argument value."""

from watchlight_pydantic_ai.traces import translate_pydantic_ai_event


def test_tool_call_input_summary_is_value_free():
    out = translate_pydantic_ai_event(
        {
            "hook": "tool_call",
            "tool_name": "send_email",
            "args": {"to": "a@example.test", "api_key": "sk-live-SECRET"},
        },
        execution_id="exec_1",
        agent_id="agent-1",
    )
    assert out is not None
    assert out["payload"]["input_summary"] == "2 args: to(str), api_key(str)"
    assert "sk-live-SECRET" not in repr(out)
    assert "a@example.test" not in repr(out)


def test_positional_args_render_only_their_type():
    out = translate_pydantic_ai_event(
        {"hook": "tool_call", "tool_name": "echo", "args": "sk-live-SECRET"},
        execution_id="exec_1",
        agent_id="agent-1",
    )
    assert out["payload"]["input_summary"] == "1 arg: (str)"
    assert "sk-live-SECRET" not in repr(out)
