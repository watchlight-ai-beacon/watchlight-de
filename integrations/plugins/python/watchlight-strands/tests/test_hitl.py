"""Approval-required decisions become Strands interrupts. The tool runs
only after the invocation is resumed with an approval AND the retried
authorization, on the same run, allows it."""

from __future__ import annotations

from typing import Any, List

import pytest
from conftest import ScriptedModel, text, tool_call
from strands import Agent, tool
from watchlight_core_testing import MockApdpClient
from watchlight_strands import APPROVAL_INTERRUPT_NAME

ran: List[str] = []


@pytest.fixture(autouse=True)
def _reset_ran() -> None:
    ran.clear()


@tool
def wire_funds(amount: int) -> str:
    """Wire funds."""
    ran.append(f"wire:{amount}")
    return "wired"


INTENT = {"objective": "pay the invoice", "category": "financial_operation"}


def _interrupted(make_plugin, mock_apdp: MockApdpClient, **plugin_kwargs: Any):
    mock_apdp.decisions[("execute", "wire_funds")] = "needs_approval"
    model = ScriptedModel([[tool_call("wire_funds", {"amount": 100})], [text("done")]])
    if not plugin_kwargs:
        # wl-apdp binds an approval to the typed intent it was requested
        # under, so the run declares one (objective AND category).
        plugin_kwargs = {
            "intent_objective": INTENT["objective"],
            "intent_category": INTENT["category"],
        }
    plugin = make_plugin("agent-root", **plugin_kwargs)
    agent = Agent(model=model, tools=[wire_funds], plugins=[plugin], callback_handler=None)
    result = agent("pay the invoice")
    return agent, model, result


def _resume(agent: Agent, result: Any, response: Any) -> Any:
    return agent(
        [
            {"interruptResponse": {"interruptId": interrupt.id, "response": response}}
            for interrupt in result.interrupts
        ]
    )


def test_approval_required_interrupts_without_running_the_tool(make_plugin, mock_apdp: MockApdpClient):
    _, _, result = _interrupted(make_plugin, mock_apdp)

    assert result.stop_reason == "interrupt"
    assert ran == []
    [interrupt] = result.interrupts
    assert interrupt.name == APPROVAL_INTERRUPT_NAME
    assert interrupt.reason["type"] == "watchlight_approval_required"
    assert interrupt.reason["tool_name"] == "wire_funds"
    # The approval request id is a bearer value: it never leaves the process.
    assert "appr_" not in repr(interrupt.reason)
    # The run stays open for the resume.
    assert mock_apdp._closed_sessions == []


def test_approved_resume_retries_on_the_same_run(make_plugin, mock_apdp: MockApdpClient):
    agent, _, result = _interrupted(make_plugin, mock_apdp)
    first_execution = mock_apdp.authorize_calls[0]["execution_id"]
    mock_apdp.decisions[("execute", "wire_funds")] = "Allow"

    resumed = _resume(agent, result, "approved")

    assert resumed.stop_reason == "end_turn"
    assert ran == ["wire:100"]
    retry = mock_apdp.authorize_calls[-1]
    # The token rides inside the run's typed intent, where wl-apdp reads it.
    assert retry["intent"]["approval_token"].startswith("appr_")
    assert {k: retry["intent"][k] for k in ("objective", "category")} == INTENT
    assert mock_apdp.authorize_calls[0]["intent"] == INTENT
    assert retry["execution_id"] == first_execution
    # One session for the whole approval round-trip, closed at the end.
    assert len(mock_apdp._closed_sessions) == 1


def test_rejected_resume_never_runs_the_tool(make_plugin, mock_apdp: MockApdpClient):
    agent, model, result = _interrupted(make_plugin, mock_apdp)
    calls_before = len(mock_apdp.authorize_calls)

    _resume(agent, result, "rejected")

    assert ran == []
    assert len(mock_apdp.authorize_calls) == calls_before
    assert any("needs human approval" in t for t in model.tool_result_texts())
    assert len(mock_apdp._closed_sessions) == 1


def test_an_approval_the_server_does_not_honour_never_runs_the_tool(make_plugin, mock_apdp: MockApdpClient):
    agent, _, result = _interrupted(make_plugin, mock_apdp)
    mock_apdp.decisions[("execute", "wire_funds")] = "Deny"

    _resume(agent, result, {"approved": True})

    assert ran == []
    assert mock_apdp.authorize_calls[-1]["intent"]["approval_token"].startswith("appr_")


def test_an_approval_without_a_declared_intent_is_refused_locally(make_plugin, mock_apdp: MockApdpClient):
    """Without a typed intent the token has nowhere wl-apdp reads it from
    (a bare token is a category-less intent, answered 422): the plugin
    refuses clearly instead of sending a request that can only fail."""
    agent, model, result = _interrupted(make_plugin, mock_apdp, log_decisions=False)
    calls_before = len(mock_apdp.authorize_calls)
    mock_apdp.decisions[("execute", "wire_funds")] = "Allow"

    _resume(agent, result, "approved")

    assert ran == []
    assert len(mock_apdp.authorize_calls) == calls_before
    assert any("declared intent" in t for t in model.tool_result_texts())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"intent_objective": "pay"},
        {"intent_category": "financial_operation"},
        {"intent_objective": "pay", "intent_category": "payments"},
        {"intent_objective": "  ", "intent_category": "research"},
    ],
)
def test_a_declared_intent_must_be_typed(make_plugin, kwargs):
    with pytest.raises(ValueError, match="intent_objective and intent_category"):
        make_plugin("agent-root", **kwargs)
