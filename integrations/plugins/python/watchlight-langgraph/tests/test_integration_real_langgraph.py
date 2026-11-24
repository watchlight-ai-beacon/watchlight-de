"""Real-LangGraph integration smoke test.

Goal: prove the callback handler captures events from a real
LangGraph ``StateGraph`` invocation — not just from unit-test
fixtures. Uses ``RunnableLambda`` nodes so no LLM or external
service is required; the test runs in CI without network access.

This test exists because unit tests on the translator + handler
prove correctness *given* the LangChain callback shapes, but
they don't prove that LangChain actually emits those shapes in a
real run. Without this test we're trusting the LangChain docs;
with it, we're trusting CI.
"""

from __future__ import annotations

from typing import TypedDict
from unittest.mock import AsyncMock

import pytest

from watchlight_langgraph import WatchlightAsyncCallbackHandler

# Real LangGraph imports. The plugin already depends on
# ``langgraph>=0.2`` (per pyproject.toml), so these are guaranteed
# to be available.
try:
    from langchain_core.runnables import RunnableLambda
    from langgraph.graph import StateGraph, END
except ImportError:
    pytest.skip(
        "langgraph / langchain_core not available — skipping integration test",
        allow_module_level=True,
    )


class _AgentState(TypedDict, total=False):
    """Minimal state for the test graph."""

    question: str
    research: str
    answer: str
    error: str


def _research_node(state: _AgentState) -> _AgentState:
    """Simulated research node — no LLM, deterministic output."""
    q = state.get("question", "")
    return {"research": f"researched: {q}"}


def _answer_node(state: _AgentState) -> _AgentState:
    """Simulated answer node — composes the prior research."""
    research = state.get("research", "")
    return {"answer": f"answer based on: {research}"}


def _failing_node(state: _AgentState) -> _AgentState:
    """Deliberately raises — used to exercise the error path."""
    raise RuntimeError("simulated upstream failure")


# In-process stand-in for unit tests only.
@pytest.fixture
def stub_apdp():
    apdp = AsyncMock()
    apdp.publish_events = AsyncMock(return_value=True)
    return apdp


@pytest.fixture
def working_graph():
    """A two-node graph: research → answer → END."""
    builder = StateGraph(_AgentState)
    builder.add_node("research", RunnableLambda(_research_node))
    builder.add_node("answer", RunnableLambda(_answer_node))
    builder.set_entry_point("research")
    builder.add_edge("research", "answer")
    builder.add_edge("answer", END)
    return builder.compile()


@pytest.fixture
def failing_graph():
    """A graph whose first node raises — exercises error
    callback path."""
    builder = StateGraph(_AgentState)
    builder.add_node("research", RunnableLambda(_failing_node))
    builder.set_entry_point("research")
    builder.add_edge("research", END)
    return builder.compile()


# ─── Tests ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_real_langgraph_invocation_captures_chain_events(
    stub_apdp, working_graph
):
    """The most important integration test: a real LangGraph
    ``ainvoke`` with our handler attached captures non-zero
    events. If LangChain ever changes its callback firing
    contract, this test fails loudly."""
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=stub_apdp,
        execution_id="exec_smoke",
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
    )

    result = await working_graph.ainvoke(
        {"question": "what is 2+2"},
        config={"callbacks": [handler]},
    )

    # Sanity: the graph ran end-to-end.
    assert result.get("answer", "").startswith("answer based on:")

    # The handler captured events. Exact count varies by
    # LangChain version (intermediate Runnable composition fires
    # extra on_chain_start/end events for nested wrappers), so
    # we assert a lower bound rather than an exact count.
    assert handler.buffered_count() > 0

    captured = handler.snapshot()
    hooks_seen = {ev["hook"] for ev in captured}
    # Must have at least one chain start + chain end (top-level
    # graph entry + exit). LangChain may also emit on_chain_*
    # for individual nodes — both shapes are acceptable.
    assert "on_chain_start" in hooks_seen
    assert "on_chain_end" in hooks_seen


@pytest.mark.asyncio
async def test_flush_after_real_invocation_translates_and_publishes(
    stub_apdp, working_graph
):
    """End-to-end: real invocation + flush + verify the published
    batch shape. This is the test that proves the canonical event
    wire contract holds in a real LangGraph run."""
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=stub_apdp,
        execution_id="exec_smoke",
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
    )

    await working_graph.ainvoke(
        {"question": "what is 2+2"},
        config={"callbacks": [handler]},
    )

    count = await handler.flush()
    assert count > 0, "flush emitted no canonical events from a real run"

    # The stub APDP captured the batch.
    assert stub_apdp.publish_events.call_count == 1
    batch = stub_apdp.publish_events.call_args[0][1]

    # Every emitted event carries the bound identity.
    for ev in batch:
        assert ev["execution_id"] == "exec_smoke"
        assert ev["agent_id"] == "agent-1"
        assert ev["session_id"] == "sess_42"
        assert ev["tenant_id"] == "acme"
        assert ev["metadata"]["source"] == "langgraph.callback"

    # We expect at least an execution_started somewhere in the
    # batch (top-level chain start fires execution_started).
    event_types = {ev["event_type"] for ev in batch}
    assert "execution_started" in event_types or "execution_completed" in event_types


@pytest.mark.asyncio
async def test_real_langgraph_error_captures_failure_event(stub_apdp, failing_graph):
    """When a node raises, LangChain fires ``on_chain_error``.
    Our handler captures it; translation emits ``ExecutionFailed``.
    Critical because anomaly emission (drift detection) depends on
    failure signals from real runs."""
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=stub_apdp,
        execution_id="exec_smoke",
        agent_id="agent-1",
    )

    # The graph will raise; we catch it because the goal is to
    # observe what LangChain emitted, not to assert no-raise on
    # invocation.
    with pytest.raises(RuntimeError):
        await failing_graph.ainvoke(
            {"question": "fail"},
            config={"callbacks": [handler]},
        )

    captured = handler.snapshot()
    hooks_seen = {ev["hook"] for ev in captured}
    assert "on_chain_error" in hooks_seen, (
        f"LangChain did not fire on_chain_error for a raising node; "
        f"saw {hooks_seen}"
    )

    # After flush, at least one ExecutionFailed event was published.
    await handler.flush()
    batch = stub_apdp.publish_events.call_args[0][1]
    event_types = [ev["event_type"] for ev in batch]
    assert "execution_failed" in event_types
