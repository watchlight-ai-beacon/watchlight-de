"""Assert the ``deepagents`` / LangChain hook surface we bind to.

The proposal (§7.1) flags the LangChain v1 ``AgentMiddleware`` API as
young and potentially unstable (``wrap_model_call`` was renamed from
``modify_model_request``). This module PINS the surface: it asserts the
hook names + signatures, the ``ToolCallRequest`` fields, the
``SubAgent.middleware`` field, and the ``task`` tool schema so an
upstream drift breaks CI loudly instead of silently disabling
governance. Skips (does not fail) when ``deepagents`` is not installed.
"""

from __future__ import annotations

import inspect

import pytest

deepagents = pytest.importorskip(
    "deepagents", reason="deepagents not installed in this sandbox"
)


def test_agent_middleware_hook_surface_exists():
    from langchain.agents.middleware.types import AgentMiddleware

    for hook in (
        "before_agent",
        "after_agent",
        "before_model",
        "wrap_model_call",
        "wrap_tool_call",
    ):
        assert hasattr(AgentMiddleware, hook), f"AgentMiddleware.{hook} missing"

    # Async variants must exist — deepagents runs on the async runtime.
    for hook in (
        "abefore_agent",
        "aafter_agent",
        "abefore_model",
        "awrap_model_call",
        "awrap_tool_call",
    ):
        assert hasattr(AgentMiddleware, hook), f"AgentMiddleware.{hook} missing"


def test_hook_signatures_are_what_we_bind_to():
    from langchain.agents.middleware.types import AgentMiddleware

    sig = inspect.signature(AgentMiddleware.before_agent)
    assert list(sig.parameters)[:3] == ["self", "state", "runtime"]

    sig = inspect.signature(AgentMiddleware.wrap_tool_call)
    assert list(sig.parameters)[:3] == ["self", "request", "handler"]

    sig = inspect.signature(AgentMiddleware.wrap_model_call)
    assert list(sig.parameters)[:3] == ["self", "request", "handler"]


def test_tool_call_request_fields():
    import dataclasses

    from langchain.agents.middleware.types import ToolCallRequest

    fields = {f.name for f in dataclasses.fields(ToolCallRequest)}
    # We read ``tool_call`` (name/args/id) and ``state``.
    assert {"tool_call", "state"} <= fields


def test_subagent_has_middleware_field():
    from deepagents.middleware.subagents import SubAgent

    assert "middleware" in SubAgent.__annotations__


def test_task_tool_schema_has_subagent_type():
    from deepagents.middleware.subagents import TaskToolSchema, TASK_TOOL_DESCRIPTION

    assert "subagent_type" in TaskToolSchema.model_fields
    assert "task" in TASK_TOOL_DESCRIPTION.lower()


def test_our_middleware_binds_against_real_base():
    """The governance middleware built against the REAL LangChain base
    exposes the async hooks + stable name."""
    from langchain.agents.middleware.types import AgentMiddleware

    from watchlight_deepagents.middleware import build_governance_middleware
    from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin

    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    mw = build_governance_middleware(
        plugin=plugin,
        agent_slug="x",
        subagent_scopes={},
        subagent_slugs={},
        is_child=False,
    )
    assert isinstance(mw, AgentMiddleware)
    assert mw.name == "watchlight_governance"
    for hook in (
        "abefore_agent",
        "aafter_agent",
        "abefore_model",
        "awrap_model_call",
        "awrap_tool_call",
    ):
        assert inspect.iscoroutinefunction(getattr(mw, hook))
