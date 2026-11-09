"""Tool names read off a real ``google.adk.agents.LlmAgent``.

The plugin derives a sub-agent's requested spawn scope and its registry
entries from ``agent.tools``. On a real ``LlmAgent`` that list holds
whatever the host declared — usually the plain Python callables ADK
wraps into ``FunctionTool`` at request time, sometimes ``BaseTool``
instances. Both must resolve to the governed tool name, with ADK's own
precedence (``get_callable_name``): a ``BaseTool`` under ``.name``, any
other callable under ``__name__``, else its class name. That name is the
``Tool::"<name>"`` resource ``before_tool_callback`` authorizes, the
registry catalogue entry, and — as the spawn scope — the identifier
wl-apdp's strict-subset check compares against the parent's effective
``allowed_tools``.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool

from watchlight_adk.plugin import WatchlightPlugin, _tool_name


def search_web(query: str) -> str:
    """Search the web."""
    return query


def fetch_url(url: str) -> str:
    """Fetch a URL."""
    return url


def summarize_text(text: str) -> str:
    """Summarize text."""
    return text


class LookupPrices:
    """A callable instance declared as a tool (no ``__name__``)."""

    def __call__(self, ticker: str) -> str:
        return ticker


def _plugin() -> WatchlightPlugin:
    return WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        agent_slug="agent-researcher",
        root_agent_name="researcher",
    )


# ─── _tool_name follows ADK's naming ────────────────────────────────────


def test_tool_name_of_a_base_tool_is_its_name():
    assert _tool_name(FunctionTool(search_web)) == "search_web"


def test_tool_name_of_a_plain_function_is_its_dunder_name():
    assert _tool_name(fetch_url) == "fetch_url"


def test_tool_name_of_a_callable_instance_is_its_class_name():
    # ADK's ``get_callable_name``: no ``__name__`` → the class name, which
    # is also what ADK's ``FunctionTool`` wrapper is registered under.
    assert _tool_name(LookupPrices()) == "LookupPrices"
    assert FunctionTool(LookupPrices()).name == "LookupPrices"


def test_tool_name_ignores_a_stray_name_attribute_on_a_function():
    def get_report(period: str) -> str:
        return period

    get_report.name = "something_else"  # type: ignore[attr-defined]
    # ADK names the wrapper after ``__name__`` and ignores ``.name``; the
    # governed name must be the one ADK dispatches under.
    assert FunctionTool(get_report).name == "get_report"
    assert _tool_name(get_report) == "get_report"


def test_tool_name_never_falls_back_to_a_repr():
    assert "<" not in _tool_name(search_web)
    assert "<" not in _tool_name(LookupPrices())


# ─── derived spawn scope = tool names ───────────────────────────────────


def test_derived_scope_reads_plain_function_tools_as_tool_names():
    agent = LlmAgent(
        name="researcher",
        model="gemini-2.0-flash",
        tools=[search_web, fetch_url, summarize_text],
    )
    assert _plugin()._derive_subagent_allowed_tools(agent) == [
        "search_web",
        "fetch_url",
        "summarize_text",
    ]


def test_derived_scope_reads_function_tool_instances():
    agent = LlmAgent(
        name="researcher",
        model="gemini-2.0-flash",
        tools=[FunctionTool(search_web), FunctionTool(fetch_url)],
    )
    assert _plugin()._derive_subagent_allowed_tools(agent) == [
        "search_web",
        "fetch_url",
    ]


def test_derived_scope_is_tool_names_not_action_verbs():
    # The requested scope carries no verb: wl-apdp compares each entry
    # literally against the parent's effective allowed_tools (tool
    # names). An action_map override changes the verb a call authorizes
    # under, never the requested spawn scope.
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        action_map={"fetch_url": "search"},
        agent_slug="agent-researcher",
        root_agent_name="researcher",
    )
    agent = LlmAgent(
        name="researcher", model="gemini-2.0-flash", tools=[fetch_url]
    )
    derived = plugin._derive_subagent_allowed_tools(agent)
    assert derived == ["fetch_url"]
    assert "search" not in derived and "read" not in derived


def test_derived_scope_deduplicates_preserving_order():
    agent = LlmAgent(
        name="researcher",
        model="gemini-2.0-flash",
        tools=[search_web, FunctionTool(search_web), fetch_url],
    )
    assert _plugin()._derive_subagent_allowed_tools(agent) == [
        "search_web",
        "fetch_url",
    ]


# ─── registry entries ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_report_tool_inventory_reads_plain_function_names():
    plugin = _plugin()
    registry = MagicMock()
    registry.report_tool_inventory = AsyncMock(return_value=True)
    plugin.registry = registry
    plugin._current_agent_id = "00000000-0000-0000-0000-000000000001"
    agent = LlmAgent(
        name="researcher",
        model="gemini-2.0-flash",
        tools=[search_web, FunctionTool(summarize_text)],
    )

    await plugin._report_tool_inventory(agent)

    registry.report_tool_inventory.assert_awaited_once()
    _agent_id, tools, *_ = registry.report_tool_inventory.call_args.args
    assert [(t["name"], t["action_verb"]) for t in tools] == [
        ("search_web", "search"),
        ("summarize_text", "summarize"),
    ]


@pytest.mark.asyncio
async def test_report_tool_inventory_truncates_description_to_registry_cap():
    plugin = _plugin()
    registry = MagicMock()
    registry.report_tool_inventory = AsyncMock(return_value=True)
    plugin.registry = registry
    plugin._current_agent_id = "00000000-0000-0000-0000-000000000001"

    long_doc = "x" * 5000
    tool = FunctionTool(search_web)
    tool.description = long_doc
    agent = LlmAgent(name="researcher", model="gemini-2.0-flash", tools=[tool])

    await plugin._report_tool_inventory(agent)

    _agent_id, tools, *_ = registry.report_tool_inventory.call_args.args
    assert len(tools[0]["description"]) == 2000
    assert tools[0]["description"] == long_doc[:2000]


@pytest.mark.asyncio
async def test_report_tool_inventory_rejection_is_logged_at_warning(caplog):
    plugin = _plugin()
    registry = MagicMock()
    registry.report_tool_inventory = AsyncMock(return_value=False)
    plugin.registry = registry
    plugin._current_agent_id = "00000000-0000-0000-0000-000000000001"
    agent = LlmAgent(name="researcher", model="gemini-2.0-flash", tools=[search_web])

    with caplog.at_level(logging.WARNING, logger="watchlight_adk"):
        await plugin._report_tool_inventory(agent)

    assert any(
        r.levelno == logging.WARNING and "Tool inventory report rejected" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_report_tool_inventory_exception_is_logged_at_warning_and_swallowed(caplog):
    plugin = _plugin()
    registry = MagicMock()
    registry.report_tool_inventory = AsyncMock(side_effect=RuntimeError("boom"))
    plugin.registry = registry
    plugin._current_agent_id = "00000000-0000-0000-0000-000000000001"
    agent = LlmAgent(name="researcher", model="gemini-2.0-flash", tools=[search_web])

    with caplog.at_level(logging.WARNING, logger="watchlight_adk"):
        await plugin._report_tool_inventory(agent)  # must not raise

    assert any(
        r.levelno == logging.WARNING and "Tool inventory report failed" in r.getMessage()
        for r in caplog.records
    )
