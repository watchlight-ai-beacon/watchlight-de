"""A real governed deep agent on the in-process engine (Developer Edition).

A scripted model drives ``create_governed_deep_agent`` end to end: the
Cedar policy decides each root tool call, and a sub-agent may call only the
tools its spawn granted. Skips when ``deepagents`` is not installed; the
compiled ``watchlight-engine`` is required."""

from __future__ import annotations

import pytest

pytest.importorskip("deepagents", reason="deepagents not installed")
# CI installs the engine, so a missing engine fails here instead of skipping.
import watchlight_engine  # noqa: E402,F401

from langchain_core.language_models.fake_chat_models import (  # noqa: E402
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage, ToolMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from watchlight_core import InProcessClient  # noqa: E402

from watchlight_deepagents import (  # noqa: E402
    WatchlightDeepAgentsPlugin,
    create_governed_deep_agent,
)


# In-process stand-in for unit tests only: replays scripted turns.
class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def _tools(ran):
    @tool
    def search_web(query: str) -> str:
        """Search the web."""
        ran.append("search_web")
        return "results"

    @tool
    def send_email(to: str, body: str) -> str:
        """Send an email."""
        ran.append("send_email")
        return "sent"

    return search_web, send_email


def _plugin(tmp_path, code):
    backend = InProcessClient(
        [{"name": "p", "code": code}], audit_path=str(tmp_path / "audit.jsonl")
    )
    return WatchlightDeepAgentsPlugin(governance=backend)


def _tool_results(out):
    return {m.name: m for m in out["messages"] if isinstance(m, ToolMessage)}


async def test_the_policy_decides_each_root_tool_call(tmp_path):
    ran = []
    search_web, send_email = _tools(ran)
    model = _ScriptedModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "search_web", "args": {"query": "q"}, "id": "c1"},
                        {"name": "send_email", "args": {"to": "a", "body": "b"}, "id": "c2"},
                    ],
                ),
                AIMessage(content="done"),
            ]
        )
    )
    agent = create_governed_deep_agent(
        model=model,
        tools=[search_web, send_email],
        agent_slug="research-orchestrator",
        plugin=_plugin(
            tmp_path, 'permit(principal is Agent, action == Action::"read", resource);'
        ),
    )
    out = await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})
    assert ran == ["search_web"]
    assert _tool_results(out)["send_email"].status == "error"


async def test_a_sub_agent_calls_only_its_granted_tools(tmp_path):
    ran = []
    search_web, send_email = _tools(ran)
    root = _ScriptedModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "task",
                            "args": {"description": "find", "subagent_type": "researcher"},
                            "id": "t1",
                        }
                    ],
                ),
                AIMessage(content="root done"),
            ]
        )
    )
    child = _ScriptedModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "search_web", "args": {"query": "q"}, "id": "c1"},
                        {"name": "send_email", "args": {"to": "a", "body": "b"}, "id": "c2"},
                    ],
                ),
                AIMessage(content="child done"),
            ]
        )
    )
    agent = create_governed_deep_agent(
        model=root,
        tools=[search_web, send_email],
        subagents=[
            {
                "name": "researcher",
                "description": "research",
                "system_prompt": "research",
                "tools": [search_web, send_email],
                "model": child,
            }
        ],
        # The grant names the tool in the namespace the call's resource uses
        # (``deepagents://tool/<name>``, as the plugin's README and example
        # do): the in-process engine checks the grant against the call's
        # action and resource, as wl-apdp does, so a bare tool name would
        # match nothing there.
        subagent_scopes={
            "researcher": {"allowed_tools": ["deepagents://tool/search_web"], "max_depth": 0}
        },
        agent_slug="research-orchestrator",
        # The policy permits everything: only the spawn's grant stops send_email.
        plugin=_plugin(tmp_path, "permit(principal is Agent, action, resource);"),
    )
    await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})
    assert ran == ["search_web"]
