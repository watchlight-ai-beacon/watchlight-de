"""A real deepagents deep agent governed through ``watchlight.deepagents``.

``governed_plugin`` hands out run handles wrapped to record refusals; these
tests drive ``create_governed_deep_agent`` end to end through that wrapper with
a scripted model, against the real published plugin and the compiled engine:

* the Cedar policy decides each tool call of the root agent, before it runs;
* a sub-agent runs under its own run and may call only the tools its spawn
  granted, whatever the policy allows; with no grant it may call none;
* every decision is in the local audit trail.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("watchlight_engine")
pytest.importorskip("watchlight_deepagents")

from langchain_core.language_models.fake_chat_models import (  # noqa: E402
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from watchlight_deepagents import create_governed_deep_agent  # noqa: E402

from watchlight.deepagents import governed_plugin  # noqa: E402

READ_WRITE = [
    {"name": "read", "code": 'permit(principal is Agent, action == Action::"read", resource);'},
    {"name": "write", "code": 'permit(principal is Agent, action == Action::"write", resource);'},
]


# A test stand-in: replays scripted turns so no model is called.
class _ScriptedModel(GenericFakeChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


def _model(*turns):
    messages = []
    for i, turn in enumerate(turns):
        if isinstance(turn, str):
            messages.append(AIMessage(content=turn))
        else:
            calls = [{"name": n, "args": a, "id": f"{n}-{i}"} for n, a in turn]
            messages.append(AIMessage(content="", tool_calls=calls))
    return _ScriptedModel(messages=iter(messages))


def _tools(ran):
    @tool
    def search_web(query: str) -> str:
        """Search the web."""
        ran.append("search_web")
        return "results"

    @tool
    def write_report(title: str) -> str:
        """Write a report."""
        ran.append("write_report")
        return "written"

    @tool
    def send_email(to: str) -> str:
        """Send an email."""
        ran.append("send_email")
        return "sent"

    return [search_web, write_report, send_email]


def _observed(audit):
    events = [json.loads(line) for line in audit.read_text().splitlines()]
    return [
        (e["payload"]["tool"]["identifier"], e["payload"]["decision"])
        for e in events
        if e.get("event_type") == "tool_call_observed"
    ]


def test_the_policy_decides_each_root_tool_call(monkeypatch, tmp_path):
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    ran = []
    audit = tmp_path / "audit.jsonl"
    agent = create_governed_deep_agent(
        model=_model([("search_web", {"query": "q"}), ("send_email", {"to": "a"})], "done"),
        tools=_tools(ran),
        agent_slug="orchestrator",
        plugin=governed_plugin(READ_WRITE, audit_path=str(audit)),
    )
    asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": "go"}]}))
    assert ran == ["search_web"]
    assert _observed(audit) == [("search_web", "Allow"), ("send_email", "Deny")]


def test_a_sub_agent_calls_only_the_tools_its_spawn_granted(monkeypatch, tmp_path):
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    ran = []
    tools = _tools(ran)
    audit = tmp_path / "audit.jsonl"
    agent = create_governed_deep_agent(
        model=_model(
            [("task", {"description": "research", "subagent_type": "researcher"})],
            [("task", {"description": "report", "subagent_type": "reporter"})],
            "done",
        ),
        tools=tools,
        subagents=[
            {
                "name": "researcher",
                "description": "research",
                "system_prompt": "research",
                "tools": tools,
                # The policy permits write; only the grant refuses it.
                "model": _model([("search_web", {"query": "q"}), ("write_report", {"title": "t"})], "ok"),
            },
            {
                "name": "reporter",
                "description": "report",
                "system_prompt": "report",
                "tools": tools,
                "model": _model([("search_web", {"query": "q"})], "ok"),
            },
        ],
        # "reporter" has no grant, so it may call no tool.
        subagent_scopes={"researcher": {"allowed_tools": ["search_web"], "max_depth": 0}},
        agent_slug="orchestrator",
        plugin=governed_plugin(READ_WRITE, audit_path=str(audit)),
    )
    asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": "go"}]}))
    assert ran == ["search_web"]
    assert _observed(audit) == [
        ("search_web", "Allow"),
        ("write_report", "Deny"),
        ("search_web", "Deny"),
    ]
