#!/usr/bin/env python3
"""Govern a deepagents deep agent: every tool call and every sub-agent.

The deep agent is built with ``create_governed_deep_agent`` from the
``watchlight-deepagents`` plugin, wired to the in-process engine by
``watchlight.deepagents.governed_plugin``. Every tool call is authorized by your
Cedar policy BEFORE it runs. Each ``task`` sub-agent runs under its own
attenuated run and may call only the tools its spawn granted; a sub-agent with
no grant may call no tool at all. No deepagents source is touched.

    pip install "watchlight[deepagents]"
    python examples/governed_deepagents.py
    watchlight dev --audit examples/.watchlight/audit.jsonl

Runs **without an API key**: a scripted model replays fixed turns so you can
see every decision offline. Set ANTHROPIC_API_KEY (and
``pip install langchain-anthropic``) to drive the same governed agent with a
real model.

Expected output (no API key; the notes in parentheses are not printed):

    agent                  tool           decision
    research-orchestrator  search_web     Allow
    research-orchestrator  send_email     Deny     (the policy permits no "execute")
    researcher             search_web     Allow
    researcher             write_report   Deny     (not in its grant, though the policy permits "write")
    reporter               get_filing     Deny     (it was granted no tools)
    research-orchestrator  write_report   Allow

    tools that ran: search_web, search_web, write_report
"""

import asyncio
import json
import os

from langchain_core.tools import tool

from watchlight.deepagents import governed_plugin
from watchlight_deepagents import create_governed_deep_agent

HERE = os.path.dirname(os.path.abspath(__file__))

# The policy: an agent may read and write; anything else (here, sending email)
# is denied. The principal is the running agent, Agent::"<uuid5 of its slug>".
POLICIES = [
    {"name": "read", "code": 'permit(principal is Agent, action == Action::"read", resource);'},
    {"name": "write", "code": 'permit(principal is Agent, action == Action::"write", resource);'},
]

# What each sub-agent may call. "reporter" is not listed, so it may call no tool.
SUBAGENT_SCOPES = {
    "researcher": {"allowed_tools": ["search_web", "get_filing"], "max_depth": 0},
}

RAN = []


# The action is read from the tool name: search_*/get_* → read,
# write_* → write, anything else → execute.
@tool
def search_web(query: str) -> str:
    """Search the web for a query."""
    RAN.append("search_web")
    return f"results for {query!r}"


@tool
def get_filing(company: str) -> str:
    """Fetch a company's latest filing."""
    RAN.append("get_filing")
    return f"filing for {company}"


@tool
def write_report(title: str, body: str) -> str:
    """Write a report."""
    RAN.append("write_report")
    return f"wrote {title!r}"


@tool
def send_email(to: str, body: str) -> str:
    """Send an email."""
    RAN.append("send_email")
    return f"sent to {to}"


TOOLS = [search_web, get_filing, write_report, send_email]


def _scripted(*turns):
    """A chat model that replays fixed turns, so the example runs offline."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    class ScriptedModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    messages = []
    for i, turn in enumerate(turns):
        if isinstance(turn, str):
            messages.append(AIMessage(content=turn))
        else:
            calls = [{"name": n, "args": a, "id": f"{n}-{i}"} for n, a in turn]
            messages.append(AIMessage(content="", tool_calls=calls))
    return ScriptedModel(messages=iter(messages))


def _models():
    """The root model and one model per sub-agent: a real model when a key is
    set, otherwise scripted turns that exercise every decision."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        model = "anthropic:claude-sonnet-5-5"
        return model, model, model
    root = _scripted(
        [("search_web", {"query": "Q3 filings"}), ("send_email", {"to": "cfo@example.com", "body": "hi"})],
        [("task", {"description": "research the filings", "subagent_type": "researcher"})],
        [("task", {"description": "draft the report", "subagent_type": "reporter"})],
        [("write_report", {"title": "Q3", "body": "summary"})],
        "done",
    )
    researcher = _scripted(
        [("search_web", {"query": "Q3"}), ("write_report", {"title": "draft", "body": "..."})],
        "research done",
    )
    reporter = _scripted([("get_filing", {"company": "ACME"})], "report done")
    return root, researcher, reporter


AUDIT = os.path.join(HERE, ".watchlight", "audit.jsonl")
AGENTS = ("research-orchestrator", "researcher", "reporter")


async def main() -> None:
    plugin = governed_plugin(POLICIES, audit_path=AUDIT)
    root_model, researcher_model, reporter_model = _models()
    agent = create_governed_deep_agent(
        model=root_model,
        tools=TOOLS,
        system_prompt="You orchestrate research using your sub-agents.",
        subagents=[
            {"name": "researcher", "description": "Research a topic",
             "system_prompt": "You research topics.", "tools": TOOLS, "model": researcher_model},
            {"name": "reporter", "description": "Write the report",
             "system_prompt": "You write reports.", "tools": TOOLS, "model": reporter_model},
        ],
        subagent_scopes=SUBAGENT_SCOPES,
        agent_slug=AGENTS[0],
        plugin=plugin,
    )
    seen = os.path.getsize(AUDIT) if os.path.exists(AUDIT) else 0
    # deepagents runs on the async LangGraph runtime; a synchronous invoke is refused.
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "Research the Q3 filings and write a report."}]}
    )
    if os.environ.get("ANTHROPIC_API_KEY"):
        print(result["messages"][-1].content[:400], "\n")
    await _print_decisions(plugin, seen)
    print("\ntools that ran:", ", ".join(RAN) or "none")
    print(f"\nwatch the decisions:  watchlight dev --audit {AUDIT}")


async def _print_decisions(plugin, offset: int) -> None:
    """Every tool call this run made, read back from the audit trail."""
    names = {}
    for slug in AGENTS:
        names[(await plugin.apdp.resolve_agent(slug))["id"]] = slug
    print(f"{'agent':22} {'tool':14} decision")
    with open(AUDIT, encoding="utf-8") as trail:
        trail.seek(offset)
        for line in trail:
            event = json.loads(line)
            if event.get("event_type") != "tool_call_observed":
                continue
            payload = event.get("payload", {})
            agent = names.get(event.get("agent_id"), event.get("agent_id"))
            tool_name = (payload.get("tool") or {}).get("identifier")
            print(f"{agent:22} {tool_name:14} {payload.get('decision')}")


if __name__ == "__main__":
    asyncio.run(main())
