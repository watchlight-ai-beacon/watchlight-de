"""A tool refused because it would run an agent outside Watchlight
is recorded in lineage once, as a Deny, never as an Allow.

Uses the cases of ``test_nested_runner_refused``, driven through ADK's
real ``InMemoryRunner``.
"""

from __future__ import annotations

from typing import Any, List, Tuple

import pytest
from google.adk.tools.agent_tool import AgentTool

from . import test_nested_runner_refused as nested


def _tool_events(apdp: Any) -> List[Tuple[Any, Any]]:
    found = []
    for call in apdp.publish_events.call_args_list:
        for event in call.args[1]:
            if event["event_type"] == "tool_call_observed":
                payload = event["payload"]
                found.append((payload.get("decision"), payload["tool"]["identifier"]))
    return found


@pytest.mark.asyncio
@pytest.mark.parametrize("case", list(nested.REFUSED))
async def test_a_nested_run_refusal_is_recorded_once_as_a_deny(case: str) -> None:
    apdp = await nested._run_root(nested._as_outer(nested.REFUSED[case]))
    assert nested.BODIES == []
    assert _tool_events(apdp) == [("Deny", "outer_tool")]


@pytest.mark.asyncio
async def test_an_agent_tool_without_plugins_is_recorded_once_as_a_deny() -> None:
    apdp = await nested._run_root(
        AgentTool(agent=nested._inner_agent(), include_plugins=False)
    )
    assert nested.EXECUTED == []
    assert _tool_events(apdp) == [("Deny", "inner")]
