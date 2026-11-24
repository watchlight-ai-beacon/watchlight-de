"""Shared fixtures for the watchlight-strands tests.

Every test drives REAL Strands agents (``strands.Agent``, ``Swarm``,
``Graph``) through their real hook system. Only two things are stand-ins:

* the model — :class:`ScriptedModel` plays back a fixed list of turns, so
  no test calls an LLM or AWS;
* the governance backend — ``watchlight_core_testing.MockApdpClient``.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest
from strands.models import Model
from watchlight_core_testing import MockApdpClient
from watchlight_strands import WatchlightStrandsPlugin

#: Agents registered with the stand-in backend: slug -> UUID.
AGENTS: Dict[str, str] = {
    "agent-root": "11111111-1111-4111-8111-111111111111",
    "agent-child": "22222222-2222-4222-8222-222222222222",
    "agent-child-b": "33333333-3333-4333-8333-333333333333",
    "agent-swarm": "44444444-4444-4444-8444-444444444444",
    "agent-graph": "55555555-5555-4555-8555-555555555555",
}

#: A value that must never leave the process (authorize context, events).
SECRET = "argument-value-that-must-stay-in-process-7f3a"

Turn = Sequence[Tuple[Any, ...]]


def tool_call(name: str, args: Optional[Dict[str, Any]] = None) -> Tuple[str, str, Dict[str, Any]]:
    return ("tool", name, args or {})


def text(value: str) -> Tuple[str, str]:
    return ("text", value)


# In-process stand-in for unit tests only.
class ScriptedModel(Model):
    """A Strands model that replays scripted turns.

    Each call to :meth:`stream` plays the next turn: tool calls and/or text.
    After the script runs out it answers ``"done"``. ``calls`` counts model
    turns, so a test can prove a refused agent never reached its model.
    """

    def __init__(self, turns: Sequence[Turn] = (), *, fail_on_call: Optional[int] = None):
        self.turns: List[Turn] = list(turns)
        self.calls = 0
        self.fail_on_call = fail_on_call
        self.seen_tool_results: List[Dict[str, Any]] = []

    def update_config(self, **model_config: Any) -> None:
        return None

    def get_config(self) -> Any:
        return {}

    async def structured_output(self, output_model: Any, prompt: Any, system_prompt: Any = None, **kwargs: Any):  # type: ignore[override]
        raise NotImplementedError("not used by these tests")
        yield  # pragma: no cover

    async def stream(self, messages: Any, tool_specs: Any = None, system_prompt: Any = None, **kwargs: Any):  # type: ignore[override]
        self.calls += 1
        for message in messages or []:
            for block in message.get("content", []):
                if isinstance(block, dict) and "toolResult" in block:
                    self.seen_tool_results.append(block["toolResult"])
        if self.fail_on_call is not None and self.calls == self.fail_on_call:
            raise RuntimeError("scripted model failure")
        turn: Turn = self.turns.pop(0) if self.turns else [text("done")]
        yield {"messageStart": {"role": "assistant"}}
        stop = "end_turn"
        for item in turn:
            if item[0] == "tool":
                stop = "tool_use"
                yield {
                    "contentBlockStart": {
                        "start": {
                            "toolUse": {
                                "toolUseId": f"tooluse-{uuid.uuid4().hex[:10]}",
                                "name": item[1],
                            }
                        }
                    }
                }
                yield {"contentBlockDelta": {"delta": {"toolUse": {"input": json.dumps(item[2])}}}}
                yield {"contentBlockStop": {}}
            else:
                yield {"contentBlockDelta": {"delta": {"text": item[1]}}}
                yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": stop}}

    def tool_result_texts(self) -> List[str]:
        out: List[str] = []
        for result in self.seen_tool_results:
            for block in result.get("content", []):
                if isinstance(block, dict) and "text" in block:
                    out.append(block["text"])
        return out


@pytest.fixture(autouse=True)
def _no_ambient_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert."""
    for name in (
        "WATCHLIGHT_APPLICATION_ID",
        "WATCHLIGHT_PROXY_URL",
        "WATCHLIGHT_PLUGIN_TOKEN",
        "WATCHLIGHT_CREDENTIAL_FILE",
        "WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_live_runs_carried_over() -> Any:
    """A test that leaves a run waiting for an approval it never resumes
    keeps it live (see model_backstop) until its agent is garbage
    collected. Collect before each test so no live run carries over."""
    import gc

    from watchlight_strands import model_backstop

    if model_backstop.live_run_count():
        gc.collect()
    assert model_backstop.live_run_count() == 0, "a governed run from an earlier test is still live"
    yield


@pytest.fixture
def mock_apdp() -> MockApdpClient:
    client = MockApdpClient(default_decision="Allow")
    client.known_agents.update(AGENTS)
    return client


@pytest.fixture
def make_plugin(mock_apdp: MockApdpClient) -> Callable[..., WatchlightStrandsPlugin]:
    """Build a plugin for one agent slug, wired to the stand-in backend."""

    def _make(slug: str, **kwargs: Any) -> WatchlightStrandsPlugin:
        kwargs.setdefault("log_decisions", False)
        plugin = WatchlightStrandsPlugin(apdp_url="http://localhost", agent_slug=slug, **kwargs)
        plugin.apdp = mock_apdp
        return plugin

    return _make


def principals(mock: MockApdpClient) -> List[str]:
    return [call["principal"] for call in mock.authorize_calls]


def resources(mock: MockApdpClient) -> List[str]:
    out = []
    for call in mock.authorize_calls:
        res = call["resource"]
        out.append(res.split('"')[1] if '"' in res else res)
    return out


def events_of(mock: MockApdpClient, event_type: str) -> List[Dict[str, Any]]:
    return [e for e in mock.published_events if e.get("event_type") == event_type]


def spawned_agents(mock: MockApdpClient) -> List[str]:
    """The agent each child run started as, in start order: what wl-apdp
    decided (the named agent, else the agent the label is mapped to, else
    the parent's agent), read from the child's own ``execution_started``."""
    return [e["agent_id"] for e in events_of(mock, "execution_started") if e.get("parent_execution_id")]


def spawn_labels(mock: MockApdpClient) -> List[Any]:
    """The label each spawn was sent with (``None`` for a spawn by agent id)."""
    return [c.get("child_label") for c in mock.spawn_subagent_calls]
