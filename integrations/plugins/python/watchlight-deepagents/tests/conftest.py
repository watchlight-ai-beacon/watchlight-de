"""Shared fixtures for watchlight-deepagents tests.

Most governance tests run against a **stub** ``AgentMiddleware`` base and
the ``watchlight_core_testing.MockApdpClient`` so the plugin's decision
logic is exercised with zero live services and — when ``deepagents`` is
not installed in the sandbox — zero framework dependency. A separate
``test_middleware_lifecycle.py`` asserts the plugin against the REAL
``deepagents`` hook surface (skipping when the package is absent) so an
upstream API drift breaks loudly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import pytest

from watchlight_core_testing import MockApdpClient

from watchlight_deepagents.middleware import (
    STATE_TOKEN_KEY,
    build_governance_middleware,
)
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin


@pytest.fixture(autouse=True)
def _no_ambient_application_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert.

    ``WATCHLIGHT_APPLICATION_ID`` is a deployment default the plugin
    reads at construction. Tests that want it set it explicitly.
    """
    monkeypatch.delenv("WATCHLIGHT_APPLICATION_ID", raising=False)


# ─── Stub AgentMiddleware base (mimics langchain's contract) ──────────


class StubAgentMiddleware:
    """Minimal stand-in for ``langchain.agents.middleware.AgentMiddleware``.

    Provides the attributes our subclass relies on: a no-arg
    ``__init__``, a ``tools`` slot, and a ``name``. The real base adds
    default no-op hooks; our subclass overrides every hook it uses, so
    the stub does not need them.
    """

    def __init__(self) -> None:
        self.tools = None
        self.state_schema = dict


# ─── Stub ToolCallRequest / ModelRequest (deepagents dataclasses) ─────


# In-process stand-in for unit tests only.
@dataclass
class StubToolCallRequest:
    """Mirror of ``langchain.agents.middleware.types.ToolCallRequest``.

    The real ``ToolCallRequest`` carries the actual ``BaseTool`` instance
    being invoked in ``tool`` (``BaseTool | None``). The declare_intent
    short-circuit keys on that instance identity, so tests exercising the
    synthetic tool set ``tool`` accordingly.
    """

    tool_call: Dict[str, Any]
    state: Dict[str, Any]
    tool: Any = None
    runtime: Any = None


# In-process stand-in for unit tests only.
@dataclass
class StubModelRequest:
    """Mirror of the fields our ``awrap_model_call`` reads."""

    state: Dict[str, Any]
    model: Any = "anthropic:claude-sonnet-4"
    runtime: Any = None


def make_tool_call_request(
    tool_name: str,
    args: Optional[Dict[str, Any]] = None,
    *,
    state: Dict[str, Any],
    tool_call_id: Optional[str] = None,
    tool: Any = None,
) -> StubToolCallRequest:
    return StubToolCallRequest(
        tool_call={
            "name": tool_name,
            "args": args or {},
            "id": tool_call_id or f"call_{uuid.uuid4().hex[:8]}",
            "type": "tool_call",
        },
        state=state,
        tool=tool,
    )


# ─── Handlers that record whether they ran ────────────────────────────


@dataclass
class RecordingHandler:
    """Async tool/model handler that records invocation + returns a
    sentinel so a test can assert whether the guarded call actually ran.
    """

    ran: bool = field(default=False)
    return_value: Any = "HANDLER_RAN"

    async def __call__(self, request: Any) -> Any:
        self.ran = True
        return self.return_value


# ─── Plugin + middleware factories wired to a mock APDP ───────────────


ROOT_SLUG = "research-orchestrator"
ROOT_UUID = "11111111-1111-1111-1111-111111111111"
CHILD_SLUG = "researcher"
CHILD_UUID = "22222222-2222-2222-2222-222222222222"


@pytest.fixture
def mock_apdp() -> MockApdpClient:
    client = MockApdpClient()
    client.known_agents[ROOT_SLUG] = ROOT_UUID
    client.known_agents[CHILD_SLUG] = CHILD_UUID
    return client


@pytest.fixture
def plugin(mock_apdp: MockApdpClient) -> WatchlightDeepAgentsPlugin:
    p = WatchlightDeepAgentsPlugin(apdp_url="http://localhost", tenant_id="acme")
    p.apdp = mock_apdp
    return p


def make_root_middleware(
    plugin: WatchlightDeepAgentsPlugin,
    *,
    subagent_scopes: Optional[Dict[str, Dict[str, Any]]] = None,
    subagent_slugs: Optional[Dict[str, str]] = None,
    child_governance_guaranteed: bool = True,
) -> Any:
    """Build a root governance middleware for tests.

    Defaults to ``child_governance_guaranteed=True`` — the governed
    ``create_governed_deep_agent`` factory path, where a child governance
    middleware has been injected into every spawnable sub-agent, so
    ``task`` spawns are allowed. Pass ``False`` to simulate the
    standalone ``plugin.middleware()`` / Option B path, where spawns are
    refused (fail-closed).
    """
    return build_governance_middleware(
        plugin=plugin,
        agent_slug=ROOT_SLUG,
        subagent_scopes=subagent_scopes or {},
        subagent_slugs=subagent_slugs or {},
        is_child=False,
        child_governance_guaranteed=child_governance_guaranteed,
        base_cls=StubAgentMiddleware,
    )


def make_child_middleware(plugin: WatchlightDeepAgentsPlugin) -> Any:
    return build_governance_middleware(
        plugin=plugin,
        agent_slug=ROOT_SLUG,
        subagent_scopes={},
        subagent_slugs={},
        is_child=True,
        base_cls=StubAgentMiddleware,
    )


async def start_root(mw: Any) -> Dict[str, Any]:
    """Drive ``abefore_agent`` on the root middleware and return the
    resulting graph state (with the run token merged in)."""
    state: Dict[str, Any] = {}
    update = await mw.abefore_agent(state, runtime=None)
    if update:
        state.update(update)
    assert STATE_TOKEN_KEY in state
    return state
