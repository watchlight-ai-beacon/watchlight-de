"""REAL-``deepagents`` integration proof for the sub-agent attenuation
fixes.

The prior suite hand-wired child middleware and never constructed a real
``create_deep_agent`` — so it could not catch that deepagents composes a
sub-agent's middleware as ``base_stack + spec["middleware"]`` (the root
``middleware=`` list never propagates) and auto-adds an UNGOVERNED
``general-purpose`` sub-agent. These tests build a REAL governed agent
and inspect the sub-agent specs that deepagents actually hands to its
``SubAgentMiddleware`` — proving our ``watchlight_governance`` middleware
survives deepagents' own merge, for BOTH the custom and the
general-purpose sub-agent.

They skip (never fail) when ``deepagents`` is not installed.
"""

from __future__ import annotations

import contextlib

import pytest

deepagents = pytest.importorskip(
    "deepagents", reason="deepagents not installed in this sandbox"
)

from watchlight_core_testing import MockApdpClient  # noqa: E402

from watchlight_deepagents import create_governed_deep_agent  # noqa: E402
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin  # noqa: E402
from watchlight_deepagents.subagents import (  # noqa: E402
    GENERAL_PURPOSE_SUBAGENT_NAME,
)

ROOT_SLUG = "research-orchestrator"
GOV_NAME = "watchlight_governance"


# In-process stand-in for unit tests only.
def _scripted_model():
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    return GenericFakeChatModel(messages=iter([AIMessage(content="ok")]))


def _plugin() -> WatchlightDeepAgentsPlugin:
    p = WatchlightDeepAgentsPlugin(apdp_url="http://localhost", tenant_id="acme")
    client = MockApdpClient()
    client.known_agents[ROOT_SLUG] = "11111111-1111-1111-1111-111111111111"
    p.apdp = client
    return p


class _Captured(Exception):
    """Raised by the SubAgentMiddleware spy once the processed sub-agent
    specs are captured, so we never need a live model to compile the
    sub-agent graphs."""


@contextlib.contextmanager
def _capture_processed_subagents():
    """Spy on ``deepagents.graph.SubAgentMiddleware`` to capture the
    fully-processed sub-agent specs deepagents builds (base stack merged
    with each spec's own middleware, plus the auto general-purpose)."""
    import deepagents.graph as g

    captured: dict = {}
    orig = g.SubAgentMiddleware

    def spy(*args, **kwargs):
        captured["subagents"] = kwargs.get("subagents")
        raise _Captured()

    g.SubAgentMiddleware = spy
    try:
        yield captured
    finally:
        g.SubAgentMiddleware = orig


def _mw_names(spec) -> list:
    return [getattr(m, "name", type(m).__name__) for m in spec.get("middleware", [])]


def test_custom_subagent_is_governed_after_real_composition():
    """A custom sub-agent's FINAL (deepagents-composed) middleware stack
    contains ``watchlight_governance``."""
    plugin = _plugin()
    subagents = [
        {"name": "researcher", "description": "d", "system_prompt": "p"},
    ]
    with _capture_processed_subagents() as captured:
        with contextlib.suppress(_Captured):
            create_governed_deep_agent(
                model=_scripted_model(),
                tools=[],
                subagents=subagents,
                agent_slug=ROOT_SLUG,
                plugin=plugin,
                subagent_scopes={"researcher": {"allowed_tools": [], "max_depth": 0}},
            )
    specs = {s["name"]: s for s in captured["subagents"]}
    assert GOV_NAME in _mw_names(
        specs["researcher"]
    ), "custom sub-agent lost governance in deepagents' base+custom merge"


def test_auto_general_purpose_is_governed_after_real_composition():
    """The ``general-purpose`` sub-agent that deepagents would
    otherwise auto-add UNGOVERNED is present AND carries
    ``watchlight_governance`` in its real composed stack."""
    plugin = _plugin()
    with _capture_processed_subagents() as captured:
        with contextlib.suppress(_Captured):
            create_governed_deep_agent(
                model=_scripted_model(),
                tools=[],
                subagents=[
                    {"name": "researcher", "description": "d", "system_prompt": "p"}
                ],
                agent_slug=ROOT_SLUG,
                plugin=plugin,
            )
    specs = {s["name"]: s for s in captured["subagents"]}
    assert GENERAL_PURPOSE_SUBAGENT_NAME in specs, "general-purpose must be present"
    assert GOV_NAME in _mw_names(
        specs[GENERAL_PURPOSE_SUBAGENT_NAME]
    ), "auto general-purpose sub-agent is UNGOVERNED — governance gap not closed"


def test_no_subagents_still_governs_general_purpose():
    """Even with NO sub-agents declared, deepagents auto-adds
    ``general-purpose``; the governed factory must still govern it."""
    plugin = _plugin()
    with _capture_processed_subagents() as captured:
        with contextlib.suppress(_Captured):
            create_governed_deep_agent(
                model=_scripted_model(),
                tools=[],
                agent_slug=ROOT_SLUG,
                plugin=plugin,
            )
    specs = {s["name"]: s for s in captured["subagents"]}
    assert GENERAL_PURPOSE_SUBAGENT_NAME in specs
    assert GOV_NAME in _mw_names(specs[GENERAL_PURPOSE_SUBAGENT_NAME])


def test_vanilla_option_b_leaves_subagents_ungoverned_proof():
    """Proof of the ungoverned-propagation mechanism: raw ``create_deep_agent`` with
    the root governance middleware in ``middleware=`` does NOT propagate
    it to sub-agents (which is exactly why ``plugin.middleware()`` refuses
    spawns). This documents the upstream behaviour our fix defends
    against — if deepagents ever DID propagate, this test would flip and
    tell us to revisit the Option-B refusal."""
    from deepagents import create_deep_agent

    plugin = _plugin()
    root_mw = plugin.middleware(agent_slug=ROOT_SLUG)
    with _capture_processed_subagents() as captured:
        with contextlib.suppress(_Captured):
            create_deep_agent(
                model=_scripted_model(),
                tools=[],
                subagents=[
                    {"name": "researcher", "description": "d", "system_prompt": "p"}
                ],
                middleware=[root_mw],
            )
    specs = {s["name"]: s for s in captured["subagents"]}
    # The root middleware did NOT reach the sub-agent — governance absent.
    assert GOV_NAME not in _mw_names(specs["researcher"])
    # ...which is why the Option-B root middleware refuses task spawns
    # (asserted at the unit level in test_subagent_bypass_closed.py).


def test_compiled_subagent_aborts_governed_construction():
    """Un-injectable sub-agent at the real factory boundary — a CompiledSubAgent cannot
    be governed by injection, so ``create_governed_deep_agent`` refuses to
    build (fail-closed) rather than shipping an ungoverned child."""
    from watchlight_core import GovernanceUnavailable

    plugin = _plugin()
    compiled = {"name": "precompiled", "description": "d", "runnable": object()}
    with pytest.raises(GovernanceUnavailable):
        create_governed_deep_agent(
            model=_scripted_model(),
            tools=[],
            subagents=[compiled],
            agent_slug=ROOT_SLUG,
            plugin=plugin,
        )


def test_middleware_tool_instance_identity_preserved_by_real_framework():
    """The declare_intent short-circuit keys on the synthetic-tool
    INSTANCE. This pins the framework contract that makes that sound:
    real langchain/deepagents passes the EXACT middleware-contributed
    ``BaseTool`` instance back in ``ToolCallRequest.tool``. If an upstream
    change ever wrapped/copied the tool, this breaks loudly (the
    short-circuit would then fail *closed* — declare_intent denied — never
    open, but we still want the signal)."""
    import asyncio

    from langchain.agents.middleware.types import AgentMiddleware
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import StructuredTool
    from deepagents import create_deep_agent

    def _syn(x: str) -> str:
        """synthetic."""
        return x

    synthetic = StructuredTool.from_function(
        func=_syn, name="watchlight.declare_intent"
    )
    seen = {}

    # In-process stand-in for unit tests only.
    class ToolCallingScriptedModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    class Spy(AgentMiddleware):
        name = "spy_gov"

        def __init__(self):
            super().__init__()
            self.tools = [synthetic]

        async def awrap_tool_call(self, request, handler):
            seen["is_same_instance"] = getattr(request, "tool", None) is synthetic
            return ToolMessage(
                content="ok",
                tool_call_id=request.tool_call["id"],
                name=request.tool_call["name"],
            )

    model = ToolCallingScriptedModel(
        messages=iter(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "watchlight.declare_intent",
                            "args": {"x": "1"},
                            "id": "call_1",
                        }
                    ],
                ),
                AIMessage(content="done"),
            ]
        )
    )
    agent = create_deep_agent(model=model, tools=[], middleware=[Spy()])
    asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": "go"}]}))
    assert seen.get("is_same_instance") is True
