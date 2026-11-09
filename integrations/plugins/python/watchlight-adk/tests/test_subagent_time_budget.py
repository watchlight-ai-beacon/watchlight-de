"""A governed ADK sub-agent only gets its turns when the spawn carries a
time budget — pinned on the REAL ADK turn sequence.

``before_agent_callback`` routes every native ADK sub-agent transfer
through wl-apdp's ``spawn_subagent`` chokepoint. It auto-derives ONE
dimension of the requested scope — ``allowed_tools``, from the child's
declared tool list — and takes every other dimension from the operator
default scope (``WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE``). That default is
empty. It names no ``time_budget_seconds``, so the field is left off the
spawn and wl-apdp gives the child its parent's REMAINING time, never more.
(The SDK used to send an explicit ``0`` there, which minted a handle that
was already expired, so the child was denied its first model turn.) The
deadline dimension (attenuation invariant #5) is checked for EVERY call a
run handle carries; the tool carve-out for ``Model::`` / ``Conversation::``
resources exempts the tool dimension, not the deadline.

That failure is invisible to a callback-level test: the spawn succeeds,
``before_agent_callback`` returns ``None`` and the sub-agent starts. It
only shows up in the TURN SEQUENCE — which agent actually got a model
turn — so that is what these tests assert, driving ADK's own ``Runner``
over a real two-agent tree with the real plugin registered and an APDP
stand-in that models wl-apdp's deadline arithmetic.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator, Dict, Iterable, List, Optional, Tuple
from unittest.mock import AsyncMock

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types
from pydantic import PrivateAttr

from watchlight_adk.plugin import WatchlightPlugin

from .conftest import stand_in_session, stand_in_spawn

ROOT_NAME = "adk_orchestrator"
CHILD_NAME = "adk_researcher"
ROOT_SLUG = "agent-adk-orchestrator"
CHILD_SLUG = "agent-adk-researcher"
ROOT_UUID = "00000000-0000-4000-8000-000000000001"
CHILD_UUID = "00000000-0000-4000-8000-000000000002"
ROOT_RUN_HANDLE = "00000000-0000-4000-8000-00000000000f"

USER_ID = "test-operator"
APP_NAME = "watchlight-adk-tests"


# ── The agents' tools (plain functions; ADK wraps them) ───────────────


def search_web(query: str) -> dict:
    """Search the web."""
    return {"result": f"results for {query}"}


def fetch_url(url: str) -> dict:
    """Fetch a URL."""
    return {"result": f"body of {url}"}


# ── A scripted ADK model that records which agent asked for a turn ────


class _RecordingScriptedLlm(BaseLlm):
    """Yields a fixed sequence of turns and appends its own label to a
    shared list on every call, so the test can read the turn ORDER."""

    _turns: List[LlmResponse] = PrivateAttr(default_factory=list)
    _cursor: int = PrivateAttr(default=0)
    _label: str = PrivateAttr(default="")
    _log: List[str] = PrivateAttr(default_factory=list)

    def script(
        self, label: str, log: List[str], turns: Iterable[LlmResponse]
    ) -> "_RecordingScriptedLlm":
        self._label = label
        self._log = log
        self._turns = list(turns)
        self._cursor = 0
        return self

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self._log.append(self._label)
        index = self._cursor
        self._cursor = index + 1
        if index < len(self._turns):
            yield self._turns[index]
        else:
            yield _final("(done)")


def _call(name: str, args: Optional[dict] = None) -> LlmResponse:
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part.from_function_call(name=name, args=dict(args or {}))],
        )
    )


def _final(text: str) -> LlmResponse:
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part.from_text(text=text)])
    )


# ── An APDP stand-in that models wl-apdp's granted deadline ───────────


#: wl-apdp's default root threshold: what an unbudgeted first-level
#: sub-agent inherits.
ROOT_BUDGET_SECONDS = 3600


class _DeadlineAwareApdp:
    """``spawn_subagent`` resolves ``time_budget_seconds`` and stamps the
    child's deadline; ``authorize`` denies every call a run handle makes
    past it — model turns included — exactly as
    wl-apdp's sub-agent attenuation validator does.

    The clock is injected (``now``) so a test can pin an expiry without
    sleeping.
    """

    def __init__(self) -> None:
        self.now = 1_000.0
        self.authorize_calls: List[Dict[str, Any]] = []
        self.spawn_bodies: List[Dict[str, Any]] = []
        self._granted_tools: Dict[str, List[str]] = {}
        self._granted_deadlines: Dict[str, float] = {}
        self._seq = 0

        async def _resolve_agent(slug: str) -> Optional[Dict[str, Any]]:
            return {"id": {ROOT_SLUG: ROOT_UUID, CHILD_SLUG: CHILD_UUID}[slug]}

        async def _check_trust(_agent_id: str) -> Dict[str, Any]:
            return {"trusted": True, "reason": ""}

        async def _create_session(**_kwargs: Any) -> Any:
            return stand_in_session(
                "ses_root",
                "sst_root",
                execution_id="exec_root",
                root_run_handle_id=ROOT_RUN_HANDLE,
            )

        async def _authorize(
            *,
            principal: str,
            action: str,
            resource: str,
            context: Optional[Dict[str, Any]] = None,
            **_kw: Any,
        ) -> Dict[str, Any]:
            ctx = context or {}
            run_handle_id = ctx.get("run_handle_id")
            decision = self._decide(action, resource, run_handle_id)
            self.authorize_calls.append(
                {
                    "principal": principal,
                    "action": action,
                    "resource": resource,
                    "run_handle_id": run_handle_id,
                    "decision": decision["decision"],
                    "reason": decision["reason"],
                }
            )
            return decision

        async def _spawn_subagent(parent: Any, body: Dict[str, Any]) -> Dict[str, Any]:
            self.spawn_bodies.append(body)
            requested = body.get("requested_scope") or {}
            self._seq += 1
            n = self._seq
            child_rh = f"00000000-0000-4000-8000-0000000000{n:02d}"
            # wl-apdp's arithmetic: an absent budget inherits the parent's
            # remaining time (the root's default threshold here, 3600 s).
            raw_budget = requested.get("time_budget_seconds")
            budget = float(ROOT_BUDGET_SECONDS if raw_budget is None else raw_budget)
            self._granted_tools[child_rh] = list(requested.get("allowed_tools") or [])
            self._granted_deadlines[child_rh] = self.now + budget
            return stand_in_spawn({
                "child_run_handle_id": child_rh,
                "granted_scope": {
                    "allowed_tools": self._granted_tools[child_rh],
                    "allowed_resources": [],
                    "allowed_intents": [],
                    "max_depth": int(requested.get("max_depth") or 0),
                    "time_budget_seconds": int(budget),
                },
                "child_execution_id": f"exec_child_{n}",
                "root_execution_id": "exec_root",
                "child_session_id": f"ses_child_{n}",
                "child_session_token": f"sst_child_{n}",
            })

        self.resolve_agent = AsyncMock(side_effect=_resolve_agent)
        self.check_agent_trust = AsyncMock(side_effect=_check_trust)
        self.create_session = AsyncMock(side_effect=_create_session)
        self.get_manifest = AsyncMock(return_value={})
        self.publish_events = AsyncMock(return_value=True)
        self.authorize = AsyncMock(side_effect=_authorize)
        self.spawn_subagent = AsyncMock(side_effect=_spawn_subagent)
        self.complete_session = AsyncMock(return_value=True)
        self.close = AsyncMock(return_value=None)

    def _decide(
        self, action: str, resource: str, run_handle_id: Optional[str]
    ) -> Dict[str, Any]:
        if run_handle_id is not None:
            if run_handle_id not in self._granted_tools:
                return {"decision": "Deny", "reason": "unknown run handle", "details": {}}
            # Invariant #5 — the granted deadline. Runs for every call the
            # handle carries, model turns included.
            if self.now > self._granted_deadlines[run_handle_id]:
                return {
                    "decision": "Deny",
                    "reason": "scope_attenuation_violation (granted deadline expired)",
                    "details": {},
                }
        if _is_model_turn(resource):
            # The tool dimension is carved out for a model turn.
            return {"decision": "Allow", "reason": "", "details": {}}
        if run_handle_id is not None:
            granted = self._granted_tools[run_handle_id]
            name = _bare(resource)
            verb = _bare(action)
            if name in granted or verb in granted:
                return {"decision": "Allow", "reason": "", "details": {}}
            return {"decision": "Deny", "reason": "subagent_out_of_scope", "details": {}}
        return {"decision": "Allow", "reason": "", "details": {}}


def _bare(cedar: str) -> str:
    return cedar.split('"')[1] if '"' in cedar else cedar


def _is_model_turn(resource: str) -> bool:
    return "::" in resource and resource.split("::", 1)[0] in ("Model", "Conversation")


# ── Harness ──────────────────────────────────────────────────────────


async def _run_transfer_invocation(
    apdp: _DeadlineAwareApdp,
) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Drive ADK's Runner over orchestrator → researcher and return
    ``(turn_labels, dispatched_tool_calls)``.

    ``turn_labels`` is one entry per MODEL call, in order, naming the
    agent that got the turn. ``dispatched_tool_calls`` is ``(author,
    tool)`` for every function call ADK emitted.
    """
    turns: List[str] = []
    child_model = _RecordingScriptedLlm(model="scripted").script(
        CHILD_NAME,
        turns,
        [
            _call("search_web", {"query": "FY revenue"}),
            _call("fetch_url", {"url": "https://example.test/"}),
            _final("Summary."),
        ],
    )
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=child_model,
        description="Focused research sub-agent.",
        tools=[search_web, fetch_url],
    )
    root_model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME,
        turns,
        [
            _call("fetch_url", {"url": "https://example.test/"}),
            _call("transfer_to_agent", {"agent_name": CHILD_NAME}),
        ],
    )
    orchestrator = LlmAgent(
        name=ROOT_NAME,
        model=root_model,
        description="Research orchestrator.",
        tools=[search_web, fetch_url],
        sub_agents=[researcher],
    )

    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        # The root slug is bound to the ADK agent it belongs to, so
        # the plugin can never authorize an unmapped agent as the root.
        root_agent_name=ROOT_NAME,
        subagent_slugs={CHILD_NAME: CHILD_SLUG},
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]

    runner = InMemoryRunner(agent=orchestrator, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(
        app_name=APP_NAME, user_id=USER_ID
    )
    message = types.Content(
        role="user", parts=[types.Part.from_text(text="Research the FY revenue.")]
    )

    dispatched: List[Tuple[str, str]] = []
    try:
        async for event in runner.run_async(
            user_id=USER_ID, session_id=session.id, new_message=message
        ):
            parts = event.content.parts if event.content and event.content.parts else []
            for part in parts:
                if part.function_call is not None:
                    dispatched.append((event.author or "", part.function_call.name or ""))
    finally:
        await plugin.close()
    return turns, dispatched


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_spawn_with_a_time_budget_gives_the_sub_agent_its_turns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The operator declares a per-spawn time budget → the child's handle
    is live, so the child gets model turns and its tool calls reach the
    PEP. This is the sequence the live demo must produce."""
    monkeypatch.setenv(
        "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE",
        '{"time_budget_seconds": 300, "max_depth": 0}',
    )
    apdp = _DeadlineAwareApdp()

    turns, dispatched = await _run_transfer_invocation(apdp)

    # The spawn requested the declared budget (the plugin only overwrites
    # allowed_tools; every other dimension is the operator's).
    assert apdp.spawn_bodies[0]["requested_scope"]["time_budget_seconds"] == 300
    # THE TURN SEQUENCE: two orchestrator turns (tool call, then the
    # transfer), then the researcher's own three.
    assert turns == [ROOT_NAME, ROOT_NAME, CHILD_NAME, CHILD_NAME, CHILD_NAME]
    # And the child actually dispatched its tool calls.
    assert (CHILD_NAME, "search_web") in dispatched
    assert (CHILD_NAME, "fetch_url") in dispatched


@pytest.mark.asyncio
async def test_a_spawn_with_no_time_budget_inherits_the_parents_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No operator scope: no budget is sent (never ``0``), the child
    inherits its parent's remaining time, gets its model turns and reaches
    the PEP with its tool calls."""
    monkeypatch.delenv("WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE", raising=False)
    apdp = _DeadlineAwareApdp()

    turns, dispatched = await _run_transfer_invocation(apdp)

    assert "time_budget_seconds" not in apdp.spawn_bodies[0]["requested_scope"]
    assert turns == [ROOT_NAME, ROOT_NAME, CHILD_NAME, CHILD_NAME, CHILD_NAME]
    assert (CHILD_NAME, "search_web") in dispatched


@pytest.mark.asyncio
async def test_an_explicit_zero_time_budget_costs_the_sub_agent_every_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An operator who sets ``time_budget_seconds: 0`` gets a handle that
    is already expired: the child's FIRST model turn is denied and it never
    calls a tool. (wl-apdp now refuses such a spawn outright as
    unsatisfiable; this stand-in models only the deadline arithmetic.)"""
    monkeypatch.setenv("WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE", '{"time_budget_seconds": 0}')
    apdp = _DeadlineAwareApdp()
    # Time advances between the spawn and the child's first call, as it
    # does in any real run.
    spawn = apdp.spawn_subagent

    async def _tick(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        result = await spawn(*args, **kwargs)
        apdp.now += 0.001
        return result

    apdp.spawn_subagent = _tick  # type: ignore[assignment]

    turns, dispatched = await _run_transfer_invocation(apdp)

    assert apdp.spawn_bodies[0]["requested_scope"]["time_budget_seconds"] == 0
    # The sub-agent started — but got no model turn at all.
    assert turns == [ROOT_NAME, ROOT_NAME]
    assert not [d for d in dispatched if d[0] == CHILD_NAME]
    # The denial is the deadline dimension, on the child's model turn.
    child_denials = [
        c
        for c in apdp.authorize_calls
        if c["decision"] == "Deny" and c["principal"] == f'Agent::"{CHILD_UUID}"'
    ]
    assert child_denials, "the child's model turn should have been denied"
    assert child_denials[0]["action"] == 'Action::"chat"'
    assert "deadline" in child_denials[0]["reason"]
