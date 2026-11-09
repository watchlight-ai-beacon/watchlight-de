"""Synthetic ``watchlight.declare_intent`` tool-injection tests.

This module pairs the SDK's synthetic-tool primitives
(``BaseRunHandle.synthetic_tools``, ``handle_declare_intent_call``,
``WATCHLIGHT_DECLARE_INTENT_TOOL``) with the Pydantic AI plugin's
monkey-patched ``Agent.run`` wrapper. The injection lands in
:func:`watchlight_pydantic_ai.instrumentation.inject_synthetic_tools`
and runs from inside ``_open_handle_for_call`` before the original
``Agent.run`` body fires — so the agent's first turn sees the
synthetic tool alongside the customer's own tools.

Coverage matrix:

| # | Test                                                                  | Asserts                                                |
|---|-----------------------------------------------------------------------|--------------------------------------------------------|
| 1 | ``greenfield_mode_injects_synthetic_tool_at_construction``           | tool is on the Agent's ``_function_toolset.tools`` map |
| 2 | ``brownfield_mode_does_not_inject_synthetic_tool``                   | tool is ABSENT in brownfield                           |
| 3 | ``declare_intent_call_stamps_provenance_to_declared``                | handle's ``_intent_provenance`` flips to DECLARED     |
| 4 | ``synthetic_tool_call_bypasses_authorize``                           | no APDP ``authorize`` round-trip for the tool call    |
| 5 | ``subsequent_authorize_action_after_declare_intent_satisfies_gate``  | APDP ``/authorize`` body carries ``intent``           |
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Optional

import pytest

# Skip the entire module if pydantic-ai isn't importable. The plugin
# declares pydantic-ai as a required dep; this fence is for
# environments where the install is broken.
pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core import (  # noqa: E402
    DECLARE_INTENT_TOOL_NAME,
    INTENT_ENFORCEMENT_MODE_ENV_VAR,
    IntentProvenance,
)
from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    WatchlightPydanticAIPlugin,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    """Each test starts with a clean ``Agent`` class + reset contextvar.

    Mirrors the convention in ``test_nested_agent_run`` and
    ``test_intent_extraction``: pre-test uninstall protects against
    leakage from an unrelated test suite running earlier in the same
    process; post-test uninstall keeps the next test's slate clean.
    """
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Each test starts with no ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE``
    env var set.

    The mode resolution helper reads the env var as its second-priority
    source. Tests that need greenfield mode set it explicitly inside
    the test body (the env-var path is the operator-visible knob, and
    we want test isolation to be evident at the call site).
    """
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    yield


DECLARE_ARGS = {"objective": "audit Q3 invoices", "category": "data_analysis"}


def _scripted(*calls: tuple) -> FunctionModel:
    """A model that makes the given ``(tool, args)`` calls, one per turn,
    then answers. TestModel fills every string argument with ``"a"``,
    which is not an intent category wl-apdp accepts."""

    def _respond(messages: list, _info: Any) -> ModelResponse:
        turn = sum(1 for m in messages if isinstance(m, ModelResponse))
        if turn < len(calls):
            tool, args = calls[turn]
            return ModelResponse(parts=[ToolCallPart(tool_name=tool, args=dict(args))])
        return ModelResponse(parts=[TextPart(content="done")])

    return FunctionModel(_respond)


def _make_plugin(
    known_agents: dict[str, str],
    decisions: Optional[dict[tuple[str, str], str]] = None,
) -> tuple[WatchlightPydanticAIPlugin, MockApdpClient]:
    """Construct a plugin wired to a fresh ``MockApdpClient``."""
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    mock = MockApdpClient()
    for slug, agent_uuid in known_agents.items():
        mock.known_agents[slug] = agent_uuid
    if decisions:
        mock.decisions.update(decisions)
    plugin.apdp = mock
    return plugin, mock


# ─── Test 1 — greenfield injection ───────────────────────────────────


def test_greenfield_mode_injects_synthetic_tool_at_construction(
    monkeypatch,
) -> None:
    """When the effective enforcement mode is ``greenfield``, the
    Pydantic AI ``Agent``'s tool list MUST include the synthetic
    ``watchlight.declare_intent`` tool by the time the agent's first
    turn fires.

    The injection point is inside the wrapped ``Agent.run`` (before the
    original body runs), so we drive the test by invoking
    ``agent.run(...)`` and asserting the tool is on
    ``agent._function_toolset.tools`` once execution reaches the
    customer's code.
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")

    plugin, _mock = _make_plugin({"declarer": "uuid-d"})

    # Force TestModel to call ONLY the synthetic tool so the test
    # doesn't depend on the default "call every tool" behaviour.
    # The synthetic tool's body reads the active handle from the
    # contextvar and stamps the objective.
    agent = Agent(
        TestModel(call_tools=[DECLARE_INTENT_TOOL_NAME]),
        name="declarer",
    )

    async def _run() -> None:
        # At this point the patched wrapper has fired, the handle is
        # open, and the synthetic tool has been injected. Pydantic AI
        # is about to drive the model; the tool MUST be on the
        # function-toolset map.
        await agent.run("audit Q3 invoices")

        tools = agent._function_toolset.tools
        assert DECLARE_INTENT_TOOL_NAME in tools, (
            f"expected {DECLARE_INTENT_TOOL_NAME!r} on the agent's "
            f"function toolset in greenfield mode; got "
            f"{list(tools.keys())!r}"
        )
        # The registered Tool should carry our sentinel marker so a
        # re-injection pass detects-and-skips.
        from watchlight_pydantic_ai.instrumentation import (
            _WL_SYNTHETIC_TOOL_MARKER,
        )

        assert getattr(
            tools[DECLARE_INTENT_TOOL_NAME], _WL_SYNTHETIC_TOOL_MARKER, False
        ), (
            "synthetic Tool should be stamped with the Watchlight "
            "marker for idempotent re-injection"
        )

    asyncio.run(_run())


# ─── Test 2 — brownfield is a no-op ──────────────────────────────────


def test_brownfield_mode_does_not_inject_synthetic_tool(
    monkeypatch,
) -> None:
    """Brownfield mode (the locked default) MUST NOT inject the
    synthetic tool. The synthetic-tool gate is inert in brownfield
    because the Cedar matrix accepts inferred provenance at every
    tier; injecting the tool would create operator-visible noise
    without enforcement value.
    """
    # Brownfield is the default; we set it explicitly to make the
    # test's intent obvious in code review.
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "brownfield")

    plugin, _mock = _make_plugin({"declarer": "uuid-d"})

    # No tools registered at all so TestModel falls back to plain
    # output rather than calling a non-existent synthetic tool.
    agent = Agent(TestModel(), name="declarer")

    async def _run() -> None:
        await agent.run("hello world")

        tools = agent._function_toolset.tools
        assert DECLARE_INTENT_TOOL_NAME not in tools, (
            f"brownfield mode must NOT inject the synthetic tool; got "
            f"{list(tools.keys())!r}"
        )

    asyncio.run(_run())


# ─── Test 3 — tool fire stamps provenance ────────────────────────────


def test_declare_intent_call_stamps_provenance_to_declared(
    monkeypatch,
) -> None:
    """Invoking the synthetic tool MUST stamp the active handle's
    ``_intent_provenance`` to :attr:`IntentProvenance.DECLARED` and
    its ``_intent_objective`` to the truncated objective from the
    tool's argument dict.

    This is the load-bearing wire between the agent's call and the
    Cedar gate: subsequent ``authorize_action`` calls auto-inject
    ``intent={"objective": ...}`` into the APDP request body,
    which the Cedar context projection sees and stamps
    ``provenance: "declared"`` on the evaluation context.

    Mechanism: we capture the active handle into a side-channel from
    inside a customer tool (which gives us a reference to the handle
    object), then drive ``Agent.run`` with ``call_tools=[
    DECLARE_INTENT_TOOL_NAME, "capture"]`` so the synthetic tool fires
    and ``capture`` runs after to snapshot the same handle reference.
    The handle's intent state is then asserted directly on the
    captured object.
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")

    plugin, _mock = _make_plugin({"declarer": "uuid-d"})

    captured: dict[str, Any] = {}

    # Force TestModel to call the synthetic tool FIRST, then the
    # ``capture`` customer tool. The order is the same as the
    # ``call_tools`` list (TestModel calls tools in iteration order).
    agent = Agent(
        _scripted((DECLARE_INTENT_TOOL_NAME, DECLARE_ARGS), ("capture", {"_x": "a"})),
        name="declarer",
    )

    @agent.tool_plain
    async def capture(_x: str) -> str:
        """Snapshot the active handle's intent fields after the
        synthetic tool has fired (in this test's tool-call ordering).
        """
        from watchlight_pydantic_ai.instrumentation import current_handle

        handle = current_handle()
        assert handle is not None, "active handle missing during tool fire"
        captured["objective"] = handle._intent_objective
        captured["category"] = handle._intent_category
        captured["provenance"] = handle._intent_provenance
        return "captured"

    async def _run() -> None:
        await agent.run("audit Q3 invoices")

    asyncio.run(_run())

    # After the synthetic tool fires, the handle's intent state MUST
    # have transitioned to DECLARED + the truncated objective.
    # ``"a"`` is TestModel's default value for a required string arg
    # (see ``pydantic_ai.models.test.TestModel.gen_tool_args``).
    assert captured.get("provenance") == IntentProvenance.DECLARED, (
        f"expected provenance=DECLARED after synthetic tool fired; "
        f"got {captured.get('provenance')!r}"
    )
    assert captured.get("objective") == "audit Q3 invoices", (
        f"expected objective to be stamped after synthetic tool fired; "
        f"got {captured.get('objective')!r}"
    )
    assert captured.get("category") == "data_analysis"


# ─── Test 4 — synthetic tool bypasses authorize ──────────────────────


def test_synthetic_tool_call_bypasses_authorize(monkeypatch) -> None:
    """A call to ``watchlight.declare_intent`` MUST NOT round-trip to
    APDP's ``authorize_action`` endpoint.

    This carve-out is deliberate: authorizing the synthetic tool
    itself would chicken-and-egg with the Cedar gate (the gate
    forbids on ``provenance != "declared"``; the agent's first
    declarative call would be denied before it could declare).

    Pydantic AI's authorize integration is via the
    :meth:`RunHandle.guarded_tool` decorator, applied explicitly by
    the customer to their own tools. The synthetic tool is
    registered WITHOUT ``guarded_tool``, so the bypass is
    structural — there is no authorize call site to intercept. This
    test locks in that structural property by asserting
    ``mock.authorize_calls`` is empty after a run that ONLY fires
    the synthetic tool.
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")

    plugin, mock = _make_plugin({"declarer": "uuid-d"})

    # ``call_tools`` restricts TestModel to ONLY the synthetic tool.
    agent = Agent(
        TestModel(call_tools=[DECLARE_INTENT_TOOL_NAME]),
        name="declarer",
    )

    async def _run() -> None:
        await agent.run("audit Q3 invoices")

    asyncio.run(_run())

    # The mock records every ``authorize()`` invocation in
    # ``authorize_calls``. No customer-driven ``authorize_action`` was
    # called; the synthetic tool fired but MUST NOT have produced an
    # authorize round-trip.
    declare_intent_authorize_calls = [
        c
        for c in mock.authorize_calls
        if DECLARE_INTENT_TOOL_NAME in (c.get("action") or "")
        or DECLARE_INTENT_TOOL_NAME in (c.get("resource") or "")
    ]
    assert not declare_intent_authorize_calls, (
        f"synthetic tool MUST NOT round-trip to authorize_action; got "
        f"{declare_intent_authorize_calls!r}"
    )
    # And in this test there's only one tool registered + no
    # ``guarded_tool`` wrappers — so we expect ZERO authorize calls
    # total. (Pydantic AI's session-management lifecycle does not
    # invoke authorize on its own.)
    assert mock.authorize_calls == [], (
        f"unexpected authorize calls during synthetic-tool-only run: "
        f"{mock.authorize_calls!r}"
    )


# ─── Test 5 — gate satisfaction after declare ────────────────────────


def test_subsequent_authorize_action_after_declare_intent_satisfies_cedar_gate(
    monkeypatch,
) -> None:
    """Integration: after the agent calls ``watchlight.declare_intent``,
    a subsequent ``authorize_action`` MUST carry
    ``intent={"objective": "<declared>"}`` in the APDP request body.

    This is the load-bearing end-to-end wire: the synthetic tool
    stamps the run handle, and
    :meth:`BaseRunHandle.authorize_action_detailed` auto-injects
    ``intent`` into the APDP request body from the stored value. On
    the server side, the Cedar context projection reads
    ``request.intent.objective`` and stamps
    ``intent_provenance: "declared"`` on the evaluation context,
    clearing the greenfield gate that forbids actions until an intent
    has been declared.

    This test does NOT invoke wl-apdp directly; it asserts on the
    request body the SDK sends, which proves the auto-inject path
    fires after the synthetic tool's mutation. The Cedar side is
    covered by wl-apdp's own test suite.
    """
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")

    plugin, mock = _make_plugin({"declarer": "uuid-d"})

    # Intercept the mock's ``authorize`` so we can capture the full
    # request body (the default ``authorize_calls`` log doesn't record
    # the ``intent`` kwarg). The captor records ``(action, resource,
    # intent)`` for every authorize call so we can assert the auto-
    # inject fires after the synthetic tool but not before.
    captured_intents: list[tuple[str, str, Optional[dict]]] = []
    original_authorize = mock.authorize

    async def _capturing_authorize(
        principal: str,
        action: str,
        resource: str,
        context: dict,
        execution_id: str,
        session_id: str,
        intent: Optional[dict] = None,
        **kwargs: object,
    ) -> dict:
        # Accept + forward any additional authorize() kwargs (e.g.
        # session_token) so this spy stays in step with the real
        # signature instead of drifting.
        captured_intents.append((action, resource, intent))
        return await original_authorize(
            principal=principal,
            action=action,
            resource=resource,
            context=context,
            execution_id=execution_id,
            session_id=session_id,
            intent=intent,
            **kwargs,
        )

    mock.authorize = _capturing_authorize  # type: ignore[method-assign]

    # Order matters: the synthetic tool MUST fire BEFORE the customer
    # tool that calls ``authorize_action``. TestModel calls tools in
    # the order given in ``call_tools``; in the real wire model the
    # LLM reads the system prompt + tool descriptions and chooses
    # ``watchlight.declare_intent`` first because the tool's
    # description tells it to.
    agent = Agent(
        _scripted(
            (DECLARE_INTENT_TOOL_NAME, DECLARE_ARGS), ("fetch_invoice", {"invoice_id": "1"})
        ),
        name="declarer",
    )

    @agent.tool_plain
    async def fetch_invoice(invoice_id: str) -> str:
        """Customer-defined tool that calls ``authorize_action`` AFTER
        the synthetic ``watchlight.declare_intent`` has already fired
        in the test's call ordering.
        """
        from watchlight_pydantic_ai.instrumentation import current_handle

        handle = current_handle()
        assert handle is not None
        await handle.authorize_action("read", "Invoice::Q3")
        return f"invoice {invoice_id}"

    async def _run() -> None:
        await agent.run("audit Q3 invoices")

    asyncio.run(_run())

    # Find the ``read`` ``Invoice::Q3`` authorize call. The auto-
    # inject MUST have populated ``intent.objective`` from the run
    # handle's stored value (set by the synthetic tool's mutation).
    invoice_authorizes = [
        (action, resource, intent)
        for (action, resource, intent) in captured_intents
        if action == 'Action::"read"' and resource == 'Resource::"Invoice::Q3"'
    ]
    assert invoice_authorizes, (
        f"expected an authorize call for read/Invoice::Q3 after the "
        f"customer tool fired; got captures={captured_intents!r}"
    )

    _action, _resource, intent = invoice_authorizes[0]
    assert isinstance(intent, dict), (
        f"authorize_action_detailed should auto-inject intent={{...}} "
        f"after a declare_intent call; got {intent!r}"
    )
    assert intent == {"objective": "audit Q3 invoices", "category": "data_analysis"}, (
        f"expected the declared typed intent (objective and category, "
        f"exactly) on the authorize request body; got {intent!r}"
    )


# ─── Typed intent (wl-apdp requires objective AND category) ──────────


def _greenfield_tool_schema(monkeypatch) -> dict:
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    from watchlight_pydantic_ai.instrumentation import _build_declare_intent_callable

    import inspect

    return inspect.signature(_build_declare_intent_callable(DECLARE_INTENT_TOOL_NAME)).parameters


def test_synthetic_tool_requires_a_category(monkeypatch) -> None:
    params = _greenfield_tool_schema(monkeypatch)
    assert list(params) == ["objective", "category", "justification"]
    assert params["objective"].default is params["objective"].empty
    assert params["category"].default is params["category"].empty
    # The justification is optional.
    assert params["justification"].default is None


def test_declare_without_a_valid_category_is_rejected_and_sends_no_intent(monkeypatch) -> None:
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    plugin, mock = _make_plugin({"declarer": "uuid-d"})
    captured: list = []
    original_authorize = mock.authorize

    async def _capturing_authorize(**kwargs: Any) -> dict:
        captured.append(kwargs.get("intent"))
        return await original_authorize(**kwargs)

    mock.authorize = _capturing_authorize  # type: ignore[method-assign]
    results: list = []
    agent = Agent(
        _scripted(
            (DECLARE_INTENT_TOOL_NAME, {"objective": "audit Q3 invoices", "category": "a"}),
            ("fetch_invoice", {"invoice_id": "1"}),
        ),
        name="declarer",
    )

    @agent.tool_plain
    async def fetch_invoice(invoice_id: str) -> str:
        from watchlight_pydantic_ai.instrumentation import current_handle

        handle = current_handle()
        results.append(handle.declared_intent_provenance)
        await handle.authorize_action("read", "Invoice::Q3")
        return "ok"

    asyncio.run(agent.run("audit Q3 invoices"))
    assert results == [None], "an untyped declare must leave the handle undeclared"
    # wl-apdp answers a category-less intent with 422: none is sent.
    assert captured and captured[-1] is None
