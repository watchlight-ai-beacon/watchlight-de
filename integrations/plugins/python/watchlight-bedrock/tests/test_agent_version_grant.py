"""A numbered Bedrock agent version runs only when policy grants it, and
custom orchestration seen in the trace ends the run.

Bedrock reports an agent's orchestration type only for its working draft,
so a numbered version is authorized as ``invoke_agent_version`` on
``bedrock://agent/<agentId>/version/<n>`` before every call. The trace is
always on, and a ``customOrchestrationTrace`` part halts the run.
"""

from __future__ import annotations

import asyncio

import pytest
from watchlight_core_testing import MockApdpClient

from watchlight_bedrock import BedrockRequestRefused, CustomOrchestrationObserved

from .test_agent_runtime import (  # noqa: F401 - fixtures
    AGENT,
    ALIAS,
    _alias,
    _definition,
    _invoke,
    _invoke_ok,
    _permit,
    ag,
    agent_client,
    apdp,
    governed,
    handle,
    rt,
    rt_client,
)


def _version_calls(apdp: MockApdpClient) -> list:
    return [c["resource"] for c in apdp.authorize_calls if c["action"] == 'Action::"invoke_agent_version"']


def _trace(part: str) -> dict:
    return {"trace": {"agentId": AGENT, "agentAliasId": ALIAS, "sessionId": "s1", "trace": {part: {"traceId": "t1"}}}}


def _chunk(text: str) -> dict:
    return {"chunk": {"bytes": text.encode()}}


@pytest.mark.asyncio
async def test_a_numbered_version_policy_does_not_name_is_refused_before_the_call(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as refused:
        await _invoke(governed)

    assert refused.value.reason == "agent_version_not_permitted"
    assert "3" not in str(refused.value).replace("(agent_version_not_permitted)", "")
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()  # invoke_agent was never called
    assert _version_calls(apdp) == [f'Resource::"bedrock://agent/{AGENT}/version/3"']


@pytest.mark.asyncio
async def test_a_permitted_version_is_invoked_with_the_trace_on(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _permit(apdp, "3")
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)

    response = await _invoke(governed, enableTrace=False)

    rt.assert_no_pending_responses()
    assert rt._params["InvokeAgent"]["enableTrace"] is True
    assert list(response["completion"]) == []


@pytest.mark.asyncio
async def test_an_alias_moved_to_a_version_policy_does_not_name_is_refused_on_the_next_call(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _permit(apdp, "3")
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)
    await _invoke(governed)

    _alias(ag, "4")
    _definition(ag, "4")
    _invoke_ok(rt)
    with pytest.raises(BedrockRequestRefused) as refused:
        await _invoke(governed)
    assert refused.value.reason == "agent_version_not_permitted"
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_the_version_is_decided_on_every_call(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)
    await _invoke(governed)
    _alias(ag, "3")  # the definition is cached now
    _invoke_ok(rt)
    await _invoke(governed)
    assert len(_version_calls(apdp)) == 2


@pytest.mark.asyncio
async def test_a_failed_version_decision_refuses_the_call(governed, rt, ag, apdp, monkeypatch):
    async def unavailable(**_):
        raise ConnectionError("down")

    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)
    monkeypatch.setattr(governed._handle, "authorize_action_detailed", unavailable)
    with pytest.raises(BedrockRequestRefused) as refused:
        await _invoke(governed)
    assert refused.value.reason == "agent_version_not_permitted"


@pytest.mark.asyncio
async def test_draft_needs_no_version_grant(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _alias(ag, "DRAFT")
    _definition(ag, "DRAFT")
    _invoke_ok(rt)

    await _invoke(governed)

    rt.assert_no_pending_responses()
    assert _version_calls(apdp) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_id", ["AGENT/version/3", "../AGENT123", "AGENT1234", "AGENT12345/"])
async def test_an_agent_id_that_is_not_one_is_refused_before_anything_is_read(governed, apdp, agent_id):
    # The version grant's URI is built from the agent id, so it must be one.
    with pytest.raises(BedrockRequestRefused) as refused:
        await governed.invoke_agent(agentId=agent_id, agentAliasId=ALIAS, sessionId="s1", inputText="go")
    assert refused.value.reason == "malformed"
    assert apdp.authorize_calls == []


@pytest.mark.asyncio
async def test_custom_orchestration_in_the_trace_ends_the_run(governed, rt, ag, apdp, handle):
    _alias(ag, "3")
    _definition(ag, "3")
    rt.add_response(
        "invoke_agent",
        {
            "completion": [_chunk("a"), _trace("orchestrationTrace"), _trace("customOrchestrationTrace"), _chunk("b")],
            "contentType": "application/json",
            "sessionId": "s1",
        },
    )

    response = await _invoke(governed)
    seen = []
    with pytest.raises(CustomOrchestrationObserved) as refused:
        for event in response["completion"]:
            seen.append(event)
    assert refused.value.reason == "custom_orchestration_observed"
    assert seen == [_chunk("a"), _trace("orchestrationTrace")], "nothing after the trace part is read"

    await asyncio.sleep(0)  # the run is ended on its own loop
    await asyncio.sleep(0)
    assert handle._completed is True
    assert "execution_failed" in handle._execution_lifecycle_emitted

    _alias(ag, "3")
    _invoke_ok(rt)
    with pytest.raises(BedrockRequestRefused) as again:
        await _invoke(governed)
    assert again.value.reason == "custom_orchestration_observed"
    with pytest.raises(BedrockRequestRefused):
        await governed.invoke_inline_agent(sessionId="s2", inputText="go", foundationModel="m", instruction="x" * 40)


@pytest.mark.asyncio
async def test_a_trace_without_custom_orchestration_is_passed_through(governed, rt, ag, handle):
    _alias(ag, "3")
    _definition(ag, "3")
    events = [_chunk("a"), _trace("orchestrationTrace"), _trace("guardrailTrace"), _chunk("b")]
    rt.add_response("invoke_agent", {"completion": events, "contentType": "application/json", "sessionId": "s1"})

    response = await _invoke(governed)
    assert list(response["completion"]) == events
    assert handle._completed is False
