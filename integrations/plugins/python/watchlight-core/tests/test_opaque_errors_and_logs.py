"""Run-ending errors carry opaque messages; client logs never print raw
error text, URLs or response bodies."""

from __future__ import annotations

import logging

import httpx
import pytest

from watchlight_core import ApdpClient, GovernanceUnavailable
from watchlight_core.decision import (
    AgentQuarantinedError,
    AgentRevokedError,
    ExecutionTerminatedError,
    SubtreeSeveredError,
)
from watchlight_core_testing import bind_test_run, register_test_run

SECRET = "policy-secret-7 reason with sk-live-SECRET"


@pytest.mark.parametrize(
    "err",
    [
        lambda: AgentQuarantinedError(
            reason=SECRET,
            anomaly_score=0.5,
            contributing_features=[],
            model_version="m",
            policy_id="policy-secret-7",
        ),
        lambda: ExecutionTerminatedError(reason=SECRET, policy_id="policy-secret-7"),
        lambda: SubtreeSeveredError(reason=SECRET, policy_id="policy-secret-7"),
        lambda: AgentRevokedError(reason=SECRET, policy_id="policy-secret-7"),
    ],
)
def test_run_ending_error_messages_are_opaque(err) -> None:
    e = err()
    assert "secret" not in str(e).lower()
    assert e.reason == SECRET
    assert e.policy_id == "policy-secret-7"


def _ours(caplog) -> str:
    """Only the SDK's own log records (httpx's request log is the
    application's logging configuration)."""
    return "\n".join(
        r.getMessage() for r in caplog.records if r.name.startswith("watchlight")
    )


def _client(handler) -> ApdpClient:
    client = ApdpClient("http://localhost:8081")
    client._probed = True
    client._client = httpx.AsyncClient(
        base_url="http://internal-apdp.corp.example:8081",
        transport=httpx.MockTransport(handler),
    )
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.resolve_agent("agent-x"),
        lambda c: c.authorize(
            principal='Agent::"a"', action='Action::"x"', resource='Tool::"t"',
            context={}, execution_id="e", session_id="s",
        ),
        lambda c: c.create_session(agent_id="a"),
        lambda c: c.submit_plan("s", [{"step_id": "1"}]),
        lambda c: c.preflight_step("s", "x", "t"),
        lambda c: c.check_agent_trust("a"),
    ],
)
async def test_client_logs_carry_no_body_url_or_error_text(call, caplog) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="BODY sk-live-SECRET from upstream proxy")

    caplog.set_level(logging.DEBUG)
    client = _client(handler)
    raised = ""
    try:
        await call(client)
    except GovernanceUnavailable as exc:
        # resolve_agent raises on a server error; its text is opaque too.
        raised = str(exc)
    text = _ours(caplog) + "\n" + raised
    assert "sk-live-SECRET" not in text
    assert "internal-apdp.corp.example" not in text


@pytest.mark.asyncio
async def test_unreachable_log_carries_no_url(caplog) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect to internal-apdp.corp.example failed")

    caplog.set_level(logging.DEBUG)
    client = _client(handler)
    await client.authorize(
        principal='Agent::"a"', action='Action::"x"', resource='Tool::"t"',
        context={}, execution_id="e", session_id="s",
    )
    await client.create_session(agent_id="a")
    assert "internal-apdp.corp.example" not in _ours(caplog)


@pytest.mark.asyncio
async def test_spawn_transport_errors_carry_no_url_or_text(caplog) -> None:
    from watchlight_core import WatchlightError

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect to internal-apdp.corp.example failed")

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read from internal-apdp.corp.example timed out")

    caplog.set_level(logging.DEBUG)
    for handler, code in ((refuse, "apdp_unreachable"), (timeout, "apdp_transport_error")):
        client = _client(handler)
        client._base_url = "http://internal-apdp.corp.example:8081"
        with pytest.raises(WatchlightError) as info:
            await client.spawn_subagent(register_test_run(client, "sst_p.sig"), {"child_agent_id": "c"})
        assert "internal-apdp.corp.example" not in str(info.value)
        assert code in str(info.value)
    assert "internal-apdp.corp.example" not in _ours(caplog)


@pytest.mark.asyncio
async def test_spawn_response_shape_error_names_fields_not_values() -> None:
    import uuid as _uuid

    from watchlight_core import WatchlightError
    from watchlight_core.telemetry import GovernanceTelemetry
    from watchlight_core_testing import MockApdpClient
    from watchlight_core import BaseRunHandle

    class _Plugin(GovernanceTelemetry):
        def __init__(self) -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t"

    plugin = _Plugin()
    root = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid=str(_uuid.uuid4()), session_id="ses_root"), "sst_root")
    root._aentered = True

    async def bad_spawn(*args, **kwargs):
        return {
            "child_run_handle_id": str(_uuid.uuid4()),
            "granted_scope": {"max_depth": "sk-live-SECRET", "time_budget_seconds": 1},
            "child_session_token": "sst_child_SECRET",
        }

    plugin.apdp.spawn_subagent = bad_spawn  # type: ignore[method-assign]
    with pytest.raises(WatchlightError) as info:
        await root.spawn_subagent(str(_uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    msg = str(info.value)
    assert "SECRET" not in msg
    assert "SpawnSubagentResponse" in msg

    async def missing_field(*args, **kwargs):
        return {"granted_scope": {"max_depth": 0, "time_budget_seconds": 1}}

    plugin.apdp.spawn_subagent = missing_field  # type: ignore[method-assign]
    with pytest.raises(WatchlightError) as info:
        await root.spawn_subagent(str(_uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert "fields: child_run_handle_id" in str(info.value)
