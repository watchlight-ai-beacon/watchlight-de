"""A sub-agent's egress binding resolves the egress (proxy) token
wl-apdp minted for the CHILD session at spawn, never its parent's. The
token stays in the backend's run table; neither handle holds it.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pytest

from watchlight_core import BaseRunHandle, InterceptorKillRegistry, ScopeAttenuationDenied
from watchlight_core.errors import ScopeViolationDimension
import httpx

from watchlight_core.apdp_client import ApdpClient
from watchlight_core.scope import spawn_subagent_response_from_dict
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import bind_test_run, register_test_run

PARENT_TOKEN = "eyJ.parent.token"
CHILD_UUID = "22222222-2222-2222-2222-222222222222"


class _Plugin:
    def __init__(self, apdp: MockApdpClient) -> None:
        self.apdp = apdp
        self.tenant_id = "tenant-a"
        self.log_decisions = False
        self.last_governance_mode = "unmeasured"
        self.last_session_id: Optional[str] = None
        self.last_manifest: Optional[Dict[str, Any]] = None
        self.last_plan_validation: Optional[Dict[str, Any]] = None
        self.last_proposed_plan: Optional[Any] = None
        self.last_actions_allowed = 0
        self.last_actions_denied = 0
        self.kill_signal_registry: Optional[InterceptorKillRegistry] = None


def _root(apdp: MockApdpClient) -> BaseRunHandle:
    handle = bind_test_run(BaseRunHandle(plugin=_Plugin(apdp), agent_uuid="00000000-0000-0000-0000-000000000001", session_id=f"ses_{uuid.uuid4()}", run_handle_id=str(uuid.uuid4())), None, proxy_token=PARENT_TOKEN)
    handle._aentered = True
    return handle


@pytest.mark.asyncio
async def test_child_handle_carries_its_own_token() -> None:
    apdp = MockApdpClient()
    apdp.proxy_token_prefix = "pxt"
    parent = _root(apdp)
    child = await parent.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"})
    assert child.egress is not None
    assert child.egress.proxy_authorization() == f"pxt_child_{child.run_handle_id}"
    assert apdp.proxy_token_for(child.run) == f"pxt_child_{child.run_handle_id}"
    assert child.egress.proxy_authorization() != parent.egress.proxy_authorization()
    assert parent.egress.proxy_authorization() == PARENT_TOKEN


@pytest.mark.asyncio
async def test_siblings_get_distinct_tokens() -> None:
    apdp = MockApdpClient()
    apdp.proxy_token_prefix = "pxt"
    parent = _root(apdp)
    a, b = await asyncio.gather(
        parent.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}), parent.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"})
    )
    assert a.egress and b.egress
    assert a.egress.proxy_authorization() != b.egress.proxy_authorization()


@pytest.mark.asyncio
async def test_parent_token_is_never_copied_to_the_child() -> None:
    # A deployment without proxy tokens: the spawn response carries none.
    parent = _root(MockApdpClient())
    child = await parent.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"})
    assert child.egress is None


@pytest.mark.asyncio
async def test_a_refused_spawn_hands_out_no_token() -> None:
    apdp = MockApdpClient()
    apdp.proxy_token_prefix = "pxt"
    apdp.spawn_error_override = ScopeAttenuationDenied(
        reason="scope_attenuation_violation",
        violations=[ScopeViolationDimension.ALLOWED_TOOLS],
    )
    parent = _root(apdp)
    runs_before = set(apdp._runs)
    with pytest.raises(ScopeAttenuationDenied):
        await parent.spawn_subagent(CHILD_UUID, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["admin.delete"])
    assert set(apdp._runs) == runs_before
    assert parent.egress.proxy_authorization() == PARENT_TOKEN


_GRANTED = {
    "allowed_tools": [],
    "allowed_resources": [],
    "allowed_intents": [],
    "max_depth": 0,
    "time_budget_seconds": 60,
    "depth": 1,
}


def _spawning_client(body: Dict[str, Any]) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    apdp = ApdpClient("http://localhost", auto_probe=False)
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    return apdp


@pytest.mark.asyncio
async def test_client_parses_the_child_token_and_expiry() -> None:
    apdp = _spawning_client(
        {
            "child_run_handle_id": str(uuid.uuid4()),
            "granted_scope": _GRANTED,
            "child_session_token": "sst_child.sig",
            "child_proxy_token": "eyJ.child.token",
            "child_proxy_token_expires_at": "2030-01-01T00:01:00.123456789Z",
        }
    )
    parent = register_test_run(apdp, "sst_parent.sig")
    resp = await apdp.spawn_subagent(parent, {"child_agent_id": CHILD_UUID})
    binding = apdp.egress_for(resp["child_run"])
    assert binding is not None
    assert binding.proxy_authorization() == "eyJ.child.token"
    assert binding.expires_at == datetime(
        2030, 1, 1, 0, 1, 0, 123456, tzinfo=timezone.utc
    )

    empty_client = _spawning_client(
        {
            "child_run_handle_id": str(uuid.uuid4()),
            "granted_scope": _GRANTED,
            "child_session_token": "sst_child.sig",
            "child_proxy_token": "",
        }
    )
    parent = register_test_run(empty_client, "sst_parent.sig")
    resp = await empty_client.spawn_subagent(parent, {"child_agent_id": CHILD_UUID})
    assert empty_client.egress_for(resp["child_run"]) is None


@pytest.mark.asyncio
async def test_response_carries_neither_child_token() -> None:
    apdp = _spawning_client(
        {
            "child_run_handle_id": str(uuid.uuid4()),
            "granted_scope": _GRANTED,
            "child_session_token": "sst_secret-session-value",
            "child_proxy_token": "eyJ.secret-proxy-value",
        }
    )
    parent = register_test_run(apdp, "sst_parent.sig")
    resp = await apdp.spawn_subagent(parent, {"child_agent_id": CHILD_UUID})
    text = repr(resp) + repr(spawn_subagent_response_from_dict(resp))
    assert "secret-session-value" not in text
    assert "secret-proxy-value" not in text
    assert resp["child_run"].startswith("run_")
