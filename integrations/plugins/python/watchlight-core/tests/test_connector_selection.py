"""Which deployments use the connector, and a child's egress on it."""

from __future__ import annotations

import uuid
from typing import Any, List, Optional

import pytest

from watchlight_core import BaseRunHandle, ChildIntent, connector_configured, run_handle
from watchlight_core.backend import EgressBinding, RunRef, fetch_egress_binding
from watchlight_core.errors import GovernanceUnavailable
from watchlight_core_testing import MockApdpClient

CHILD_UUID = "22222222-2222-2222-2222-222222222222"


class _Plugin:
    def __init__(self, apdp: MockApdpClient) -> None:
        self.apdp = apdp
        self.tenant_id = "tenant-a"
        self.log_decisions = False
        self.last_governance_mode = "unmeasured"
        self.last_session_id: Optional[str] = None
        self.last_manifest: Optional[Any] = None
        self.last_plan_validation: Optional[Any] = None
        self.last_proposed_plan: Optional[Any] = None
        self.last_actions_allowed = 0
        self.last_actions_denied = 0
        self.kill_signal_registry = None


def _root(apdp: MockApdpClient) -> BaseRunHandle:
    handle = BaseRunHandle(
        plugin=_Plugin(apdp),
        agent_uuid="00000000-0000-0000-0000-000000000001",
        session_id=f"ses_{uuid.uuid4()}",
        run_handle_id=str(uuid.uuid4()),
    )
    handle._aentered = True
    return handle


@pytest.mark.parametrize(
    "env",
    [
        {"WATCHLIGHT_BACKEND": "sidecar"},
        {"WATCHLIGHT_BACKEND": " Sidecar "},
        {"WATCHLIGHT_SIDECAR_SOCKET": "/run/wl/control.sock"},
        {"WATCHLIGHT_SIDECAR_ADDR": "127.0.0.1:41000"},
    ],
)
def test_deployment_config_selects_the_connector(env: dict) -> None:
    assert connector_configured(env) is True


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"WATCHLIGHT_BACKEND": "in_process"},
        # An existing relay install: these don't select the connector.
        {"WATCHLIGHT_PROXY_URL": "https://wl-proxy:3128"},
        {"WATCHLIGHT_APDP_URL": "https://wl-apdp:8081"},
        {"WATCHLIGHT_PLUGIN_TOKEN": "x"},
    ],
)
def test_other_config_stays_where_it_is(env: dict) -> None:
    assert connector_configured(env) is False


@pytest.mark.parametrize(
    "env",
    [
        {"WATCHLIGHT_BACKEND": "relay"},
        {"WATCHLIGHT_BACKEND": "in_process", "WATCHLIGHT_SIDECAR_SOCKET": "/run/wl/control.sock"},
        {"WATCHLIGHT_BACKEND": "in_process", "WATCHLIGHT_SIDECAR_ADDR": "127.0.0.1:41000"},
    ],
)
def test_conflicting_config_is_refused_not_guessed(env: dict) -> None:
    with pytest.raises(GovernanceUnavailable):
        connector_configured(env)


class _Connector:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.fetched: List[Any] = []
        self.binding: Optional[Any] = None

    async def fetch_egress(self, run: RunRef) -> Any:
        self.fetched.append(run)
        if self.fails:
            raise GovernanceUnavailable("egress: no endpoint")

    def egress_for(self, run: RunRef) -> Any:
        return self.binding


@pytest.mark.asyncio
async def test_a_connector_is_asked_for_the_endpoint() -> None:
    backend = _Connector()
    backend.binding = EgressBinding(proxy_url="http://127.0.0.1:41001", expires_at=None, token_source=lambda: None)
    assert await fetch_egress_binding(backend, RunRef("run-1")) is backend.binding
    assert backend.fetched == [RunRef("run-1")]


@pytest.mark.asyncio
async def test_a_connector_that_answers_with_nothing_refuses() -> None:
    with pytest.raises(GovernanceUnavailable, match="no egress endpoint"):
        await fetch_egress_binding(_Connector(), RunRef("run-1"))


@pytest.mark.asyncio
async def test_a_connector_that_gives_no_endpoint_refuses() -> None:
    with pytest.raises(GovernanceUnavailable):
        await fetch_egress_binding(_Connector(fails=True), RunRef("run-1"))


@pytest.mark.asyncio
async def test_a_backend_that_only_answers_is_only_read() -> None:
    class _Answers:
        def egress_for(self, run: RunRef) -> None:
            return None

    assert await fetch_egress_binding(_Answers(), RunRef("run-1")) is None
    assert await fetch_egress_binding(_Answers(), None) is None


class _NoChildEndpoint(MockApdpClient):
    def __init__(self) -> None:
        super().__init__()
        self.ended: List[str] = []

    async def fetch_egress(self, run: RunRef) -> None:
        raise GovernanceUnavailable("egress: no endpoint")

    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool:
        self.ended.append(reason)
        return True


@pytest.mark.asyncio
async def test_a_child_with_no_endpoint_is_refused_and_its_session_closed() -> None:
    apdp = _NoChildEndpoint()
    root = _root(apdp)
    with pytest.raises(GovernanceUnavailable, match="no endpoint"):
        await root.spawn_subagent(
            CHILD_UUID,
            child_intent=ChildIntent("research", "Collect the Q3 filings", max_actions=5),
            allowed_intents=["research"],
        )
    assert apdp.ended == ["spawn_refused"]
    assert run_handle._current_subagent_handle.get() is None


@pytest.mark.asyncio
async def test_a_child_whose_endpoint_comes_back_empty_is_refused_and_closed() -> None:
    class _EmptyEndpoint(_NoChildEndpoint):
        async def fetch_egress(self, run: RunRef) -> None:
            return None

    apdp = _EmptyEndpoint()
    root = _root(apdp)
    with pytest.raises(GovernanceUnavailable, match="no egress endpoint"):
        await root.spawn_subagent(
            CHILD_UUID,
            child_intent=ChildIntent("research", "Collect the Q3 filings", max_actions=5),
            allowed_intents=["research"],
        )
    assert apdp.ended == ["spawn_refused"]
    assert run_handle._current_subagent_handle.get() is None


@pytest.mark.asyncio
async def test_a_fetch_that_only_returns_an_awaitable_is_still_awaited() -> None:
    backend = _Connector()
    backend.binding = EgressBinding(proxy_url="http://127.0.0.1:41001", expires_at=None, token_source=lambda: None)
    plain = backend.fetch_egress

    class _Wrapped:
        fetch_egress = staticmethod(lambda run: plain(run))
        egress_for = staticmethod(backend.egress_for)

    assert await fetch_egress_binding(_Wrapped(), RunRef("run-1")) is backend.binding
    assert backend.fetched == [RunRef("run-1")]
