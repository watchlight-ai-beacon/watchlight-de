"""Sub-agent handle binding fails closed.

* the sub-agent context variable is cleared before each spawn
  attempt and reset (token-based) on the child's complete / terminate,
  so a refused spawn never leaves a usable handle visible, and a
  completed sibling is never handed to the next child.
* a failed context-variable bind refuses the spawn / run entry
  instead of being swallowed.
* a networked spawn whose response carries no
  ``child_session_token`` is refused (the child would otherwise run with
  its lineage dropped).
"""

from __future__ import annotations

import uuid

import pytest

from watchlight_core import (
    BaseRunHandle,
    GovernanceUnavailable,
    ScopeAttenuationDenied,
    current_subagent_handle,
)
from watchlight_core import run_handle as rh
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import register_test_run, bind_test_run


class _Plugin(GovernanceTelemetry):
    def __init__(self, apdp=None) -> None:
        super().__init__()
        self.apdp = apdp or MockApdpClient()
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = None


def _root(plugin: _Plugin) -> BaseRunHandle:
    h = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid=str(uuid.uuid4()), session_id=f"ses_{uuid.uuid4()}", run_handle_id=str(uuid.uuid4())), "sst_root")
    h._aentered = True
    return h


@pytest.fixture(autouse=True)
def _clean_contextvar():
    token = rh._current_subagent_handle.set(None)
    yield
    rh._current_subagent_handle.reset(token)


# ─── cleared before each spawn, reset on close ──────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("close", ["complete", "terminate"])
async def test_subagent_contextvar_is_reset_when_child_closes(close) -> None:
    root = _root(_Plugin())
    child = await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert current_subagent_handle() is child
    if close == "complete":
        await child.complete()
    else:
        await child.terminate("done")
    assert rh._current_subagent_handle.get() is None
    assert current_subagent_handle() is None


@pytest.mark.asyncio
async def test_refused_spawn_after_completed_sibling_sees_no_handle() -> None:
    plugin = _Plugin()
    root = _root(plugin)
    sibling = await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    await sibling.complete()

    plugin.apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
    with pytest.raises(ScopeAttenuationDenied):
        await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert rh._current_subagent_handle.get() is None


@pytest.mark.asyncio
async def test_refused_spawn_does_not_leave_live_sibling_visible() -> None:
    plugin = _Plugin()
    root = _root(plugin)
    await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])

    plugin.apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
    with pytest.raises(ScopeAttenuationDenied):
        await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    # The next child to start must not pick up the earlier sibling.
    assert rh._current_subagent_handle.get() is None


@pytest.mark.asyncio
async def test_grandchild_close_restores_the_spawning_sub_agent() -> None:
    root = _root(_Plugin())
    child = await root.spawn_subagent(
        str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"], max_depth=2
    )
    child._aentered = True
    grandchild = await child.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert current_subagent_handle() is grandchild
    await grandchild.complete()
    assert current_subagent_handle() is child
    await child.complete()
    assert current_subagent_handle() is None


@pytest.mark.asyncio
async def test_refused_grandchild_leaves_the_spawner_bound_not_a_sibling() -> None:
    plugin = _Plugin()
    root = _root(plugin)
    child = await root.spawn_subagent(
        str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"], max_depth=2
    )
    child._aentered = True
    await child.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    plugin.apdp.spawn_error_override = ScopeAttenuationDenied("nope", [])
    with pytest.raises(ScopeAttenuationDenied):
        await child.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert rh._current_subagent_handle.get() is child


@pytest.mark.asyncio
async def test_current_subagent_handle_never_returns_a_closed_handle() -> None:
    root = _root(_Plugin())
    child = await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    await child.complete()
    # Even if a stale binding survives in some other context.
    rh._current_subagent_handle.set(child)
    assert current_subagent_handle() is None


# ─── a failed bind refuses ──────────────────────────────────────────


class _BrokenVar:
    def __init__(self, real) -> None:
        self._real = real

    def get(self, *a):
        return self._real.get(*a)

    def set(self, value):
        if value is None:
            return self._real.set(value)
        raise RuntimeError("bind failed")

    def reset(self, token):
        return self._real.reset(token)


@pytest.mark.asyncio
async def test_subagent_contextvar_bind_failure_refuses_spawn(monkeypatch) -> None:
    plugin = _Plugin()
    root = _root(plugin)
    monkeypatch.setattr(
        rh, "_current_subagent_handle", _BrokenVar(rh._current_subagent_handle)
    )
    with pytest.raises(GovernanceUnavailable):
        await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    # The child that could not be bound is closed server-side.
    assert len(plugin.apdp._closed_sessions) == 1


class _UnclearableVar(_BrokenVar):
    def set(self, value):
        raise RuntimeError("clear failed")


@pytest.mark.asyncio
async def test_subagent_contextvar_clear_failure_refuses_spawn_typed(monkeypatch) -> None:
    """A binding that cannot even be cleared before the spawn refuses it
    with the typed governance error, before any wl-apdp round-trip."""
    plugin = _Plugin()
    root = _root(plugin)
    monkeypatch.setattr(
        rh, "_current_subagent_handle", _UnclearableVar(rh._current_subagent_handle)
    )
    with pytest.raises(GovernanceUnavailable, match="cleared"):
        await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert plugin.apdp._closed_sessions == []


@pytest.mark.asyncio
async def test_lineage_contextvar_bind_failure_refuses_run_entry(monkeypatch) -> None:
    plugin = _Plugin()
    handle = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid=str(uuid.uuid4()), session_id=f"ses_{uuid.uuid4()}"), "sst_root")
    monkeypatch.setattr(
        rh, "_current_handle_lineage", _BrokenVar(rh._current_handle_lineage)
    )
    with pytest.raises(GovernanceUnavailable):
        await handle.__aenter__()
    assert handle._aentered is False


# ─── a spawn without a child credential is refused ──────────────────


@pytest.mark.asyncio
async def test_spawn_without_child_session_token_is_refused() -> None:
    plugin = _Plugin()
    root = _root(plugin)
    child_handle_id = str(uuid.uuid4())
    plugin.apdp.spawn_response_override = {
        "child_run_handle_id": child_handle_id,
        "granted_scope": {
            "allowed_tools": ["t"],
            "allowed_resources": [],
            "allowed_intents": [],
            "max_depth": 0,
            "time_budget_seconds": 0,
            "depth": 1,
        },
        "child_execution_id": f"exec_{uuid.uuid4()}",
        "child_session_id": f"ses_{child_handle_id}",
    }
    with pytest.raises(GovernanceUnavailable):
        await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert rh._current_subagent_handle.get() is None


@pytest.mark.asyncio
async def test_publish_failure_is_logged_at_warning(monkeypatch) -> None:
    """A publish error other than the retry budget is visible in ops logs."""
    import logging

    import httpx

    from watchlight_core.apdp_client import ApdpClient

    records: list = []

    class _H(logging.Handler):
        def emit(self, record):
            records.append(record)

    lg = logging.getLogger("watchlight.core.apdp_client")
    h = _H(logging.DEBUG)
    lg.addHandler(h)
    try:
        apdp = ApdpClient("http://localhost")
        apdp._probed = True

        async def _boom(*a, **k):
            raise RuntimeError("unexpected")

        monkeypatch.setattr(apdp, "_send_events", _boom)
        apdp._client = httpx.AsyncClient(base_url="http://localhost")
        ok = await apdp.publish_events(register_test_run(apdp, "sst_x"), [{"event_type": "tool_call_observed"}])
    finally:
        lg.removeHandler(h)
    assert ok is False
    assert any(
        r.levelno >= logging.WARNING and "publish" in r.getMessage().lower()
        for r in records
    )
