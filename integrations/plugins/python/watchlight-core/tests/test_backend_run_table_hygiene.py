"""The governance backend's run table holds nothing longer than it must.

Follow-ups to the ``GovernanceBackend`` / ``RunRef`` split:

* ``SessionInfo.session`` carries only documented, non-secret session
  fields; an unknown key, or anything token-like, never reaches the caller.
* A run's credentials leave the client when the run ends, is dropped
  (its handle garbage-collected) or is evicted: the egress token at once
  on end, both tokens on drop or eviction, and a delivery lane's copy once
  its queued lineage is sent.
* A child spawn is refused locally when the parent run holds no
  credential: no request goes out, under the shared bearer or otherwise.
* The expiry heap does not keep entries for runs that already left the
  table, so its size stays bounded across many start/end cycles.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
import pytest

from watchlight_core import (
    ApdpClient,
    BaseRunHandle,
    GovernanceUnavailable,
    ParentRunUncredentialed,
    SessionInfo,
)
from watchlight_core import apdp_client as apdp_client_module
from watchlight_core.backend import PUBLIC_SESSION_KEYS, public_session_record
from watchlight_core.telemetry import GovernanceTelemetry

AGENT = "11111111-1111-4111-8111-111111111111"
CHILD_AGENT = "22222222-2222-4222-8222-222222222222"
MARKERS = ("ROOTSECRET", "ROOTPROXYSECRET", "UNKNOWNSECRET", "NESTEDSECRET")


def _b64(obj: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _sst(marker: str, exp: Optional[float] = None) -> str:
    claims: Dict[str, Any] = {"sid": "ses_root", "aid": AGENT}
    if exp is not None:
        claims["exp"] = int(exp)
    return f"sst_{_b64(claims)}.{marker}"


def _proxy_jwt(marker: str) -> str:
    return f"{_b64({'alg': 'ES256'})}.{_b64({'exec_id': 'exec_root'})}.{marker}"


class _Wire:
    """A stand-in wl-apdp that records every request."""

    def __init__(self) -> None:
        self.requests: List[httpx.Request] = []
        self.session_token: Optional[str] = "sst_ROOTSECRET.c2ln"
        self.extra_session_fields: Dict[str, Any] = {}
        self.events_status = 202

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/sessions":
            session: Dict[str, Any] = {
                "id": "ses_root",
                "agent_id": AGENT,
                "status": "active",
                "ttl_seconds": 3600,
                "application_id": None,
            }
            session.update(self.extra_session_fields)
            body: Dict[str, Any] = {
                "session": session,
                "proxy_token": _proxy_jwt("ROOTPROXYSECRET"),
                "proxy_token_expires_at": "2030-01-01T00:00:00Z",
                "execution_id": "exec_root",
            }
            if self.session_token is not None:
                body["session_token"] = self.session_token
            return httpx.Response(200, json=body)
        if path == "/v1/spawn_subagent":
            return httpx.Response(500, json={"reason": "must not be called"})
        if path == "/v1/events":
            return httpx.Response(self.events_status, json={"accepted": 1})
        return httpx.Response(200, json={})

    def paths(self) -> List[str]:
        return [r.url.path for r in self.requests]


def _client(wire: _Wire) -> ApdpClient:
    apdp = ApdpClient("https://apdp.test")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(wire)
    )
    return apdp


class _Plugin(GovernanceTelemetry):
    def __init__(self, apdp: Any) -> None:
        super().__init__()
        self.apdp = apdp
        self.tenant_id = "acme"
        self.log_decisions = False
        self.kill_signal_registry = None


def _strings_in(obj: Any, seen: Optional[set] = None, depth: int = 0) -> List[str]:
    """Every string reachable from ``obj`` (attributes, slots, containers)."""
    seen = set() if seen is None else seen
    if depth > 10 or id(obj) in seen:
        return []
    seen.add(id(obj))
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, (int, float, bool, type(None), bytes)) or isinstance(obj, type):
        return []
    if type(obj).__module__ in ("asyncio", "logging", "_contextvars", "httpx", "ssl"):
        return []
    out: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _strings_in(k, seen, depth + 1) + _strings_in(v, seen, depth + 1)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)) or type(obj).__name__ == "deque":
        for v in obj:
            out += _strings_in(v, seen, depth + 1)
        return out
    attrs: Dict[str, Any] = {}
    if hasattr(obj, "__dict__"):
        attrs.update(vars(obj))
    for cls in type(obj).__mro__:
        for slot in getattr(cls, "__slots__", ()):
            if hasattr(obj, slot):
                attrs[slot] = getattr(obj, slot)
    for name, value in attrs.items():
        if name == "_client":  # the HTTP client (transport + recorded wire)
            continue
        if callable(value) and not hasattr(value, "__dict__"):
            continue
        out += _strings_in(value, seen, depth + 1)
    return out


def _holds(apdp: ApdpClient, marker: str) -> bool:
    return any(marker in s for s in _strings_in(apdp))


# ── 1. SessionInfo.session is an allowlist ─────────────────────────────


@pytest.mark.asyncio
async def test_session_info_passes_only_documented_non_secret_keys():
    wire = _Wire()
    wire.extra_session_fields = {
        "goal_id": "goal-1",
        "created_at": "2026-10-08T00:00:00Z",
        # Unknown keys and token-like keys: none may reach the caller.
        "internal_routing_hint": "UNKNOWNSECRET",
        "refresh_token": "UNKNOWNSECRET",
        "sessionToken": "UNKNOWNSECRET",
        "credentials": {"value": "NESTEDSECRET"},
        "metadata": {"note": "NESTEDSECRET"},
        # A documented key whose value is credential-shaped is dropped too.
        "termination_reason": "sst_UNKNOWNSECRET.c2ln",
        "plan_hash": _proxy_jwt("UNKNOWNSECRET"),
    }
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    assert isinstance(info, SessionInfo)
    session = dict(info.session)
    assert set(session) <= PUBLIC_SESSION_KEYS
    assert session["id"] == "ses_root"
    assert session["agent_id"] == AGENT
    assert session["goal_id"] == "goal-1"
    assert session["created_at"] == "2026-10-08T00:00:00Z"
    for dropped in (
        "internal_routing_hint",
        "refresh_token",
        "sessionToken",
        "credentials",
        "metadata",
        "termination_reason",
        "plan_hash",
    ):
        assert dropped not in session, dropped
    text = repr(info)
    for marker in MARKERS:
        assert marker not in text


def test_public_session_record_drops_unknown_and_credential_shaped_values():
    record = public_session_record(
        {
            "id": "ses_1",
            "status": "active",
            "max_actions": 5,
            "session_token": "sst_x.y",
            "proxy_token": "a.b.c",
            "anything_else": "v",
            "tenant_id": "Bearer abc",
            "goal_id": "wlapdp_ak_123",
            "agent_id": ["not", "a", "scalar"],
        }
    )
    assert record == {"id": "ses_1", "status": "active", "max_actions": 5}
    assert public_session_record(None) == {}
    assert public_session_record("not a mapping") == {}


@pytest.mark.asyncio
async def test_in_process_and_adopted_sessions_use_the_same_allowlist():
    from watchlight_core import InProcessClient
    from watchlight_core.run_grant import RunGrant

    from watchlight_core_testing import MockApdpClient

    # The session bookkeeping only: create_session does not touch the
    # compiled engine, so the in-process client is built without it.
    in_process = object.__new__(InProcessClient)
    in_process._sessions = {}
    in_process._runs = {}
    in_process._run_handles = {}
    in_process._root_handles = set()
    in_process._run_agents = {}
    in_process._identity_agent_id = None
    for client in (in_process, MockApdpClient()):
        info = await client.create_session(
            AGENT, goal_id="g", metadata={"note": "NESTEDSECRET"}
        )
        assert info is not None
        assert set(info.session) <= PUBLIC_SESSION_KEYS, type(client).__name__
        assert info.session["goal_id"] == "g"
        assert "NESTEDSECRET" not in repr(info)

    apdp = _client(_Wire())
    grant = RunGrant.from_session_response(
        {
            "session": {"id": "ses_g", "agent_id": AGENT},
            "session_token": _sst("ROOTSECRET"),
            "execution_id": "exec_g",
        }
    )
    adopted = apdp.adopt_run_grant(grant)
    assert set(adopted.session) <= PUBLIC_SESSION_KEYS
    assert "ROOTSECRET" not in repr(adopted)


# ── 2. No lingering credential after end / drop / eviction ─────────────
#
# An ended run keeps its run credential in the run table, and only there,
# for its late lineage (its terminal event is published after the session
# close), within MAX_ENDED_RUNS and the credential's own expiry. Its egress
# token goes at once, a delivery lane holds a copy only while it has
# lineage queued, and eviction or expiry wipes the entry.


def _lanes_hold(apdp: ApdpClient, marker: str) -> bool:
    return any(marker in s for s in _strings_in(apdp._lanes))


def _only_the_run_table_holds_the_run_credential(apdp: ApdpClient, run: Any) -> None:
    entry = apdp._runs[run]
    assert entry.ended
    assert entry.proxy_token is None
    assert not _lanes_hold(apdp, "ROOTSECRET")
    saved, entry.session_token = entry.session_token, None
    try:
        assert not _holds(apdp, "ROOTSECRET")
        assert not _holds(apdp, "ROOTPROXYSECRET")
    finally:
        entry.session_token = saved


@pytest.mark.asyncio
async def test_ending_a_run_clears_its_egress_token_at_once():
    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    assert _holds(apdp, "ROOTPROXYSECRET")
    assert await apdp.complete_session(info.run) is True
    _only_the_run_table_holds_the_run_credential(apdp, info.run)
    # The run credential is still there for the run's late lineage.
    assert await apdp.publish_events(info.run, [{"event_type": "execution_completed"}])
    assert not _lanes_hold(apdp, "ROOTSECRET")


@pytest.mark.asyncio
async def test_a_dropped_handle_leaves_no_egress_or_lane_credential():
    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    assert await apdp.publish_events(info.run, [{"event_type": "x"}])
    apdp._release_dropped_run(info.run)
    _only_the_run_table_holds_the_run_credential(apdp, info.run)
    # Control calls on the run are refused from now on (fail closed).
    assert apdp.egress_for(info.run) is None
    with pytest.raises(GovernanceUnavailable):
        apdp.run_authorization(info.run)


@pytest.mark.asyncio
async def test_a_garbage_collected_handle_leaves_no_egress_or_lane_credential():
    import gc

    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    handle = BaseRunHandle(
        plugin=_Plugin(apdp), agent_uuid=AGENT, session_id=info.session_id, run=info.run
    )
    del handle
    gc.collect()
    _only_the_run_table_holds_the_run_credential(apdp, info.run)


@pytest.mark.asyncio
async def test_evicted_ended_runs_are_wiped(monkeypatch):
    monkeypatch.setattr(apdp_client_module, "MAX_ENDED_RUNS", 2)
    wire = _Wire()
    apdp = _client(wire)
    first = await apdp.create_session(AGENT)
    entry = apdp._runs[first.run]
    await apdp.complete_session(first.run)
    wire.session_token = "sst_OTHER.c2ln"
    for _ in range(3):
        info = await apdp.create_session(AGENT)
        await apdp.complete_session(info.run)
    assert first.run not in apdp._runs
    # The evicted entry itself is wiped, not only unlinked.
    assert entry.session_token is None and entry.proxy_token is None
    assert not _holds(apdp, "ROOTSECRET")


@pytest.mark.asyncio
async def test_expired_runs_are_wiped():
    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    entry = apdp._runs[info.run]
    apdp._clock = lambda: time.time() + 10 * apdp_client_module.DEFAULT_RUN_TTL_SECONDS
    assert apdp.egress_for(info.run) is None
    assert info.run not in apdp._runs
    assert entry.session_token is None and entry.proxy_token is None
    assert not _holds(apdp, "ROOTSECRET")


@pytest.mark.asyncio
async def test_a_lane_drops_its_credential_once_its_queue_is_delivered():
    from watchlight_core._lineage_retry import LineageRetryPolicy

    wire = _Wire()
    wire.events_status = 503
    apdp = _client(wire)
    apdp._lineage_retry = apdp_client_module.RetryRunner(
        LineageRetryPolicy(max_attempts=1, max_wait_seconds=0.01)
    )
    info = await apdp.create_session(AGENT)
    # An exhausted delivery leaves the run's lane degraded (kept, idle).
    assert await apdp.publish_events(info.run, [{"event_type": "a"}]) is False
    key, lane = next(iter(apdp._lanes.items()))
    assert lane.degraded
    # A batch queued for background delivery is sent under the run's
    # credential; once the queue is empty the lane holds no credential.
    wire.events_status = 202
    assert apdp._enqueue(lane, key, "sst_ROOTSECRET.c2ln", [{"event_type": "b"}], delay=0.0)
    assert lane.token is not None
    for _ in range(100):
        if not lane.worker_active():
            break
        await asyncio.sleep(0.01)
    assert not lane.worker_active()
    assert lane.token is None
    assert not _lanes_hold(apdp, "ROOTSECRET")


# ── 3. A parent without a credential cannot spawn ──────────────────────


@pytest.mark.asyncio
async def test_spawn_from_an_uncredentialed_parent_is_refused_locally():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    assert info is not None
    # Defence in depth: a parent whose credential is gone from the table.
    apdp._runs[info.run].session_token = None
    with pytest.raises(ParentRunUncredentialed) as exc:
        await apdp.spawn_subagent(
            info.run,
            {"parent_agent_id": AGENT, "child_agent_id": CHILD_AGENT, "requested_scope": {}},
        )
    assert isinstance(exc.value, GovernanceUnavailable)
    assert "credential" in str(exc.value)
    # No spawn request left the client: not under the shared bearer, not
    # under any credential.
    assert "/v1/spawn_subagent" not in wire.paths()
    assert len(apdp._runs) == 1


@pytest.mark.asyncio
async def test_run_handle_spawn_from_an_uncredentialed_parent_never_starts_the_child():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    apdp._runs[info.run].session_token = None
    root = BaseRunHandle(
        plugin=_Plugin(apdp), agent_uuid=AGENT, session_id=info.session_id, run=info.run
    )
    root._aentered = True
    with pytest.raises(ParentRunUncredentialed):
        await root.spawn_subagent(CHILD_AGENT, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
    assert "/v1/spawn_subagent" not in wire.paths()
    assert len(apdp._runs) == 1


@pytest.mark.asyncio
async def test_spawn_after_the_parent_credential_expired_is_refused_locally():
    wire = _Wire()
    wire.session_token = _sst("ROOTSECRET", exp=time.time() + 60)
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    apdp._clock = lambda: time.time() + 120
    with pytest.raises(GovernanceUnavailable):
        await apdp.spawn_subagent(
            info.run,
            {"parent_agent_id": AGENT, "child_agent_id": CHILD_AGENT, "requested_scope": {}},
        )
    assert "/v1/spawn_subagent" not in wire.paths()


# ── 4. The expiry heap stays bounded ───────────────────────────────────


@pytest.mark.asyncio
async def test_expiry_heap_stays_bounded_across_many_start_end_cycles(monkeypatch):
    monkeypatch.setattr(apdp_client_module, "MAX_ENDED_RUNS", 8)
    apdp = _client(_Wire())
    for _ in range(500):
        info = await apdp.create_session(AGENT)
        await apdp.complete_session(info.run)
    assert len(apdp._runs) <= 8
    assert len(apdp._run_expiry) <= 2 * len(apdp._runs) + apdp_client_module.EXPIRY_HEAP_SLACK


@pytest.mark.asyncio
async def test_expiry_heap_stays_bounded_across_many_dropped_handles(monkeypatch):
    monkeypatch.setattr(apdp_client_module, "MAX_ENDED_RUNS", 8)
    apdp = _client(_Wire())
    for _ in range(500):
        info = await apdp.create_session(AGENT)
        apdp._release_dropped_run(info.run)
    assert len(apdp._runs) <= 8
    assert len(apdp._run_expiry) <= 2 * len(apdp._runs) + apdp_client_module.EXPIRY_HEAP_SLACK


@pytest.mark.asyncio
async def test_a_compacted_heap_still_expires_live_runs():
    apdp = _client(_Wire())
    live = await apdp.create_session(AGENT)
    for _ in range(300):
        info = await apdp.create_session(AGENT)
        apdp._release_dropped_run(info.run)
    assert live.run in apdp._runs
    apdp._clock = lambda: time.time() + 10 * apdp_client_module.DEFAULT_RUN_TTL_SECONDS
    assert apdp.egress_for(live.run) is None
    assert live.run not in apdp._runs
    assert not _holds(apdp, "ROOTSECRET")


def test_followup_names_are_exported():
    import watchlight_core

    assert "ParentRunUncredentialed" in watchlight_core.__all__
    assert "RunUncredentialed" in watchlight_core.__all__
    assert issubclass(watchlight_core.ParentRunUncredentialed, watchlight_core.RunUncredentialed)


# ── Review follow-ups ──────────────────────────────────────────

_SPAWN_BODY = {"parent_agent_id": AGENT, "child_agent_id": CHILD_AGENT, "requested_scope": {}}


@pytest.mark.asyncio
async def test_a_session_without_a_run_credential_is_refused_at_registration():
    from watchlight_core import RunUncredentialed

    wire = _Wire()
    wire.session_token = None
    apdp = _client(wire)
    with pytest.raises(RunUncredentialed) as exc:
        await apdp.create_session(AGENT)
    assert isinstance(exc.value, GovernanceUnavailable)
    assert "credential" in str(exc.value)
    assert apdp._runs == {}
    # Registration itself refuses, whatever the caller.
    with pytest.raises(RunUncredentialed):
        apdp._register_run(session_id="ses_x", agent_id=AGENT, session_token="")


@pytest.mark.asyncio
async def test_authorize_manifest_and_close_never_go_out_on_the_plugin_bearer_alone():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    apdp._runs[info.run].session_token = None  # defence in depth
    before = len(wire.requests)
    decision = await apdp.authorize("p", "a", "r", run=info.run)
    assert decision["decision"] == "Deny"
    assert await apdp.get_manifest(AGENT, run=info.run) is None
    assert await apdp.complete_session(info.run) is False
    assert len(wire.requests) == before


@pytest.mark.asyncio
async def test_publish_after_the_probe_never_repopulates_a_forgotten_runs_lane():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    apdp._probed = False

    async def _probe_then_forget() -> None:
        apdp._probed = True
        apdp._forget_run(info.run)  # the run leaves the table during the probe

    apdp._ensure_probed = _probe_then_forget  # type: ignore[method-assign]
    before = len(wire.requests)
    assert await apdp.publish_events(info.run, [{"event_type": "x"}]) is False
    assert len(wire.requests) == before
    assert not _lanes_hold(apdp, "ROOTSECRET")
    assert apdp._lanes == {}


def test_allowlist_catches_jwe_non_finite_numbers_and_known_secret_prefixes():
    jwe = "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn"
    record = public_session_record(
        {
            "id": "wl_session_id_is_not_a_secret",
            "plan_hash": jwe,
            "action_count": float("nan"),
            "max_actions": float("inf"),
            "goal_id": "wlsa_service_key",
            "tenant_id": "wlpa_plugin_key",
            "status": "active",
        }
    )
    assert record == {"id": "wl_session_id_is_not_a_secret", "status": "active"}


@pytest.mark.asyncio
async def test_a_child_is_not_registered_when_the_parent_ends_during_the_spawn():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    child_handle = str(uuid.uuid4())

    def _spawn(request: httpx.Request) -> httpx.Response:
        apdp._end_run(info.run, "run_completed")  # the parent ends meanwhile
        return httpx.Response(
            200,
            json={
                "child_run_handle_id": child_handle,
                "child_session_id": "ses_child",
                "child_session_token": _sst("CHILDSECRET"),
                "granted_scope": {},
            },
        )

    original = wire.__call__

    def _route(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/spawn_subagent":
            wire.requests.append(request)
            return _spawn(request)
        return original(request)

    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(_route)
    )
    with pytest.raises(GovernanceUnavailable) as exc:
        await apdp.spawn_subagent(info.run, dict(_SPAWN_BODY))
    assert "ended" in str(exc.value)
    assert "CHILDSECRET" not in str(exc.value)
    assert len(apdp._runs) == 1  # the parent only; no child registered
    # The child's session is ended at wl-apdp, best effort, under its own
    # credential.
    closes = [r for r in wire.requests if r.url.path == "/sessions/ses_child/complete"]
    assert closes and "CHILDSECRET" in closes[0].headers.get("x-wl-run-authorization", "")


@pytest.mark.asyncio
async def test_an_ended_runs_credential_is_dropped_after_drain_and_grace():
    wire = _Wire()
    apdp = _client(wire)
    now = [time.time()]
    apdp._clock = lambda: now[0]
    info = await apdp.create_session(AGENT)
    assert await apdp.complete_session(info.run) is True
    # The terminal event goes out under the run's own credential.
    assert await apdp.publish_events(info.run, [{"event_type": "execution_completed"}])
    sent = [r for r in wire.requests if r.url.path == "/v1/events"]
    assert sent and "ROOTSECRET" in sent[-1].headers["authorization"]
    await apdp.drain(info.run)
    assert info.run in apdp._runs
    now[0] += apdp_client_module.ENDED_RUN_GRACE_SECONDS + 1
    apdp._sweep_expired(now[0])
    assert info.run not in apdp._runs
    assert not _holds(apdp, "ROOTSECRET")


@pytest.mark.asyncio
async def test_the_grace_waits_for_queued_lineage_to_drain():
    wire = _Wire()
    apdp = _client(wire)
    now = [time.time()]
    apdp._clock = lambda: now[0]
    info = await apdp.create_session(AGENT)
    await apdp.complete_session(info.run)
    key = apdp._lane_key(apdp._runs[info.run].session_token)
    lane = apdp._lane(key)
    lane.users += 1  # lineage still being delivered
    now[0] += apdp_client_module.ENDED_RUN_GRACE_SECONDS + 1
    apdp._sweep_expired(now[0])
    assert info.run in apdp._runs  # kept while its lineage drains
    lane.users -= 1
    now[0] += apdp_client_module.ENDED_RUN_GRACE_SECONDS + 1
    apdp._sweep_expired(now[0])
    assert info.run not in apdp._runs


@pytest.mark.asyncio
async def test_a_child_is_not_registered_when_the_parent_expires_during_the_spawn():
    wire = _Wire()
    now = [time.time()]
    wire.session_token = _sst("ROOTSECRET", exp=now[0] + 60)
    apdp = _client(wire)
    apdp._clock = lambda: now[0]
    info = await apdp.create_session(AGENT)
    original = wire.__call__

    def _route(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/spawn_subagent":
            wire.requests.append(request)
            now[0] += 120  # the parent's credential expires meanwhile
            return httpx.Response(
                200,
                json={
                    "child_run_handle_id": str(uuid.uuid4()),
                    "child_session_id": "ses_child",
                    "child_session_token": _sst("CHILDSECRET"),
                    "granted_scope": {},
                },
            )
        return original(request)

    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(_route)
    )
    with pytest.raises(GovernanceUnavailable):
        await apdp.spawn_subagent(info.run, dict(_SPAWN_BODY))
    assert apdp._runs == {}  # neither the expired parent nor a child
    assert any(r.url.path == "/sessions/ses_child/complete" for r in wire.requests)
