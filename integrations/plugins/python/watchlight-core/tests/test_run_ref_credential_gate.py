"""Gate: run credentials stay inside the governance backend.

A run handle names its run by an opaque ``RunRef``. The run's ``sst_``
session token and its wl-proxy token live only in ``ApdpClient``'s run
table, which attaches them to the wire itself. These tests drive a full
governed run (root and child) over a recording transport and check that:

* no token value is reachable from a run handle's attributes, its repr,
  the logs, or an exception the SDK raises;
* every request still carries the right run's credential (root calls the
  root token, child calls the child token): the wire is unchanged;
* the client refuses a run reference it did not issue, or one whose run
  has ended (fail closed), and keeps an ended run's late lineage flowing.
"""

from __future__ import annotations

import base64
import json
import logging
import pickle
import uuid
from dataclasses import fields, is_dataclass
from typing import Any, Dict, List

import httpx
import pytest

from watchlight_core import (
    ApdpClient,
    BaseRunHandle,
    EgressBinding,
    GovernanceBackend,
    GovernanceUnavailable,
    InProcessClient,
    RunRef,
)
from watchlight_core import apdp_client as apdp_client_module
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient

AGENT = "11111111-1111-4111-8111-111111111111"
CHILD_AGENT = "22222222-2222-4222-8222-222222222222"
ROOT_SST = "sst_ROOTSECRET.c2lnbmF0dXJl"
CHILD_SST = "sst_CHILDSECRET.c2lnbmF0dXJl"


def _jwt(claims: Dict[str, Any], marker: str) -> str:
    def seg(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{seg({'alg': 'ES256'})}.{seg(claims)}.{marker}"


ROOT_PROXY = _jwt({"exec_id": "exec_root_from_token"}, "ROOTPROXYSECRET")
CHILD_PROXY = _jwt({"sub": "child"}, "CHILDPROXYSECRET")
SECRETS = (ROOT_SST, CHILD_SST, ROOT_PROXY, CHILD_PROXY)
SECRET_MARKERS = ("ROOTSECRET", "CHILDSECRET", "ROOTPROXYSECRET", "CHILDPROXYSECRET")


class _Wire:
    """A stand-in wl-apdp: answers every route the run uses and records
    each request with the run credential it carried."""

    def __init__(self) -> None:
        self.requests: List[httpx.Request] = []
        self.child_handle = str(uuid.uuid4())
        self.omit_child_token = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/sessions":
            return httpx.Response(
                200,
                json={
                    "session": {"id": "ses_root", "agent_id": AGENT},
                    "session_token": ROOT_SST,
                    "proxy_token": ROOT_PROXY,
                    "proxy_token_expires_at": "2030-01-01T00:00:00Z",
                    "execution_id": "exec_root",
                    "root_run_handle_id": str(uuid.uuid4()),
                },
            )
        if path == "/agents/resolve":
            slug = json.loads(request.content).get("slug")
            agent = {"child-agent": CHILD_AGENT}.get(slug, AGENT)
            return httpx.Response(200, json={"id": agent, "slug": slug, "name": slug})
        if path == "/constraints/manifest":
            return httpx.Response(200, json={"manifest": {"agent_id": AGENT}})
        if path == "/authorize":
            return httpx.Response(200, json={"decision": "Allow", "reason": "ok"})
        if path == "/v1/spawn_subagent":
            body: Dict[str, Any] = {
                "child_run_handle_id": self.child_handle,
                "granted_scope": {
                    "allowed_tools": ["search.web"],
                    "allowed_resources": [],
                    "allowed_intents": [],
                    "max_depth": 0,
                    "time_budget_seconds": 60,
                    "depth": 1,
                },
                "child_execution_id": "exec_child",
                "root_execution_id": "exec_root",
                "child_session_id": f"ses_{self.child_handle}",
                "child_proxy_token": CHILD_PROXY,
            }
            if not self.omit_child_token:
                body["child_session_token"] = CHILD_SST
            return httpx.Response(200, json=body)
        if path == "/v1/events":
            return httpx.Response(202, json={"accepted": 1})
        if path.endswith("/complete"):
            return httpx.Response(200, json={})
        return httpx.Response(200, json={})

    def credential_of(self, request: httpx.Request) -> str:
        run_auth = request.headers.get("x-wl-run-authorization")
        if run_auth:
            return run_auth
        return request.headers.get("authorization", "")


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
        self.log_decisions = True
        self.kill_signal_registry = None


def _values_reachable(obj: Any, *, skip: Any, seen: set, depth: int = 0) -> List[str]:
    """Every string (and bytes, decoded) reachable from ``obj`` through
    attributes, slots, containers and dataclass fields, including the
    plugin, stopping only at the governance backend ``skip`` (the one place
    the credentials are meant to live) and at plain functions."""
    if depth > 12 or id(obj) in seen or obj is skip:
        return []
    seen.add(id(obj))
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, (bytes, bytearray)):
        return [bytes(obj).decode("utf-8", errors="replace")]
    if isinstance(obj, (int, float, bool, type(None))):
        return []
    if isinstance(obj, type) or type(obj).__module__ in ("asyncio", "logging", "_contextvars"):
        return []
    if callable(obj) and not hasattr(obj, "__dict__"):
        return []
    out: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _values_reachable(k, skip=skip, seen=seen, depth=depth + 1)
            out += _values_reachable(v, skip=skip, seen=seen, depth=depth + 1)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            out += _values_reachable(v, skip=skip, seen=seen, depth=depth + 1)
        return out
    if is_dataclass(obj) and not isinstance(obj, type):
        for f in fields(obj):
            out += _values_reachable(
                getattr(obj, f.name, None), skip=skip, seen=seen, depth=depth + 1
            )
    attrs: Dict[str, Any] = {}
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        attrs.update(vars(obj))
    for cls in type(obj).__mro__:
        for slot in getattr(cls, "__slots__", ()):
            if hasattr(obj, slot):
                attrs[slot] = getattr(obj, slot)
    for name, value in attrs.items():
        if callable(value) and not hasattr(value, "__dict__"):
            continue
        out += _values_reachable(value, skip=skip, seen=seen, depth=depth + 1)
    return out


def _assert_no_secret(text: str, where: str) -> None:
    for marker in SECRET_MARKERS:
        assert marker not in text, f"a run credential reached {where}"


@pytest.mark.asyncio
async def test_full_run_keeps_every_credential_out_of_handles_logs_and_errors(caplog):
    caplog.set_level(logging.DEBUG)
    wire = _Wire()
    apdp = _client(wire)
    plugin = _Plugin(apdp)

    info = await apdp.create_session(AGENT)
    assert info is not None
    _assert_no_secret(repr(info), "the SessionInfo")
    assert await apdp.get_manifest(AGENT, run=info.run) == {"agent_id": AGENT}
    root = BaseRunHandle(
        plugin=plugin,
        agent_uuid=AGENT,
        session_id=info.session_id,
        run=info.run,
        egress=apdp.egress_for(info.run),
        execution_id=info.execution_id,
    )
    async with root:
        await root.authorize_action("search", "web")
        child = await root.spawn_subagent(CHILD_AGENT, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        await child.authorize_action("search", "web")
        for handle, name in ((root, "root"), (child, "child")):
            reachable = _values_reachable(handle, skip=apdp, seen=set())
            for value in reachable:
                _assert_no_secret(value, f"a {name} handle attribute")
            _assert_no_secret(repr(handle), f"the {name} handle repr")
            _assert_no_secret(repr(handle.egress), f"the {name} egress repr")
            _assert_no_secret(str(handle.egress), f"the {name} egress str")
            _assert_no_secret(repr(vars(handle)), f"the {name} handle vars")
            with pytest.raises(AttributeError):
                handle.session_token  # noqa: B018 - removed attribute
            with pytest.raises(AttributeError):
                handle.proxy_token  # noqa: B018 - removed attribute
            with pytest.raises(AttributeError):
                handle.session_token = "sst_x"
        # The egress binding resolves the run's own token on demand.
        assert root.egress.proxy_authorization() == ROOT_PROXY
        assert child.egress.proxy_authorization() == CHILD_PROXY
        with pytest.raises(TypeError):
            pickle.dumps(root.egress)
        await child.complete()

    # Adopted from the server response, not from a token on the handle.
    assert root.execution_id == "exec_root"
    assert child.execution_id == "exec_child"

    _assert_no_secret(caplog.text, "the logs")
    for record in caplog.records:
        _assert_no_secret(repr(record.args), "a log record's arguments")

    # The wire is unchanged: each call carried its own run's credential.
    by_path: Dict[str, List[str]] = {}
    for request in wire.requests:
        by_path.setdefault(request.url.path, []).append(wire.credential_of(request))
    assert by_path["/authorize"] == [f"Bearer {ROOT_SST}", f"Bearer {CHILD_SST}"]
    assert by_path["/v1/spawn_subagent"] == [f"Bearer {ROOT_SST}"]
    assert by_path["/constraints/manifest"] == [f"Bearer {ROOT_SST}"]
    events = [
        (json.loads(r.content)[0]["execution_id"], wire.credential_of(r))
        for r in wire.requests
        if r.url.path == "/v1/events"
    ]
    assert events, "lineage must have been published"
    for execution_id, credential in events:
        expected = CHILD_SST if execution_id == "exec_child" else ROOT_SST
        assert credential == f"Bearer {expected}", execution_id
    assert by_path[f"/sessions/{info.session_id}/complete"] == [f"Bearer {ROOT_SST}"]
    assert by_path[f"/sessions/ses_{wire.child_handle}/complete"] == [f"Bearer {CHILD_SST}"]

    # Both runs have ended: their egress tokens are no longer handed out,
    # and the refusal names no value.
    with pytest.raises(GovernanceUnavailable) as info_exc:
        root.egress.proxy_authorization()
    _assert_no_secret(str(info_exc.value), "an exception")


@pytest.mark.asyncio
async def test_spawn_without_a_child_credential_is_refused_without_leaking(caplog):
    caplog.set_level(logging.DEBUG)
    wire = _Wire()
    wire.omit_child_token = True
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    root = BaseRunHandle(
        plugin=_Plugin(apdp), agent_uuid=AGENT, session_id=info.session_id, run=info.run
    )
    root._aentered = True
    with pytest.raises(GovernanceUnavailable) as exc:
        await root.spawn_subagent(CHILD_AGENT, child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
    _assert_no_secret(str(exc.value) + repr(exc.value.__cause__), "an exception")
    _assert_no_secret(caplog.text, "the logs")
    # No child run was registered for the refused spawn.
    assert len(apdp._runs) == 1


@pytest.mark.asyncio
async def test_client_maps_root_and_child_runs_to_their_own_credentials():
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    response = await apdp.spawn_subagent(
        info.run,
        {"parent_agent_id": AGENT, "child_agent_id": CHILD_AGENT, "requested_scope": {}},
    )
    child_run = response["child_run"]
    assert "child_session_token" not in response
    assert "child_proxy_token" not in response
    assert child_run != info.run
    assert apdp._runs[info.run].session_token == ROOT_SST
    assert apdp._runs[child_run].session_token == CHILD_SST
    assert apdp._runs[child_run].parent == info.run
    assert apdp._runs[child_run].session_id == f"ses_{wire.child_handle}"
    assert apdp.run_authorization(info.run) == f"Bearer {ROOT_SST}"
    assert apdp.run_authorization(child_run) == f"Bearer {CHILD_SST}"
    assert apdp.egress_for(child_run).proxy_authorization() == CHILD_PROXY
    # The table's own repr is redacted too.
    _assert_no_secret(repr(apdp._runs), "the run table repr")


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["unknown", "ended"])
async def test_client_refuses_unknown_and_ended_runs_fail_closed(state):
    wire = _Wire()
    apdp = _client(wire)
    info = await apdp.create_session(AGENT)
    if state == "unknown":
        run = RunRef("run_forged")
    else:
        run = info.run
        assert await apdp.complete_session(run) is True
    before = len(wire.requests)

    decision = await apdp.authorize('Agent::"a"', 'Action::"x"', 'Resource::"y"', run=run)
    assert decision["decision"] == "Deny"
    assert await apdp.preflight_step(run, "x", "y") is None
    assert await apdp.submit_plan(run, [{"step_id": "s1", "action": "x"}]) is None
    assert await apdp.get_manifest(AGENT, run=run) is None
    assert await apdp.complete_session(run) is False
    assert apdp.egress_for(run) is None
    with pytest.raises(GovernanceUnavailable):
        await apdp.spawn_subagent(run, {"child_agent_id": CHILD_AGENT})
    with pytest.raises(GovernanceUnavailable):
        apdp.run_authorization(run)
    fired: List[Any] = []
    apdp.subscribe_kill(run, fired.append)
    assert [n.reason for n in fired] == ["unknown_run" if state == "unknown" else "run_ended"]
    # Not one of these reached the wire.
    assert len(wire.requests) == before

    published = await apdp.publish_events(run, [{"event_id": "e1", "event_type": "x"}])
    if state == "unknown":
        assert published is False
        assert len(wire.requests) == before
    else:
        # An ended run's late lineage still goes out, under its own credential.
        assert published is True
        assert wire.credential_of(wire.requests[-1]) == f"Bearer {ROOT_SST}"


@pytest.mark.asyncio
async def test_terminate_ends_the_run_and_tells_kill_subscribers():
    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    fired: List[Any] = []
    unsubscribe_other = apdp.subscribe_kill(info.run, lambda n: fired.append("other"))
    unsubscribe_other()
    apdp.subscribe_kill(info.run, fired.append)
    assert await apdp.terminate_session(info.run, "run_failed: X") is False
    assert [n.reason for n in fired] == ["run_terminated"]
    decision = await apdp.authorize('Agent::"a"', 'Action::"x"', 'Resource::"y"', run=info.run)
    assert decision["decision"] == "Deny"


@pytest.mark.asyncio
async def test_ended_runs_are_bounded(monkeypatch):
    monkeypatch.setattr(apdp_client_module, "MAX_ENDED_RUNS", 2)
    wire = _Wire()
    apdp = _client(wire)
    runs = [(await apdp.create_session(AGENT)).run for _ in range(3)]
    for run in runs:
        await apdp.complete_session(run)
    # The oldest ended run fell out of the table: its late lineage is refused.
    assert runs[0] not in apdp._runs
    assert await apdp.publish_events(runs[0], [{"event_id": "e"}]) is False
    assert await apdp.publish_events(runs[2], [{"event_id": "e"}]) is True


def test_egress_binding_redacts_and_does_not_store_the_token():
    binding = EgressBinding(
        proxy_url="https://wl-proxy:8443", expires_at=None, token_source=lambda: "eyJ.SECRET.x"
    )
    assert "SECRET" not in repr(binding)
    assert "SECRET" not in str(binding)
    assert "SECRET" not in f"{binding}"
    assert binding.proxy_authorization() == "eyJ.SECRET.x"
    assert not hasattr(binding, "__dict__")
    ended = EgressBinding(proxy_url=None, expires_at=None, token_source=lambda: None)
    with pytest.raises(GovernanceUnavailable):
        ended.proxy_authorization()


def test_every_backend_satisfies_the_protocol(tmp_path):
    assert isinstance(ApdpClient("https://apdp.test"), GovernanceBackend)
    assert isinstance(MockApdpClient(), GovernanceBackend)
    pytest.importorskip("watchlight_engine")
    assert isinstance(
        InProcessClient(audit_path=str(tmp_path / "audit.jsonl")), GovernanceBackend
    )


def test_old_protocol_import_path_still_works():
    from watchlight_core.in_process_client import GovernanceBackend as Old

    assert Old is GovernanceBackend


# ── The walker itself ────────────────────────────────────────────────


def test_the_walker_finds_a_credential_planted_anywhere_but_the_backend():
    apdp = ApdpClient("https://apdp.test")
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(plugin=plugin, agent_uuid=AGENT, session_id="ses_x")
    assert not [v for v in _values_reachable(handle, skip=apdp, seen=set()) if "ROOTSECRET" in v]
    plugin.leak = {"nested": [ROOT_SST.encode()]}
    found = _values_reachable(handle, skip=apdp, seen=set())
    assert any("ROOTSECRET" in v for v in found), "the walker must reach the plugin and bytes"


# ── A plugin's own RunHandle subclass, adopt_run and the launcher ─────


def _handles_hold_no_secret(apdp: Any, *handles: Any) -> None:
    for handle in handles:
        for value in _values_reachable(handle, skip=apdp, seen=set()):
            _assert_no_secret(value, f"a {type(handle).__name__} attribute")
        _assert_no_secret(repr(handle), "a plugin handle repr")


def _sst(claims: Dict[str, Any], marker: str) -> str:
    raw = json.dumps(claims).encode()
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return f"sst_{body}.{marker}"


@pytest.mark.asyncio
async def test_plugin_subclass_handles_hold_no_credential(caplog):
    lg = pytest.importorskip("watchlight_langgraph")
    caplog.set_level(logging.DEBUG)
    wire = _Wire()
    apdp = _client(wire)
    plugin = lg.WatchlightLangGraphPlugin(governance=apdp, log_decisions=True)
    async with await plugin.start_run("root-agent") as root:
        assert type(root).__name__ == "RunHandle"
        child = await root.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["search.web"])
        await child.authorize_action("search", "web")
        _handles_hold_no_secret(apdp, root, child)
        for value in _values_reachable(plugin, skip=apdp, seen=set()):
            _assert_no_secret(value, "the plugin")
        await child.complete()
    _assert_no_secret(caplog.text, "the logs")
    creds = {wire.credential_of(r) for r in wire.requests if r.url.path == "/authorize"}
    assert creds == {f"Bearer {CHILD_SST}"}


@pytest.mark.asyncio
async def test_launcher_grant_and_adopt_run_hold_no_credential_outside_the_client(caplog):
    lg = pytest.importorskip("watchlight_langgraph")
    from watchlight_core.credentials import ServiceCredential
    from watchlight_core.launcher import open_bound_run, workload_ref

    caplog.set_level(logging.DEBUG)
    wref = {"kind": "openshell", "source_id": "openshell-local", "workload_id": "sbx-1"}
    run_sst = _sst(
        {"sid": "ses_bound", "aid": AGENT, "eid": "exec_bound", "wref": wref},
        "BOUNDSECRET",
    )

    def launcher_wire(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"session": {"id": "ses_bound"}, "session_token": run_sst},
        )

    launcher = ApdpClient(
        "https://apdp.test",
        credential=ServiceCredential.new("wlsa_LAUNCHERSECRET", "launcher"),
    )
    launcher._probed = True
    launcher._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(launcher_wire)
    )
    grant = await open_bound_run(
        launcher,
        agent_id=AGENT,
        workload=workload_ref(kind="openshell", source_id="openshell-local", workload_id="sbx-1"),
    )
    # The launcher holds nothing: the grant goes to the agent process.
    assert launcher._runs == {}
    assert "BOUNDSECRET" not in repr(grant) and "BOUNDSECRET" not in str(grant)

    seen: List[httpx.Request] = []

    def agent_wire(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/constraints/manifest":
            return httpx.Response(200, json={"manifest": {"agent_id": AGENT}})
        if request.url.path == "/authorize":
            return httpx.Response(200, json={"decision": "Allow"})
        return httpx.Response(202, json={})

    agent_client = ApdpClient("https://apdp.test", credential=grant.credential())
    agent_client._probed = True
    agent_client._client = httpx.AsyncClient(
        base_url="https://apdp.test",
        headers=agent_client._build_auth_headers(),
        transport=httpx.MockTransport(agent_wire),
    )
    plugin = lg.WatchlightLangGraphPlugin(governance=agent_client, log_decisions=True)
    async with await plugin.adopt_run(grant) as handle:
        await handle.authorize_action("document_read", "q1")
        _handles_hold_no_secret(agent_client, handle)
        assert handle.execution_id == "exec_bound"
    del grant
    assert "BOUNDSECRET" not in caplog.text and "LAUNCHERSECRET" not in caplog.text
    assert "/sessions/ses_bound/complete" in [r.url.path for r in seen]


# ── Live runs are bounded: expiry and dropped handles ─────────────────


@pytest.mark.asyncio
async def test_a_live_run_is_dropped_at_its_credential_expiry():
    apdp = ApdpClient("https://apdp.test")
    now = [1_000_000.0]
    apdp._clock = lambda: now[0]
    with_exp = apdp._register_run(
        session_id="s1", agent_id="a", session_token=_sst({"sid": "s1", "aid": "a", "exp": 1_000_100}, "x")
    )
    with_ttl = apdp._register_run(session_id="s2", agent_id="a", session_token="sst_y.z", ttl_seconds=300)
    child = apdp._register_run(session_id="s3", agent_id="c", session_token="sst_c.z", parent=with_ttl)
    fired: List[Any] = []
    apdp.subscribe_kill(with_exp, fired.append)
    now[0] = 1_000_101.0
    assert apdp.run_authorization(with_ttl) == "Bearer sst_y.z"
    assert with_exp not in apdp._runs
    assert [n.reason for n in fired] == ["run_expired"]
    now[0] = 1_000_301.0
    assert await apdp.publish_events(with_ttl, [{"event_id": "e"}]) is False
    assert with_ttl not in apdp._runs and child not in apdp._runs
    assert apdp._runs == {}


@pytest.mark.asyncio
async def test_a_dropped_handle_ends_its_run():
    import gc

    apdp = _client(_Wire())
    info = await apdp.create_session(AGENT)
    handle = BaseRunHandle(plugin=_Plugin(apdp), agent_uuid=AGENT, session_id=info.session_id, run=info.run)
    assert apdp._runs[info.run].ended is False
    del handle
    gc.collect()
    assert apdp._runs[info.run].ended is True
    decision = await apdp.authorize('Agent::"a"', 'Action::"x"', 'Resource::"y"', run=info.run)
    assert decision["decision"] == "Deny"


# ── The child is its own run ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_child_run_equal_to_the_parent_run_is_refused():
    mock = MockApdpClient()
    plugin = _Plugin(mock)
    parent_run = mock.open_run("ses_p", AGENT)
    handle = BaseRunHandle(plugin=plugin, agent_uuid=AGENT, session_id="ses_p", run=parent_run)
    handle._aentered = True
    mock.spawn_response_override = {
        "child_run_handle_id": str(uuid.uuid4()),
        "granted_scope": {"allowed_tools": [], "allowed_resources": [], "allowed_intents": [],
                          "max_depth": 0, "time_budget_seconds": 60, "depth": 1},
        "child_session_token": "sst_child.sig",
        "child_run": parent_run,
    }
    with pytest.raises(GovernanceUnavailable, match="parent's own run"):
        await handle.spawn_subagent(CHILD_AGENT, child_intent={"category": "research", "objective": "Delegated sub-task"})
    # The parent run itself is not ended by the refusal.
    assert mock._runs[parent_run]["ended"] is False


@pytest.mark.asyncio
async def test_a_child_run_issued_for_a_refused_spawn_is_released():
    mock = MockApdpClient()
    plugin = _Plugin(mock)
    parent_run = mock.open_run("ses_p", AGENT)
    handle = BaseRunHandle(plugin=plugin, agent_uuid=AGENT, session_id="ses_p", run=parent_run)
    handle._aentered = True
    # Malformed: the backend registered a child run, but the response does
    # not parse (no granted_scope) and the SDK refuses the spawn.
    mock.spawn_response_override = {
        "child_run_handle_id": str(uuid.uuid4()),
        "child_session_token": "sst_child.sig",
    }
    from watchlight_core import WatchlightError

    with pytest.raises(WatchlightError):
        await handle.spawn_subagent(CHILD_AGENT, child_intent={"category": "research", "objective": "Delegated sub-task"})
    children = [r for r in mock._runs if r != parent_run]
    assert len(children) == 1
    assert mock._runs[children[0]]["ended"] is True
    assert [sid for sid, _ in mock._terminated_sessions] == [mock._runs[children[0]]["session_id"]]
