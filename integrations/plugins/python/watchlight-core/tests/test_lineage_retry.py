"""Lineage and run-end reporting retry a transient answer, in order,
without ever holding up the governance decision.

wl-apdp answers ``503`` + ``Retry-After`` while a replica cannot yet know
a run's state, and ``429`` when a run-end budget is spent; a gateway
answers ``502`` / ``504``. All are transient; dropping a lineage batch on
them loses audit evidence. These tests pin the contract:

* 429 / 502 / 503 / 504 / transport errors are retried within a bounded,
  hard wall-clock budget, honouring ``Retry-After`` (capped); the batch
  is delivered once. A 500 and every other 4xx (a 403 above all) are
  final and never retried.
* Giving up logs one line, value-free (types and counts, no payloads),
  and marks the run degraded: its later publishes get one attempt and are
  then queued, until a delivery succeeds.
* Awaited publishes for a run reach the server in call order, even when
  an earlier batch is being retried.
* The decision path never waits on lineage: a decision-path publish
  returns at once while a retry is in flight, the quarantine kill fires
  before any lineage is attempted, and ``authorize`` (with its
  ``execution_started`` mint) is not delayed.
* ``complete_session`` retries a transient answer; the handle is not
  marked completed until the server accepted it or the budget ran out.
* A cancelled publish is counted and logged once.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional

import httpx
import pytest

from watchlight_core import AgentQuarantinedError, BaseRunHandle, WatchlightError
from watchlight_core._lineage_retry import (
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_WAIT_SECONDS,
    ENV_MAX_ATTEMPTS,
    ENV_MAX_WAIT_SECONDS,
    LineageRetryPolicy,
    MAX_SINGLE_DELAY_SECONDS,
    lineage_decision_path,
    parse_retry_after,
)
from watchlight_core.apdp_client import ApdpClient
from watchlight_core.credentials import PluginCredential
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import register_test_run, bind_test_run

LOGGER = "watchlight.core.apdp_client"
SECRET = "do-not-log-this-payload-value"
PROMPT = 1.0  # seconds: "returns promptly" (a retry in flight would take far longer)


class _FakeClock:
    """Monotonic clock advanced only by the fake sleep. With ``gate`` set,
    every backoff sleep blocks until the gate opens: a retry stays in
    flight for as long as the test wants."""

    def __init__(self, gate: Optional[asyncio.Event] = None) -> None:
        self.now = 0.0
        self.sleeps: List[float] = []
        self.gate = gate

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if self.gate is not None:
            await self.gate.wait()
        self.now += seconds
        await asyncio.sleep(0)


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    policy: Optional[LineageRetryPolicy] = None,
    clock: Optional[_FakeClock] = None,
) -> ApdpClient:
    apdp = ApdpClient(
        "http://localhost",
        credential=PluginCredential.new("wlpa_shared", tenant_id="acme"),
        lineage_retry=policy or LineageRetryPolicy(),
    )
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    clock = clock or _FakeClock()
    apdp._lineage_retry.clock = clock.clock
    apdp._lineage_retry.sleep = clock.sleep
    apdp._lineage_retry.random = lambda: 0.5
    return apdp


def _events(*types: str, prefix: str = "evt") -> List[Dict[str, Any]]:
    return [
        {"event_id": f"{prefix}_{i}", "event_type": t, "payload": {"note": SECRET}}
        for i, t in enumerate(types)
    ]


class _Script:
    """Answers each request with the next scripted status (the last one
    repeats) and records what was sent."""

    def __init__(self, *answers: Any) -> None:
        self.answers = list(answers)
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, tuple):
            status, headers = answer
            return httpx.Response(status, headers=headers, text="unavailable")
        return httpx.Response(answer, json={"accepted": 1})


# ─── publish_events: retry ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_503_then_202_delivers_once() -> None:
    script = _Script(503, 202)
    apdp = _client(script)
    ok = await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("execution_started"))
    assert ok is True
    assert len(script.requests) == 2
    assert apdp.lineage_delivery_counters["delivered_after_retry"] == 1
    assert apdp.lineage_delivery_counters["retries"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 502, 503, 504])
async def test_transient_statuses_are_retried(status: int) -> None:
    script = _Script(status, 202)
    apdp = _client(script)
    assert await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    assert len(script.requests) == 2


@pytest.mark.asyncio
async def test_retry_after_is_honoured_and_capped() -> None:
    clock = _FakeClock()
    script = _Script((503, {"Retry-After": "3"}), (429, {"Retry-After": "120"}), 202)
    apdp = _client(script, clock=clock)
    assert await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    # 3 s hint plus a little jitter; 120 s hint capped to the single-wait cap.
    assert 3.0 <= clock.sleeps[0] < 3.5
    assert clock.sleeps[1] == MAX_SINGLE_DELAY_SECONDS
    assert len(script.requests) == 3


@pytest.mark.asyncio
async def test_transport_error_is_retried() -> None:
    script = _Script(httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), 202)
    apdp = _client(script)
    assert await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    assert len(script.requests) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 500])
async def test_definitive_answer_is_never_retried(status: int) -> None:
    script = _Script(status)
    apdp = _client(script)
    ok = await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    assert ok is False
    assert len(script.requests) == 1
    assert apdp.lineage_delivery_counters["refused"] == 1
    assert apdp.lineage_delivery_counters["retries"] == 0


@pytest.mark.asyncio
async def test_exhaustion_logs_once_without_payloads(caplog) -> None:
    script = _Script(503)
    apdp = _client(script, policy=LineageRetryPolicy(max_attempts=4))
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        ok = await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation", "tool_call_observed"))
    assert ok is False
    assert len(script.requests) == 4
    gave_up = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(gave_up) == 1
    msg = gave_up[0].getMessage()
    assert "reason=lineage_retry_exhausted" in msg
    assert "2 event(s)" in msg and "observation" in msg and "503" in msg
    assert SECRET not in caplog.text
    assert "sst_a" not in caplog.text
    assert apdp.lineage_delivery_counters["exhausted"] == 1


@pytest.mark.asyncio
async def test_total_wait_budget_bounds_the_retries() -> None:
    clock = _FakeClock()
    script = _Script((503, {"Retry-After": "4"}))
    apdp = _client(
        script,
        policy=LineageRetryPolicy(max_attempts=20, max_wait_seconds=10),
        clock=clock,
    )
    assert not await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    assert sum(clock.sleeps) <= 10.0 + 1e-9
    assert len(script.requests) < 20


@pytest.mark.asyncio
async def test_each_attempt_timeout_is_cut_to_the_budget() -> None:
    timeouts: List[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"]["read"])
        return httpx.Response(202, json={})

    apdp = _client(handler, policy=LineageRetryPolicy(max_wait_seconds=2))
    assert await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    assert apdp._timeout == 30.0
    assert timeouts == [2.0]


@pytest.mark.asyncio
async def test_order_preserved_across_a_retried_batch() -> None:
    """A later awaited publish for the same run waits for the earlier
    batch's retry; it never overtakes it."""
    sent: List[str] = []
    first_attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        if "evt_first" in body:
            first_attempts["n"] += 1
            if first_attempts["n"] < 3:
                return httpx.Response(503, headers={"Retry-After": "1"})
        sent.append("first" if "evt_first" in body else "second")
        return httpx.Response(202, json={"accepted": 1})

    apdp = _client(handler)
    first = [{"event_id": "evt_first", "event_type": "observation"}]
    second = [{"event_id": "evt_second", "event_type": "execution_completed"}]
    results = await asyncio.gather(
        apdp.publish_events(register_test_run(apdp, "sst_run"), first),
        apdp.publish_events(register_test_run(apdp, "sst_run"), second),
    )
    assert results == [True, True]
    assert sent == ["first", "second"]


@pytest.mark.asyncio
async def test_other_runs_are_not_serialised_behind_a_retry() -> None:
    sent: List[str] = []
    gate = asyncio.Event()
    calls = {"a": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        token = request.headers["authorization"]
        if token.endswith("sst_a"):
            calls["a"] += 1
            if calls["a"] == 1:
                return httpx.Response(503)
        sent.append(token[-5:])
        if token.endswith("sst_b"):
            gate.set()
        return httpx.Response(202, json={})

    apdp = _client(handler, clock=_FakeClock(gate))
    await asyncio.gather(
        apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation")),
        apdp.publish_events(register_test_run(apdp, "sst_b"), _events("observation")),
    )
    assert sent == ["sst_b", "sst_a"]


# ─── decision path never waits ──────────────────────────────────────


def _retry_in_flight_handler(
    sent: List[str],
) -> Callable[[httpx.Request], httpx.Response]:
    """The run's ``evt_slow`` batch gets one 503 (its retry then waits on
    the clock gate); everything else is accepted and recorded by kind."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/authorize":
            sent.append("authorize")
            return httpx.Response(200, json={"decision": "Allow", "details": {}})
        if request.url.path != "/v1/events":
            sent.append(request.url.path)
            return httpx.Response(200, json={})
        body = request.read().decode()
        if "evt_slow" in body:
            if "slow-503" not in sent:
                sent.append("slow-503")
                return httpx.Response(503, headers={"Retry-After": "5"})
            sent.append("slow")
        elif "execution_started" in body:
            sent.append("started")
        elif "evt_decision" in body:
            sent.append("decision")
        else:
            sent.append("event")
        return httpx.Response(202, json={})

    return handler


@pytest.mark.asyncio
async def test_decision_path_publish_returns_promptly_behind_a_retry() -> None:
    sent: List[str] = []
    gate = asyncio.Event()
    apdp = _client(_retry_in_flight_handler(sent), clock=_FakeClock(gate))
    slow = asyncio.create_task(
        apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_slow", "event_type": "observation"}])
    )
    await asyncio.sleep(0.05)
    assert sent == ["slow-503"]  # the slow batch is now retrying
    with lineage_decision_path():
        ok = await asyncio.wait_for(
            apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_decision", "event_type": "decision"}]),
            PROMPT,
        )
    assert ok is True  # queued for background delivery, not sent inline
    assert sent == ["slow-503"]
    assert apdp.lineage_delivery_counters["queued"] == 1
    gate.set()
    assert await slow is True
    await apdp.drain(register_test_run(apdp, "sst_run"))
    assert sent == ["slow-503", "slow", "decision"]


@pytest.mark.asyncio
async def test_decision_path_transient_answer_is_queued_not_retried_inline() -> None:
    script = _Script(503, 202)
    apdp = _client(script)
    with lineage_decision_path():
        ok = await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("execution_started"))
    assert ok is True
    assert len(script.requests) == 1  # one attempt inline
    await apdp.drain(register_test_run(apdp, "sst_a"))
    assert len(script.requests) == 2  # delivered in the background


@pytest.mark.asyncio
async def test_decision_path_definitive_refusal_is_not_queued() -> None:
    script = _Script(403)
    apdp = _client(script)
    with lineage_decision_path():
        ok = await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("execution_started"))
    assert ok is False
    await apdp.drain(register_test_run(apdp, "sst_a"))
    assert len(script.requests) == 1


# ─── degraded run ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_degraded_run_gets_one_attempt_then_queues_until_success() -> None:
    state = {"up": False}
    requests: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.read().decode())
        if not state["up"]:
            return httpx.Response(503)
        return httpx.Response(202, json={})

    apdp = _client(handler, policy=LineageRetryPolicy(max_attempts=3))
    # First batch spends the budget and degrades the run.
    assert not await apdp.publish_events(register_test_run(apdp, "sst_r"), _events("observation", prefix="a"))
    assert len(requests) == 3
    # Later awaited publish: one attempt, then queued (returns True).
    before = len(requests)
    ok = await apdp.publish_events(register_test_run(apdp, "sst_r"), _events("observation", prefix="b"))
    assert ok is True
    assert len(requests) == before + 1
    # The server recovers; the queued batch is delivered and the run heals.
    state["up"] = True
    await apdp.drain(register_test_run(apdp, "sst_r"))
    assert "b_0" in requests[-1]
    lane = apdp._lanes.get(apdp._lane_key("sst_r"))
    assert lane is None or lane.degraded is False
    before = len(requests)
    assert await apdp.publish_events(register_test_run(apdp, "sst_r"), _events("observation", prefix="c"))
    assert len(requests) == before + 1


# ─── run handle: the decision is never delayed ──────────────────────


class _Plugin(GovernanceTelemetry):
    def __init__(self, apdp: ApdpClient, registry: Any = None) -> None:
        super().__init__()
        self.apdp = apdp
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = registry


class _Handle(BaseRunHandle):
    _observation_source = "testfw.workload"


class _KillRegistry:
    def __init__(self, sent: List[str]) -> None:
        self.sent = sent

    async def cancel(self, reason: str) -> list:
        self.sent.append(f"kill:{reason}")
        return []


def _handle(apdp: ApdpClient, registry: Any = None) -> _Handle:
    return bind_test_run(_Handle(plugin=_Plugin(apdp, registry), agent_uuid="agent-uuid-001", session_id="ses_retry_1", execution_id="exec_retry_1"), "sst_run")


_QUARANTINE_RESPONSE = {
    "decision": "Quarantine",
    "reason": "test",
    "details": {
        "quarantine": {
            "reason": "test",
            "anomaly_score": 0.9,
            "contributing_features": [],
            "model_version": None,
            "policy_id": "p.q",
        }
    },
}


@pytest.mark.asyncio
async def test_quarantine_kill_fires_promptly_behind_a_retry() -> None:
    sent: List[str] = []
    gate = asyncio.Event()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/authorize":
            return httpx.Response(
                200,
                json={
                    "decision": "Quarantine",
                    "reason": "test",
                    "details": {
                        "quarantine": {
                            "reason": "test",
                            "anomaly_score": 0.9,
                            "contributing_features": [],
                            "model_version": None,
                            "policy_id": "p.q",
                        }
                    },
                },
            )
        body = request.read().decode()
        if "evt_slow" in body and not gate.is_set():
            sent.append("slow-503")
            return httpx.Response(503, headers={"Retry-After": "5"})
        sent.append("quarantined" if "execution_quarantined" in body else "event")
        return httpx.Response(202, json={})

    apdp = _client(handler, clock=_FakeClock(gate))
    h = _handle(apdp, _KillRegistry(sent))
    h._aentered = True
    h.mark_execution_started_emitted(h.execution_id)
    slow = asyncio.create_task(
        apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_slow", "event_type": "observation"}])
    )
    await asyncio.sleep(0.05)
    with pytest.raises(AgentQuarantinedError):
        await asyncio.wait_for(h.authorize_action_detailed("read", "doc-1"), PROMPT)
    await asyncio.sleep(0)  # the kill's cancel() task runs
    assert "kill:quarantine" in sent
    assert "quarantined" not in sent  # queued behind the retry, not awaited
    gate.set()
    await slow
    await apdp.drain(register_test_run(apdp, "sst_run"))
    assert sent.index("kill:quarantine") < sent.index("quarantined")


@pytest.mark.asyncio
async def test_authorize_not_delayed_by_a_retrying_started_mint() -> None:
    """An awaited mint (as from publish_observation) is retrying; the
    authorize-path mint makes its own single direct attempt (same event)
    instead of waiting behind it."""
    sent: List[str] = []
    gate = asyncio.Event()
    event_ids: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/authorize":
            sent.append("authorize")
            return httpx.Response(200, json={"decision": "Allow", "details": {}})
        event_ids.append(json.loads(request.read())[0]["event_id"])
        if "events-503" not in sent:
            sent.append("events-503")
            return httpx.Response(503, headers={"Retry-After": "5"})
        sent.append("events")
        return httpx.Response(202, json={})

    apdp = _client(handler, clock=_FakeClock(gate))
    h = _handle(apdp)
    h._aentered = True
    mint = asyncio.create_task(h._ensure_execution_started_emitted(h.execution_id))
    await asyncio.sleep(0.05)
    assert sent == ["events-503"]
    result = await asyncio.wait_for(h.authorize_action_detailed("read", "doc-1"), PROMPT)
    assert result.is_allow()
    assert sent == ["events-503", "events", "authorize"]
    assert len(set(event_ids)) == 1  # the same execution_started event
    gate.set()
    await mint


@pytest.mark.asyncio
async def test_authorize_path_mint_bypasses_a_busy_lane() -> None:
    """The run's lane is busy with another batch's retry; the mint in
    front of authorize goes out directly, never behind the retry."""
    sent: List[str] = []
    gate = asyncio.Event()
    apdp = _client(_retry_in_flight_handler(sent), clock=_FakeClock(gate))
    h = _handle(apdp)
    h._aentered = True
    slow = asyncio.create_task(
        apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_slow", "event_type": "observation"}])
    )
    await asyncio.sleep(0.05)
    result = await asyncio.wait_for(h.authorize_action_detailed("read", "doc-1"), PROMPT)
    assert result.is_allow()
    assert sent == ["slow-503", "started", "authorize"]
    assert h.execution_id in h._emitted_execution_started_for
    gate.set()
    await slow


@pytest.mark.asyncio
async def test_transient_mint_failure_fails_authorize_closed() -> None:
    """A 503 on the mint: authorize does not proceed, the id stays
    unmarked, and the event is queued for background delivery. A later
    authorize re-sends the same event (deduplicated by event_id)."""
    state = {"up": False}
    paths: List[str] = []
    event_ids: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/authorize":
            return httpx.Response(200, json={"decision": "Allow", "details": {}})
        event_ids.append(json.loads(request.read())[0]["event_id"])
        if not state["up"]:
            return httpx.Response(503, headers={"Retry-After": "1"})
        return httpx.Response(202, json={})

    apdp = _client(handler, policy=LineageRetryPolicy(max_attempts=2))
    h = _handle(apdp)
    h._aentered = True
    with pytest.raises(WatchlightError):
        await asyncio.wait_for(h.authorize_action_detailed("read", "doc-1"), PROMPT)
    assert paths[0] == "/v1/events"  # one direct attempt; the rest is background
    assert "/authorize" not in paths
    assert h.execution_id not in h._emitted_execution_started_for
    assert apdp.lineage_delivery_counters["queued"] == 1
    # The queued copy is delivered in the background; the id stays
    # unmarked (only an accepted direct attempt marks it).
    state["up"] = True
    await apdp.drain(register_test_run(apdp, "sst_run"))
    assert h.execution_id not in h._emitted_execution_started_for
    result = await h.authorize_action_detailed("read", "doc-1")
    assert result.is_allow()
    assert h.execution_id in h._emitted_execution_started_for
    assert len(set(event_ids)) == 1


@pytest.mark.asyncio
async def test_concurrent_authorize_sees_the_first_mint_failure() -> None:
    """Two authorize calls race: the second awaits the first caller's
    single attempt and fails with it; one request in total."""
    release = asyncio.Event()
    paths: List[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/authorize":
            return httpx.Response(200, json={"decision": "Allow", "details": {}})
        await release.wait()
        return httpx.Response(503)

    apdp = _client(handler)  # type: ignore[arg-type]
    h = _handle(apdp)
    h._aentered = True
    first = asyncio.create_task(h.authorize_action_detailed("read", "doc-1"))
    await asyncio.sleep(0.02)
    second = asyncio.create_task(h.authorize_action_detailed("read", "doc-2"))
    await asyncio.sleep(0.02)
    assert paths == ["/v1/events"]  # the second caller did not send its own
    release.set()
    results = await asyncio.gather(first, second, return_exceptions=True)
    assert all(isinstance(r, WatchlightError) for r in results)
    assert "/authorize" not in paths
    assert h.execution_id not in h._emitted_execution_started_for
    await apdp.drain(register_test_run(apdp, "sst_run"), timeout_s=0.1)


@pytest.mark.asyncio
async def test_authorize_path_mint_refused_fails_closed() -> None:
    paths: List[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/v1/events":
            return httpx.Response(403)
        return httpx.Response(200, json={"decision": "Allow"})

    apdp = _client(handler)
    h = _handle(apdp)
    h._aentered = True
    with pytest.raises(WatchlightError):
        await h.authorize_action_detailed("read", "doc-1")
    assert paths == ["/v1/events"]
    assert h.execution_id not in h._emitted_execution_started_for
    assert apdp.lineage_delivery_counters["queued"] == 0


@pytest.mark.asyncio
async def test_kill_fires_before_the_quarantine_event_is_attempted() -> None:
    order: List[str] = []

    class _OrderHandle(_Handle):
        def _fire_kill_signal(self, *args: Any, **kwargs: Any) -> None:
            order.append("kill")
            super()._fire_kill_signal(*args, **kwargs)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/authorize":
            return httpx.Response(200, json=_QUARANTINE_RESPONSE)
        if b"execution_quarantined" in request.read():
            order.append("quarantined-attempt")
        return httpx.Response(202, json={})

    apdp = _client(handler)
    h = bind_test_run(_OrderHandle(plugin=_Plugin(apdp), agent_uuid="agent-uuid-001", session_id="ses_retry_1", execution_id="exec_retry_1"), "sst_run")
    h._aentered = True
    h.mark_execution_started_emitted(h.execution_id)
    with pytest.raises(AgentQuarantinedError):
        await h.authorize_action_detailed("read", "doc-1")
    assert order == ["kill", "quarantined-attempt"]


@pytest.mark.asyncio
async def test_handle_not_completed_until_close_accepted() -> None:
    seen_completed_during_retry: List[bool] = []
    holder: Dict[str, _Handle] = {}
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/complete"):
            attempts["n"] += 1
            seen_completed_during_retry.append(holder["h"]._completed)
            if attempts["n"] < 3:
                return httpx.Response(503, headers={"Retry-After": "1"})
            return httpx.Response(200, json={})
        return httpx.Response(202, json={})

    apdp = _client(handler)
    holder["h"] = h = _handle(apdp)
    await h.complete()
    assert attempts["n"] == 3
    assert seen_completed_during_retry == [False, False, False]
    assert h._completed is True


@pytest.mark.asyncio
async def test_queued_decision_event_lands_before_execution_completed() -> None:
    order: List[str] = []
    events_calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/events":
            events_calls["n"] += 1
            body = request.read().decode()
            kind = "failed" if "execution_failed" in body else "completed"
            if events_calls["n"] == 1:
                order.append(f"{kind}:503")
                return httpx.Response(503, headers={"Retry-After": "1"})
            order.append(kind)
            return httpx.Response(202, json={})
        order.append("close")
        return httpx.Response(200, json={})

    apdp = _client(handler)
    h = _handle(apdp)
    event = h._build_execution_failed_event("policy_terminate: test")
    await h._emit_lifecycle_event(event, decision_path=True)
    assert order == ["failed:503"]  # one attempt inline, then queued
    await h.complete()
    assert order[0] == "failed:503"
    assert "close" in order
    assert order.index("failed") < order.index("completed")


# ─── complete_session ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_complete_session_retried_then_succeeds() -> None:
    script = _Script((503, {"Retry-After": "1"}), (429, {}), (502, {}), 200)
    apdp = _client(script)
    assert await apdp.complete_session(register_test_run(apdp, "sst_a", "ses_1")) is True
    assert len(script.requests) == 4
    assert all(r.url.path == "/sessions/ses_1/complete" for r in script.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 500])
async def test_complete_session_definitive_answer_is_final(status: int) -> None:
    script = _Script(status, 200)
    apdp = _client(script)
    assert await apdp.complete_session(register_test_run(apdp, "sst_a", "ses_1")) is False
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_complete_session_exhaustion_logs_once(caplog) -> None:
    script = _Script(503)
    apdp = _client(script, policy=LineageRetryPolicy(max_attempts=3))
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        assert await apdp.complete_session(register_test_run(apdp, "sst_a", "ses_1")) is False
    assert len(script.requests) == 3
    lines = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(lines) == 1
    assert "reason=session_complete_retry_exhausted" in lines[0].getMessage()
    assert "sst_a" not in caplog.text


@pytest.mark.asyncio
async def test_complete_session_not_held_behind_a_retrying_lane() -> None:
    sent: List[str] = []
    gate = asyncio.Event()
    apdp = _client(_retry_in_flight_handler(sent), clock=_FakeClock(gate))
    slow = asyncio.create_task(
        apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_slow", "event_type": "observation"}])
    )
    await asyncio.sleep(0.05)
    assert await asyncio.wait_for(
        apdp.complete_session(register_test_run(apdp, "sst_run", "ses_1")), PROMPT
    )
    gate.set()
    await slow


# ─── bounds: queue cap, lane eviction, drain timeout ────────────────


@pytest.mark.asyncio
async def test_run_queue_is_capped_and_logged_once(caplog) -> None:
    sent: List[str] = []
    gate = asyncio.Event()
    apdp = _client(_retry_in_flight_handler(sent), clock=_FakeClock(gate))
    slow = asyncio.create_task(
        apdp.publish_events(register_test_run(apdp, "sst_run"), [{"event_id": "evt_slow", "event_type": "observation"}])
    )
    await asyncio.sleep(0.05)
    many = [{"event_id": f"q_{i}", "event_type": "observation"} for i in range(1000)]
    with caplog.at_level(logging.DEBUG, logger=LOGGER), lineage_decision_path():
        assert await apdp.publish_events(register_test_run(apdp, "sst_run"), many) is True
        assert await apdp.publish_events(register_test_run(apdp, "sst_run"), _events("observation")) is False
        assert await apdp.publish_events(register_test_run(apdp, "sst_run"), _events("observation")) is False
    assert apdp.lineage_delivery_counters["dropped_queue_full"] == 2
    full = [r for r in caplog.records if "reason=lineage_queue_full" in r.getMessage()]
    assert len(full) == 1 and full[0].levelno == logging.ERROR
    assert SECRET not in caplog.text
    gate.set()
    await slow
    await apdp.drain(register_test_run(apdp, "sst_run"))


@pytest.mark.asyncio
async def test_idle_degraded_lanes_are_trimmed_oldest_first() -> None:
    apdp = _client(_Script(503), policy=LineageRetryPolicy(max_attempts=1))
    apdp._max_idle_lanes = 2
    for token in ("sst_1", "sst_2", "sst_3"):
        assert not await apdp.publish_events(register_test_run(apdp, token), _events("observation"))
    keys = list(apdp._lanes)
    assert keys == [apdp._lane_key("sst_2"), apdp._lane_key("sst_3")]
    assert all(apdp._lanes[k].degraded for k in keys)


@pytest.mark.asyncio
async def test_drain_run_is_bounded_by_its_timeout() -> None:
    gate = asyncio.Event()  # the queued batch's backoff never ends
    apdp = _client(_Script((503, {"Retry-After": "5"})), clock=_FakeClock(gate))
    with lineage_decision_path():
        assert await apdp.publish_events(register_test_run(apdp, "sst_a"), _events("observation"))
    loop = asyncio.get_running_loop()
    start = loop.time()
    await asyncio.wait_for(apdp.drain(register_test_run(apdp, "sst_a"), timeout_s=0.05), PROMPT)
    assert loop.time() - start < PROMPT
    lane = apdp._lanes[apdp._lane_key("sst_a")]
    assert lane.worker_active()  # still running; the drain stopped waiting
    lane.worker.cancel()  # type: ignore[union-attr]
    await asyncio.sleep(0)


# ─── cancellation ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cancelled_publish_is_counted_and_logged_once(caplog) -> None:
    gate = asyncio.Event()  # never opened: the retry hangs until cancelled
    apdp = _client(_Script(503), clock=_FakeClock(gate))
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        for token in ("sst_a", "sst_b"):
            task = asyncio.create_task(
                apdp.publish_events(register_test_run(apdp, token), _events("observation"))
            )
            await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    assert apdp.lineage_delivery_counters["cancelled"] == 2
    lines = [r for r in caplog.records if "reason=lineage_publish_cancelled" in r.getMessage()]
    assert [r.levelno for r in lines] == [logging.WARNING, logging.DEBUG]
    assert SECRET not in caplog.text


# ─── policy / parsing ───────────────────────────────────────────────


def test_policy_bounds_are_clamped() -> None:
    p = LineageRetryPolicy(max_attempts=10_000, max_wait_seconds=1e9)
    assert p.max_attempts == 20 and p.max_wait_seconds == 300.0
    p = LineageRetryPolicy(max_attempts=0, max_wait_seconds=-5)
    assert p.max_attempts == 1 and p.max_wait_seconds == 0.0


def test_policy_from_env(monkeypatch) -> None:
    monkeypatch.setenv(ENV_MAX_ATTEMPTS, "3")
    monkeypatch.setenv(ENV_MAX_WAIT_SECONDS, "7.5")
    p = LineageRetryPolicy.from_env()
    assert p.max_attempts == 3 and p.max_wait_seconds == 7.5
    monkeypatch.setenv(ENV_MAX_ATTEMPTS, "lots")
    monkeypatch.setenv(ENV_MAX_WAIT_SECONDS, "nan")
    p = LineageRetryPolicy.from_env()
    assert p.max_attempts == DEFAULT_MAX_ATTEMPTS
    assert p.max_wait_seconds == DEFAULT_MAX_WAIT_SECONDS


def test_parse_retry_after() -> None:
    assert parse_retry_after("2") == 2.0
    assert parse_retry_after(" 0 ") == 0.0
    assert parse_retry_after("-1") is None
    assert parse_retry_after("soon") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
