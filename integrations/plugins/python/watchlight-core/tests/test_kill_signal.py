"""Pytest coverage for the Python interceptor kill registry.

Mirrors the TS lane tests in
``watchlight-agent-sdk-ts/tests/kill-signal.test.ts`` so the
two SDK lanes stay in lockstep.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

import pytest

from watchlight_core.kill_signal import (
    DISPOSITION_GRACEFUL,
    DISPOSITION_PROXY_HARD_KILL,
    DISPOSITION_UNCONFIRMED,
    ESCALATION_ATTEMPTED,
    ESCALATION_CONFIRMED,
    ESCALATION_FAILED,
    ESCALATION_SKIPPED,
    ESCALATION_UNKNOWN,
    InterceptorKillRegistry,
    KILL_SIGNAL_GRACEFUL_WINDOW_MS,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
    LlmCallInterruptedPayload,
    LlmCallInterruptedValidationError,
    RegisterRequestOptions,
    classify_kill_endpoint_status,
    default_kill_signal_registry,
)


def _payload(**overrides: Any) -> LlmCallInterruptedPayload:
    base = dict(
        method="POST",
        host="api.anthropic.com",
        path="/v1/messages",
        bytes_sent=128,
        bytes_received=64,
        duration_ms=1000,
        reason="quarantine",
        disposition="graceful",
    )
    base.update(overrides)
    return LlmCallInterruptedPayload(**base)  # type: ignore[arg-type]


# ─── Payload validation ────────────────────────────────────────────────


class TestLlmCallInterruptedPayloadValidation:
    def test_valid_payload_validates(self) -> None:
        _payload().validate()

    def test_empty_method_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="method"):
            _payload(method="").validate()

    def test_method_too_long_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="method"):
            _payload(method="X" * 17).validate()

    def test_empty_host_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="host"):
            _payload(host="").validate()

    def test_host_with_path_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="bare hostname"):
            _payload(host="api.example.com/v1").validate()

    def test_host_with_scheme_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="bare hostname"):
            _payload(host="https://api.example.com").validate()

    def test_path_must_start_with_slash(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="path must start"):
            _payload(path="v1/messages").validate()

    def test_path_with_query_rejected(self) -> None:
        # Defense: never let OAuth-style `?access_token=…`
        # leak into the lineage event.
        with pytest.raises(LlmCallInterruptedValidationError, match="query string"):
            _payload(path="/v1/messages?token=SECRET").validate()

    def test_bytes_over_cap_rejected(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="bytes_sent"):
            _payload(bytes_sent=(1 << 30) + 1).validate()
        with pytest.raises(LlmCallInterruptedValidationError, match="bytes_received"):
            _payload(bytes_received=(1 << 30) + 1).validate()

    def test_disposition_must_be_closed_set(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="disposition"):
            _payload(disposition="something_else").validate()

    def test_disposition_accepts_all_canonical_values(self) -> None:
        _payload(disposition="graceful", escalation=ESCALATION_SKIPPED).validate()
        _payload(
            disposition="proxy_hard_kill", escalation=ESCALATION_CONFIRMED
        ).validate()
        for esc in (
            ESCALATION_SKIPPED,
            ESCALATION_ATTEMPTED,
            ESCALATION_FAILED,
            ESCALATION_UNKNOWN,
        ):
            _payload(disposition="unconfirmed", escalation=esc).validate()

    def test_escalation_must_be_closed_set(self) -> None:
        with pytest.raises(LlmCallInterruptedValidationError, match="escalation"):
            _payload(
                disposition="unconfirmed", escalation="probably_worked"
            ).validate()

    def test_proxy_hard_kill_requires_a_confirmed_escalation(self) -> None:
        """The audit-integrity invariant, enforced at the payload boundary.

        A payload may not assert ``proxy_hard_kill`` unless the kill
        endpoint confirmed the kill. This is the defect that put kills
        that never happened into the evidence trail.
        """
        for esc in (
            ESCALATION_SKIPPED,
            ESCALATION_ATTEMPTED,
            ESCALATION_FAILED,
            ESCALATION_UNKNOWN,
        ):
            with pytest.raises(
                LlmCallInterruptedValidationError, match="requires escalation"
            ):
                _payload(disposition="proxy_hard_kill", escalation=esc).validate()

    def test_confirmed_escalation_requires_proxy_hard_kill(self) -> None:
        with pytest.raises(
            LlmCallInterruptedValidationError, match="requires disposition"
        ):
            _payload(
                disposition="unconfirmed", escalation=ESCALATION_CONFIRMED
            ).validate()

    def test_graceful_requires_skipped_escalation(self) -> None:
        with pytest.raises(
            LlmCallInterruptedValidationError, match="requires escalation 'skipped'"
        ):
            _payload(disposition="graceful", escalation=ESCALATION_FAILED).validate()

    def test_wire_dict_shape_is_stable(self) -> None:
        d = _payload().to_dict()
        # SIEM rules pivot on these names — bumping them breaks ops.
        assert set(d) == {
            "method",
            "host",
            "path",
            "bytes_sent",
            "bytes_received",
            "duration_ms",
            "reason",
            "disposition",
            "escalation",
        }
        assert d["escalation"] == ESCALATION_SKIPPED


class TestKillEndpointStatusClassification:
    """`{"status": ...}` from wl-proxy → escalation token."""

    def test_killed_and_already_dead_are_confirmed(self) -> None:
        assert classify_kill_endpoint_status("killed") == ESCALATION_CONFIRMED
        assert classify_kill_endpoint_status("already_dead") == ESCALATION_CONFIRMED

    def test_unknown_status_is_not_a_kill(self) -> None:
        # The historically UNIVERSAL outcome: nothing was ever
        # registered, so the endpoint answers `unknown` with a 200.
        assert classify_kill_endpoint_status("unknown") == ESCALATION_UNKNOWN

    def test_unrecognised_or_missing_status_is_attempted(self) -> None:
        assert classify_kill_endpoint_status(None) == ESCALATION_ATTEMPTED
        assert classify_kill_endpoint_status("weird") == ESCALATION_ATTEMPTED


# ─── Registry — kill paths ─────────────────────────────────────────────


def _make_registry(
    *,
    proxy_url: Optional[str] = None,
    graceful_window_ms: int = KILL_SIGNAL_GRACEFUL_WINDOW_MS,
    escalator_calls: Optional[list[tuple[str, str]]] = None,
    escalator_raises: Optional[Exception] = None,
    escalator_outcome: Optional[str] = ESCALATION_CONFIRMED,
) -> tuple[InterceptorKillRegistry, list[LlmCallInterruptedPayload]]:
    events: list[LlmCallInterruptedPayload] = []

    async def escalator(session_id: str, reason: str) -> Optional[str]:
        if escalator_calls is not None:
            escalator_calls.append((session_id, reason))
        if escalator_raises is not None:
            raise escalator_raises
        return escalator_outcome

    reg = InterceptorKillRegistry(
        graceful_window_ms=graceful_window_ms,
        emit_event=events.append,
        hard_kill_escalator=escalator if proxy_url else None,
    )
    return reg, events


@pytest.mark.asyncio
async def test_cancel_aborts_pending_request_within_graceful_window() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy")

    request_id, cancel_requested = reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-1",
        )
    )

    # Simulate the interceptor: race the upstream future against the
    # cancel_requested event. When cancel fires, "abort" the
    # upstream and call complete().
    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        # Interceptor ack'd the cancel by calling complete() within
        # the graceful window.
        reg.complete(request_id)

    reg.record_bytes(request_id, 1024, 0)

    upstream_task = asyncio.create_task(stub_upstream())
    started = time.monotonic()
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    assert len(results) == 1
    assert results[0].disposition == DISPOSITION_GRACEFUL
    assert elapsed_ms < KILL_SIGNAL_GRACEFUL_WINDOW_MS
    assert len(events) == 1
    assert events[0].disposition == "graceful"
    assert events[0].reason == "quarantine"
    assert events[0].host == "api.anthropic.com"
    assert events[0].path == "/v1/messages"
    upstream_task.result()  # already done


@pytest.mark.asyncio
async def test_hard_kill_escalation_when_upstream_ignores_abort() -> None:
    escalator_calls: list[tuple[str, str]] = []
    reg, events = _make_registry(
        proxy_url="http://wl-proxy",
        graceful_window_ms=100,
        escalator_calls=escalator_calls,
    )

    reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-stuck",
        )
    )
    # No stub upstream — interceptor never acks complete(). Registry
    # must escalate after the graceful window.

    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert len(results) == 1
    # The endpoint CONFIRMED the kill — this is the one and only case
    # that licenses the `proxy_hard_kill` assertion.
    assert results[0].disposition == DISPOSITION_PROXY_HARD_KILL
    assert results[0].escalation == ESCALATION_CONFIRMED
    assert results[0].killed is True
    assert len(events) == 1
    assert events[0].disposition == "proxy_hard_kill"
    assert events[0].escalation == "confirmed"
    assert escalator_calls == [("sess-stuck", "quarantine")]


@pytest.mark.asyncio
async def test_unknown_kill_response_does_not_claim_a_hard_kill() -> None:
    """The historically universal case: nothing was ever registered.

    wl-proxy answers 200 `{"status":"unknown"}`, meaning it contained
    nothing. The lineage record must NOT assert a proxy hard kill.
    """
    escalator_calls: list[tuple[str, str]] = []
    reg, events = _make_registry(
        proxy_url="http://wl-proxy",
        graceful_window_ms=60,
        escalator_calls=escalator_calls,
        escalator_outcome=ESCALATION_UNKNOWN,
    )
    reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-never-registered",
        )
    )
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_UNKNOWN
    assert results[0].killed is False
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL
    assert events[0].disposition == DISPOSITION_UNCONFIRMED
    assert events[0].escalation == ESCALATION_UNKNOWN
    assert escalator_calls == [("sess-never-registered", "quarantine")]


@pytest.mark.asyncio
async def test_legacy_escalator_returning_none_is_attempted_not_confirmed() -> None:
    """An escalator on the old `-> None` signature proves nothing."""
    reg, events = _make_registry(
        proxy_url="http://wl-proxy",
        graceful_window_ms=60,
        escalator_outcome=None,
    )
    reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-legacy",
        )
    )
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_ATTEMPTED
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL


@pytest.mark.asyncio
async def test_escalator_returning_garbage_is_not_trusted() -> None:
    reg, events = _make_registry(
        proxy_url="http://wl-proxy",
        graceful_window_ms=60,
        escalator_outcome="totally_killed_trust_me",
    )
    reg.register(
        RegisterRequestOptions(
            method="POST", host="api.anthropic.com", path="/v1/messages",
            session_id="sess-liar",
        )
    )
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_ATTEMPTED
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL


@pytest.mark.asyncio
async def test_multiple_in_flight_requests_all_cancelled_atomically() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy")
    handles = []
    for i in range(5):
        rid, cancel_requested = reg.register(
            RegisterRequestOptions(
                method="POST",
                host="api.openai.com",
                path=f"/v1/chat/{i}",
                session_id=f"sess-{i}",
            )
        )
        handles.append((rid, cancel_requested))

    # In-process stand-in for unit tests only.
    async def stub_upstream(rid: int, evt: asyncio.Event) -> None:
        await evt.wait()
        reg.complete(rid)

    # Spawn stub upstreams so each request acks promptly.
    upstream_tasks = [
        asyncio.create_task(stub_upstream(rid, evt)) for rid, evt in handles
    ]

    assert reg.size() == 5
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    for t in upstream_tasks:
        await t
    assert len(results) == 5
    assert all(r.disposition == DISPOSITION_GRACEFUL for r in results)
    assert len(events) == 5
    assert reg.size() == 0


@pytest.mark.asyncio
async def test_cancel_called_twice_is_idempotent() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy")
    rid, cancel_requested = reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-twice",
        )
    )

    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        reg.complete(rid)

    upstream_task = asyncio.create_task(stub_upstream())
    r1, r2 = await asyncio.gather(
        reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE),
        reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE),
    )
    await upstream_task

    # Across both calls, exactly one cancellation observed.
    assert (len(r1) + len(r2)) == 1
    assert len(events) == 1

    # Empty registry — third cancel is a no-op with no events.
    r3 = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert r3 == []
    assert len(events) == 1


@pytest.mark.asyncio
async def test_event_payload_includes_bytes_sent_and_received() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy")
    rid, cancel_requested = reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.anthropic.com",
            path="/v1/messages",
            session_id="sess-bytes",
        )
    )

    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        reg.complete(rid)

    upstream = asyncio.create_task(stub_upstream())
    reg.record_bytes(rid, 12345, 6789)
    await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    await upstream
    assert len(events) == 1
    assert events[0].bytes_sent == 12345
    assert events[0].bytes_received == 6789
    assert events[0].duration_ms >= 0


@pytest.mark.asyncio
async def test_strips_query_string_from_path_at_register_time() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy")
    rid, cancel_requested = reg.register(
        RegisterRequestOptions(
            method="POST",
            host="example.com",
            path="/oauth/callback?code=SECRET&state=42",
            session_id="sess-secret",
        )
    )

    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        reg.complete(rid)

    upstream = asyncio.create_task(stub_upstream())
    await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    await upstream
    assert len(events) == 1
    assert events[0].path == "/oauth/callback"
    assert "SECRET" not in events[0].path


@pytest.mark.asyncio
async def test_complete_called_before_cancel_drops_request_from_registry() -> None:
    reg, events = _make_registry()
    rid, _ = reg.register(
        RegisterRequestOptions(method="GET", host="example.com", path="/healthz")
    )
    assert reg.size() == 1
    reg.complete(rid)
    assert reg.size() == 0
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results == []
    assert events == []


@pytest.mark.asyncio
async def test_cancel_without_reason_raises() -> None:
    reg, _ = _make_registry()
    with pytest.raises(ValueError, match="non-empty reason"):
        await reg.cancel("")


@pytest.mark.asyncio
async def test_hard_kill_skipped_when_no_escalator_configured(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A SKIPPED escalation must never be recorded as a hard kill."""
    reg, events = _make_registry(graceful_window_ms=80)
    assert reg.hard_kill_available is False
    reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.openai.com",
            path="/v1/chat",
            session_id="sess-noproxy",
        )
    )
    with caplog.at_level(logging.WARNING, logger="watchlight.core.kill_signal"):
        results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_SKIPPED
    assert results[0].killed is False
    assert len(events) == 1
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL
    assert events[0].escalation == ESCALATION_SKIPPED
    # ...and it says so, loudly.
    assert any("UNAVAILABLE" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_hard_kill_skipped_when_request_has_no_session_id() -> None:
    reg, events = _make_registry(proxy_url="http://wl-proxy", graceful_window_ms=60)
    reg.register(
        RegisterRequestOptions(method="POST", host="api.openai.com", path="/v1/chat")
    )
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_SKIPPED
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL


@pytest.mark.asyncio
async def test_hard_kill_logs_warning_when_escalator_raises(
    caplog: pytest.LogCaptureFixture,
) -> None:
    reg, events = _make_registry(
        proxy_url="http://wl-proxy",
        graceful_window_ms=60,
        escalator_raises=RuntimeError("wl-proxy returned 503"),
    )
    reg.register(
        RegisterRequestOptions(
            method="POST",
            host="api.openai.com",
            path="/v1/chat",
            session_id="sess-503",
        )
    )
    with caplog.at_level(logging.WARNING, logger="watchlight.core.kill_signal"):
        results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    # A FAILED escalation is not a kill. The record says `unconfirmed`.
    assert results[0].disposition == DISPOSITION_UNCONFIRMED
    assert results[0].escalation == ESCALATION_FAILED
    assert results[0].killed is False
    assert len(events) == 1
    assert events[0].disposition != DISPOSITION_PROXY_HARD_KILL
    assert events[0].escalation == ESCALATION_FAILED
    assert any("hard-kill" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_emits_no_event_when_emitter_unset() -> None:
    reg = InterceptorKillRegistry(graceful_window_ms=30)
    rid, cancel_requested = reg.register(
        RegisterRequestOptions(method="POST", host="example.com", path="/x")
    )

    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        reg.complete(rid)

    upstream = asyncio.create_task(stub_upstream())
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    await upstream
    assert results[0].disposition == DISPOSITION_GRACEFUL


@pytest.mark.asyncio
async def test_graceful_path_reports_escalation_skipped() -> None:
    """Escalation is never reached when the abort is acked in window."""
    reg, events = _make_registry(proxy_url="http://wl-proxy", graceful_window_ms=500)
    rid, cancel_requested = reg.register(
        RegisterRequestOptions(
            method="POST", host="example.com", path="/x", session_id="sess-ok"
        )
    )

    # In-process stand-in for unit tests only.
    async def stub_upstream() -> None:
        await cancel_requested.wait()
        reg.complete(rid)

    upstream = asyncio.create_task(stub_upstream())
    results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
    await upstream
    assert results[0].disposition == DISPOSITION_GRACEFUL
    assert results[0].escalation == ESCALATION_SKIPPED
    assert events[0].escalation == ESCALATION_SKIPPED


# ─── Shipped default: the registry is ON ───────────────────────────────


class TestDefaultKillSignalRegistry:
    def test_default_registry_is_live_but_needs_no_infrastructure(self) -> None:
        reg = default_kill_signal_registry()
        assert isinstance(reg, InterceptorKillRegistry)
        # Degrades safely: no escalator means no network, no
        # credentials, and no breakage for an in-process run.
        assert reg.hard_kill_available is False

    def test_default_registry_accepts_an_escalator(self) -> None:
        async def esc(_sid: str, _reason: str) -> str:
            return ESCALATION_CONFIRMED

        reg = default_kill_signal_registry(hard_kill_escalator=esc)
        assert reg.hard_kill_available is True

    @pytest.mark.asyncio
    async def test_cancel_with_nothing_registered_is_loud_but_harmless(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A registry no interceptor feeds cannot contain anything.

        It must say so rather than let an operator believe in-flight
        interruption is active.
        """
        reg = default_kill_signal_registry()
        with caplog.at_level(logging.WARNING, logger="watchlight.core.kill_signal"):
            results = await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
        assert results == []
        assert any(
            "NO in-flight request is registered" in r.message for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_no_interceptor_warning_is_emitted_once(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        reg = default_kill_signal_registry()
        with caplog.at_level(logging.WARNING, logger="watchlight.core.kill_signal"):
            await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
            await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
            await reg.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE)
        hits = [r for r in caplog.records if "NO in-flight request" in r.message]
        assert len(hits) == 1
