"""A lineage publish REJECTED for its schema must not read like a
transport blip.

Lineage publish is fail-open by design — it must never block a run — so a
rejected batch produces no error anywhere the workload can see. The only
operator-visible trace is the log line, and before this change a 422 from
``POST /v1/events`` looked exactly like a 502 or a timeout: one WARNING,
same wording, and the whole run silently missing from the
execution-lineage view.

A 4xx schema rejection is a BUG IN THE EMITTER, not a transient failure,
and the two must be distinguishable:

  * 400 / 422 → ERROR, naming the event types that were dropped and
    saying the run will not appear in lineage.
  * anything else non-2xx → WARNING, unchanged.

Fail-open behaviour itself is unchanged: both branches return ``False``
and neither raises.
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from watchlight_core._lineage_retry import LineageRetryPolicy
from watchlight_core.apdp_client import ApdpClient
from watchlight_core.credentials import PluginCredential
from watchlight_core_testing import register_test_run


_MALFORMED_BODY = (
    "Failed to deserialize the JSON body into the target type: data did "
    "not match any variant of untagged enum IngestExecutionEventsRequest"
)


def _client_returning(status: int, body: str) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body)

    apdp = ApdpClient(
        "http://localhost",
        credential=PluginCredential.new("wlpa_shared", tenant_id="acme"),
        # One attempt: these tests are about how a final answer is
        # logged, not the retry (see test_lineage_retry.py).
        lineage_retry=LineageRetryPolicy(max_attempts=1),
    )
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost",
        transport=httpx.MockTransport(handler),
    )
    return apdp


LOGGER = "watchlight.core.apdp_client"


def _own(caplog) -> list:
    """The records of the client's own logger. Another component's
    background thread (an OTLP exporter left by another test, say) can log
    while a test runs, and its records must not answer for this logger."""
    return [r for r in caplog.records if r.name == LOGGER]


def _publish(apdp: ApdpClient) -> bool:
    events = [
        {"event_id": "evt_1", "event_type": "execution_started"},
        {"event_id": "evt_2", "event_type": "tool_call_observed"},
    ]
    return asyncio.run(apdp.publish_events(register_test_run(apdp, "sst_run.sig"), events))


def test_schema_rejection_logs_at_error_and_names_the_dropped_events(caplog):
    apdp = _client_returning(422, _MALFORMED_BODY)
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        ok = _publish(apdp)

    # Fail-open is preserved: no raise, and the caller just learns it
    # didn't land.
    assert ok is False

    errors = [r for r in _own(caplog) if r.levelno >= logging.ERROR]
    assert errors, "a schema rejection must surface at ERROR, not WARNING"
    message = errors[-1].getMessage()
    assert "422" in message
    # Says what it is, so the operator isn't hunting a network problem.
    assert "emitter schema bug" in message
    assert "not a transport failure" in message
    # Names what was lost.
    assert "execution_started" in message
    assert "tool_call_observed" in message
    assert "2 event(s)" in message
    assert "NOT appear in execution lineage" in message


def test_bad_request_is_treated_as_a_schema_rejection_too(caplog):
    apdp = _client_returning(400, "bad request")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        assert _publish(apdp) is False
    assert any(r.levelno >= logging.ERROR for r in _own(caplog))


def test_transport_class_failures_stay_at_warning(caplog):
    """A 502 is a transient upstream failure — retrying later may work
    (it is retried; here the budget is one attempt), nothing is wrong
    with the event. It must NOT be promoted to ERROR,
    or the ERROR level stops meaning "fix your emitter"."""
    apdp = _client_returning(502, "bad gateway")
    with caplog.at_level(logging.DEBUG, logger=LOGGER):
        assert _publish(apdp) is False

    assert not [r for r in _own(caplog) if r.levelno >= logging.ERROR]
    warnings = [r for r in _own(caplog) if r.levelno == logging.WARNING]
    assert warnings
    assert "502" in warnings[-1].getMessage()
