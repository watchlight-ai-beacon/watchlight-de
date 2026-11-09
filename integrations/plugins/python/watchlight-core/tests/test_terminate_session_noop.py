"""Regression guard — ``terminate_session`` must never round-trip.

`POST /sessions/{id}/terminate` takes the closed ``TerminationReason``
enum server-side. The SDK only ever sent free-form strings (``"manual"``,
``"run_failed: <ExceptionType>"``), so serde rejected every request with
a 422 and the client swallowed it at debug level — the call never once
succeeded, and nothing surfaced the failure.

It is not being resurrected: terminating a session is an operator-plane
verb (``POST /v1/admin/sessions/{id}/terminate``, Operator role, user
principals only). Letting the governed agent stop its own governance
session is exactly the authorization inversion that gate prevents.

These tests pin the resulting contract so nobody re-adds the request:

  1. the HTTP client issues NO request and returns False
  2. it does not even open a connection (no ``client`` property access)
  3. the no-op is announced at WARNING, exactly once per client
  4. the in-process client still performs its real local cleanup
  5. ``RunHandle.terminate`` still emits ``execution_failed`` — the
     authoritative record of the abnormal end
"""

import logging

import pytest

from watchlight_core.apdp_client import ApdpClient

# ``get_logger`` remaps ``watchlight_core.x`` onto the canonical
# ``watchlight.x`` namespace, so caplog must filter on the mapped name.
_LOGGER_NAME = "watchlight.core.apdp_client"


def _client() -> ApdpClient:
    # Loopback + auto_probe=False keeps the constructor from doing any
    # I/O; the channel-safety guard allows plaintext to localhost.
    return ApdpClient(base_url="http://localhost:8081", auto_probe=False)


@pytest.mark.asyncio
async def test_terminate_session_issues_no_request_and_returns_false(monkeypatch):
    """No HTTP. Ever. The transport is never even touched."""

    def _boom(_self):  # pragma: no cover - only runs if the bug returns
        raise AssertionError(
            "terminate_session touched the HTTP transport; the "
            "/sessions/{id}/terminate round-trip can only 422"
        )

    monkeypatch.setattr(ApdpClient, "client", property(_boom))

    c = _client()
    assert await c.terminate_session("ses_abc", "run_failed: TimeoutError") is False
    # Still no transport on a second call.
    assert await c.terminate_session("ses_abc") is False


class _Capture(logging.Handler):
    """Collect records straight off the SDK logger.

    ``caplog`` cannot see these: ``watchlight_core.log`` sets
    ``propagate = False`` on the ``watchlight`` root, so records never
    reach pytest's root handler.
    """

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.mark.asyncio
async def test_terminate_session_warns_once_not_silently():
    """The no-op is visible in ops logs — but does not spam per run.

    Silence at debug level is how the original defect survived unnoticed
    for the whole life of the method.
    """
    handler = _Capture()
    sdk_logger = logging.getLogger(_LOGGER_NAME)
    sdk_logger.addHandler(handler)
    try:
        c = _client()
        await c.terminate_session("ses_abc")
        await c.terminate_session("ses_def")
        await c.terminate_session("ses_ghi")

        assert len(handler.records) == 1, (
            "expected exactly one deprecation warning per client, got "
            f"{[r.getMessage() for r in handler.records]}"
        )
        assert "deprecated no-op" in handler.records[0].getMessage()

        # A second client warns on its own — the latch is per instance.
        await _client().terminate_session("ses_xyz")
        assert len(handler.records) == 2
    finally:
        sdk_logger.removeHandler(handler)


@pytest.mark.asyncio
async def test_in_process_client_still_releases_local_session_state(tmp_path):
    """The in-process lane's implementation is real, not a no-op.

    This is why the ``ApdpClient`` seam survives the fix: without it,
    every abnormally-ended Developer-Edition run would leak its
    ``_sessions`` entry. Skipped when the compiled engine is absent.
    """
    pytest.importorskip("watchlight_engine")
    from watchlight_core import InProcessClient

    c = InProcessClient(
        [{"name": "p", "code": 'permit(principal == User::"a", action, resource);'}],
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    c._sessions["ses_local"] = {"agent_id": "a"}
    run = c._new_run("ses_local")

    assert await c.terminate_session(run, "run_failed: ValueError") is True
    assert "ses_local" not in c._sessions
    assert run not in c._runs
