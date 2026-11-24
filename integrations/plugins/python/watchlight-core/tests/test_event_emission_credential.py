"""Execution-lineage integrity — the SDK emits
execution events under a PER-RUN ``sst_`` session token, never the shared,
long-lived tenant plugin/service bearer.

wl-apdp's ``POST /v1/events`` gate requires a run-scoped credential and
binds every event's identity (``agent_id`` / ``execution_id`` /
``root_execution_id`` / ``session_id``) to the session that credential was
issued for — refusing cross-run / forged events fail-closed. These tests
pin the SDK side of that contract:

  1. ``ApdpClient.publish_events`` attaches the per-run token as the
     ``Authorization`` header for the emission request ONLY, overriding
     the client's default (shared) bearer.
  2. ``BaseRunHandle`` captures the per-run ``session_token`` and passes
     it on every emit.
  3. A spawned sub-agent handle carries its OWN child credential + adopts
     the server-resolved child ``execution_id`` (so its events bind to the
     child session, not the parent's).
  4. Parent-declared vs child-started spawn events ride DIFFERENT
     credentials (the split the server binding gate requires).

Closes threats: spoofing agent identity in events, injecting
governance-affecting events for a run not owned, and shared-credential
blast radius.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from watchlight_core.apdp_client import ApdpClient
from watchlight_core.credentials import PluginCredential
from watchlight_core.run_handle import BaseRunHandle
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import register_test_run, bind_test_run


# ─── 1. ApdpClient.publish_events attaches the per-run token ────────────


def _capture_client(recorder: list) -> ApdpClient:
    """An ApdpClient whose transport records the Authorization header of
    every request, with a shared plugin bearer as the client default."""

    def handler(request: httpx.Request) -> httpx.Response:
        recorder.append(
            (request.url.path, request.headers.get("authorization"))
        )
        return httpx.Response(202, json={"accepted": 1, "event_ids": ["evt_x"]})

    apdp = ApdpClient(
        "http://localhost",
        credential=PluginCredential.new("wlpa_shared_tenant_bearer", tenant_id="acme"),
    )
    # Skip the startup probe and inject the recording transport.
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost",
        headers=apdp._build_auth_headers(),
        transport=httpx.MockTransport(handler),
    )
    return apdp


def test_publish_events_attaches_per_run_session_token():
    recorder: list = []
    apdp = _capture_client(recorder)
    events = [{"event_id": "evt_1", "event_type": "tool_call_observed"}]

    ok = asyncio.run(
        apdp.publish_events(register_test_run(apdp, "sst_run_a.signature"), events)
    )
    assert ok is True
    assert recorder, "the emission request must have been sent"
    path, auth = recorder[-1]
    assert path == "/v1/events"
    # The PER-RUN token overrides the shared tenant bearer on emission.
    assert auth == "Bearer sst_run_a.signature"
    assert "wlpa_shared_tenant_bearer" not in (auth or "")


def test_publish_events_without_token_refuses_and_does_not_emit():
    # Emission is run-credential-ONLY: with no per-run token the SDK must
    # NOT fall back to the shared tenant bearer — it refuses to send the
    # request at all (fail-closed) and returns False.
    recorder: list = []
    apdp = _capture_client(recorder)
    ok = asyncio.run(apdp.publish_events(None, [{"event_id": "evt_1"}]))
    assert ok is False
    assert recorder == [], (
        "no request may be sent when the per-run credential is absent "
        "(no shared-bearer fallback)"
    )


# ─── 2. BaseRunHandle threads its per-run token onto every emit ─────────


class _MockPlugin:
    """Minimal governed-plugin surface for BaseRunHandle unit tests."""

    def __init__(self, apdp: MockApdpClient):
        self.apdp = apdp
        self.tenant_id = "acme"
        self.log_decisions = False
        self.last_actions_allowed = 0
        self.last_actions_denied = 0


def test_base_run_handle_stores_and_emits_with_session_token():
    mock = MockApdpClient()
    plugin = _MockPlugin(mock)
    handle = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid="11111111-1111-1111-1111-111111111111", session_id="ses_run_a", execution_id="exec_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), "sst_run_a.signature")
    assert mock.token_for(handle.run) == "sst_run_a.signature"

    # Trigger a real emit path (the defensive execution_started emit).
    asyncio.run(handle._emit_execution_started(handle.execution_id))

    assert mock.published_event_batches, "an event must have been published"
    token, events = mock.published_event_batches[-1]
    assert token == "sst_run_a.signature", (
        "the run handle must emit under its PER-RUN credential, not the "
        "shared bearer"
    )
    # And the emitted event is bound to this run's identity.
    assert events[0]["execution_id"] == handle.execution_id
    assert events[0]["agent_id"] == handle.agent_uuid


# ─── 3. start_run (through the mock) captures the run credential ────────


def test_handle_built_from_create_session_carries_run_credential():
    # Simulate a plugin start_run: create_session returns session_token +
    # execution_id; the handle adopts both.
    mock = MockApdpClient()
    session = asyncio.run(mock.create_session(agent_id="agent-x"))
    assert session is not None
    assert mock.token_for(session.run).startswith("sst_mock")
    assert session.execution_id.startswith("exec_")

    handle = BaseRunHandle(plugin=_MockPlugin(mock), agent_uuid="agent-x", session_id=session.session_id, execution_id=session.execution_id, run=session.run)
    assert handle.run == session.run
    assert mock.token_for(handle.run).startswith("sst_mock")
    assert handle.execution_id == session.execution_id


# ─── 4. Sub-agent handle carries its OWN child credential ───────────────


def test_spawn_subagent_child_carries_child_credential_and_execution_id():
    mock = MockApdpClient()
    plugin = _MockPlugin(mock)
    parent = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid="22222222-2222-2222-2222-222222222222", session_id="ses_parent", execution_id="exec_parent"), "sst_parent.signature")

    child = asyncio.run(
        parent.spawn_subagent(
            "33333333-3333-3333-3333-333333333333",
            child_intent={"category": "*", "objective": "Delegated sub-task"},
            allowed_tools=["search.web"],
            allowed_resources=["*"],
            allowed_intents=["*"],
            max_depth=1,
            time_budget_seconds=60,
        )
    )

    # The spawn was authenticated with the PARENT's per-run credential
    # (not the shared bearer) — this is what lets the server derive the
    # child's tree position from the parent's VERIFIED claims.
    assert mock.spawn_subagent_tokens == ["sst_parent.signature"]
    # The child presents its OWN run credential (NOT the parent's / shared).
    assert mock.token_for(child.run) is not None
    assert mock.token_for(child.run) != mock.token_for(parent.run)
    assert mock.token_for(child.run).startswith("sst_mock_child_")
    # And it adopts the server-resolved child execution_id so its events
    # bind to the child session.
    assert child.execution_id.startswith("exec_")
    # The child's root is inherited from the parent's tree.
    assert child.root_execution_id == parent.root_execution_id


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
