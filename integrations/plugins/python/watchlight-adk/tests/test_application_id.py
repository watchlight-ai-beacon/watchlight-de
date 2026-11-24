"""Run attribution to an AI application.

``application_id`` names the AI application a governed run belongs to.
ADK opens the root run from ``before_agent_callback`` (there is no
``start_run``), so the plugin constructor — or the
``WATCHLIGHT_APPLICATION_ID`` env var — is the entry point. The id
reaches the ``POST /sessions`` body only when set and is absent
otherwise. Explicit configuration, never inferred from prompts or agent
names.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from watchlight_adk import WatchlightPlugin

APP = "0b6f7c2e-5d1a-4c8e-9f3b-2a1d4e5f6a7b"
OTHER_APP = "7d3e9a10-2b4c-4f6e-8a1b-3c5d7e9f0a2b"


def _plugin(sent: list, **kwargs) -> WatchlightPlugin:
    """A plugin whose ApdpClient records every ``/sessions`` body."""
    kwargs.setdefault("agent_slug", "agent-research-analyst")
    kwargs.setdefault("root_agent_name", "research_analyst")
    plugin = WatchlightPlugin(apdp_url="http://localhost:8081", **kwargs)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/sessions":
            sent.append(json.loads(request.content))
            return httpx.Response(
                200, json={"session": {"id": "ses_test"}, "session_token": "sst_test.c2ln"}
            )
        return httpx.Response(200, json={})

    plugin.apdp._probed = True
    plugin.apdp._client = httpx.AsyncClient(
        base_url="http://localhost:8081", transport=httpx.MockTransport(handler)
    )
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin._current_agent_id = "agent-uuid"  # set by before_agent_callback normally
    plugin._current_execution_id = "exec_test"
    return plugin


# In-process stand-in for unit tests only.
def _stub_callback_context() -> MagicMock:
    ctx = MagicMock()
    ctx.state = {}
    return ctx


@pytest.mark.asyncio
async def test_constructor_application_id_reaches_the_session_body():
    sent: list = []
    await _plugin(sent, application_id=APP)._open_session_and_manifest(
        _stub_callback_context()
    )
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_without_an_application_id_the_body_omits_the_field():
    sent: list = []
    await _plugin(sent)._open_session_and_manifest(_stub_callback_context())
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_env_var_is_the_default_when_nothing_explicit_is_given(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", APP)
    sent: list = []
    await _plugin(sent)._open_session_and_manifest(_stub_callback_context())
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_the_constructor_argument_wins_over_the_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", OTHER_APP)
    sent: list = []
    plugin = _plugin(sent, application_id=APP)
    assert plugin.application_id == APP
    await plugin._open_session_and_manifest(_stub_callback_context())
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_an_empty_env_var_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "")
    sent: list = []
    await _plugin(sent)._open_session_and_manifest(_stub_callback_context())
    assert "application_id" not in sent[0]


# ─── Empty / whitespace / non-UUID handling ──────
#
# Both entry points go through ``watchlight_core.resolve_application_id``:
# ``""`` and whitespace mean unset, surrounding whitespace is trimmed,
# and a non-UUID is refused at construction. Format check only —
# wl-apdp stays the authority on membership.


@pytest.mark.asyncio
async def test_a_whitespace_only_env_var_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "   ")
    sent: list = []
    await _plugin(sent)._open_session_and_manifest(_stub_callback_context())
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_an_empty_constructor_argument_means_unset(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", APP)
    sent: list = []
    await _plugin(sent, application_id="")._open_session_and_manifest(
        _stub_callback_context()
    )
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_surrounding_whitespace_is_trimmed_at_every_entry_point(monkeypatch):
    sent: list = []
    await _plugin(sent, application_id=f"  {APP} ")._open_session_and_manifest(
        _stub_callback_context()
    )
    assert sent[0]["application_id"] == APP

    sent.clear()
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", f"\t{OTHER_APP}\n")
    await _plugin(sent)._open_session_and_manifest(_stub_callback_context())
    assert sent[0]["application_id"] == OTHER_APP


def test_a_non_uuid_constructor_argument_is_refused():
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([], application_id="my-app")


def test_a_non_uuid_env_var_is_refused_at_construction(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "my-app")
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([])
