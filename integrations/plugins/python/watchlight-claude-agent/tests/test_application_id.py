"""Run attribution to an AI application.

``application_id`` names the AI application a governed run belongs to.
It reaches the ``POST /sessions`` body only when set — per run on
``start_run``, on the plugin constructor, or via
``WATCHLIGHT_APPLICATION_ID`` — and is absent otherwise. It is explicit
configuration, never inferred from prompts or names.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin

APP = "0b6f7c2e-5d1a-4c8e-9f3b-2a1d4e5f6a7b"
OTHER_APP = "7d3e9a10-2b4c-4f6e-8a1b-3c5d7e9f0a2b"


def _plugin(sent: list, **kwargs) -> WatchlightClaudeAgentSDKPlugin:
    """A plugin whose ApdpClient records every ``/sessions`` body."""
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081", **kwargs)

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
    plugin.apdp.resolve_agent = AsyncMock(return_value={"id": "agent-uuid"})  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_per_run_application_id_reaches_the_session_body():
    sent: list = []
    await _plugin(sent).start_run("agent-x", application_id=APP)
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_without_an_application_id_the_body_omits_the_field():
    sent: list = []
    await _plugin(sent).start_run("agent-x")
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_constructor_application_id_is_the_default_for_every_run():
    sent: list = []
    await _plugin(sent, application_id=APP).start_run("agent-x")
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_env_var_is_the_default_when_nothing_explicit_is_given(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", APP)
    sent: list = []
    await _plugin(sent).start_run("agent-x")
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_explicit_arguments_win_over_the_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", OTHER_APP)
    sent: list = []
    plugin = _plugin(sent, application_id=APP)
    assert plugin.application_id == APP
    await plugin.start_run("agent-x", application_id=OTHER_APP)
    # The per-run argument outranks the constructor default.
    assert sent[0]["application_id"] == OTHER_APP


@pytest.mark.asyncio
async def test_an_empty_env_var_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "")
    sent: list = []
    await _plugin(sent).start_run("agent-x")
    assert "application_id" not in sent[0]


# ─── Empty / whitespace / non-UUID handling ──────
#
# Every entry point goes through ``watchlight_core.resolve_application_id``:
# ``""`` and whitespace mean unset, surrounding whitespace is trimmed,
# and a non-UUID is refused before any session opens. Format check
# only — wl-apdp stays the authority on membership.


@pytest.mark.asyncio
async def test_an_empty_per_run_argument_means_unset_and_the_plugin_default_applies():
    sent: list = []
    await _plugin(sent, application_id=APP).start_run("agent-x", application_id="")
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_a_whitespace_only_per_run_argument_with_no_default_omits_the_field():
    sent: list = []
    await _plugin(sent).start_run("agent-x", application_id="   ")
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_a_whitespace_only_env_var_is_treated_as_unset(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "   ")
    sent: list = []
    await _plugin(sent).start_run("agent-x")
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_surrounding_whitespace_is_trimmed_at_every_entry_point(monkeypatch):
    sent: list = []
    await _plugin(sent, application_id=f"  {APP} ").start_run("agent-x")
    assert sent[0]["application_id"] == APP

    sent.clear()
    await _plugin(sent).start_run("agent-x", application_id=f"\t{OTHER_APP}\n")
    assert sent[0]["application_id"] == OTHER_APP

    sent.clear()
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", f" {APP}  ")
    await _plugin(sent).start_run("agent-x")
    assert sent[0]["application_id"] == APP


def test_a_non_uuid_constructor_argument_is_refused():
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([], application_id="my-app")


def test_a_non_uuid_env_var_is_refused_at_construction(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "my-app")
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([])


@pytest.mark.asyncio
async def test_a_non_uuid_per_run_argument_is_refused_before_any_session_opens():
    sent: list = []
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        await _plugin(sent).start_run("agent-x", application_id="not-a-uuid")
    assert sent == []
