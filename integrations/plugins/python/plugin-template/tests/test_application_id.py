"""Run attribution to an AI application — template wiring.

``application_id`` names the AI application a governed run belongs to.
It reaches ``create_session`` only when set — per run on ``start_run``,
on the plugin constructor, or via ``WATCHLIGHT_APPLICATION_ID`` — and
is absent otherwise. Explicit configuration, never inferred from
prompts or names. Keep these passing when you fork the template.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from watchlight_core_testing import MockApdpClient

from watchlight_template.plugin import WatchlightTemplatePlugin

APP = "0b6f7c2e-5d1a-4c8e-9f3b-2a1d4e5f6a7b"
OTHER_APP = "7d3e9a10-2b4c-4f6e-8a1b-3c5d7e9f0a2b"


def _plugin(sent: List[Dict[str, Any]], **kwargs: Any) -> WatchlightTemplatePlugin:
    """A plugin on the SDK's mock client, recording every ``create_session`` call."""
    plugin = WatchlightTemplatePlugin(apdp_url="https://localhost:8081", **kwargs)
    mock = MockApdpClient()
    mock.known_agents["agent-x"] = "11111111-1111-1111-1111-111111111111"
    original = mock.create_session

    async def recording(**call_kwargs: Any) -> Any:
        sent.append(call_kwargs)
        return await original(**call_kwargs)

    mock.create_session = recording  # type: ignore[method-assign]
    plugin.apdp = mock  # type: ignore[assignment]
    return plugin


@pytest.mark.asyncio
async def test_per_run_application_id_reaches_create_session() -> None:
    sent: List[Dict[str, Any]] = []
    await _plugin(sent).start_run("agent-x", application_id=APP)
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_without_an_application_id_the_field_is_absent() -> None:
    sent: List[Dict[str, Any]] = []
    await _plugin(sent).start_run("agent-x")
    assert "application_id" not in sent[0]


@pytest.mark.asyncio
async def test_constructor_application_id_is_the_default_for_every_run() -> None:
    sent: List[Dict[str, Any]] = []
    await _plugin(sent, application_id=APP).start_run("agent-x")
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_env_var_is_the_default_when_nothing_explicit_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", f" {APP} ")
    sent: List[Dict[str, Any]] = []
    await _plugin(sent).start_run("agent-x")
    assert sent[0]["application_id"] == APP


@pytest.mark.asyncio
async def test_explicit_arguments_win_over_the_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", OTHER_APP)
    sent: List[Dict[str, Any]] = []
    plugin = _plugin(sent, application_id=APP)
    assert plugin.application_id == APP
    await plugin.start_run("agent-x", application_id=f"  {OTHER_APP}")
    assert sent[0]["application_id"] == OTHER_APP


@pytest.mark.asyncio
async def test_an_empty_per_run_argument_means_unset() -> None:
    sent: List[Dict[str, Any]] = []
    await _plugin(sent, application_id=APP).start_run("agent-x", application_id="")
    assert sent[0]["application_id"] == APP
    sent.clear()
    await _plugin(sent).start_run("agent-x", application_id="   ")
    assert "application_id" not in sent[0]


def test_a_non_uuid_is_refused_at_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([], application_id="my-app")
    monkeypatch.setenv("WATCHLIGHT_APPLICATION_ID", "my-app")
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        _plugin([])


@pytest.mark.asyncio
async def test_a_non_uuid_per_run_argument_is_refused_before_any_session_opens() -> None:
    sent: List[Dict[str, Any]] = []
    with pytest.raises(ValueError, match="application_id must be a UUID"):
        await _plugin(sent).start_run("agent-x", application_id="not-a-uuid")
    assert sent == []
