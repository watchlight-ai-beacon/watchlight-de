"""Run lifecycle: a run opens on BeforeInvocation, closes on
AfterInvocation (also on error), and a run that cannot be opened stops the
invocation before any model turn."""

from __future__ import annotations

import asyncio
from typing import Any, List

import pytest
from conftest import AGENTS, ScriptedModel, events_of, text, tool_call
from strands import Agent, tool
from strands.types.exceptions import EventLoopException
from watchlight_core import AgentNotRegistered, GovernanceUnavailable
from watchlight_core_testing import MockApdpClient
from watchlight_strands import (
    AgentNotIdentified,
    UngovernableChild,
    WatchlightStrandsPlugin,
    governing_plugin,
)

ran: List[str] = []


@pytest.fixture(autouse=True)
def _reset_ran() -> None:
    ran.clear()


@tool
def lookup(q: str) -> str:
    """Look something up."""
    ran.append(q)
    return "found"


def _event_types(mock: MockApdpClient) -> List[str]:
    return [e["event_type"] for e in mock.published_events]


def test_one_run_per_invocation(make_plugin, mock_apdp: MockApdpClient):
    plugin = make_plugin("agent-root")
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("one")], [text("two")]])
    agent = Agent(model=model, tools=[lookup], plugins=[plugin], callback_handler=None)

    agent("first")
    agent("second")

    assert len(mock_apdp._closed_sessions) == 2
    started = events_of(mock_apdp, "execution_started")
    completed = events_of(mock_apdp, "execution_completed")
    assert len(started) == 2 and len(completed) == 2
    assert {e["execution_id"] for e in started} == {e["execution_id"] for e in completed}
    assert started[0]["agent_id"] == AGENTS["agent-root"]
    # Every authorize call carried the run's own execution.
    assert mock_apdp.authorize_calls[0]["execution_id"] == started[0]["execution_id"]


def test_model_failure_closes_the_run_as_failed(make_plugin, mock_apdp: MockApdpClient):
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})]], fail_on_call=2)
    agent = Agent(model=model, tools=[lookup], plugins=[make_plugin("agent-root")], callback_handler=None)

    with pytest.raises((RuntimeError, EventLoopException), match="scripted model failure"):
        agent("go")

    assert ran == ["a"]
    assert _event_types(mock_apdp)[-1] == "execution_failed"
    assert len(mock_apdp._terminated_sessions) == 1


def test_unregistered_agent_never_reaches_its_model(make_plugin, mock_apdp: MockApdpClient):
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})]])
    agent = Agent(model=model, tools=[lookup], plugins=[make_plugin("agent-unknown")], callback_handler=None)

    with pytest.raises(AgentNotRegistered):
        agent("go")

    assert model.calls == 0 and ran == []


def test_refused_session_never_reaches_the_model(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    async def refuse(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(mock_apdp, "create_session", refuse)
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})]])
    agent = Agent(model=model, tools=[lookup], plugins=[make_plugin("agent-root")], callback_handler=None)

    with pytest.raises(GovernanceUnavailable):
        agent("go")
    assert model.calls == 0


def test_missing_manifest_refuses_and_closes_the_session(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    async def no_manifest(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(mock_apdp, "get_manifest", no_manifest)
    model = ScriptedModel()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)

    with pytest.raises(GovernanceUnavailable):
        agent("go")
    assert model.calls == 0
    assert len(mock_apdp._closed_sessions) == 1


def test_proxy_configured_without_a_proxy_token_refuses(make_plugin, mock_apdp: MockApdpClient):
    model = ScriptedModel()
    plugin = make_plugin("agent-root", connect_proxy_url="https://wl-proxy.example:8443")
    agent = Agent(model=model, plugins=[plugin], callback_handler=None)

    with pytest.raises(GovernanceUnavailable):
        agent("go")
    assert model.calls == 0
    assert len(mock_apdp._closed_sessions) == 1


def test_sidecar_install_failure_refuses(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    import watchlight_core

    def broken_install(*args: Any, **kwargs: Any) -> None:
        raise GovernanceUnavailable("wl-sidecar binary missing")

    monkeypatch.setattr(watchlight_core, "install_sidecar", broken_install)
    mock_apdp.proxy_token_prefix = "wlp_standin"
    model = ScriptedModel()
    plugin = make_plugin("agent-root", connect_proxy_url="https://wl-proxy.example:8443")
    agent = Agent(model=model, plugins=[plugin], callback_handler=None)

    with pytest.raises(GovernanceUnavailable):
        agent("go")
    assert model.calls == 0


def test_sidecar_is_installed_with_the_runs_proxy_token(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    import watchlight_core

    installed: List[Any] = []

    def record_install(url: str, token: Any, **kwargs: Any) -> None:
        installed.append((url, bool(token)))

    monkeypatch.setattr(watchlight_core, "install_sidecar", record_install)
    mock_apdp.proxy_token_prefix = "wlp_standin"
    plugin = make_plugin("agent-root", connect_proxy_url="https://wl-proxy.example:8443")
    agent = Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)

    agent("go")
    assert installed == [("https://wl-proxy.example:8443", True)]


def test_hook_provider_attachment_is_equivalent(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.default_decision = "Deny"
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    plugin = make_plugin("agent-root")
    agent = Agent(model=model, tools=[lookup], hooks=[plugin], callback_handler=None)

    agent("go")

    assert ran == []
    assert governing_plugin(agent) is plugin
    assert plugin.governed_object is agent


def test_one_plugin_governs_one_agent(make_plugin):
    plugin = make_plugin("agent-root")
    first = Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)
    with pytest.raises(ValueError, match="already installed on another root"):
        Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)
    assert plugin.governed_object is first


def test_two_watchlight_plugins_on_one_agent_are_refused(make_plugin):
    # Strands itself refuses a second plugin with the same name ...
    with pytest.raises(ValueError):
        Agent(
            model=ScriptedModel(),
            plugins=[make_plugin("agent-root"), make_plugin("agent-child")],
            callback_handler=None,
        )
    # ... and the plugin refuses a second identity attached as a hook provider.
    with pytest.raises(ValueError, match="already carries a Watchlight plugin"):
        Agent(
            model=ScriptedModel(),
            plugins=[make_plugin("agent-root")],
            hooks=[make_plugin("agent-child")],
            callback_handler=None,
        )


def test_the_same_plugin_twice_is_registered_once(make_plugin, mock_apdp: MockApdpClient):
    plugin = make_plugin("agent-root")
    agent = Agent(model=ScriptedModel(), plugins=[plugin], hooks=[plugin], callback_handler=None)
    agent("go")
    assert len(mock_apdp._closed_sessions) == 1


def test_a_root_that_cannot_be_identified_is_refused(mock_apdp: MockApdpClient):
    plugin = WatchlightStrandsPlugin(apdp_url="http://localhost", log_decisions=False)
    plugin.apdp = mock_apdp
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})]])
    agent = Agent(model=model, tools=[lookup], plugins=[plugin], callback_handler=None)

    with pytest.raises(AgentNotIdentified):
        agent("go")
    assert model.calls == 0 and ran == []
    assert mock_apdp.authorize_calls == []


def test_root_identity_from_the_environment(mock_apdp: MockApdpClient, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_AGENT_SLUG", "agent-root")
    plugin = WatchlightStrandsPlugin(apdp_url="http://localhost", log_decisions=False)
    plugin.apdp = mock_apdp
    agent = Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)

    agent("go")
    assert events_of(mock_apdp, "execution_started")[0]["agent_id"] == AGENTS["agent-root"]


def test_root_identity_from_an_agent_map_file(mock_apdp: MockApdpClient, monkeypatch, tmp_path):
    import json

    path = tmp_path / "agents.json"
    path.write_text(json.dumps({"planner": "agent-root"}), encoding="utf-8")
    monkeypatch.setenv("WATCHLIGHT_AGENT_MAP", str(path))
    plugin = WatchlightStrandsPlugin(apdp_url="http://localhost", log_decisions=False)
    plugin.apdp = mock_apdp
    agent = Agent(name="planner", model=ScriptedModel(), plugins=[plugin], callback_handler=None)

    agent("go")
    assert events_of(mock_apdp, "execution_started")[0]["agent_id"] == AGENTS["agent-root"]


def test_background_tasks_are_refused(make_plugin):
    import inspect

    if "background_tasks" not in inspect.signature(Agent.__init__).parameters:
        pytest.skip("this strands-agents release has no background tasks")
    with pytest.raises(UngovernableChild, match="background_tasks"):
        Agent(
            model=ScriptedModel(),
            plugins=[make_plugin("agent-root")],
            background_tasks=True,
            callback_handler=None,
        )


def test_unsupported_objects_are_refused(make_plugin):
    plugin = make_plugin("agent-root")
    with pytest.raises(UngovernableChild):
        plugin._install(object())


def test_scope_and_timeout_configuration_is_validated():
    with pytest.raises(ValueError):
        WatchlightStrandsPlugin(apdp_url="http://localhost", subagent_scopes={"x": {"allowed_actions": []}})
    with pytest.raises(ValueError):
        WatchlightStrandsPlugin(apdp_url="http://localhost", subagent_scopes={"x": {"time_budget_seconds": 0}})
    with pytest.raises(ValueError):
        WatchlightStrandsPlugin(apdp_url="http://localhost", agent_map={"x": ""})
    with pytest.raises(ValueError):
        WatchlightStrandsPlugin(apdp_url="http://localhost", authorize_timeout_seconds=0)
    with pytest.raises(ValueError):
        WatchlightStrandsPlugin(apdp_url="http://localhost", agent_slug="  ")


def test_application_id_is_forwarded(make_plugin, mock_apdp: MockApdpClient):
    app_id = "66666666-6666-4666-8666-666666666666"
    seen: List[Any] = []
    original = mock_apdp.create_session

    async def recording(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("application_id"))
        return await original(*args, **kwargs)

    mock_apdp.create_session = recording  # type: ignore[method-assign]
    agent = Agent(
        model=ScriptedModel(),
        plugins=[make_plugin("agent-root", application_id=app_id)],
        callback_handler=None,
    )
    agent("go")
    assert seen == [app_id]


def test_governance_backend_is_used_verbatim(mock_apdp: MockApdpClient):
    plugin = WatchlightStrandsPlugin(
        apdp_url="http://localhost",
        agent_slug="agent-root",
        governance=mock_apdp,  # type: ignore[arg-type]
        log_decisions=False,
    )
    assert plugin.apdp is mock_apdp
    agent = Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)
    asyncio.run(agent.invoke_async("go"))
    assert len(mock_apdp._closed_sessions) == 1


def test_model_turn_without_a_run_is_refused(make_plugin, mock_apdp: MockApdpClient):
    """A BeforeModelCallEvent that belongs to no governed run raises."""
    from strands.hooks import BeforeModelCallEvent

    plugin = make_plugin("agent-root")
    agent = Agent(model=ScriptedModel(), plugins=[plugin], callback_handler=None)
    with pytest.raises(GovernanceUnavailable):
        asyncio.run(plugin._before_model_call(BeforeModelCallEvent(agent=agent, invocation_state={})))
