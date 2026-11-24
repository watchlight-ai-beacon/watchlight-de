"""The plugin's spawn binds the child as the current sub-agent with a
token the child uses to unbind itself, and a failed bind refuses the
spawn instead of letting the child run on the parent's handle."""

from __future__ import annotations

import pytest
from watchlight_core import GovernanceUnavailable, current_subagent_handle
from watchlight_core_testing import MockApdpClient

from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

PARENT = "11111111-1111-4111-8111-aaaaaaaaaaaa"
CHILD = "11111111-1111-4111-8111-bbbbbbbbbbbb"


def _plugin() -> WatchlightPydanticAIPlugin:
    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost:8081", auto_instrument=False
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["parent-agent"] = PARENT
    plugin.apdp.known_agents["child-agent"] = CHILD
    return plugin


class _UnbindableVar:
    """Stand-in for the SDK's sub-agent context variable: clearing it
    works, binding a child handle to it fails."""

    def set(self, value):
        if value is None:
            return None
        raise RuntimeError("bind failed")

    def get(self, default=None):
        return default


@pytest.mark.asyncio
async def test_spawned_child_unbinds_itself_with_its_token_on_complete():
    plugin = _plugin()
    parent = await plugin.start_run("parent-agent")
    parent._aentered = True
    child = await parent.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
    assert child._subagent_cv_token is not None
    assert current_subagent_handle() is child
    await child.complete()
    assert current_subagent_handle() is None


@pytest.mark.asyncio
async def test_spawn_refused_when_subagent_bind_fails(monkeypatch):
    plugin = _plugin()
    parent = await plugin.start_run("parent-agent")
    parent._aentered = True
    import watchlight_core.run_handle as rh

    monkeypatch.setattr(rh, "_current_subagent_handle", _UnbindableVar())
    with pytest.raises(GovernanceUnavailable, match="bind"):
        await parent.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})


@pytest.mark.asyncio
async def test_spawn_refused_when_parent_registration_fails(monkeypatch):
    """A child its parent cannot track would escape the parent's
    quarantine cascade: the spawn is refused."""
    plugin = _plugin()
    parent = await plugin.start_run("parent-agent")
    parent._aentered = True

    def _broken(child):  # type: ignore[no-untyped-def]
        raise RuntimeError("registration failed")

    monkeypatch.setattr(parent, "_register_child_handle", _broken)
    with pytest.raises(GovernanceUnavailable, match="registered"):
        await parent.spawn_subagent("child-agent", child_intent={"category": "research", "objective": "Delegated sub-task"})
    assert current_subagent_handle() is None
