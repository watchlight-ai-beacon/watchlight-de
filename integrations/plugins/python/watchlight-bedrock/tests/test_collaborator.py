"""Tests for the cross-process collaborator pattern.

Governed cross-process spawn itself is DEFERRED to a future single-use
spawn-authorization token because we refuse to cross the parent run's
``sst_`` credential through Bedrock session attributes (AWS control
plane / CloudTrail exposure). So these tests cover:

- the NON-sensitive reference plumbing (``CollaboratorSpawnRef`` +
  ``extract_collaborator_spawn_ref``) — run-handle id / agent id only,
  never a credential;
- the scope-derivation helpers + env-scope fallback (retained plumbing
  for the deferred path);
- the fail-closed posture of ``spawn_collaborator_subagent`` (no ref, and
  ref-present-but-governed-spawn-not-available);
- that the orchestrator crosses ONLY non-sensitive references and NEVER
  the ``sst_`` token.

All tests are order-independent: every test builds its own plugin + mock
APDP client, and no module-level mutable state is shared.
"""

from unittest.mock import AsyncMock

import pytest

from watchlight_bedrock import (
    CollaboratorGovernanceUnavailable,
    CollaboratorSpawnRef,
    WatchlightBedrockPlugin,
    extract_collaborator_spawn_ref,
    requested_scope_from_env,
    scope_from_action_group_tools,
    spawn_collaborator_subagent,
)
from watchlight_bedrock.collaborator import (
    ENV_DEFAULT_SUBAGENT_SCOPE,
    SESSION_ATTR_PARENT_AGENT_ID,
    SESSION_ATTR_PARENT_RUN_HANDLE_ID,
    SESSION_ATTR_PARENT_SESSION_ID,
)

from .conftest import as_session

PARENT_AGENT_ID = "1d2bdf18-1a89-4bd1-81ad-33269b484266"
PARENT_RUN_HANDLE_ID = "8f14e45f-ceea-467a-9e0f-3b5a3c9f0001"
# A stand-in for the parent sst_ credential — used ONLY to assert it never
# lands in session attributes. It is never crossed.
PARENT_SPAWN_TOKEN = "sst_parent_secret_must_never_cross"


def _full_attrs():
    """The complete NON-sensitive reference (no credential key exists)."""
    return {
        SESSION_ATTR_PARENT_AGENT_ID: PARENT_AGENT_ID,
        SESSION_ATTR_PARENT_SESSION_ID: "ses_parent",
        SESSION_ATTR_PARENT_RUN_HANDLE_ID: PARENT_RUN_HANDLE_ID,
    }


@pytest.fixture
def plugin():
    p = WatchlightBedrockPlugin(apdp_url="https://apdp.test", tenant_id="acme")
    # spawn_subagent must NEVER be reached (governed spawn is deferred).
    p.apdp.spawn_subagent = AsyncMock(
        side_effect=AssertionError("spawn_subagent must not be called")
    )
    p.apdp.resolve_agent = AsyncMock(
        side_effect=AssertionError("resolve_agent must not be called")
    )
    p.apdp.publish_events = AsyncMock(return_value=True)
    p.apdp.complete_session = AsyncMock(return_value=True)
    p.apdp.terminate_session = AsyncMock(return_value=True)
    return p


# ─── extract_collaborator_spawn_ref (non-sensitive plumbing) ──────────


def test_extract_ref_none_when_no_parent_attrs():
    assert extract_collaborator_spawn_ref({}) is None
    assert extract_collaborator_spawn_ref({"sessionAttributes": {}}) is None


def test_extract_ref_full_reference():
    ref = extract_collaborator_spawn_ref({"sessionAttributes": _full_attrs()})
    assert ref is not None
    assert ref.parent_agent_id == PARENT_AGENT_ID
    assert ref.parent_session_id == "ses_parent"
    assert ref.parent_run_handle_id == PARENT_RUN_HANDLE_ID
    assert ref.has_parent_reference is True


def test_extract_ref_has_no_credential_field():
    # The ref type carries no credential attribute at all.
    ref = extract_collaborator_spawn_ref({"sessionAttributes": _full_attrs()})
    assert not hasattr(ref, "parent_spawn_token")


def test_extract_ref_from_full_bedrock_event_session_state():
    event = {"sessionState": {"sessionAttributes": _full_attrs()}}
    ref = extract_collaborator_spawn_ref(event)
    assert ref is not None
    assert ref.has_parent_reference is True


def test_extract_ref_accepts_bare_attrs_mapping():
    ref = extract_collaborator_spawn_ref(_full_attrs())
    assert ref is not None
    assert ref.has_parent_reference is True


def test_extract_ref_partial_reference_not_complete():
    attrs = {SESSION_ATTR_PARENT_AGENT_ID: PARENT_AGENT_ID}
    ref = extract_collaborator_spawn_ref({"sessionAttributes": attrs})
    assert ref is not None
    assert ref.has_parent_reference is False


def test_extract_ref_blank_strings_treated_as_absent():
    attrs = {
        SESSION_ATTR_PARENT_AGENT_ID: "   ",
        SESSION_ATTR_PARENT_RUN_HANDLE_ID: "",
    }
    assert extract_collaborator_spawn_ref({"sessionAttributes": attrs}) is None


# ─── requested_scope_from_env / scope helpers ─────────────────────────


def test_requested_scope_from_env_absent_is_empty():
    assert requested_scope_from_env({}).is_empty()


def test_requested_scope_from_env_parsed():
    env = {
        ENV_DEFAULT_SUBAGENT_SCOPE: (
            '{"allowed_tools": ["research/search"], '
            '"allowed_intents": ["summarize"], '
            '"max_depth": 1, "time_budget_seconds": 300}'
        )
    }
    scope = requested_scope_from_env(env)
    assert scope.allowed_tools == ["research/search"]
    assert scope.allowed_intents == ["summarize"]
    assert scope.max_depth == 1
    assert scope.time_budget_seconds == 300
    assert not scope.is_empty()


def test_requested_scope_from_env_malformed_json_fails_closed():
    scope = requested_scope_from_env({ENV_DEFAULT_SUBAGENT_SCOPE: "{not json"})
    assert scope.is_empty()


def test_requested_scope_from_env_non_object_fails_closed():
    scope = requested_scope_from_env({ENV_DEFAULT_SUBAGENT_SCOPE: "[1, 2, 3]"})
    assert scope.is_empty()


def test_scope_from_action_group_tools_dedups_and_sets_tools():
    scope = scope_from_action_group_tools(
        ["research/search", "research/search", "research/fetch"],
        max_depth=2,
    )
    assert scope.allowed_tools == ["research/search", "research/fetch"]
    assert scope.max_depth == 2
    assert scope.allowed_resources == []


# ─── spawn_collaborator_subagent — fail-closed (spawn deferred) ───────


@pytest.mark.asyncio
async def test_spawn_collaborator_no_ref_fails_closed(plugin):
    with pytest.raises(CollaboratorGovernanceUnavailable):
        await spawn_collaborator_subagent(plugin, None, "research-collaborator")
    plugin.apdp.spawn_subagent.assert_not_awaited()
    plugin.apdp.resolve_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_spawn_collaborator_partial_ref_fails_closed(plugin):
    ref = CollaboratorSpawnRef(parent_agent_id=PARENT_AGENT_ID)  # no run-handle
    assert ref.has_parent_reference is False
    with pytest.raises(CollaboratorGovernanceUnavailable):
        await spawn_collaborator_subagent(plugin, ref, "research-collaborator")
    plugin.apdp.spawn_subagent.assert_not_awaited()


@pytest.mark.asyncio
async def test_spawn_collaborator_complete_ref_still_fails_closed_deferred(
    plugin,
):
    # A COMPLETE non-sensitive reference is present, but governed spawn is
    # deferred: the sst_ is never crossed, so no spawn is possible.
    ref = extract_collaborator_spawn_ref({"sessionAttributes": _full_attrs()})
    assert ref is not None and ref.has_parent_reference is True

    with pytest.raises(CollaboratorGovernanceUnavailable) as exc:
        await spawn_collaborator_subagent(
            plugin,
            ref,
            "research-collaborator",
            requested_scope=scope_from_action_group_tools(["research/search"]),
        )

    # The deferral message explains the missing spawn-authorization token and
    # never attempts a spawn or a resolve.
    assert "spawn-authorization token" in str(exc.value)
    plugin.apdp.spawn_subagent.assert_not_awaited()
    plugin.apdp.resolve_agent.assert_not_awaited()


@pytest.mark.asyncio
async def test_spawn_collaborator_never_touches_credential(plugin):
    # The ref type has no credential field and the fail-closed path never
    # reads one; the parent sst_ stand-in never appears in the error.
    ref = extract_collaborator_spawn_ref({"sessionAttributes": _full_attrs()})
    with pytest.raises(CollaboratorGovernanceUnavailable) as exc:
        await spawn_collaborator_subagent(plugin, ref, "research-collaborator")
    assert PARENT_SPAWN_TOKEN not in str(exc.value)


# ─── Orchestrator-side hand-off (NON-sensitive only) ──────────────────


async def _start_orchestrator(plugin):
    plugin.apdp.resolve_agent = AsyncMock(
        return_value={"id": PARENT_AGENT_ID, "slug": "orchestrator"}
    )
    plugin.apdp.create_session = AsyncMock(
        return_value=as_session(
            plugin.apdp,
            {
                "session": {"id": "ses_orch"},
                "root_run_handle_id": PARENT_RUN_HANDLE_ID,
                # The run DOES have an sst_ credential (held by the backend)...
                "session_token": PARENT_SPAWN_TOKEN,
                "execution_id": "exec_orch",
            },
        )
    )
    plugin.apdp.get_manifest = AsyncMock(return_value={})
    plugin.apdp.publish_events = AsyncMock(return_value=True)
    return await plugin.start_run("orchestrator")


@pytest.mark.asyncio
async def test_orchestrator_threads_only_nonsensitive_reference(plugin):
    handle = await _start_orchestrator(plugin)
    # The run really does have an sst_ credential in-process (in the
    # backend's run table, never on the handle)...
    assert handle.run is not None
    assert PARENT_SPAWN_TOKEN not in repr(vars(handle))

    attrs = handle._bedrock_collaborator_session_attributes()

    # ...but ONLY the non-sensitive reference crosses the boundary.
    assert attrs[SESSION_ATTR_PARENT_AGENT_ID] == PARENT_AGENT_ID
    assert attrs[SESSION_ATTR_PARENT_RUN_HANDLE_ID] == PARENT_RUN_HANDLE_ID
    # The sst_ credential value appears in NO attribute.
    assert PARENT_SPAWN_TOKEN not in attrs.values()


@pytest.mark.asyncio
async def test_orchestrator_attrs_never_contain_a_credential_key(plugin):
    handle = await _start_orchestrator(plugin)
    attrs = handle._bedrock_collaborator_session_attributes()
    # No key hints at a token/credential/secret being carried.
    for key in attrs:
        lowered = key.lower()
        assert "token" not in lowered
        assert "credential" not in lowered
        assert "secret" not in lowered
        assert "sst" not in lowered


@pytest.mark.asyncio
async def test_orchestrator_method_takes_no_credential_flag(plugin):
    import inspect

    handle = await _start_orchestrator(plugin)
    sig = inspect.signature(handle._bedrock_collaborator_session_attributes)
    # The removed opt-in must be gone entirely.
    assert "include_spawn_credential" not in sig.parameters


@pytest.mark.asyncio
async def test_orchestrator_attrs_roundtrip_to_nonsensitive_ref(plugin):
    handle = await _start_orchestrator(plugin)
    attrs = handle._bedrock_collaborator_session_attributes()

    # The collaborator side parses exactly the non-sensitive reference...
    ref = extract_collaborator_spawn_ref({"sessionAttributes": attrs})
    assert ref is not None
    assert ref.has_parent_reference is True
    assert ref.parent_run_handle_id == PARENT_RUN_HANDLE_ID
    # ...and a governed spawn under it still fails closed (deferred).
    with pytest.raises(CollaboratorGovernanceUnavailable):
        await spawn_collaborator_subagent(plugin, ref, "research-collaborator")


def test_no_spawn_token_session_attr_key_exists():
    # Belt-and-suspenders: the credential session-attribute key must not
    # exist as an importable symbol anywhere in the public module.
    import watchlight_bedrock as wb
    import watchlight_bedrock.collaborator as col

    assert not hasattr(col, "SESSION_ATTR_PARENT_SPAWN_TOKEN")
    assert not hasattr(wb, "SESSION_ATTR_PARENT_SPAWN_TOKEN")
