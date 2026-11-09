"""InProcessClient — the Developer-Edition backend over the compiled engine.

Skipped when `watchlight-engine` is not installed, so the open-source
`watchlight_core` suite stays green without the (proprietary) compiled wheel.
Where the wheel is present, these prove real, fail-closed decisions in-process.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core import GovernanceBackend, InProcessClient  # noqa: E402

ADMIN_ALL = {
    "name": "admin-all",
    "code": 'permit(principal == User::"admin", action, resource);',
}


def _client(tmp_path, policies=(ADMIN_ALL,)):
    return InProcessClient(list(policies), audit_path=str(tmp_path / "audit.jsonl"))


def test_satisfies_backend_protocol(tmp_path):
    assert isinstance(_client(tmp_path), GovernanceBackend)


@pytest.mark.asyncio
async def test_a_caller_cannot_claim_an_enforcement_point(tmp_path):
    # Where a decision is enforced is derived by the server from a verified
    # platform-service credential. In process there is none, so a caller
    # that claims one is refused by the engine: never evaluated, never able
    # to satisfy a policy keyed on it.
    gateway_only = {
        "name": "gateway-only",
        "code": (
            "permit(principal, action, resource) when "
            '{ context has enforcement_point && context.enforcement_point == "gateway" };'
        ),
    }
    c = _client(tmp_path, policies=(gateway_only,))
    with pytest.raises(RuntimeError, match="enforcement_point_not_caller_settable"):
        await c.authorize("admin", "delete", "doc", context={"enforcement_point": "gateway"})
    # Without the claim the gateway-only permit does not match.
    assert (await c.authorize("admin", "delete", "doc"))["decision"] == "Deny"


@pytest.mark.asyncio
async def test_authorize_allow_and_deny(tmp_path):
    c = _client(tmp_path)
    allow = await c.authorize("admin", "delete", "doc")
    deny = await c.authorize("alice", "delete", "doc")
    assert allow["decision"] == "Allow"
    assert deny["decision"] == "Deny"
    # Shape matches ApdpClient/MockApdpClient: decision + details always present.
    assert "details" in allow


@pytest.mark.asyncio
async def test_authorize_preserves_cedar_entity_types(tmp_path):
    # Callers may pass bare or Cedar-typed entities; both must work — but a
    # typed one reaches the engine WITH ITS TYPE, it is not collapsed to a bare
    # name. ``ADMIN_ALL`` names ``User::"admin"``, so the typed principal must
    # match and a differently-typed one with the same id must NOT.
    c = _client(tmp_path)
    allow = await c.authorize('User::"admin"', 'Action::"delete"', 'Resource::"doc"')
    assert allow["decision"] == "Allow"
    deny = await c.authorize('Agent::"admin"', 'Action::"delete"', 'Resource::"doc"')
    assert deny["decision"] == "Deny"


@pytest.mark.asyncio
async def test_session_lifecycle_and_preflight_uses_session_agent(tmp_path):
    # Policy permits the 'admin' agent; preflight carries no principal, so it
    # must authorize under the session's agent, as an Agent (never as a User
    # with the same id).
    c = _client(
        tmp_path,
        (ADMIN_ALL, {"name": "agent-admin", "code": 'permit(principal == Agent::"admin", action == Action::"delete", resource);'}),
    )
    user_only = _client(tmp_path)
    user_session = await user_only.create_session(agent_id="admin")
    assert (await user_only.preflight_step(user_session.run, "delete", "doc"))["preflight"][
        "decision"
    ] == "Deny"
    session = await c.create_session(agent_id="admin")
    sid = session.session_id
    assert sid.startswith("ses_")
    assert session.execution_id.startswith("exec_")

    ok = await c.preflight_step(session.run, "delete", "doc")
    assert ok["preflight"]["decision"] == "Allow"

    # An unknown run cannot resolve a principal → fail-closed Deny.
    denied = await c.preflight_step("run_nope", "delete", "doc")
    assert denied["preflight"]["decision"] == "Deny"

    assert await c.complete_session(session.run) is True
    # An ended run no longer resolves either.
    ended = await c.preflight_step(session.run, "delete", "doc")
    assert ended["preflight"]["decision"] == "Deny"


@pytest.mark.asyncio
async def test_resolve_agent_is_deterministic(tmp_path):
    c = _client(tmp_path)
    a = await c.resolve_agent("research-agent")
    b = await c.resolve_agent("research-agent")
    assert a["id"] == b["id"]  # uuid5 — stable per slug
    assert a["slug"] == "research-agent"


@pytest.mark.asyncio
async def test_publish_events_appends_local_jsonl(tmp_path):
    audit = tmp_path / "audit.jsonl"
    c = InProcessClient([ADMIN_ALL], audit_path=str(audit))
    assert await c.publish_events(None, []) is True  # empty is a no-op
    assert await c.publish_events(None, [{"event_type": "execution_started"}]) is True
    lines = audit.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "execution_started"


@pytest.mark.asyncio
async def test_manifest_and_trust_and_health(tmp_path):
    c = _client(tmp_path)
    assert await c.health_check() is True
    manifest = await c.get_manifest("admin")
    assert manifest is not None and manifest["agent_id"] == "admin"
    trust = await c.check_agent_trust("admin")
    assert trust["trusted"] is True


@pytest.mark.asyncio
async def test_submit_plan_deferred_to_binding(tmp_path):
    # spawn_subagent is implemented (see test_spawn_subagent_in_process.py);
    # plan validation still needs a compiled-engine method not yet bound.
    c = _client(tmp_path)
    with pytest.raises(NotImplementedError):
        await c.submit_plan("ses_x", [])


@pytest.mark.asyncio
async def test_authorize_tolerates_null_context(tmp_path):
    # The SDK auto-wires optional context fields that may be None; Cedar forbids
    # JSON null, so InProcessClient must strip them (regression for the bug found
    # wiring the pydantic-ai plugin end-to-end).
    c = _client(tmp_path)
    allow = await c.authorize(
        "admin",
        "delete",
        "doc",
        context={
            "run_handle_id": None,
            "tenant_id": None,
            "nested": {"x": None},
            "mfa": True,
        },
    )
    assert allow["decision"] == "Allow"


@pytest.mark.asyncio
async def test_real_plugin_runs_governed_zero_infra(tmp_path):
    # The whole point: an UNMODIFIED framework plugin runs a governed agent
    # against the in-process engine — same code, one backend swap, zero infra.
    import uuid as _uuid

    pytest.importorskip("watchlight_pydantic_ai")
    from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

    from watchlight_core.in_process_client import _AGENT_NS

    agent_id = str(_uuid.uuid5(_AGENT_NS, "research-agent"))
    policy = {
        "name": "agent-read",
        # The acting agent is an AGENT. Naming it ``User::`` used to work —
        # every term was collapsed to a bare name, and a bare name matches a
        # policy of ANY entity type. See tests/test_cedar_entity_shaping.py.
        "code": f'permit(principal == Agent::"{agent_id}", action == Action::"read", resource);',
    }
    audit = tmp_path / "audit.jsonl"
    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost:8081", auto_instrument=False
    )
    plugin.apdp = InProcessClient([policy], audit_path=str(audit))

    async with await plugin.start_run("research-agent") as handle:
        assert await handle.authorize_action("read", "dataset") is True
        assert await handle.authorize_action("delete", "dataset") is False

    assert audit.exists() and audit.read_text(encoding="utf-8").strip()


@pytest.mark.asyncio
async def test_unknown_and_ended_runs_are_refused(tmp_path):
    """The DE backend honours the GovernanceBackend contract: an unknown or
    ended run is refused; an ended run's late lineage is still written; a
    call naming no run (``None``) is the documented DE exception."""
    from watchlight_core import GovernanceUnavailable

    audit = tmp_path / "audit.jsonl"
    c = InProcessClient([ADMIN_ALL], audit_path=str(audit))
    session = await c.create_session(agent_id="admin")
    run = session.run
    terms = ('User::"admin"', 'Action::"delete"', 'Resource::"doc"')
    assert (await c.authorize(*terms, run=run))["decision"] == "Allow"

    for bad in ("run_forged", None):
        if bad is None:
            assert await c.complete_session(run) is True
            bad = run  # now ended
        assert (await c.authorize(*terms, run=bad))["decision"] == "Deny"
        assert await c.get_manifest("admin", run=bad) is None
        with pytest.raises(GovernanceUnavailable):
            await c.spawn_subagent(bad, {})
        assert await c.complete_session(bad) is False
        assert await c.terminate_session(bad) is False

    # Late lineage for the ended run is written; an unknown run's is not.
    assert await c.publish_events(run, [{"event_type": "execution_completed"}]) is True
    assert await c.publish_events("run_forged", [{"event_type": "x"}]) is False
    # No run named: the decorator path, written as before.
    assert await c.publish_events(None, [{"event_type": "execution_started"}]) is True
    assert (await c.authorize(*terms))["decision"] == "Allow"
    lines = audit.read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(x)["event_type"] for x in lines] == [
        "execution_completed",
        "execution_started",
    ]
