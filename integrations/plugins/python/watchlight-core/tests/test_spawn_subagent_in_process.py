"""In-process ``InProcessClient.spawn_subagent`` — strict-subset attenuation.

These exercise the REAL compiled engine (skipped when it is not installed).
They pin the Developer-Edition contract:

- a root's first delegation is validated by the engine against the root's
  effective scope (the requested tools, resources, intents and depth, and the
  root's time ceiling), as wl-apdp validates a root spawn;
- every DESCENDANT is strict-subset-validated by the engine;
- an overreach raises the typed ``ScopeAttenuationDenied`` (mirroring the
  networked 403 path), never a silent allow;
- each spawn writes a value-free ``attenuation`` lineage record — the shape the
  ``watchlight dev`` attenuation-tree view reads.
"""

import json
from pathlib import Path
from uuid import UUID, uuid4

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core.errors import (  # noqa: E402
    ScopeAttenuationDenied,
    ScopeViolationDimension,
)
from watchlight_core.in_process_client import InProcessClient  # noqa: E402
from watchlight_core.scope import (  # noqa: E402
    RequestedScope,
    ResourceMatcher,
    SpawnSubagentRequest,
    spawn_subagent_request_to_dict,
    ChildIntent,
    spawn_subagent_response_from_dict,
)



async def _parent(client):
    """A live ROOT run of ``client`` to spawn under (one per client)."""
    run = getattr(client, "_test_parent_run", None)
    if run is None:
        session = await client.create_session(agent_id="root-agent")
        run = session.run
        client._test_parent_run = run
        client._test_root_handle = session.root_run_handle_id
    return run


def _root_handle(client):
    """The root run's handle, minted by ``create_session``."""
    return client._test_root_handle


# child_run_handle_id -> the child's own run. A sub-agent spawns from its OWN
# run: the backend binds the run to its handle and never trusts a handle id
# the request names.
_CHILD_RUNS = {}


def _parsed(response):
    parsed = spawn_subagent_response_from_dict(response)
    _CHILD_RUNS[str(parsed.child_run_handle_id)] = response["child_run"]
    return parsed


def _run_of(handle_id):
    return _CHILD_RUNS[str(handle_id)]


def _request(parent_handle, *, tools, max_depth, time_budget, resources=None, intents=None):
    return spawn_subagent_request_to_dict(
        SpawnSubagentRequest(
            child_intent=ChildIntent(category="research", objective="Delegated sub-task"),
            parent_agent_id=uuid4(),
            child_agent_id=uuid4(),
            parent_run_handle_id=parent_handle,
            requested_scope=RequestedScope(
                allowed_tools=list(tools),
                allowed_resources=[ResourceMatcher(matcher=m) for m in (resources or [])],
                allowed_intents=list(intents or []),
                max_depth=max_depth,
                time_budget_seconds=time_budget,
            ),
        )
    )


def _attenuation_records(audit_path: Path):
    return [
        rec
        for line in audit_path.read_text().splitlines()
        if line.strip()
        for rec in [json.loads(line)]
        if rec.get("event") == "attenuation"
    ]


@pytest.mark.asyncio
async def test_root_delegates_freely_and_records_lineage(tmp_path):
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    parent = await _parent(client)
    root_handle = _root_handle(client)

    resp = await client.spawn_subagent(parent,
        _request(root_handle, tools=["read", "write"], max_depth=3, time_budget=3600)
    )
    parsed = spawn_subagent_response_from_dict(resp)

    # The root's own grant: the requested tools, at depth 1.
    assert parsed.granted_scope.allowed_tools == ["read", "write"]
    assert parsed.granted_scope.depth == 1
    assert parsed.child_run_handle_id is not None

    # A value-free attenuation node landed for the dashboard tree.
    records = _attenuation_records(audit)
    assert len(records) == 1
    node = records[0]
    assert node["decision"] == "Allow"
    assert node["depth"] == 1
    assert node["parent_id"] == str(root_handle)
    assert node["tools"] == ["read", "write"]
    assert "arguments" not in node  # value-free


@pytest.mark.asyncio
async def test_descendant_strict_subset_is_granted_exactly(tmp_path):
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))

    parent = _parsed(
        await client.spawn_subagent(await _parent(client),
            _request(_root_handle(client), tools=["read", "write"], max_depth=3, time_budget=3600)
        )
    )
    child = _parsed(
        await client.spawn_subagent(_run_of(parent.child_run_handle_id),
            _request(
                parent.child_run_handle_id,
                tools=["read"],
                max_depth=1,
                time_budget=1800,
            )
        )
    )
    # A real strict subset is granted, one level deeper, with exactly the
    # named budget (never clamped).
    assert child.granted_scope.allowed_tools == ["read"]
    assert child.granted_scope.depth == 2
    assert child.granted_scope.time_budget_seconds == 1800

    records = _attenuation_records(audit)
    assert [r["decision"] for r in records] == ["Allow", "Allow"]
    assert records[1]["parent_id"] == str(parent.child_run_handle_id)


@pytest.mark.asyncio
async def test_descendant_overreach_raises_typed_denial(tmp_path):
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))

    parent = _parsed(
        await client.spawn_subagent(await _parent(client),
            _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=3600)
        )
    )
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(_run_of(parent.child_run_handle_id),
            _request(
                parent.child_run_handle_id,
                tools=["read", "delete"],  # 'delete' is not in the parent
                max_depth=1,
                time_budget=1800,
            )
        )
    assert ScopeViolationDimension.ALLOWED_TOOLS in excinfo.value.violations

    # The denied node is recorded too (so the tree shows the refusal).
    records = _attenuation_records(audit)
    assert records[-1]["decision"] == "Deny"
    assert "read" in records[-1]["tools"] and "delete" in records[-1]["tools"]


@pytest.mark.asyncio
async def test_a_spawn_past_the_depth_budget_carries_the_delegation_depth_code(tmp_path):
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    # Root delegation → depth 1 with a budget of 1; its child → depth 2, budget 0.
    child = _parsed(
        await client.spawn_subagent(await _parent(client), _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=3600))
    )
    grandchild = _parsed(
        await client.spawn_subagent(_run_of(child.child_run_handle_id),
            _request(child.child_run_handle_id, tools=["read"], max_depth=0, time_budget=1800)
        )
    )
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(_run_of(grandchild.child_run_handle_id),
            _request(grandchild.child_run_handle_id, tools=["read"], max_depth=0, time_budget=900)
        )
    err = excinfo.value
    assert err.reason_code == "DELEGATION_DEPTH_EXCEEDED"
    assert (err.observed_depth, err.max_delegation_depth) == (3, 2)

    last = _attenuation_records(audit)[-1]
    assert last["decision"] == "Deny"
    assert last["reason_code"] == "DELEGATION_DEPTH_EXCEEDED"
    assert (last["depth"], last["max_delegation_depth"]) == (3, 2)


@pytest.mark.asyncio
async def test_time_budget_overreach_surfaces_typed_dimension(tmp_path):
    # Regression: the engine spells this violation 'time_budget' while the SDK
    # enum value is 'time_budget_seconds'; without the wire alias the typed
    # dimension was silently dropped (the deny still fired, but callers keying on
    # ScopeViolationDimension.TIME_BUDGET_SECONDS never saw it).
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    parent = _parsed(
        await client.spawn_subagent(await _parent(client),
            _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=100)
        )
    )
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(_run_of(parent.child_run_handle_id),
            _request(
                parent.child_run_handle_id,
                tools=["read"],  # valid subset — only the time budget overreaches
                max_depth=1,
                time_budget=9999,
            )
        )
    assert ScopeViolationDimension.TIME_BUDGET_SECONDS in excinfo.value.violations


# ── An unknown parent scope refuses the spawn, never a root grant ──


@pytest.mark.asyncio
async def test_a_sub_agent_naming_an_unknown_parent_handle_is_refused(tmp_path):
    """A handle id the backend does not hold is never treated as a ROOT: a
    narrowed sub-agent that names a fresh id is refused, no child run is
    opened, and the tree records the refusal."""
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    narrowed = _parsed(
        await client.spawn_subagent(
            await _parent(client), _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=600)
        )
    )
    runs_before = set(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(
            _run_of(narrowed.child_run_handle_id),
            _request(uuid4(), tools=["read", "delete"], max_depth=3, time_budget=3600),
        )
    assert excinfo.value.reason == "parent_run_handle_not_found"
    assert set(client._runs) == runs_before, "a refused spawn opened a child run"
    last = _attenuation_records(audit)[-1]
    assert (last["decision"], last["reason"]) == ("Deny", "parent_run_handle_not_found")


@pytest.mark.asyncio
async def test_a_sub_agent_naming_another_handle_is_refused(tmp_path):
    """A sub-agent's spawn is validated against ITS OWN handle. Naming a wider
    sibling's handle is refused, not attenuated against the sibling."""
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    wide = _parsed(
        await client.spawn_subagent(
            await _parent(client),
            _request(_root_handle(client), tools=["read", "delete"], max_depth=3, time_budget=600),
        )
    )
    narrow = _parsed(
        await client.spawn_subagent(
            await _parent(client), _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=600)
        )
    )
    with pytest.raises(ScopeAttenuationDenied, match="could not be established"):
        await client.spawn_subagent(
            _run_of(narrow.child_run_handle_id),
            _request(wide.child_run_handle_id, tools=["delete"], max_depth=1, time_budget=60),
        )


@pytest.mark.asyncio
async def test_a_root_run_naming_a_sub_agent_handle_is_refused(tmp_path):
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    child = _parsed(
        await client.spawn_subagent(
            await _parent(client), _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=600)
        )
    )
    with pytest.raises(ScopeAttenuationDenied, match="could not be established"):
        await client.spawn_subagent(
            await _parent(client),
            _request(child.child_run_handle_id, tools=["read"], max_depth=1, time_budget=60),
        )


@pytest.mark.asyncio
async def test_a_sub_agent_whose_scope_is_unknown_is_refused(tmp_path):
    """The parent run is a sub-agent, but its scope cannot be established.
    Fail closed: refused, never granted the requested scope."""
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    child = _parsed(
        await client.spawn_subagent(
            await _parent(client), _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=600)
        )
    )
    del client._scopes[str(child.child_run_handle_id)]
    with pytest.raises(ScopeAttenuationDenied, match="could not be established"):
        await client.spawn_subagent(
            _run_of(child.child_run_handle_id),
            _request(child.child_run_handle_id, tools=["read"], max_depth=1, time_budget=60),
        )


@pytest.mark.asyncio
async def test_run_handle_spawns_are_attenuated_end_to_end(tmp_path):
    """Through the real ``BaseRunHandle``: each sub-agent spawns from its own
    run, a known parent's child gets at most the parent's scope, and an
    overreach is refused."""
    from watchlight_core import BaseRunHandle

    class _Plugin:
        tenant_id = "tenant-a"
        log_decisions = False
        last_governance_mode = "unmeasured"
        last_session_id = None
        last_manifest = None
        last_plan_validation = None
        last_proposed_plan = None
        last_actions_allowed = 0
        last_actions_denied = 0
        kill_signal_registry = None

    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    plugin = _Plugin()
    plugin.apdp = client
    session = await client.create_session(agent_id=str(uuid4()))
    root = BaseRunHandle(
        plugin=plugin,
        agent_uuid=str(uuid4()),
        session_id=session.session_id,
        run=session.run,
        run_handle_id=session.root_run_handle_id,
        server_run_handle=True,
    )
    root._aentered = True

    child = await root.spawn_subagent(
        str(uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["read", "write"], max_depth=2, time_budget_seconds=600
    )
    child._aentered = True
    grandchild = await child.spawn_subagent(
        str(uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["read"], max_depth=1, time_budget_seconds=300
    )
    assert grandchild.granted_scope.allowed_tools == ["read"]
    assert set(grandchild.granted_scope.allowed_tools) <= set(child.granted_scope.allowed_tools)
    with pytest.raises(ScopeAttenuationDenied):
        await child.spawn_subagent(
            str(uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["delete"], max_depth=1, time_budget_seconds=300
        )


@pytest.mark.asyncio
async def test_a_root_run_naming_an_unknown_handle_is_refused(tmp_path):
    """A root run's handle is minted by ``create_session``; a root spawn
    naming any other id is refused, as wl-apdp refuses an unknown handle."""
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    parent = await _parent(client)
    runs_before = set(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(
            parent, _request(uuid4(), tools=["read"], max_depth=1, time_budget=60)
        )
    assert excinfo.value.reason == "parent_run_handle_not_found"
    assert set(client._runs) == runs_before
    assert _attenuation_records(audit)[-1]["decision"] == "Deny"


def test_create_session_returns_the_root_handle(tmp_path):
    import asyncio

    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    session = asyncio.run(client.create_session(agent_id="a"))
    assert session.root_run_handle_id
    assert str(UUID(session.root_run_handle_id)) == session.root_run_handle_id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", [None, "", 123, "not-a-uuid", ["x"], {"id": "x"}, "missing"]
)
async def test_a_malformed_parent_handle_id_is_a_typed_refusal(tmp_path, bad):
    """None, "", an int, a non-UUID string, another type or a missing key is
    the same typed refusal with a Deny record, never a TypeError,
    ValueError, AttributeError or KeyError."""
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    parent = await _parent(client)
    body = _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=60)
    if bad == "missing":
        del body["parent_run_handle_id"]
    else:
        body["parent_run_handle_id"] = bad
    runs_before = set(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(parent, body)
    assert excinfo.value.reason == "parent_run_handle_not_found"
    assert set(client._runs) == runs_before
    last = _attenuation_records(audit)[-1]
    assert (last["decision"], last["reason"]) == ("Deny", "parent_run_handle_not_found")


@pytest.mark.asyncio
async def test_a_malformed_request_body_is_a_typed_refusal(tmp_path):
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    parent = await _parent(client)
    body = _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=60)
    body["requested_scope"] = "not-a-scope"
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(parent, body)
    assert excinfo.value.reason == "invalid_spawn_request"


@pytest.mark.asyncio
async def test_a_spawn_without_a_child_intent_is_refused_in_process(tmp_path):
    """The in-process path refuses a spawn that declares
    no child intent, like wl-apdp, and records the refusal."""
    audit = tmp_path / "a.jsonl"
    client = InProcessClient(policies=None, audit_path=str(audit))
    parent = await _parent(client)
    body = _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=60)
    del body["child_intent"]
    runs_before = set(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(parent, body)
    assert excinfo.value.reason == "child_intent_required"
    assert set(client._runs) == runs_before
    last = _attenuation_records(audit)[-1]
    assert (last["decision"], last["reason"]) == ("Deny", "child_intent_required")


@pytest.mark.asyncio
async def test_requested_intents_must_be_the_child_intent_in_process(tmp_path):
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    parent = await _parent(client)
    body = _request(
        _root_handle(client), tools=["read"], max_depth=1, time_budget=60,
        intents=["research", "financial_operation"],
    )
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(parent, body)
    assert excinfo.value.reason == "intent_not_derived"
    # Exactly the category is accepted, and the child is granted only it.
    ok = _parsed(
        await client.spawn_subagent(
            parent,
            _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=60),
        )
    )
    assert ok.granted_scope.allowed_intents == ["research"]


@pytest.mark.asyncio
async def test_a_partially_overlapping_request_is_refused(tmp_path):
    """Asking for one tool the parent holds and one it does not is refused
    whole; the child never gets the overlap alone."""
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    parent = _parsed(
        await client.spawn_subagent(
            await _parent(client),
            _request(_root_handle(client), tools=["read", "write"], max_depth=3, time_budget=600),
        )
    )
    runs_before = set(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as excinfo:
        await client.spawn_subagent(
            _run_of(parent.child_run_handle_id),
            _request(parent.child_run_handle_id, tools=["write", "delete"], max_depth=1, time_budget=60),
        )
    assert ScopeViolationDimension.ALLOWED_TOOLS in excinfo.value.violations
    assert set(client._runs) == runs_before


@pytest.mark.asyncio
async def test_an_ended_parent_cannot_spawn(tmp_path):
    from watchlight_core import GovernanceUnavailable

    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    root = await _parent(client)
    child = _parsed(
        await client.spawn_subagent(
            root, _request(_root_handle(client), tools=["read"], max_depth=3, time_budget=600)
        )
    )
    child_run = _run_of(child.child_run_handle_id)
    assert await client.complete_session(child_run) is True
    with pytest.raises(GovernanceUnavailable):
        await client.spawn_subagent(
            child_run,
            _request(child.child_run_handle_id, tools=["read"], max_depth=1, time_budget=60),
        )
    # An ended root's handle no longer names a root either.
    assert await client.complete_session(root) is True
    with pytest.raises(GovernanceUnavailable):
        await client.spawn_subagent(
            root, _request(_root_handle(client), tools=["read"], max_depth=1, time_budget=60)
        )


@pytest.mark.asyncio
async def test_submit_plan_still_explicit_not_implemented(tmp_path):
    client = InProcessClient(policies=None, audit_path=str(tmp_path / "a.jsonl"))
    with pytest.raises(NotImplementedError):
        await client.submit_plan("ses_x", [{"action": "read", "resource": "doc"}])
