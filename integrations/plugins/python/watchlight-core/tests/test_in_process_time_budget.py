"""In-process sub-agent time budgets match wl-apdp.

wl-apdp validates a root spawn against the root's effective scope and refuses
a child whose resolved time budget is zero (it could make no call), and it
denies every call a sub-agent makes once its deadline has passed. The
in-process backend now does both. These exercise the REAL compiled engine
(skipped when it is not installed).
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core.errors import ScopeAttenuationDenied  # noqa: E402
from watchlight_core.in_process_client import (  # noqa: E402
    InProcessClient,
    _deadline_passed,
)
from watchlight_core.scope import (  # noqa: E402
    RequestedScope,
    SpawnSubagentRequest,
    spawn_subagent_request_to_dict,
    ChildIntent,
    spawn_subagent_response_from_dict,
)

POLICIES = [
    {
        "name": "allow-search",
        "code": 'permit(principal, action == Action::"search", resource);',
    }
]


def _client(tmp_path):
    return InProcessClient(policies=POLICIES, audit_path=str(tmp_path / "audit.jsonl"))


async def _root(client):
    """A root run and the handle a spawn under it names: the one the backend
    minted for the run, when it mints one."""
    info = await client.create_session(str(uuid4()))
    return info.run, (info.root_run_handle_id or uuid4())


# The grant names the TOOL (`Tool::"web"`), never the `search` verb: the
# membership check matches a call on its tool identity only.
def _request(parent_handle, *, time_budget, tools=("web",), max_depth=1):
    return spawn_subagent_request_to_dict(
        SpawnSubagentRequest(
            child_intent=ChildIntent(category="research", objective="Delegated sub-task"),
            parent_agent_id=uuid4(),
            child_agent_id=uuid4(),
            parent_run_handle_id=parent_handle,
            requested_scope=RequestedScope(
                allowed_tools=list(tools),
                max_depth=max_depth,
                time_budget_seconds=time_budget,
            ),
        )
    )


async def _authorize(client, run):
    return await client.authorize(
        'Agent::"child"', 'Action::"search"', 'Tool::"web"', {}, run=run
    )


@pytest.mark.asyncio
async def test_a_first_level_child_with_a_zero_budget_is_refused(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(root, _request(root_handle, time_budget=0))
    assert "unsatisfiable" in str(exc.value)
    # The child never runs: no run was opened for it.
    assert len(client._runs) == 1


@pytest.mark.asyncio
async def test_a_child_with_a_normal_budget_is_granted_and_allowed(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=300))
    granted = spawn_subagent_response_from_dict(resp).granted_scope
    assert granted.allowed_tools == ["web"]
    assert granted.time_budget_seconds == 300
    assert granted.deadline is not None
    remaining = granted.deadline - datetime.now(timezone.utc)
    assert timedelta(seconds=290) < remaining <= timedelta(seconds=300)
    assert (await _authorize(client, resp["child_run"]))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_child_is_denied_once_its_budget_has_passed(tmp_path, monkeypatch):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=1))
    child = resp["child_run"]
    assert (await _authorize(client, child))["decision"] == "Allow"

    import watchlight_core.in_process_client as ipc

    later = datetime.now(timezone.utc) + timedelta(seconds=2)

    class _Later(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: D401 - the clock two seconds on
            return later if tz is not None else later.replace(tzinfo=None)

    monkeypatch.setattr(ipc, "datetime", _Later)
    decision = await _authorize(client, child)
    assert decision["decision"] == "Deny"
    assert decision["reason"] == "time_budget_exceeded"
    # The same child named by its handle in the context is denied too.
    handle = str(resp["child_run_handle_id"])
    by_handle = await client.authorize(
        'Agent::"child"', 'Action::"search"', 'Tool::"web"', {"run_handle_id": handle}
    )
    assert by_handle["decision"] == "Deny"
    # The root, which has no budget of its own, is unaffected.
    assert (await _authorize(client, root))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_grandchild_budget_never_outlives_its_parent(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    child = await client.spawn_subagent(root, _request(root_handle, time_budget=60, max_depth=1))
    child_handle = child["child_run_handle_id"]
    grand = await client.spawn_subagent(
        child["child_run"], _request(child_handle, time_budget=30, max_depth=0)
    )
    child_deadline = spawn_subagent_response_from_dict(child).granted_scope.deadline
    grand_deadline = spawn_subagent_response_from_dict(grand).granted_scope.deadline
    assert grand_deadline <= child_deadline
    # A budget larger than the parent's is a widening, and refused.
    with pytest.raises(ScopeAttenuationDenied):
        await client.spawn_subagent(
            child["child_run"], _request(child_handle, time_budget=3600, max_depth=0)
        )
    # A grandchild that requests no budget resolves to zero and is refused.
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(
            child["child_run"], _request(child_handle, time_budget=0, max_depth=0)
        )
    assert "unsatisfiable" in str(exc.value)


def test_an_unreadable_deadline_counts_as_passed():
    now = datetime.now(timezone.utc)
    assert _deadline_passed({"deadline": "not a time"}, now) is True
    # A sub-agent scope without a deadline counts as passed (fail closed),
    # as wl-apdp's membership check treats it; "not a sub-agent" has none.
    assert _deadline_passed({"deadline": None}, now) is True
    # An empty scope is a sub-agent scope with no deadline: passed.
    assert _deadline_passed({}, now) is True
    assert _deadline_passed(None, now) is False
    # Nanosecond precision, as the engine writes it, is read.
    future = (now + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "123Z"
    assert _deadline_passed({"deadline": future}, now) is False



# ── an absent budget inherits the parent's remaining time ───────────────


def _attenuations(tmp_path):
    import json as _json

    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [
        rec
        for rec in (_json.loads(line) for line in path.read_text().splitlines() if line)
        if rec.get("event") == "attenuation"
    ]


def _remaining(granted):
    return granted.deadline - datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_an_absent_budget_inherits_the_root_ceiling(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=None))
    granted = spawn_subagent_response_from_dict(resp).granted_scope
    # The DE root's ceiling is wl-apdp's default threshold, 3600 s.
    assert granted.time_budget_seconds == 3600
    assert timedelta(seconds=3590) < _remaining(granted) <= timedelta(seconds=3600)
    assert (await _authorize(client, resp["child_run"]))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_the_root_ceiling_is_configurable_and_bounds_inheritance(tmp_path):
    client = InProcessClient(
        policies=POLICIES,
        audit_path=str(tmp_path / "audit.jsonl"),
        subagent_time_budget_threshold_seconds=120,
    )
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=None))
    assert spawn_subagent_response_from_dict(resp).granted_scope.time_budget_seconds == 120
    # Asking for more than the root has is a widening, and refused.
    with pytest.raises(ScopeAttenuationDenied):
        await client.spawn_subagent(root, _request(root_handle, time_budget=121))


@pytest.mark.parametrize("bad", [0, -1, 2**32, 1.5, "60", True, None])
def test_the_root_ceiling_must_be_a_positive_integer(tmp_path, bad):
    with pytest.raises(ValueError):
        InProcessClient(
            policies=POLICIES,
            audit_path=str(tmp_path / "audit.jsonl"),
            subagent_time_budget_threshold_seconds=bad,
        )


@pytest.mark.asyncio
async def test_an_absent_budget_from_a_child_inherits_what_the_child_has_left(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    child = await client.spawn_subagent(root, _request(root_handle, time_budget=60, max_depth=1))
    child_granted = spawn_subagent_response_from_dict(child).granted_scope
    grand = await client.spawn_subagent(
        child["child_run"],
        _request(child["child_run_handle_id"], time_budget=None, max_depth=0),
    )
    grand_granted = spawn_subagent_response_from_dict(grand).granted_scope
    assert grand_granted.time_budget_seconds <= 60
    assert grand_granted.deadline <= child_granted.deadline


@pytest.mark.asyncio
async def test_a_parent_with_no_time_left_cannot_give_any_away(tmp_path):
    import asyncio

    client = _client(tmp_path)
    root, root_handle = await _root(client)
    child = await client.spawn_subagent(root, _request(root_handle, time_budget=1, max_depth=1))
    await asyncio.sleep(1.2)
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(
            child["child_run"],
            _request(child["child_run_handle_id"], time_budget=None, max_depth=0),
        )
    assert exc.value.reason_code == "UNSATISFIABLE_SCOPE"


@pytest.mark.asyncio
async def test_an_explicit_zero_carries_the_unsatisfiable_reason_code(tmp_path):
    from watchlight_core.subagent_registry import _denial_class

    client = _client(tmp_path)
    root, root_handle = await _root(client)
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(root, _request(root_handle, time_budget=0))
    assert exc.value.reason_code == "UNSATISFIABLE_SCOPE"
    assert _denial_class(exc.value) == "unsatisfiable_scope"
    denied = [r for r in _attenuations(tmp_path) if r.get("decision") == "Deny"]
    assert len(denied) == 1


# ── a budget that is not an integer in range is a typed refusal ─────────


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [-1, 2**32, 10**20, 1e20, 1.5, "10", True])
async def test_a_budget_out_of_range_or_not_an_integer_is_refused(tmp_path, bad):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    body = _request(root_handle, time_budget=None)
    body["requested_scope"]["time_budget_seconds"] = bad
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(root, body)
    assert exc.value.reason == "invalid_spawn_request"
    denied = [r for r in _attenuations(tmp_path) if r.get("decision") == "Deny"]
    assert len(denied) == 1
    assert len(client._runs) == 1  # no child run was opened


@pytest.mark.asyncio
async def test_an_engine_that_cannot_read_the_request_is_a_typed_refusal(tmp_path, monkeypatch):
    client = _client(tmp_path)
    root, root_handle = await _root(client)

    class _OldEngine:
        def __init__(self, inner):
            self._inner = inner

        def attenuate_scope(self, parent, requested):
            raise ValueError("invalid requested scope JSON: missing field")

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(client, "_engine", _OldEngine(client._engine))
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(root, _request(root_handle, time_budget=None))
    assert exc.value.reason == "invalid_spawn_request"
    assert [r for r in _attenuations(tmp_path) if r.get("decision") == "Deny"]


# ── expiry, everywhere a sub-agent asks ─────────────────────────────────


@pytest.mark.asyncio
async def test_preflight_is_denied_once_the_budget_has_passed(tmp_path):
    import asyncio

    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=1))
    child = resp["child_run"]
    before = await client.preflight_step(child, 'Action::"search"', 'Tool::"web"')
    assert before["preflight"]["decision"] == "Allow"
    await asyncio.sleep(1.2)
    after = await client.preflight_step(child, 'Action::"search"', 'Tool::"web"')
    assert after["preflight"] == {"decision": "Deny", "reason": "time_budget_exceeded"}


@pytest.mark.asyncio
async def test_a_sub_agent_scope_without_a_deadline_is_denied(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=60))
    client._scopes[str(resp["child_run_handle_id"])].pop("deadline")
    decision = await _authorize(client, resp["child_run"])
    assert decision == {"decision": "Deny", "reason": "time_budget_exceeded", "details": {}}


@pytest.mark.asyncio
async def test_preflight_from_an_ended_sub_agent_run_is_denied(tmp_path):
    client = _client(tmp_path)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=60))
    child = resp["child_run"]
    assert await client.complete_session(child)
    after = await client.preflight_step(child, 'Action::"search"', 'Tool::"web"')
    assert after["preflight"] == {"decision": "Deny", "reason": "unknown or ended run"}
