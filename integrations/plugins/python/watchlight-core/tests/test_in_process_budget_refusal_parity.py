"""A NAMED sub-agent time budget is granted exactly or refused, never clamped.

A spawn that names a ``time_budget_seconds``
larger than its parent can give, whether more than the parent's granted
budget, more than the parent's REMAINING time, or more than the tenant
threshold, is refused with a typed ``TimeBudget`` scope violation. wl-apdp
and the in-process path must agree, so these cases mirror the Rust validator
tests (wl-apdp's sub-agent attenuation validator) and run against
the REAL compiled engine (skipped when it is not installed).

The in-process root has no tenant threshold of its own: the client's
``subagent_time_budget_threshold_seconds`` is the root's budget, so the
threshold case refuses as "more than the parent's granted budget".
"""

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core.errors import (  # noqa: E402
    ScopeAttenuationDenied,
    ScopeViolationDimension,
)
from watchlight_core.in_process_client import InProcessClient  # noqa: E402
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


def _client(tmp_path, threshold=None):
    kwargs = {} if threshold is None else {"subagent_time_budget_threshold_seconds": threshold}
    return InProcessClient(
        policies=POLICIES, audit_path=str(tmp_path / "audit.jsonl"), **kwargs
    )


async def _root(client):
    info = await client.create_session(str(uuid4()))
    return info.run, info.root_run_handle_id


def _request(parent_handle, *, time_budget, max_depth=0):
    return spawn_subagent_request_to_dict(
        SpawnSubagentRequest(
            child_intent=ChildIntent(category="research", objective="Delegated sub-task"),
            parent_agent_id=uuid4(),
            child_agent_id=uuid4(),
            parent_run_handle_id=parent_handle,
            requested_scope=RequestedScope(
                allowed_tools=["search"],
                max_depth=max_depth,
                time_budget_seconds=time_budget,
            ),
        )
    )


def _denials(tmp_path):
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [
        rec
        for rec in (json.loads(line) for line in path.read_text().splitlines() if line)
        if rec.get("event") == "attenuation" and rec.get("decision") == "Deny"
    ]


async def _child_with_deadline(client, *, budget, deadline_in):
    """A first-level child granted ``budget`` seconds whose deadline is then
    pinned ``deadline_in`` from now, so its REMAINING time is known exactly
    (the engine reads the stored scope as the next spawn's parent)."""
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(
        root, _request(root_handle, time_budget=budget, max_depth=1)
    )
    handle = str(resp["child_run_handle_id"])
    client._scopes[handle]["deadline"] = (
        datetime.now(timezone.utc) + deadline_in
    ).isoformat()
    return resp["child_run"], handle


async def _assert_refused(client, tmp_path, run, handle, budget, needle):
    runs_before = len(client._runs)
    denials_before = len(_denials(tmp_path))
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(run, _request(handle, time_budget=budget))
    assert exc.value.violations == [ScopeViolationDimension.TIME_BUDGET_SECONDS]
    # A widening, not an unsatisfiable scope.
    assert exc.value.reason_code is None
    assert needle in str(exc.value), str(exc.value)
    # The child never runs: no run was opened, and the refusal is recorded.
    assert len(client._runs) == runs_before
    assert len(_denials(tmp_path)) == denials_before + 1


# ── the parent's remaining time ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_named_budget_above_the_parents_remaining_time_is_refused(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=60, milliseconds=990)
    )
    await _assert_refused(
        client, tmp_path, run, handle, 300,
        "time_budget_seconds 300 exceeds the 60 seconds the parent has left",
    )
    await _assert_refused(
        client, tmp_path, run, handle, 61, "the 60 seconds the parent has left"
    )


@pytest.mark.asyncio
async def test_a_named_budget_equal_to_the_parents_remaining_time_is_granted(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=60, milliseconds=990)
    )
    resp = await client.spawn_subagent(run, _request(handle, time_budget=60))
    granted = spawn_subagent_response_from_dict(resp).granted_scope
    assert granted.time_budget_seconds == 60
    parent_deadline = datetime.fromisoformat(client._scopes[handle]["deadline"])
    assert granted.deadline <= parent_deadline


@pytest.mark.asyncio
async def test_an_absent_budget_still_inherits_the_remaining_time(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=60, milliseconds=990)
    )
    resp = await client.spawn_subagent(run, _request(handle, time_budget=None))
    assert spawn_subagent_response_from_dict(resp).granted_scope.time_budget_seconds == 60


@pytest.mark.asyncio
async def test_a_parent_with_under_a_second_left_refuses_a_named_budget(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(milliseconds=990)
    )
    runs_before = len(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(run, _request(handle, time_budget=1))
    # Refused either way: as a widening while under a second is left, or as
    # unsatisfiable if the parent expired before the engine read its clock
    # (a loaded machine), so the test does not race the clock.
    if exc.value.reason_code is None:
        assert "time_budget_seconds 1 exceeds the 0 seconds the parent has left" in str(
            exc.value
        )
    else:
        assert exc.value.reason_code == "UNSATISFIABLE_SCOPE"
    assert len(client._runs) == runs_before


@pytest.mark.asyncio
async def test_a_named_budget_from_an_expired_parent_is_unsatisfiable(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=-5)
    )
    runs_before = len(client._runs)
    with pytest.raises(ScopeAttenuationDenied) as exc:
        await client.spawn_subagent(run, _request(handle, time_budget=60))
    assert exc.value.reason_code == "UNSATISFIABLE_SCOPE"
    assert len(client._runs) == runs_before


# ── the parent's granted budget ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_named_budget_above_the_parents_granted_budget_states_what_is_left(tmp_path):
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=100, milliseconds=990)
    )
    await _assert_refused(
        client, tmp_path, run, handle, 601,
        "time_budget_seconds 601 exceeds parent.time_budget_seconds 600; "
        "at most 100 seconds are available",
    )


# ── the root ceiling (the in-process stand-in for the tenant threshold) ──


@pytest.mark.asyncio
async def test_a_named_budget_above_the_root_ceiling_is_refused(tmp_path):
    client = _client(tmp_path, threshold=120)
    root, root_handle = await _root(client)
    await _assert_refused(
        client, tmp_path, root, root_handle, 121,
        "time_budget_seconds 121 exceeds parent.time_budget_seconds 120",
    )


@pytest.mark.asyncio
async def test_a_named_budget_equal_to_the_root_ceiling_is_granted(tmp_path):
    client = _client(tmp_path, threshold=120)
    root, root_handle = await _root(client)
    resp = await client.spawn_subagent(root, _request(root_handle, time_budget=120))
    assert spawn_subagent_response_from_dict(resp).granted_scope.time_budget_seconds == 120


@pytest.mark.asyncio
async def test_a_grant_is_exactly_the_named_budget_or_a_refusal(tmp_path):
    """Sweep: with 123.x seconds left of 600, every named budget is granted
    exactly, with a deadline no later than the parent's, or refused."""
    client = _client(tmp_path)
    run, handle = await _child_with_deadline(
        client, budget=600, deadline_in=timedelta(seconds=123, milliseconds=990)
    )
    parent_deadline = datetime.fromisoformat(client._scopes[handle]["deadline"])
    for budget in (1, 60, 122, 123, 124, 300, 600, 601):
        try:
            resp = await client.spawn_subagent(run, _request(handle, time_budget=budget))
        except ScopeAttenuationDenied as exc:
            assert budget > 123, f"{budget} refused: {exc}"
            assert exc.violations == [ScopeViolationDimension.TIME_BUDGET_SECONDS]
            continue
        granted = spawn_subagent_response_from_dict(resp).granted_scope
        assert budget <= 123, f"{budget} granted"
        assert granted.time_budget_seconds == budget
        assert granted.deadline <= parent_deadline
