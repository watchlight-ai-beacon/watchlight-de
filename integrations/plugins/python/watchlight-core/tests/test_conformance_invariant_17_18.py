"""Conformance invariants 17 (labelled spawn is attenuated) and 18
(credential-bound root). Numbered and named as in the TypeScript lane."""

from __future__ import annotations

from typing import Any, Dict

import pytest

from watchlight_core import open_root_session
from watchlight_core_testing.conformance import (
    CREDENTIAL_BOUND_ROOT_INVARIANT_NAME,
    CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER,
    INVARIANTS,
    LABELLED_SPAWN_ATTENUATED_INVARIANT_NAME,
    LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER,
    ConformanceFailure,
    check_credential_bound_root,
    check_labelled_spawn_attenuated,
)
from watchlight_core_testing import MockApdpClient

BOUND = "11111111-1111-4111-8111-111111111111"


def _spawn(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {"event_type": "agent_spawn_observed", "payload": payload}


def test_numbers_and_names_match_the_ts_lane() -> None:
    assert (LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER, LABELLED_SPAWN_ATTENUATED_INVARIANT_NAME) == (
        17, "labelled_spawn_attenuated")
    assert (CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER, CREDENTIAL_BOUND_ROOT_INVARIANT_NAME) == (
        18, "credential_bound_root")
    table = {n: name for n, name, _ in INVARIANTS}
    assert table[17] == "labelled_spawn_attenuated"
    assert table[18] == "credential_bound_root"


def test_labelled_spawn_with_granted_scope_passes() -> None:
    check_labelled_spawn_attenuated(
        [
            _spawn({"spawned_label": "research-agent", "granted_scope": {"allowed_tools": []}}),
            _spawn({"granted_scope": {}}),  # unlabelled: invariant 13's concern
            {"event_type": "execution_started", "payload": {}},
        ]
    )
    check_labelled_spawn_attenuated([])  # vacuous


@pytest.mark.parametrize(
    "payload",
    [
        {"spawned_label": "research-agent"},
        {"spawned_label": "research-agent", "granted_scope": None},
        {"spawned_label": "bad;label", "granted_scope": {}},
        {"spawned_label": "", "granted_scope": {}},
    ],
)
def test_labelled_spawn_violations_fail(payload: Dict[str, Any]) -> None:
    with pytest.raises(ConformanceFailure) as info:
        check_labelled_spawn_attenuated([_spawn(payload)])
    assert info.value.args[0] == 17


@pytest.mark.asyncio
async def test_credential_bound_root_passes_for_a_bound_credential() -> None:
    apdp = MockApdpClient()
    apdp.credential_agent = BOUND
    await check_credential_bound_root(lambda: open_root_session(apdp), BOUND)


@pytest.mark.asyncio
async def test_credential_bound_root_fails_without_a_binding_or_on_another_agent() -> None:
    with pytest.raises(ConformanceFailure) as info:
        await check_credential_bound_root(lambda: open_root_session(MockApdpClient()), BOUND)
    assert info.value.args[0] == 18
    apdp = MockApdpClient()
    apdp.credential_agent = "33333333-3333-4333-8333-333333333333"
    with pytest.raises(ConformanceFailure):
        await check_credential_bound_root(lambda: open_root_session(apdp), BOUND)
