"""`/agents/resolve` already carries the agent's trust state.

A caller that has just resolved a slug must read the trust state off that
payload rather than issuing `GET /agents/:id`, which is a control-plane
read a plugin's data-plane bearer is not authorized for.
"""

from __future__ import annotations

import pytest

from watchlight_core import TRUSTED_AGENT_STATES, trust_from_resolved


def _resolved(state: object) -> dict:
    return {"id": "a-uuid", "slug": "agent-x", "name": "x", "trust_state": state}


@pytest.mark.parametrize("state", TRUSTED_AGENT_STATES)
def test_a_cleared_state_is_trusted(state):
    verdict = trust_from_resolved(_resolved(state))
    assert verdict == {
        "trusted": True,
        "trust_state": state,
        "reason": f"Trust state: {state}",
    }


@pytest.mark.parametrize("state", ["unverified", "quarantined", "compromised", "revoked"])
def test_every_other_state_is_refused(state):
    verdict = trust_from_resolved(_resolved(state))
    assert verdict is not None
    assert verdict["trusted"] is False
    assert verdict["trust_state"] == state


@pytest.mark.parametrize("state", [None, "", "   ", 7, True])
def test_a_payload_without_a_usable_state_defers_rather_than_trusting(state):
    """None means "this transport carries no trust state" — the caller then
    asks the client. It must never be read as trusted."""
    assert trust_from_resolved(_resolved(state)) is None


def test_a_payload_missing_the_field_entirely_defers():
    assert trust_from_resolved({"id": "a-uuid", "slug": "agent-x"}) is None


def test_surrounding_whitespace_does_not_defeat_the_check():
    verdict = trust_from_resolved(_resolved("  trusted  "))
    assert verdict is not None and verdict["trusted"] is True
