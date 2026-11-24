"""The in-process engine honours ``Policy.active`` and fails closed.

The engine behind the Python SDK and the Developer Edition
(``watchlight_engine.PolicyEngine``) runs the same policy manager as the
wl-apdp service, so it must decide the same way:

- an inactive permit is never loaded, so it never allows;
- an inactive forbid stays enforced;
- a policy text holds one statement, so a mixed permit/forbid text is refused.

CI builds the engine from this tree and runs these with
``WATCHLIGHT_REQUIRE_ENGINE=1`` (set in CI).
"""

import json

import pytest

engine_mod = pytest.importorskip("watchlight_engine")

from watchlight_core.in_process_client import InProcessClient  # noqa: E402

PERMIT_READ = 'permit(principal, action == Action::"read", resource);'
FORBID_READ = 'forbid(principal, action == Action::"read", resource);'

READ = {
    "principal": 'User::"alice"',
    "action": 'Action::"read"',
    "resource": 'Document::"d1"',
    "context": {},
}


def _policy(pid, code, active):
    return {"id": pid, "name": pid, "code": code, "active": active}


def _decision(engine):
    return json.loads(engine.authorize(json.dumps(READ)))["decision"]


def test_an_inactive_permit_never_allows():
    engine = engine_mod.PolicyEngine()
    engine.add_policy(json.dumps(_policy("permit-read", PERMIT_READ, False)))
    assert _decision(engine) == "Deny"


def test_an_omitted_active_flag_still_means_active():
    engine = engine_mod.PolicyEngine()
    engine.add_policy(json.dumps({"name": "permit-read", "code": PERMIT_READ}))
    assert _decision(engine) == "Allow"


def test_an_inactive_forbid_still_denies():
    engine = engine_mod.PolicyEngine()
    engine.add_policy(json.dumps(_policy("permit-read", PERMIT_READ, True)))
    assert _decision(engine) == "Allow"
    engine.add_policy(json.dumps(_policy("forbid-read", FORBID_READ, False)))
    assert _decision(engine) == "Deny"


@pytest.mark.parametrize("active", [True, False])
def test_a_mixed_permit_and_forbid_text_is_refused(active):
    engine = engine_mod.PolicyEngine()
    with pytest.raises(Exception):
        engine.add_policy(
            json.dumps(_policy("mixed", PERMIT_READ + "\n" + FORBID_READ, active))
        )
    assert _decision(engine) == "Deny"


@pytest.mark.parametrize("bad", [None, "false", 0])
def test_a_non_boolean_active_flag_is_refused(bad):
    engine = engine_mod.PolicyEngine()
    with pytest.raises(Exception):
        engine.add_policy(json.dumps(_policy("p", PERMIT_READ, bad)))
    assert _decision(engine) == "Deny"


def test_the_in_process_client_loads_policies_the_same_way(tmp_path):
    client = InProcessClient(
        policies=[
            _policy("permit-read", PERMIT_READ, False),
            _policy("forbid-write", 'forbid(principal, action == Action::"write", resource);', False),
            _policy("permit-write", 'permit(principal, action == Action::"write", resource);', True),
        ],
        audit_path=None,
    )
    assert _decision(client._engine) == "Deny"
    write = dict(READ, action='Action::"write"')
    assert json.loads(client._engine.authorize(json.dumps(write)))["decision"] == "Deny"
