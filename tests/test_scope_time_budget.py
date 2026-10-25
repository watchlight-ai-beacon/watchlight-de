"""A sub-agent scope's time budget is granted exactly or refused, never shortened.

A budget a child NAMES must fit in the whole seconds its parent has left (and in
the parent's own budget); a larger one is refused with a ``TimeBudget``
violation whose reason states the seconds available. A child that names none
inherits the parent's remaining whole seconds. An expired parent refuses.

The step-by-step cases live in ``tests/fixtures/scope-time-budget.json``, which
the TypeScript suite runs too, so both lanes decide them identically. The wall
clock is pinned so every case is exact.
"""
import json
import pathlib
import time

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import AttenuationDenied, ScopeTokenError, Watchlight
from watchlight.scope_token import sign_scope_token

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "scope-time-budget.json").read_text(encoding="utf-8")
)
SECRET = "unit-test-secret-0123456789abcdef"


class Clock:
    """A wall clock the test moves by hand."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = Clock(1_800_000_000.0)
    monkeypatch.setattr(time, "time", c)
    return c


def _gov(tmp_path: pathlib.Path, **opts) -> Watchlight:
    return Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"), signing_secret=SECRET, **opts)


def _records(tmp_path: pathlib.Path) -> list[dict]:
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    return [json.loads(line) for line in audit.read_text().splitlines()]


def _attenuate(scope, budget):
    if budget is None:
        return scope.attenuate(tools=["t"])
    return scope.attenuate(tools=["t"], time_budget_seconds=budget)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_shared_time_budget_cases(tmp_path, clock, case):
    clock.now = case["start"]
    scope = _gov(tmp_path).scope(tools=["t"], time_budget_seconds=case["root_budget"])
    for i, step in enumerate(case["steps"]):
        clock.now = case["start"] + step["at"]
        where = f"step {i}"
        if step["expect"] == "granted":
            child = _attenuate(scope, step["time_budget_seconds"])
            assert child.time_budget_seconds == step["granted"], where
            # Granted exactly: the child lives its whole budget, inside its parent.
            assert child.expires_at <= scope.expires_at, where
            assert child.expires_at - clock.now >= step["granted"] - 1, where
            scope = child
        elif step["expect"] == "refused":
            with pytest.raises(AttenuationDenied) as err:
                _attenuate(scope, step["time_budget_seconds"])
            assert err.value.violations == step["violations"], where
            assert err.value.reason == step["reason"], where
            assert f"at most {step['available']} seconds" in str(err.value), where
        else:
            with pytest.raises(ScopeTokenError) as err:
                _attenuate(scope, step["time_budget_seconds"])
            assert err.value.code == "expired", where


def test_the_reported_probe_is_refused_not_silently_shortened(tmp_path, clock):
    root = _gov(tmp_path).scope(tools=["t"], time_budget_seconds=10)
    clock.now += 2.1
    with pytest.raises(AttenuationDenied) as err:
        root.attenuate(tools=["t"], time_budget_seconds=10)
    assert err.value.violations == ["TimeBudget"]
    assert "at most 7 seconds are available" in err.value.reason
    # The reason is fixed: it never echoes the requested value.
    assert "10" not in err.value.reason


def test_remaining_seconds_rounds_down_and_never_exceeds_the_budget(tmp_path, clock):
    clock.now = 1_800_000_000.0
    root = _gov(tmp_path).scope(tools=["t"], time_budget_seconds=10)
    assert root.remaining_seconds() == 10
    clock.now += 7.1
    assert root.remaining_seconds() == 2
    clock.now += 2.0
    assert root.remaining_seconds() == 0
    clock.now += 5
    assert root.remaining_seconds() == 0


def test_a_refused_budget_is_recorded_as_a_deny(tmp_path, clock):
    root = _gov(tmp_path).scope(tools=["t"], time_budget_seconds=10)
    clock.now += 2.1
    with pytest.raises(AttenuationDenied):
        root.attenuate(tools=["t"], time_budget_seconds=9, agent="worker")
    deny = [r for r in _records(tmp_path) if r.get("decision") == "Deny"]
    assert len(deny) == 1
    assert deny[0]["reason"] == "time_budget_seconds exceeds the parent's remaining time; at most 7 seconds are available"
    assert deny[0]["actor_chain"] == ["test-agent", "worker"]


def test_delegate_refuses_a_budget_the_parent_cannot_give(tmp_path, clock):
    g = _gov(tmp_path)
    root = g.scope(tools=["t"], time_budget_seconds=10)
    clock.now += 2.1
    with pytest.raises(AttenuationDenied) as err:
        g.delegate(root, "worker", tools=["t"], time_budget_seconds=8)
    assert err.value.violations == ["TimeBudget"]
    sub = g.delegate(root, "worker", tools=["t"])
    assert sub.delegated_scope.time_budget_seconds == 7


def test_a_preview_decides_the_budget_as_attenuate_does(tmp_path, clock):
    g = _gov(tmp_path)
    root = g.scope(tools=["t"], time_budget_seconds=10)
    clock.now += 2.1
    refused = root.preview_attenuate(tools=["t"], time_budget_seconds=8)
    assert not refused.allowed
    assert refused.violations == ["TimeBudget"]
    assert refused.reason == "time_budget_seconds exceeds the parent's remaining time; at most 7 seconds are available"
    inherited = root.preview_attenuate(tools=["t"])
    assert inherited.allowed and inherited.time_budget_seconds == 7
    assert root.attenuate(tools=["t"]).time_budget_seconds == 7


@pytest.mark.parametrize("bad", [0, -1, 2**32, 2**63])
def test_an_out_of_range_root_budget_is_refused(tmp_path, bad):
    with pytest.raises(ValueError):
        _gov(tmp_path).scope(tools=["t"], time_budget_seconds=bad)
    with pytest.raises(ValueError):
        _gov(tmp_path).preview_scope(tools=["t"], time_budget_seconds=bad)


@pytest.mark.parametrize("bad", [True, 1.5, "5", None])
def test_a_root_budget_that_is_not_an_int_is_refused(tmp_path, bad):
    with pytest.raises(TypeError):
        _gov(tmp_path).scope(tools=["t"], time_budget_seconds=bad)


INVALID = "time_budget_seconds must be a whole number of seconds from 1 to 4294967295"


@pytest.mark.parametrize(
    "bad",
    [0, -1, True, False, 1.5, 2.9, 600.0, float("nan"), float("inf"), "600", 2**32, 2**53, 2**63, [600]],
    ids=repr,
)
def test_an_invalid_child_budget_is_refused_before_the_engine_and_recorded(tmp_path, bad):
    g = _gov(tmp_path)
    root = g.scope(tools=["t"], time_budget_seconds=600)
    with pytest.raises(AttenuationDenied) as err:
        root.attenuate(tools=["t"], time_budget_seconds=bad, agent="worker")
    assert err.value.violations == ["TimeBudget"]
    assert err.value.reason == INVALID
    # Fixed and value-free: the reason never carries the input.
    assert str(err.value) == f"attenuation denied (TimeBudget): {INVALID}"
    deny = [r for r in _records(tmp_path) if r.get("decision") == "Deny"]
    assert len(deny) == 1 and deny[0]["reason"] == INVALID
    with pytest.raises(AttenuationDenied):
        g.delegate(root, "worker", tools=["t"], time_budget_seconds=bad)
    preview = root.preview_attenuate(tools=["t"], time_budget_seconds=bad)
    assert not preview.allowed and preview.reason == INVALID


def test_none_is_an_absent_child_budget_and_inherits(tmp_path, clock):
    root = _gov(tmp_path).scope(tools=["t"], time_budget_seconds=10)
    clock.now += 2.1
    assert root.attenuate(tools=["t"], time_budget_seconds=None).time_budget_seconds == 7


# Each chain is (level-1 budget, level-2 budget, level-3 budget); None = omitted.
CHAINS = [
    (None, None, None),
    (600, None, None),
    (599, None, None),
    (599, 599, None),
    (599, 598, None),
    (599, 598, 598),
    (599, 598, 597),
    (300, 300, None),
    (300, 299, 298),
    (None, 599, None),
    (None, 598, 597),
]


def _real_chain(g, budgets):
    """Create the chain at once; return each level's (allowed, budget, reason)."""
    out, scope = [], g.scope(tools=["t"], time_budget_seconds=600)
    for b in budgets:
        try:
            scope = _attenuate(scope, b)
            out.append((True, scope.time_budget_seconds, ""))
        except AttenuationDenied as e:
            out.append((False, 0, e.reason))
            break
    return out


def _preview_chain(g, budgets):
    out, preview = [], g.preview_scope(tools=["t"], time_budget_seconds=600)
    for b in budgets:
        preview = preview.preview_attenuate(tools=["t"], time_budget_seconds=b)
        out.append((preview.allowed, preview.time_budget_seconds if preview.allowed else 0, preview.reason))
        if not preview.allowed:
            break
    return out


@pytest.mark.parametrize("budgets", CHAINS, ids=repr)
def test_a_preview_chain_decides_exactly_as_the_real_chain(tmp_path, clock, budgets):
    clock.now = 1_800_000_000.25  # mid-second, as almost every real call is
    g = _gov(tmp_path)
    assert _preview_chain(g, budgets) == _real_chain(g, budgets)


# ── scope tokens ────────────────────────────────────────────────────


def test_a_scope_rebuilt_from_a_token_gives_no_more_than_the_token_has_left(tmp_path, clock):
    g = _gov(tmp_path)
    token = g.scope(tools=["t"], time_budget_seconds=600).attenuate(tools=["t"], time_budget_seconds=300).to_token(
        ttl_seconds=5
    )
    back = g.scope_from_token(token)
    assert back.time_budget_seconds == 300
    clock.now += 0.5
    with pytest.raises(AttenuationDenied) as err:
        back.attenuate(tools=["t"], time_budget_seconds=6)
    assert err.value.reason == "time_budget_seconds exceeds the parent's remaining time; at most 4 seconds are available"
    assert back.attenuate(tools=["t"]).time_budget_seconds == 4


def test_a_token_replay_is_not_refused_when_the_second_ticks_mid_replay(tmp_path, monkeypatch):
    """The chain is replayed at one instant: a child that was given exactly
    what its parent had left still replays when the clock moves between levels."""
    clock = Clock(1_800_000_000.0)
    monkeypatch.setattr(time, "time", clock)
    g = _gov(tmp_path)
    root = g.scope(tools=["t"], time_budget_seconds=600)
    clock.now += 0.5
    child = root.attenuate(tools=["t"], time_budget_seconds=root.remaining_seconds())
    assert child.time_budget_seconds == 599
    grandchild = child.attenuate(tools=["t"])
    token = grandchild.to_token()

    # Every read of the clock moves it on by 0.6 seconds.
    class Moving(Clock):
        def __call__(self) -> float:
            self.now += 0.6
            return self.now

    monkeypatch.setattr(time, "time", Moving(clock.now + 0.3))
    back = g.scope_from_token(token)
    assert back.depth == 2 and back.time_budget_seconds == grandchild.time_budget_seconds


def _signed(claims: dict) -> str:
    return sign_scope_token(claims, SECRET.encode())


def test_a_signed_chain_that_names_more_time_than_its_parent_is_refused(tmp_path):
    now = int(time.time())
    claims = {
        "agent": "test-agent",
        "root": {"tools": ["t"], "resources": [], "intents": [], "max_depth": 5, "time_budget_seconds": 100},
        "chain": [{"tools": ["t"], "resources": [], "intents": [], "time_budget_seconds": 200}],
        "depth": 1,
        "iat": now,
        "exp": now + 150,
    }
    with pytest.raises(AttenuationDenied) as err:
        _gov(tmp_path).scope_from_token(_signed(claims))
    assert err.value.violations == ["TimeBudget"]


@pytest.mark.parametrize("step_budget", [0, 2**32, 2**53 - 1])
def test_a_signed_chain_budget_out_of_range_is_malformed(tmp_path, step_budget):
    now = int(time.time())
    claims = {
        "agent": "test-agent",
        "root": {"tools": ["t"], "resources": [], "intents": [], "max_depth": 5, "time_budget_seconds": 600},
        "chain": [
            {"tools": ["t"], "resources": [], "intents": [], "time_budget_seconds": step_budget},
            {"tools": ["t"], "resources": [], "intents": [], "time_budget_seconds": 60},
        ],
        "depth": 2,
        "iat": now,
        "exp": now + 60,
    }
    with pytest.raises(ScopeTokenError) as err:
        _gov(tmp_path).scope_from_token(_signed(claims))
    assert err.value.code == "malformed"


@pytest.mark.parametrize("root_budget", [0, 2**32])
def test_a_signed_root_budget_out_of_range_is_malformed(tmp_path, root_budget):
    now = int(time.time())
    claims = {
        "agent": "test-agent",
        "root": {"tools": ["t"], "resources": [], "intents": [], "max_depth": 5, "time_budget_seconds": root_budget},
        "chain": [{"tools": ["t"], "resources": [], "intents": [], "time_budget_seconds": 60}],
        "depth": 1,
        "iat": now,
        "exp": now + 60,
    }
    with pytest.raises(ScopeTokenError) as err:
        _gov(tmp_path).scope_from_token(_signed(claims))
    assert err.value.code == "malformed"
