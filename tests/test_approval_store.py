"""Approval secret + seen-token store (Python), mirroring the TS suite.

Two defaults are per-process and neither may be upgraded silently:

* the signing key — random per process, so a token never crosses a process
  boundary and a restart invalidates outstanding approvals;
* the seen-token store — a dict in this process, so "single use" is per-replica
  unless a shared store is configured.

This exercises both: a configured secret makes a token portable, a wrong secret
refuses it, a shared store makes single-use hold across governors, and EVERY
store failure refuses rather than admits. It also pins the signed payload, which
is length-prefixed so no two different (principal, action, resource) triples can
sign the same bytes. Runs the real ``watchlight_engine``.
"""
import hashlib
import hmac
import time

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import APPROVAL_KEY_LABEL, APPROVAL_PAYLOAD_VERSION, ApprovalError, Watchlight
from watchlight._approval import derive_approval_key, normalize_approval_secret

WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);'
ANY = '@enforcement_effect("require_approval")\npermit(principal, action, resource);'
SECRET_A = "a-shared-approval-secret-32-bytes"
SECRET_B = "a-different-approval-secret-abcd"
WARNING = "approval store failed"


class SharedStore:
    """The shape an integrator supplies: a store several governors share, whose
    ``add`` is an atomic check-and-set reporting whether the id was new."""

    def __init__(self):
        self.seen = {}
        self.calls = []

    def add(self, id, expires_at):  # noqa: A002
        self.calls.append(("add", id, expires_at))
        if id in self.seen:
            return False
        self.seen[id] = expires_at
        return True


def _gov(tmp_path, name="a", policy=WIRE, **kw):
    g = Watchlight(agent="appr-agent", audit_dir=str(tmp_path / name / ".watchlight"), **kw)
    g.allow(policy, "wire")
    return g


def _held(g, approval=None):
    return g.authorize(action="wire", resource="acct/1", approval=approval)


# ── the signing key ─────────────────────────────────────────────────────────


def test_configured_secret_makes_a_token_cross_a_process(tmp_path):
    minter = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SharedStore())
    consumer = _gov(tmp_path, "b", approval_secret=SECRET_A, approval_store=SharedStore())
    d = _held(consumer, minter.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "Allow" and d["approved"] is True


def test_a_different_secret_refuses_fail_closed(tmp_path):
    minter = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SharedStore())
    other = _gov(tmp_path, "b", approval_secret=SECRET_B, approval_store=SharedStore())
    d = _held(other, minter.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval" and d["allowed"] is False and d["approved"] is False
    # The refusal never says WHICH check refused.
    assert d["reason"] == "approval required"


def test_token_secret_alone_configures_approvals(tmp_path):
    minter = _gov(tmp_path, "a", token_secret=SECRET_A, approval_store=SharedStore())
    consumer = _gov(tmp_path, "b", approval_secret=SECRET_A, approval_store=SharedStore())
    d = _held(consumer, minter.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "Allow" and d["approved"] is True
    assert APPROVAL_KEY_LABEL == "watchlight-de:approval-token:v1"


def test_a_weak_approval_secret_fails_closed_at_construction(tmp_path):
    with pytest.raises(ApprovalError) as exc:
        _gov(tmp_path, "a", approval_secret="too-short")
    assert exc.value.code == "weak_secret"
    assert "too-short" not in str(exc.value)  # never echoes the secret


def test_the_per_process_default_still_works_inside_one_process(tmp_path):
    g = _gov(tmp_path, "a")
    assert _held(g, g.mint_approval(action="wire", resource="acct/1"))["decision"] == "Allow"
    foreign = _gov(tmp_path, "b", approval_secret=SECRET_A)
    d = _held(foreign, g.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval"


def test_an_env_secret_configures_approvals(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_APPROVAL_SECRET", SECRET_A)
    minter = _gov(tmp_path, "a", approval_store=SharedStore())
    consumer = _gov(tmp_path, "b", approval_secret=SECRET_A, approval_store=SharedStore())
    d = _held(consumer, minter.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "Allow"


# ── single use across replicas ──────────────────────────────────────────────


def test_a_shared_store_refuses_a_replay_from_another_replica(tmp_path):
    store = SharedStore()
    a = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=store)
    b = _gov(tmp_path, "b", approval_secret=SECRET_A, approval_store=store)
    token = a.mint_approval(action="wire", resource="acct/1")
    assert _held(a, token)["decision"] == "Allow"
    second = _held(b, token)
    assert second["decision"] == "NeedsApproval" and second["approved"] is False


def test_separate_stores_admit_the_same_token_once_on_each(tmp_path):
    """The gap the shared store closes — pinned so it cannot become a silent default."""
    c = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SharedStore())
    d = _gov(tmp_path, "b", approval_secret=SECRET_A, approval_store=SharedStore())
    token = c.mint_approval(action="wire", resource="acct/1")
    assert _held(c, token)["decision"] == "Allow"
    assert _held(d, token)["decision"] == "Allow"


def test_the_store_id_is_exp_dot_nonce_never_the_signature(tmp_path):
    store = SharedStore()
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=store)
    token = g.mint_approval(action="wire", resource="acct/1")
    _held(g, token)
    exp, nonce, sig = token.split(".")
    add = next(c for c in store.calls if c[0] == "add")
    assert add[1] == f"{exp}.{nonce}"
    assert sig not in str(store.calls)
    assert add[2] == int(exp) > int(time.time() * 1000)


def test_the_reservation_is_a_single_call(tmp_path):
    """One atomic check-and-set — never a read followed by a write, which would
    be a window that concurrent consumes of one token could all pass through."""
    store = SharedStore()
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=store)
    _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert [c[0] for c in store.calls] == ["add"]


def test_add_returning_false_refuses(tmp_path):
    class Conditional:
        def add(self, id, expires_at):  # noqa: A002
            return False  # an atomic insert that found the row already present

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Conditional())
    d = _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval"


@pytest.mark.parametrize("value", [None, 1, "ok", object()])
def test_a_store_that_does_not_report_reservation_refuses(tmp_path, capsys, value):
    """A store whose `add` will not say whether the id was new cannot enforce
    single use, so it never gets to admit one."""

    class Silent:
        def add(self, id, expires_at):  # noqa: A002
            return value

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Silent())
    assert _held(g, g.mint_approval(action="wire", resource="acct/1"))["decision"] == "NeedsApproval"
    assert "newly reserved" in capsys.readouterr().err


def test_the_in_memory_default_is_still_single_use_within_one_process(tmp_path):
    g = _gov(tmp_path, "a")
    token = g.mint_approval(action="wire", resource="acct/1")
    assert _held(g, token)["decision"] == "Allow"
    assert _held(g, token)["decision"] == "NeedsApproval"


# ── fail closed ─────────────────────────────────────────────────────────────


class Boom:
    def add(self, id, expires_at):  # noqa: A002
        raise RuntimeError("store down")


def test_a_raising_store_refuses_and_is_reported_without_the_error(tmp_path, capsys):
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Boom())
    d = _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval"  # refused, never admitted
    err = capsys.readouterr().err
    assert WARNING in err and "store down" not in err


def test_a_broken_store_is_reported_once(tmp_path, capsys):
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Boom())
    for _ in range(3):
        _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert capsys.readouterr().err.count(WARNING) == 1


def test_an_async_store_refuses_rather_than_admitting(tmp_path, capsys, recwarn):
    """The decision path is synchronous, so a coroutine can never be awaited."""

    class AsyncStore:
        async def add(self, id, expires_at):  # noqa: A002
            return True

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=AsyncStore())
    assert _held(g, g.mint_approval(action="wire", resource="acct/1"))["decision"] == "NeedsApproval"
    assert "awaitable" in capsys.readouterr().err
    # The coroutine is closed, so it never surfaces as "never awaited".
    assert not [w for w in recwarn if "never awaited" in str(w.message)]


# ── concurrency: one token, one Allow ───────────────────────────────────────


def test_parallel_consumes_of_one_token_yield_exactly_one_allow(tmp_path):
    """The default store reserves atomically, so a single agent fanning out
    parallel tool calls after ONE human confirmation cannot reuse the token."""
    import concurrent.futures

    g = _gov(tmp_path, "a")
    token = g.mint_approval(action="wire", resource="acct/1")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _held(g, token)["decision"], range(8)))
    assert results.count("Allow") == 1
    assert results.count("NeedsApproval") == 7


def test_the_expiry_sweep_under_contention_never_refuses_a_valid_approval(tmp_path):
    """The default store prunes expired rows on every reservation. Two threads
    sweeping at once must not trip over each other: a sweep that raised would be
    caught and the approval REFUSED — fail-closed, but a valid approval denied.
    """
    import concurrent.futures
    import sys

    from watchlight._approval import _MemoryApprovalStore

    store = _MemoryApprovalStore()
    stale = int(time.time() * 1000) - 60_000
    # Thousands of expired rows, so every reservation does real sweeping work
    # and threads are very likely to be inside the sweep together.
    store._seen.update({f"stale-{i}": stale for i in range(5_000)})

    fresh = int(time.time() * 1000) + 120_000
    switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # maximise interleaving
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            reserved = list(pool.map(lambda i: store.add(f"fresh-{i}", fresh), range(12)))
    finally:
        sys.setswitchinterval(switch)

    # Every id is distinct, so every reservation is new: none may be refused.
    assert reserved == [True] * 12
    assert all(f"fresh-{i}" in store._seen for i in range(12))
    assert not any(k.startswith("stale-") for k in store._seen)  # the sweep still ran


def test_the_sweep_runs_on_the_governed_path_without_spurious_denials(tmp_path, capsys):
    """The same, end to end: distinct valid approvals across threads, with the
    process-wide default store already holding expired rows."""
    import concurrent.futures
    import sys

    from watchlight._approval import _DEFAULT_STORE

    stale = int(time.time() * 1000) - 60_000
    _DEFAULT_STORE._seen.update({f"swept-{i}": stale for i in range(2_000)})

    g = _gov(tmp_path, "a", policy=ANY)
    tokens = [g.mint_approval(principal="U", action="a", resource=f"r{i}") for i in range(12)]
    switch = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            decisions = list(
                pool.map(
                    lambda it: g.authorize(
                        principal="U", action="a", resource=f"r{it[0]}", approval=it[1]
                    )["decision"],
                    enumerate(tokens),
                )
            )
    finally:
        sys.setswitchinterval(switch)

    assert decisions == ["Allow"] * 12          # no valid approval spuriously denied
    assert "approval store" not in capsys.readouterr().err  # and nothing warned


def test_parallel_consumes_against_a_latency_injected_store(tmp_path):
    """Same guarantee when the store itself is slow, provided its `add` is the
    atomic check-and-set the contract requires."""
    import concurrent.futures
    import threading

    class SlowAtomicStore:
        def __init__(self):
            self._seen = set()
            self._lock = threading.Lock()

        def add(self, id, expires_at):  # noqa: A002
            time.sleep(0.01)  # latency between the caller and the store
            with self._lock:  # the store's own atomicity, as the contract requires
                if id in self._seen:
                    return False
                self._seen.add(id)
                return True

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SlowAtomicStore())
    token = g.mint_approval(action="wire", resource="acct/1")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _held(g, token)["decision"], range(8)))
    assert results.count("Allow") == 1


def test_a_forged_token_never_reaches_the_store(tmp_path):
    store = SharedStore()
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=store)
    token = g.mint_approval(action="wire", resource="acct/1")
    exp, nonce, _sig = token.split(".")
    assert _held(g, f"{exp}.{nonce}.{'0' * 64}")["decision"] == "NeedsApproval"
    assert store.calls == []
    # The genuine token still works — its id was not burned by the forgery.
    assert _held(g, token)["decision"] == "Allow"


def test_binding_and_ttl_are_unchanged(tmp_path):
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SharedStore())
    wrong = g.mint_approval(action="wire", resource="acct/OTHER")
    assert _held(g, wrong)["decision"] == "NeedsApproval"
    expired = g.mint_approval(action="wire", resource="acct/1", ttl_ms=-1)
    assert _held(g, expired)["decision"] == "NeedsApproval"


# ── the signed payload is unambiguous ───────────────────────────────────────


def _any_gov(tmp_path, name):
    """Every action needs approval, so only the TOKEN decides the verdict and a
    payload collision would show up as an Allow."""
    return _gov(tmp_path, name, policy=ANY, approval_secret=SECRET_A, approval_store=SharedStore())


def test_a_field_boundary_cannot_be_shifted(tmp_path):
    g = _any_gov(tmp_path, "a")
    token = g.mint_approval(principal="U", action="a", resource="r1 r2")
    shifted = g.authorize(principal="U", action="a r1", resource="r2", approval=token)
    assert shifted["decision"] == "NeedsApproval" and shifted["approved"] is False
    # …and the same token still verifies for the triple it was minted for.
    exact = g.authorize(principal="U", action="a", resource="r1 r2", approval=token)
    assert exact["decision"] == "Allow"


def test_the_principal_action_boundary_cannot_be_shifted(tmp_path):
    g = _any_gov(tmp_path, "a")
    token = g.mint_approval(principal="U u2", action="a", resource="r")
    assert g.authorize(principal="U", action="u2 a", resource="r", approval=token)["decision"] == "NeedsApproval"


def test_awkward_fields_round_trip(tmp_path):
    g = _any_gov(tmp_path, "a")
    ch = {
        "principal": 'User::"a b\\c" 12:34',
        "action": "wire funds",
        "resource": 'acct/"x y"\\z — ünïcode',
    }
    d = g.authorize(**ch, approval=g.mint_approval(**ch))
    assert d["decision"] == "Allow" and d["approved"] is True


def test_a_field_shaped_like_a_length_prefix_round_trips(tmp_path):
    g = _any_gov(tmp_path, "a")
    ch = {"principal": "3:abc", "action": "5:defgh", "resource": "0:"}
    assert g.authorize(**ch, approval=g.mint_approval(**ch))["decision"] == "Allow"
    near = g.authorize(
        principal="3:abc5", action=":defgh", resource="0:", approval=g.mint_approval(**ch)
    )
    assert near["decision"] == "NeedsApproval"


def test_a_token_under_the_previous_payload_format_does_not_verify(tmp_path):
    """The version marker makes the format change a refusal, never a silent
    reinterpretation."""
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=SharedStore())
    key = derive_approval_key(normalize_approval_secret(SECRET_A))
    exp = int(time.time() * 1000) + 120_000
    nonce = "0011223344556677"
    legacy = hmac.new(
        key, f"appr-agent wire acct/1 {exp} {nonce}".encode(), hashlib.sha256
    ).hexdigest()
    assert _held(g, f"{exp}.{nonce}.{legacy}")["decision"] == "NeedsApproval"
    assert APPROVAL_PAYLOAD_VERSION == "watchlight-de:approval:v1"


def test_the_payload_is_identical_to_the_typescript_lane(tmp_path):
    """Pinned bytes: both packages sign `<utf8 len>:<field>` in this order, so a
    token minted by either verifies in the other under the same secret."""
    from watchlight._approval import _payload_for

    assert _payload_for("U", "a", "r", 1, "n") == (
        b"25:watchlight-de:approval:v11:U1:a1:r1:11:n"
    )
