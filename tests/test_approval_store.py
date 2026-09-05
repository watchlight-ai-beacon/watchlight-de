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
    """The shape an integrator supplies: a store several governors share."""

    def __init__(self):
        self.seen = {}
        self.calls = []

    def has(self, id):  # noqa: A002
        self.calls.append(("has", id))
        return id in self.seen

    def add(self, id, expires_at):  # noqa: A002
        self.calls.append(("add", id, expires_at))
        self.seen[id] = expires_at


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


def test_add_returning_false_refuses(tmp_path):
    class Conditional:
        def has(self, id):  # noqa: A002
            return False

        def add(self, id, expires_at):  # noqa: A002
            return False  # an atomic insert that found the row already present

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Conditional())
    d = _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval"


def test_the_in_memory_default_is_still_single_use_within_one_process(tmp_path):
    g = _gov(tmp_path, "a")
    token = g.mint_approval(action="wire", resource="acct/1")
    assert _held(g, token)["decision"] == "Allow"
    assert _held(g, token)["decision"] == "NeedsApproval"


# ── fail closed ─────────────────────────────────────────────────────────────


class Boom:
    def __init__(self, which):
        self.which = which

    def has(self, id):  # noqa: A002
        if self.which == "has":
            raise RuntimeError("store down")
        return False

    def add(self, id, expires_at):  # noqa: A002
        if self.which == "add":
            raise RuntimeError("store down")


@pytest.mark.parametrize("which", ["has", "add"])
def test_a_raising_store_refuses_and_is_reported_without_the_error(tmp_path, capsys, which):
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Boom(which))
    d = _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert d["decision"] == "NeedsApproval"  # refused, never admitted
    err = capsys.readouterr().err
    assert WARNING in err and "store down" not in err


def test_a_broken_store_is_reported_once(tmp_path, capsys):
    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=Boom("has"))
    for _ in range(3):
        _held(g, g.mint_approval(action="wire", resource="acct/1"))
    assert capsys.readouterr().err.count(WARNING) == 1


def test_an_async_store_refuses_rather_than_admitting(tmp_path, capsys, recwarn):
    """The decision path is synchronous, so a coroutine can never be awaited."""

    class AsyncStore:
        async def has(self, id):  # noqa: A002
            return False

        async def add(self, id, expires_at):  # noqa: A002
            return None

    g = _gov(tmp_path, "a", approval_secret=SECRET_A, approval_store=AsyncStore())
    assert _held(g, g.mint_approval(action="wire", resource="acct/1"))["decision"] == "NeedsApproval"
    assert WARNING in capsys.readouterr().err
    # The coroutine is closed, so it never surfaces as "never awaited".
    assert not [w for w in recwarn if "never awaited" in str(w.message)]


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
