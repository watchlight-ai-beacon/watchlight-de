"""Serialisable attenuated scopes — ``Scope.to_token()`` / ``Watchlight.scope_from_token()``.

Runs the real ``watchlight-engine``: the receiving side must REPLAY the chain
through the engine's strict-subset validator, so a widened chain is refused
even with a valid signature. Cross-lane: ``tests/fixtures/scope-token.json`` is
shared with the TypeScript suite — both lanes must reproduce the canonical JSON
and the token byte-for-byte.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import time

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import AttenuationDenied, ScopeTokenError, Watchlight
from watchlight.scope_token import (
    MAX_TOKEN_LENGTH,
    SCOPE_TOKEN_PREFIX,
    canonical_json,
    normalize_claims,
    sign_scope_token,
    verify_scope_token,
)

SECRET = "unit-test-secret-0123456789abcdef"
FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "scope-token.json").read_text())


@pytest.fixture(autouse=True)
def _no_env_secret(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_TOKEN_SECRET", raising=False)


def _gov(tmp_path: pathlib.Path, name: str = "a", **kw) -> Watchlight:
    kw.setdefault("token_secret", SECRET)
    return Watchlight(agent="test-agent", audit_dir=str(tmp_path / name / ".watchlight"), **kw)


def _now() -> int:
    return int(time.time())


def _base(**over) -> dict:
    claims = {
        "agent": "test-agent",
        "root": {"tools": ["read"], "resources": [], "intents": [], "max_depth": 5, "time_budget_seconds": 600},
        "chain": [],
        "depth": 0,
        "iat": _now(),
        "exp": _now() + 60,
    }
    claims.update(over)
    return claims


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _hand_sign(raw_payload: str) -> str:
    body = f"{SCOPE_TOKEN_PREFIX}.{_b64url(raw_payload.encode())}"
    sig = hmac.new(SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64url(sig)}"


# ── round trip ──────────────────────────────────────────────────────────────


def test_round_trip_rebuilds_the_scope_through_the_engine(tmp_path):
    g = _gov(tmp_path)
    root = g.scope(tools=["read", "search", "write"], resources=["docs/*"], intents=["research"], time_budget_seconds=600)
    grandchild = root.attenuate(tools=["read", "search"]).attenuate(tools=["read"], time_budget_seconds=300)
    token = grandchild.to_token()

    assert token.startswith(f"{SCOPE_TOKEN_PREFIX}.") and token.count(".") == 2
    back = g.scope_from_token(token)
    assert back.depth == 2
    assert sorted(back.allowed_tools) == ["read"]
    assert sorted(back.allowed_resources) == ["docs/*"] and sorted(back.allowed_intents) == ["research"]
    assert back.time_budget_seconds == 300
    assert back.expires_at <= grandchild.expires_at
    assert back.attenuate(tools=["read"]).depth == 3
    with pytest.raises(AttenuationDenied):
        back.attenuate(tools=["read", "write"])


def test_payload_carries_only_the_documented_claims(tmp_path):
    g = _gov(tmp_path)
    child = g.scope(tools=["read", "search"], time_budget_seconds=600).attenuate(tools=["read"])
    token = child.to_token()
    seg = token.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    assert sorted(payload) == ["agent", "chain", "depth", "exp", "iat", "root"]
    assert "audit" not in token and SECRET not in token and str(tmp_path) not in json.dumps(payload)
    # per-level GRANTED dims, never a raw request
    assert [sorted(s["tools"]) for s in payload["chain"]] == [["read"]]


def test_second_process_with_the_same_secret_accepts_the_token(tmp_path):
    token = _gov(tmp_path, "one").scope(tools=["read", "search"], time_budget_seconds=600).attenuate(tools=["read"]).to_token()
    worker = _gov(tmp_path, "two")  # fresh engine + fresh audit dir
    back = worker.scope_from_token(token)
    assert back.depth == 1 and back.allowed_tools == ["read"]
    # the worker's own trail records the rebuilt tree (root + replayed attenuation)
    recs = [json.loads(l) for l in (tmp_path / "two" / ".watchlight" / "audit.jsonl").read_text().splitlines()]
    assert [r["depth"] for r in recs if r.get("event") == "attenuation"] == [0, 1]


# ── the three acceptance criteria ───────────────────────────────────────────


def test_tampered_payload_is_rejected(tmp_path):
    g = _gov(tmp_path)
    token = g.scope(tools=["read"], time_budget_seconds=600).to_token()
    v, p, s = token.split(".")
    flipped = p[:10] + ("B" if p[10] == "A" else "A") + p[11:]
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(f"{v}.{flipped}.{s}")
    assert ei.value.code == "signature"
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(f"{v}.{p}.{s[:-1]}{'B' if s.endswith('A') else 'A'}")
    assert ei.value.code == "signature"
    with pytest.raises(ScopeTokenError) as ei:
        _gov(tmp_path, "other", token_secret="another-secret-0123456789abcdef").scope_from_token(token)
    assert ei.value.code == "signature"


def test_widened_scope_with_a_valid_signature_is_refused_by_the_engine(tmp_path):
    g = _gov(tmp_path)
    widened = sign_scope_token(
        _base(
            chain=[{"tools": ["read", "delete"], "resources": [], "intents": [], "time_budget_seconds": 600}],
            depth=1,
        ),
        SECRET.encode(),
    )
    with pytest.raises(AttenuationDenied) as ei:  # the ENGINE says no — not the token check
        g.scope_from_token(widened)
    assert "AllowedTools" in ei.value.violations


def test_expired_token_is_rejected(tmp_path):
    g = _gov(tmp_path)
    expired = sign_scope_token(_base(iat=_now() - 700, exp=_now() - 100), SECRET.encode())
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(expired)
    assert ei.value.code == "expired"


# ── fail-closed + hardening ─────────────────────────────────────────────────


def test_no_secret_fails_closed(tmp_path):
    bare = Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"))
    with pytest.raises(ScopeTokenError) as ei:
        bare.scope(tools=["read"]).to_token()
    assert ei.value.code == "no_secret" and "token_secret" in str(ei.value)
    with pytest.raises(ScopeTokenError) as ei:
        bare.scope_from_token("wls1.x.y")
    assert ei.value.code == "no_secret"


def test_weak_secret_is_refused_and_not_echoed(tmp_path):
    with pytest.raises(ScopeTokenError) as ei:
        Watchlight(agent="x", audit_dir=str(tmp_path), token_secret="short")
    assert ei.value.code == "weak_secret" and "short" not in str(ei.value)


def test_env_secret_is_honoured(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_TOKEN_SECRET", SECRET)
    g = Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"))
    assert g.scope_from_token(g.scope(tools=["read"]).to_token()).depth == 0


def test_token_is_bound_to_the_agent(tmp_path):
    token = _gov(tmp_path).scope(tools=["read"]).to_token()
    other = Watchlight(agent="other-agent", audit_dir=str(tmp_path / "o"), token_secret=SECRET)
    with pytest.raises(ScopeTokenError) as ei:
        other.scope_from_token(token)
    assert ei.value.code == "identity"


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda v, p, s: f"wls2.{p}.{s}", "version"),
        (lambda v, p, s: f"{v}.{p}", "malformed"),
        (lambda v, p, s: f"{v}.{p}==.{s}", "malformed"),
        (lambda v, p, s: f"{v}.{p}+/.{s}", "malformed"),
        (lambda v, p, s: f"{v}.{'A' * MAX_TOKEN_LENGTH}.{s}", "too_large"),
    ],
)
def test_format_hardening(tmp_path, mutate, code):
    g = _gov(tmp_path)
    v, p, s = g.scope(tools=["read"]).to_token().split(".")
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(mutate(v, p, s))
    assert ei.value.code == code


def test_non_string_token_is_malformed(tmp_path):
    with pytest.raises(ScopeTokenError) as ei:
        _gov(tmp_path).scope_from_token(12345)  # type: ignore[arg-type]
    assert ei.value.code == "malformed"


@pytest.mark.parametrize(
    "over, code",
    [
        ({"iat": _now() + 3600, "exp": _now() + 3900}, "future_iat"),
        ({"iat": _now(), "exp": _now() + 601}, "lifetime"),
        ({"root": {"tools": ["read"], "resources": [], "intents": [], "max_depth": 9, "time_budget_seconds": 600}}, "malformed"),
        ({"depth": 1}, "malformed"),
    ],
)
def test_claim_hardening(tmp_path, over, code):
    g = _gov(tmp_path)
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(sign_scope_token(_base(**over), SECRET.encode()))
    assert ei.value.code == code


def test_unknown_fields_and_non_canonical_payloads_are_rejected(tmp_path):
    g = _gov(tmp_path)
    extra = dict(normalize_claims(_base()), extra="x")
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(_hand_sign(canonical_json(extra)))
    assert ei.value.code == "malformed"
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(_hand_sign(json.dumps(_base(), indent=1)))  # valid HMAC, but whitespace
    assert ei.value.code == "malformed"


def test_ttl_is_capped_at_the_scope_lifetime(tmp_path):
    g = _gov(tmp_path)
    root = g.scope(tools=["read"], time_budget_seconds=120)
    claims = verify_scope_token(root.to_token(ttl_seconds=999_999), SECRET.encode(), agent="test-agent")
    assert claims["exp"] <= root.expires_at and claims["exp"] - claims["iat"] <= 120
    with pytest.raises(ScopeTokenError) as ei:
        root.to_token(ttl_seconds=0)
    assert ei.value.code == "lifetime"


# ── cross-lane fixture (shared with ts/test/scope-token.test.mjs) ───────────


def test_fixture_canonical_json_matches_byte_for_byte():
    assert canonical_json(normalize_claims(FIXTURE["claims"])) == FIXTURE["canonical"]


def test_fixture_token_matches_byte_for_byte():
    assert sign_scope_token(FIXTURE["claims"], FIXTURE["secret"].encode()) == FIXTURE["token"]


def test_fixture_verifies_and_yields_normalised_claims():
    claims = verify_scope_token(FIXTURE["token"], FIXTURE["secret"].encode(), agent=FIXTURE["agent"], now=FIXTURE["now"])
    assert canonical_json(claims) == FIXTURE["canonical"]


def test_fixture_replays_through_the_engine(tmp_path):
    g = Watchlight(agent=FIXTURE["agent"], audit_dir=str(tmp_path / ".watchlight"), token_secret=FIXTURE["secret"])
    scope = g.scope_from_token(FIXTURE["token"])
    assert scope.depth == 2 and scope.allowed_tools == ["read_file"]
    with pytest.raises(ScopeTokenError) as ei:
        _gov(tmp_path, "wrong", token_secret=FIXTURE["secret"]).scope_from_token(FIXTURE["token"])
    assert ei.value.code == "identity"


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_fixture_edge_cases_match_byte_for_byte(case):
    secret = FIXTURE["secret"].encode()
    assert canonical_json(normalize_claims(case["claims"])) == case["canonical"]
    assert sign_scope_token(case["claims"], secret) == case["token"]
    claims = verify_scope_token(case["token"], secret, agent=FIXTURE["agent"], now=FIXTURE["now"])
    assert canonical_json(claims) == case["canonical"]


def test_spent_rebuilt_scope_refuses_attenuate_and_to_token(tmp_path):
    g = _gov(tmp_path)
    live = g.scope_from_token(g.scope(tools=["read", "search"], time_budget_seconds=600).attenuate(tools=["read"]).to_token())
    live._bind_expiry(_now() - 1)  # simulate the token's exp having passed
    assert live.expired is True
    with pytest.raises(ScopeTokenError) as ei:
        live.attenuate(tools=["read"])
    assert ei.value.code == "expired" and str(ei.value).endswith("scope has expired")
    with pytest.raises(ScopeTokenError) as ei:
        live.to_token()
    assert ei.value.code == "expired"
    with pytest.raises(ScopeTokenError):
        live.assert_active()


def test_blank_env_secret_is_treated_as_unset(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_TOKEN_SECRET", "   ")
    g = Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"))  # must not raise
    with pytest.raises(ScopeTokenError) as ei:
        g.scope(tools=["read"]).to_token()
    assert ei.value.code == "no_secret"
    assert Watchlight(agent="test-agent", audit_dir=str(tmp_path / "b"), token_secret="").scope(tools=["read"]).depth == 0


def test_bytearray_secret_is_copied(tmp_path):
    key = bytearray(SECRET.encode())
    g = Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"), token_secret=key)
    key[:] = b"\0" * len(key)
    assert _gov(tmp_path, "v").scope_from_token(g.scope(tools=["read"]).to_token()).depth == 0


def test_trailing_newline_in_token_segment_is_malformed(tmp_path):
    g = _gov(tmp_path)
    v, p, s = g.scope(tools=["read"]).to_token().split(".")
    with pytest.raises(ScopeTokenError) as ei:
        g.scope_from_token(f"{v}.{p}.{s}\n")
    assert ei.value.code == "malformed"


def test_token_rebuilt_scope_reports_through_the_audit_sink(tmp_path):
    token = _gov(tmp_path, "src").scope(tools=["read", "search"], time_budget_seconds=600).attenuate(tools=["read"]).to_token()
    sunk: list[dict] = []
    g = Watchlight(agent="test-agent", audit_dir=str(tmp_path / "w" / ".watchlight"), audit_sink=sunk.append, token_secret=SECRET)
    g.scope_from_token(token).attenuate(tools=["read"])
    sunk_att = [r for r in sunk if r.get("event") == "attenuation"]
    assert [r["depth"] for r in sunk_att] == [0, 1, 2]  # rebuilt root, replayed level, further attenuation
    file_att = [
        r for r in (json.loads(l) for l in (tmp_path / "w" / ".watchlight" / "audit.jsonl").read_text().splitlines())
        if r.get("event") == "attenuation"
    ]
    assert [r["node_id"] for r in file_att] == [r["node_id"] for r in sunk_att]
    blob = json.dumps(sunk)
    assert "wls1." not in blob and SECRET not in blob
