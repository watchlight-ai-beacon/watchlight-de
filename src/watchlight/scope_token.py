"""Serialisable attenuated scopes — the wire format behind ``Scope.to_token()``
and ``Watchlight.scope_from_token()``.

A scope token lets a scope derived in one process be re-established in another
(a queue worker, a scheduler) WITHOUT trusting the job payload: the token is an
HMAC over the canonical scope claims, and the receiving side re-runs the
engine's strict-subset attenuation for every level of the chain before the scope
is usable. The token is integrity, not authority — the engine, not the token,
decides whether the requested chain is a subset.

This module is pure (no engine, no I/O): canonicalisation, signing and
verification. It mirrors ``ts/src/scope-token.ts`` byte-for-byte.

Token format::

    wls1.<base64url(canonical JSON claims)>.<base64url(HMAC-SHA256)>

* ``wls1`` is the format version; unknown versions are rejected.
* The HMAC key is the raw bytes of the token secret. The HMAC input is the ASCII
  bytes of ``"wls1." + base64url(payload)`` — so the version is signed.
* base64url is RFC 4648 §5 with NO padding; non-canonical encodings and padding
  are rejected.
* The whole token is bounded to :data:`MAX_TOKEN_LENGTH` characters.

Claims::

    {
      "agent": "<governor identity>",
      "chain": [ {"intents": [...], "resources": [...], "time_budget_seconds": N, "tools": [...]}, ... ],
      "depth": <len(chain)>,
      "exp":   <epoch seconds>,
      "iat":   <epoch seconds>,
      "root":  {"intents": [...], "max_depth": N, "resources": [...], "time_budget_seconds": N, "tools": [...]}
    }

``root`` is the root scope's grant; ``chain[i]`` is the ENGINE-GRANTED scope at
depth ``i+1`` (never a raw request), which the verifier replays as the request
for that level. Exactly these keys, no others.

Canonical JSON (both lanes MUST agree byte-for-byte):

* Object keys sorted by Unicode code point; all keys are ASCII.
* No whitespace anywhere.
* ``tools``, ``resources``, ``intents`` are sets: sorted by Unicode code point,
  duplicates preserved.
* Integers only for numbers (plain decimal); every number is a non-negative
  integer below 2**53.
* Strings escaped per RFC 8259 with the minimal escape set: ``"`` ``\\`` and
  control characters U+0000–U+001F (``\\b \\f \\n \\r \\t``, else ``\\u00XX``);
  everything else — including non-ASCII — is emitted literally (UTF-8). Strings
  must be valid Unicode scalar values (no lone surrogates).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Optional, Sequence, Union

__all__ = [
    "ScopeTokenError",
    "SCOPE_TOKEN_PREFIX",
    "MAX_TOKEN_LENGTH",
    "MAX_IAT_SKEW_SECONDS",
    "MIN_SECRET_BYTES",
    "MAX_CHAIN_LENGTH",
    "canonical_json",
    "normalize_claims",
    "sign_scope_token",
    "verify_scope_token",
]

#: Token format version prefix.
SCOPE_TOKEN_PREFIX = "wls1"
#: Upper bound on a token's length (characters); longer input is rejected unparsed.
MAX_TOKEN_LENGTH = 16_384
#: Tolerated clock skew for a token whose ``iat`` is in the future (seconds).
MAX_IAT_SKEW_SECONDS = 60
#: Minimum token-secret length (bytes).
MIN_SECRET_BYTES = 16
#: Maximum chain length a token may carry (mirrors the DE depth ceiling).
MAX_CHAIN_LENGTH = 5

_HMAC_BYTES = 32
_MAX_SAFE_INT = 2**53 - 1
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")

_STEP_KEYS = ("intents", "resources", "time_budget_seconds", "tools")
_ROOT_KEYS = _STEP_KEYS + ("max_depth",)
_CLAIM_KEYS = ("agent", "chain", "depth", "exp", "iat", "root")


class ScopeTokenError(PermissionError):
    """Raised when a scope token cannot be minted or is rejected. The message
    never contains the token, its claims, or the secret."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"scope token rejected ({code}): {message}")


# ── canonical JSON ──────────────────────────────────────────────────────────


def _canonical_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ScopeTokenError("malformed", "string is not valid Unicode") from None
    # ensure_ascii=False emits exactly the minimal RFC 8259 escape set.
    return json.dumps(s, ensure_ascii=False)


def canonical_json(value: Any) -> str:
    """Serialise a claims value to canonical JSON. Lists are emitted in the order
    given — callers sort set-valued lists first (see :func:`normalize_claims`)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not 0 <= value <= _MAX_SAFE_INT:
            raise ScopeTokenError("malformed", "numbers must be non-negative integers below 2**53")
        return str(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        # Python sorts str by code point — the same order the TS lane uses.
        keys = sorted(value)
        return "{" + ",".join(f"{_canonical_string(k)}:{canonical_json(value[k])}" for k in keys) + "}"
    raise ScopeTokenError("malformed", "unsupported value in claims")


def _sorted_set(xs: Sequence[str]) -> list[str]:
    return sorted(xs)


def _normalize_step(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "tools": _sorted_set(step["tools"]),
        "resources": _sorted_set(step["resources"]),
        "intents": _sorted_set(step["intents"]),
        "time_budget_seconds": step["time_budget_seconds"],
    }


def normalize_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``claims`` with every set-valued list sorted — the exact
    object whose canonical JSON is signed."""
    root = _normalize_step(claims["root"])
    root["max_depth"] = claims["root"]["max_depth"]
    return {
        "agent": claims["agent"],
        "root": root,
        "chain": [_normalize_step(s) for s in claims["chain"]],
        "depth": claims["depth"],
        "iat": claims["iat"],
        "exp": claims["exp"],
    }


# ── secret handling ─────────────────────────────────────────────────────────


def normalize_secret(secret: Union[str, bytes, bytearray, None]) -> Optional[bytes]:
    """Coerce a configured secret to bytes and enforce the minimum length. Never
    echoes the secret."""
    if secret is None:
        return None
    raw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    if len(raw) < MIN_SECRET_BYTES:
        raise ScopeTokenError("weak_secret", f"token secret must be at least {MIN_SECRET_BYTES} bytes")
    return raw


def require_secret(secret: Optional[bytes]) -> bytes:
    if not secret:
        raise ScopeTokenError(
            "no_secret",
            "scope tokens require a token secret — construct Watchlight(token_secret=...) "
            "(or set WATCHLIGHT_TOKEN_SECRET); there is no default",
        )
    return secret


# ── sign / verify ───────────────────────────────────────────────────────────


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Strict base64url decode: alphabet-only, no padding, canonical encoding."""
    if not s or not _B64URL.match(s) or len(s) % 4 == 1:
        raise ScopeTokenError("malformed", "token segment is not base64url")
    padded = s + "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
    except (ValueError, TypeError):
        raise ScopeTokenError("malformed", "token segment is not base64url") from None
    if _b64url(raw) != s:
        raise ScopeTokenError("malformed", "token segment is not canonical base64url")
    return raw


def _hmac(secret: bytes, signed_part: str) -> bytes:
    return hmac.new(secret, signed_part.encode("utf-8"), hashlib.sha256).digest()


def sign_scope_token(claims: dict[str, Any], secret: bytes) -> str:
    """Mint a token over ``claims`` (normalised + canonicalised here)."""
    payload = canonical_json(normalize_claims(claims)).encode("utf-8")
    signed_part = f"{SCOPE_TOKEN_PREFIX}.{_b64url(payload)}"
    token = f"{signed_part}.{_b64url(_hmac(secret, signed_part))}"
    if len(token) > MAX_TOKEN_LENGTH:
        raise ScopeTokenError("too_large", f"token exceeds {MAX_TOKEN_LENGTH} characters")
    return token


def _expect_string_list(v: Any, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ScopeTokenError("malformed", f"{what} must be a list of strings")
    return v


def _expect_int(v: Any, what: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= _MAX_SAFE_INT:
        raise ScopeTokenError("malformed", f"{what} must be a non-negative integer")
    return v


def _expect_exact_keys(obj: Any, keys: Sequence[str], what: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ScopeTokenError("malformed", f"{what} must be an object")
    if sorted(obj) != sorted(keys):
        raise ScopeTokenError("malformed", f"{what} has unexpected or missing fields")
    return obj


def _parse_step(v: Any, what: str) -> dict[str, Any]:
    o = _expect_exact_keys(v, _STEP_KEYS, what)
    return {
        "tools": _expect_string_list(o["tools"], f"{what}.tools"),
        "resources": _expect_string_list(o["resources"], f"{what}.resources"),
        "intents": _expect_string_list(o["intents"], f"{what}.intents"),
        "time_budget_seconds": _expect_int(o["time_budget_seconds"], f"{what}.time_budget_seconds"),
    }


def parse_claims(raw: Any) -> dict[str, Any]:
    """Validate an already-authenticated payload against the exact claims schema."""
    o = _expect_exact_keys(raw, _CLAIM_KEYS, "claims")
    agent = o["agent"]
    if not isinstance(agent, str) or not agent:
        raise ScopeTokenError("malformed", "claims.agent must be a non-empty string")
    root_rec = _expect_exact_keys(o["root"], _ROOT_KEYS, "claims.root")
    root = _parse_step({k: root_rec[k] for k in _STEP_KEYS}, "claims.root")
    root["max_depth"] = _expect_int(root_rec["max_depth"], "claims.root.max_depth")
    if root["max_depth"] > MAX_CHAIN_LENGTH:
        raise ScopeTokenError("malformed", f"claims.root.max_depth must not exceed {MAX_CHAIN_LENGTH}")
    chain_raw = o["chain"]
    if not isinstance(chain_raw, list) or len(chain_raw) > MAX_CHAIN_LENGTH:
        raise ScopeTokenError("malformed", f"claims.chain must be a list of at most {MAX_CHAIN_LENGTH} steps")
    chain = [_parse_step(s, f"claims.chain[{i}]") for i, s in enumerate(chain_raw)]
    depth = _expect_int(o["depth"], "claims.depth")
    if depth != len(chain):
        raise ScopeTokenError("malformed", "claims.depth must equal the chain length")
    iat = _expect_int(o["iat"], "claims.iat")
    exp = _expect_int(o["exp"], "claims.exp")
    return {"agent": agent, "root": root, "chain": chain, "depth": depth, "iat": iat, "exp": exp}


def now_seconds() -> int:
    """Whole-second epoch clock."""
    return int(time.time())


def verify_scope_token(token: Any, secret: bytes, *, agent: str, now: Optional[int] = None) -> dict[str, Any]:
    """Verify a token's shape, signature (constant-time), identity binding and
    time window, and return its claims. Does NOT touch the engine — the caller
    must still replay the chain through ``attenuate()`` before trusting the scope."""
    if not isinstance(token, str):
        raise ScopeTokenError("malformed", "token must be a string")
    if len(token) > MAX_TOKEN_LENGTH:
        raise ScopeTokenError("too_large", f"token exceeds {MAX_TOKEN_LENGTH} characters")
    parts = token.split(".")
    if len(parts) != 3:
        raise ScopeTokenError("malformed", "token must have three segments")
    version, payload_b64, sig_b64 = parts
    if version != SCOPE_TOKEN_PREFIX:
        raise ScopeTokenError("version", "unsupported token version")

    # Shape checks only (strict base64url; decoding is not parsing), then
    # authenticate BEFORE anything inside the payload is interpreted.
    payload = _b64url_decode(payload_b64)
    provided = _b64url_decode(sig_b64)
    expected = _hmac(secret, f"{version}.{payload_b64}")
    if len(provided) != _HMAC_BYTES or not hmac.compare_digest(provided, expected):
        raise ScopeTokenError("signature", "signature does not verify")

    try:
        raw = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ScopeTokenError("malformed", "payload is not JSON") from None
    claims = parse_claims(raw)
    # The payload must be in canonical form — a re-encoding of the parsed claims
    # that differs from what was signed is rejected (no alternate encodings).
    if canonical_json(claims).encode("utf-8") != payload:
        raise ScopeTokenError("malformed", "payload is not canonical")

    if claims["agent"] != agent:
        raise ScopeTokenError("identity", "token is bound to a different agent")

    now_s = now_seconds() if now is None else now
    if claims["iat"] > now_s + MAX_IAT_SKEW_SECONDS:
        raise ScopeTokenError("future_iat", "token issued in the future")
    if claims["exp"] <= now_s:
        raise ScopeTokenError("expired", "token has expired")
    if claims["exp"] <= claims["iat"]:
        raise ScopeTokenError("lifetime", "token expires before it was issued")
    # A token may never outlive the scope it names: its lifetime is bounded by
    # the (engine-clamped) time budget of the deepest level it carries.
    budget = (claims["chain"][-1] if claims["chain"] else claims["root"])["time_budget_seconds"]
    if claims["exp"] - claims["iat"] > budget:
        raise ScopeTokenError("lifetime", "token lifetime exceeds the scope's time budget")
    return claims


def same_set(a: Sequence[str], b: Sequence[str]) -> bool:
    """Set-equality on string lists (order-insensitive, multiplicity-sensitive)."""
    return len(a) == len(b) and sorted(a) == sorted(b)
