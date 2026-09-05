"""Approval tokens — the single-use, TTL-bounded confirmation that downgrades a
``NeedsApproval`` decision to ``Allow``.

A token is ``<exp>.<nonce>.<hmac>``, bound to the exact (principal, action,
resource) it was minted for. Two things decide whether it is honoured:

1. the KEY it is signed with — by default a random per-process key, so a token
   never leaves the process that minted it and a restart invalidates every
   outstanding approval. Configure ``approval_secret`` (or ``token_secret``,
   from which the approval key is derived) and a token minted in one process
   verifies in another, and survives a redeploy inside its TTL.
2. the SEEN-TOKEN STORE that makes it single-use — by default an in-process
   dict, so "used once" holds only within one process: behind two replicas the
   same token can be consumed once on each. Configure ``approval_store`` with a
   shared store and single-use holds across every replica.

Single use is ONE atomic check-and-set: ``add(id, expires_at)`` reserves the id
and answers whether the reservation was new. There is deliberately no "check,
then insert" — anything between the two is a window in which N concurrent
consumes of one token all observe "not yet used". A single agent fanning out
parallel tool calls after one human confirmation is exactly that race.

Both defaults are safe for a single-process agent and are the wrong choice for a
replicated deployment; neither is silently upgraded. Every refusal here is
fail-closed: the caller sees the SAME ``NeedsApproval`` hold whichever check
refused (expired, tampered, signed with another key, already consumed, or a store
that could not answer), so a probing caller learns nothing about which one it
was. Enterprise mints these KMS-signed and records them in signed lineage.

Mirrors ``ts/src/approval.ts`` byte-for-byte on the wire: the same key
derivation, the same length-prefixed payload, the same token layout — a token
minted by either language package verifies in the other under the same secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sys
import time
from typing import Any, Optional, Protocol, Union, runtime_checkable

__all__ = [
    "APPROVAL_KEY_LABEL",
    "APPROVAL_MIN_SECRET_BYTES",
    "APPROVAL_PAYLOAD_VERSION",
    "ApprovalError",
    "ApprovalStore",
    "ApprovalTokens",
    "derive_approval_key",
    "normalize_approval_secret",
]

#: Minimum length of a configured approval secret, in bytes. Matches the
#: scope-token secret bound.
APPROVAL_MIN_SECRET_BYTES = 16

#: Domain separator for the approval key.
#:
#: The approval key is never the configured secret itself: it is
#: ``HMAC-SHA256(secret, APPROVAL_KEY_LABEL)``. So one secret can configure both
#: halves of the SDK — ``token_secret`` signs scope tokens with the raw secret
#: and approval tokens with this derived key — and the two keys stay
#: independent: a scope token can never be replayed as an approval, nor the
#: reverse, and disclosure of one derived key does not yield the other.
APPROVAL_KEY_LABEL = "watchlight-de:approval-token:v1"

#: Domain separator AND format version of the signed payload. It is the first
#: field of every payload, so a token minted under a different payload format
#: simply does not verify — the change is a refusal, never a silent
#: reinterpretation — and the format can evolve by bumping this string.
APPROVAL_PAYLOAD_VERSION = "watchlight-de:approval:v1"


class ApprovalError(ValueError):
    """The approval configuration itself is unusable — raised at construction
    rather than at the first approval. Never echoes the secret."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"approval configuration rejected ({code}): {message}")


@runtime_checkable
class ApprovalStore(Protocol):
    """An application-supplied store of approval-token ids that have already been
    reserved — the same shape as an ``audit_sink``: your object, your storage,
    called by the SDK. Configured via ``Watchlight(approval_store=...)``.

    ``add(id, expires_at)`` is the whole contract, and it MUST BE AN ATOMIC
    CHECK-AND-SET: reserve ``id`` only if it is not already present, and return
    ``True`` when the reservation was new, ``False`` when the id was already
    there. ``expires_at`` is epoch MILLISECONDS — the moment the token expires on
    its own, so a row may be dropped after it (a TTL / expiry index).

    In SQL that is an insert that fails (or affects no row) on a duplicate key;
    in Redis it is ``SET key value NX PXAT <expires_at>``, whose ``None`` reply
    means "already present"::

        def add(self, id, expires_at):
            return self._redis.set(f"wl:appr:{id}", "1", nx=True, pxat=expires_at) is not None

    **A store that cannot do this in one atomic step cannot enforce single
    use** — a separate "does it exist?" read followed by a write leaves a window
    in which N concurrent consumes of the same token all see it unused, and every
    one of them is approved. Do not implement ``add`` as a read plus an
    unconditional write.

    ``add`` must be SYNCHRONOUS: the decision path in this package is
    synchronous, so there is no loop to await on, and a coroutine return refuses
    the approval. Use your client's own connect/read timeout to bound it — the
    TypeScript package, whose ``authorize`` is async, additionally accepts a
    promise-returning store and races it against a deadline. Every other
    behaviour is identical.

    The id is ``<exp>.<nonce>`` — unique per mint, and deliberately NOT the
    token: the signature never leaves the process, so a store whose rows leak
    yields no usable approval.

    Fail-closed, in every direction: ``False`` refuses; a raise refuses; and a
    return that is not a ``bool`` refuses too, because a store that will not say
    whether the reservation was new cannot be relied on for single use. A store
    that cannot answer never admits.
    """

    def add(self, id: str, expires_at: int) -> bool:  # noqa: A002 - named `id` in both lanes
        """Atomically reserve ``id``. ``True`` = newly reserved (the approval may
        proceed); ``False`` = already present (the approval is refused)."""
        ...

    # ``has(id)`` is optional and is NEVER consulted when consuming a token —
    # single use is decided by ``add`` alone, in one step. Define it only if you
    # also want a read for your own inspection.


class _MemoryApprovalStore:
    """The default seen-token store: an in-process dict of id -> expiry.

    Atomic WITHIN this process — of N consumes of one token, exactly one is
    approved — and PER-PROCESS ONLY. It is shared by every governor in one
    process, and by nothing else: behind two replicas the same approval token can
    be consumed once on each, and a restart forgets every consumed id (harmless, since the
    same restart also invalidates the random per-process key — unless an
    ``approval_secret`` is configured, which is exactly when a shared store is
    needed too). Ids are dropped once they expire, so the dict stays bounded by
    the number of approvals live inside one TTL.
    """

    def __init__(self) -> None:
        self._seen: dict[str, int] = {}

    def add(self, id: str, expires_at: int) -> bool:  # noqa: A002
        """Test-and-set in ONE step, with nothing that yields between the lookup
        and the write: of N consumes of the same token, exactly one sees
        ``True``."""
        now = int(time.time() * 1000)
        seen_at = self._seen.get(id)
        if seen_at is not None and now <= seen_at:
            return False  # already reserved
        for key in [k for k, exp in self._seen.items() if now > exp]:
            del self._seen[key]
        self._seen[id] = expires_at
        return True


# Process-wide default store, so the in-memory single-use registry behaves
# exactly as it did before it was pluggable: shared by every governor in the
# process, and by nothing outside it.
_DEFAULT_STORE = _MemoryApprovalStore()

# Random per-process approval key — the default when no secret is configured.
# Minted once at import, so every governor in the process agrees, and no other
# process (or restart) ever does.
_PROCESS_KEY = secrets.token_bytes(32)


def normalize_approval_secret(
    secret: Union[str, bytes, bytearray, None]
) -> Optional[bytes]:
    """Coerce a configured approval secret to bytes. An empty / whitespace-only
    value (an unfilled ``.env`` placeholder) is "unset". Never echoes the secret."""
    if secret is None:
        return None
    if isinstance(secret, str):
        if not secret.strip():
            return None
        return secret.encode("utf-8")
    if not isinstance(secret, (bytes, bytearray)):
        raise ApprovalError("invalid_secret", "approval secret must be a string or bytes")
    if len(secret) == 0:
        return None
    return bytes(secret)  # bytes() copies


def derive_approval_key(secret: bytes) -> bytes:
    """Derive the approval key from a configured secret. See
    :data:`APPROVAL_KEY_LABEL`."""
    if len(secret) < APPROVAL_MIN_SECRET_BYTES:
        raise ApprovalError(
            "weak_secret", f"approval secret must be at least {APPROVAL_MIN_SECRET_BYTES} bytes"
        )
    return hmac.new(secret, APPROVAL_KEY_LABEL.encode("utf-8"), hashlib.sha256).digest()


def resolve_approval_key(
    approval_secret: Union[str, bytes, bytearray, None],
    token_secret: Optional[bytes],
    env_secret: Union[str, bytes, bytearray, None] = None,
) -> bytes:
    """Resolve the key approval tokens are signed with, in order of precedence:
    an explicit ``approval_secret``, ``$WATCHLIGHT_APPROVAL_SECRET``, the already
    normalized ``token_secret`` (which also covers ``$WATCHLIGHT_TOKEN_SECRET``),
    and finally the random per-process key. A configured secret is never used raw
    — see :func:`derive_approval_key`."""
    configured = normalize_approval_secret(approval_secret)
    if configured is None:
        configured = normalize_approval_secret(env_secret)
    if configured is None:
        configured = token_secret
    return _PROCESS_KEY if configured is None else derive_approval_key(configured)


def _payload_for(principal: str, action: str, resource: str, exp: int, nonce: str) -> bytes:
    """The exact bytes an approval token signs — the ONE function both minting
    and verification go through, so there is no second implementation to drift.

    Every field is length-prefixed: ``<utf8 byte length>:<field>``, concatenated
    in a fixed order. Nothing is escaped because nothing needs to be — the length
    says where each field ends, so no combination of field values can produce the
    bytes of a different combination. A delimiter-joined payload could: with
    ``principal action resource``, the triple (``U``, ``a``, ``r1 r2``) and the
    triple (``U``, ``a r1``, ``r2``) join to the same string, and one approval
    would then be valid for the other — reachable in practice, since a principal
    carries an identifier from a token claim and a resource routinely carries a
    path. Lengths are UTF-8 BYTES so both language packages sign identical bytes.
    """
    out = bytearray()
    for field in (APPROVAL_PAYLOAD_VERSION, principal, action, resource, str(exp), nonce):
        raw = field.encode("utf-8")
        out += f"{len(raw)}:".encode("ascii")
        out += raw
    return bytes(out)


class ApprovalTokens:
    """Mints and consumes approval tokens for one governor."""

    def __init__(self, key: bytes, store: Optional[ApprovalStore] = None) -> None:
        self._key = key
        self._store: Any = _DEFAULT_STORE if store is None else store
        self._warned = False

    def mint(self, principal: str, action: str, resource: str, ttl_ms: int) -> str:
        """Mint a token bound to ``(principal, action, resource)``, valid for
        ``ttl_ms`` milliseconds."""
        exp = int(time.time() * 1000) + ttl_ms
        # A per-mint nonce makes every token unique, so two approvals for the
        # same (principal, action, resource) minted in the same millisecond never
        # collide — and "single-use" is genuinely per-mint, not per-(challenge, exp).
        nonce = secrets.token_hex(8)
        sig = hmac.new(
            self._key, _payload_for(principal, action, resource, exp, nonce), hashlib.sha256
        ).hexdigest()
        return f"{exp}.{nonce}.{sig}"

    def consume(self, token: str, principal: str, action: str, resource: str) -> bool:
        """Verify + CONSUME a token (single-use). Bound to the exact (principal,
        action, resource); refuses a token that is malformed, expired, tampered,
        signed with a different key, or already consumed — and refuses when the
        seen-token store cannot answer. Returns ``False`` for every refusal; the
        caller turns that into the same ``NeedsApproval`` hold in every case."""
        parts = token.split(".")
        if len(parts) != 3:
            return False
        exp_str, nonce, sig = parts
        try:
            exp = int(exp_str)
        except ValueError:
            return False
        if int(time.time() * 1000) > exp:
            return False
        expected = hmac.new(
            self._key, _payload_for(principal, action, resource, exp, nonce), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        # Only an authentic token reaches the store, so an unauthenticated caller
        # can never burn an id or drive load into it.
        token_id = f"{exp}.{nonce}"
        # ONE atomic reservation. Nothing is read before it: a check followed by
        # a separate write is a window that N concurrent consumes of one token
        # would all pass through.
        try:
            reserved = self._store.add(token_id, exp)
        except Exception:  # noqa: BLE001 — a store must never admit on failure
            return self._refuse("approval store failed")
        if self._is_awaitable(reserved):
            return self._refuse("approval store returned an awaitable on the synchronous decision path")
        if reserved is True:
            return True
        if reserved is False:
            return False  # the store already held the id
        # A store that will not say whether the reservation was new cannot be
        # relied on for single use, so it does not get to admit one.
        return self._refuse("approval store did not report whether the id was newly reserved")

    @staticmethod
    def _is_awaitable(value: Any) -> bool:
        # A coroutine here would never run: the decision path is synchronous.
        # Close it so it does not surface as "never awaited", and refuse.
        if hasattr(value, "__await__") or hasattr(value, "cr_await"):
            close = getattr(value, "close", None)
            if callable(close):
                close()
            return True
        return False

    def _refuse(self, what: str) -> bool:
        """Fail-closed: a store that cannot answer refuses the approval. The
        failure is reported once, without the error or the id."""
        if not self._warned:
            self._warned = True
            print(
                f"watchlight: {what}; the approval was refused (fail-closed) — "
                "further approval-store failures are suppressed",
                file=sys.stderr,
            )
        return False
