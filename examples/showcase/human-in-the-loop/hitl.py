"""Shared by agent.py and approve.py: the pending request, the approval grant,
and audit-trail lookups.

Two small JSON documents cross the process boundary between the agent and the
approver. Neither carries a secret or a tool payload — only the identity of the
request:

    .watchlight/hitl/pending.json   {decision_id, principal, action, resource, requested_at}
    .watchlight/hitl/grant.json     {pending_decision_id, principal, action, resource, exp, nonce, sig}

`sig` is HMAC-SHA256 over the grant's other fields under the approver's secret.
The secret is read from `$APPROVER_SECRET` by both processes and is never
written anywhere. The agent verifies the signature, the binding (principal,
action, resource) and the expiry, records the grant's nonce in `consumed.json`
so the same grant cannot be presented twice, and requires the grant to name the
request it currently has outstanding in `pending.json` (a file the agent itself
wrote), so a grant for an earlier request cannot be planted for a later one.

Why a grant and not the SDK's own approval token: the DE mints approval tokens
under a random secret generated when the process starts, and remembers used
tokens in memory. A token minted by approve.py therefore cannot be verified by
agent.py. The grant is what the approver signs; the token is minted by the SDK
inside the agent process once the grant verifies (`on_needs_approval` → True).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sys
import time
from typing import Optional

HERE = pathlib.Path(__file__).resolve().parent
AUDIT_DIR = HERE / ".watchlight"
AUDIT_PATH = AUDIT_DIR / "audit.jsonl"
STATE_DIR = AUDIT_DIR / "hitl"
PENDING = STATE_DIR / "pending.json"
GRANT = STATE_DIR / "grant.json"
CONSUMED = STATE_DIR / "consumed.json"

SECRET_ENV = "APPROVER_SECRET"
GRANT_TTL_MS = 5 * 60 * 1000
_GRANT_FIELDS = ("pending_decision_id", "principal", "action", "resource", "exp", "nonce")


def now_ms() -> int:
    return int(time.time() * 1000)


def approver_secret() -> bytes:
    """The shared secret, from the environment only. Fails closed when unset."""
    value = os.environ.get(SECRET_ENV, "")
    if len(value) < 16:
        print(
            f"{SECRET_ENV} is not set (or is shorter than 16 characters). approve.py and\n"
            f"'agent.py resume' share it through the environment only — generate one per session:\n"
            f'  export {SECRET_ENV}="$(openssl rand -hex 32)"',
            file=sys.stderr,
        )
        raise SystemExit(2)
    return value.encode()


# ── files ────────────────────────────────────────────────────────────────────

def _write(path: pathlib.Path, doc: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def _read(path: pathlib.Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        doc = json.loads(path.read_text())
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def reset() -> None:
    """Start a new approval loop: drop any pending request or unused grant."""
    for path in (PENDING, GRANT):
        path.unlink(missing_ok=True)


# ── pending request ──────────────────────────────────────────────────────────

def write_pending(decision_id: str, principal: str, action: str, resource: str) -> dict:
    doc = {
        "decision_id": decision_id,
        "principal": principal,
        "action": action,
        "resource": resource,
        "requested_at": now_ms(),
    }
    _write(PENDING, doc)
    return doc


def read_pending() -> Optional[dict]:
    return _read(PENDING)


# ── approval grant ───────────────────────────────────────────────────────────

def _sign(grant: dict, secret: bytes) -> str:
    payload = "\n".join(str(grant[k]) for k in _GRANT_FIELDS).encode()
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def write_grant(pending: dict, secret: bytes) -> dict:
    """Approve a pending request: sign a grant bound to exactly that request and
    write it next to the (still outstanding) pending file."""
    grant = {
        "pending_decision_id": pending["decision_id"],
        "principal": pending["principal"],
        "action": pending["action"],
        "resource": pending["resource"],
        "exp": now_ms() + GRANT_TTL_MS,
        "nonce": secrets.token_hex(16),
    }
    grant["sig"] = _sign(grant, secret)
    _write(GRANT, grant)
    # pending.json stays: the agent compares the grant against it on resume and
    # removes both once the grant is consumed.
    return grant


def peek_grant() -> Optional[dict]:
    """Read the grant without consuming it (for display and for the join)."""
    return _read(GRANT)


def plant_grant(grant: dict) -> None:
    """Write a grant document as-is — used by the replay check to re-present a
    grant that was already consumed."""
    _write(GRANT, grant)


def take_grant(principal: str, action: str, resource: str, secret: bytes) -> tuple[Optional[dict], str]:
    """Verify and consume the grant on disk for exactly (principal, action, resource).

    Returns `(grant, "ok")` or `(None, why)`. The file is removed as soon as it is
    read, before any verification, so a crash mid-way never leaves a reusable
    grant. A verified grant's nonce is recorded so the same document cannot be
    presented again, and the grant must name the request this agent currently
    has outstanding (`pending.json`, which the agent itself wrote) — so a grant
    approved for an earlier request cannot be planted for a later one. On
    success the pending file is removed too.
    """
    grant = _read(GRANT)
    GRANT.unlink(missing_ok=True)
    if grant is None:
        return None, "no grant"
    if any(k not in grant for k in (*_GRANT_FIELDS, "sig")):
        return None, "malformed grant"
    if not hmac.compare_digest(str(grant["sig"]), _sign(grant, secret)):
        return None, "signature does not verify"
    if (grant["principal"], grant["action"], grant["resource"]) != (principal, action, resource):
        return None, "grant is bound to a different request"
    if not isinstance(grant["exp"], int) or now_ms() > grant["exp"]:
        return None, "grant expired"
    used = (_read(CONSUMED) or {}).get("nonces", [])
    if grant["nonce"] in used:
        return None, "grant already used (replay)"
    _write(CONSUMED, {"nonces": [*used, grant["nonce"]]})
    pending = read_pending()
    if pending is None or (
        pending.get("decision_id"), pending.get("principal"), pending.get("action"), pending.get("resource")
    ) != (grant["pending_decision_id"], principal, action, resource):
        return None, "grant does not match the outstanding pending request"
    PENDING.unlink(missing_ok=True)
    return grant, "ok"


# ── audit trail ──────────────────────────────────────────────────────────────

def audit_lines() -> list[str]:
    if not AUDIT_PATH.exists():
        return []
    return [line for line in AUDIT_PATH.read_text().splitlines() if line.strip()]


def audit_line(decision_id: str) -> Optional[str]:
    """The raw audit line carrying `decision_id` (the last one, if several)."""
    for line in reversed(audit_lines()):
        try:
            if json.loads(line).get("decision_id") == decision_id:
                return line
        except ValueError:
            continue
    return None
