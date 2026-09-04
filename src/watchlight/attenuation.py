"""Sub-agent scope attenuation for the Developer Edition.

When an agent spawns a sub-agent, the child must receive a **strict subset** of
the parent's authority — never more. That strict-subset validation is performed
by the Watchlight engine (``watchlight_engine.attenuate_scope``): a child that
asks for a tool, intent, or resource the parent does not hold is denied, and a
valid request comes back **clamped** to what the parent actually has.

The Developer Edition governs these trees up to **depth 5** (:data:`DE_MAX_DEPTH`).
Server-side enforcement, signed lineage, and fleet-wide revocation are provided
by the Enterprise plane.

    root = govern.scope(tools=["read", "write", "search"], intents=["research"])
    analyst = root.attenuate(tools=["read", "search"])   # depth 1  (strict subset)
    reader  = analyst.attenuate(tools=["read"])           # depth 2
    # ... a sixth level raises DevEditionCeiling (the Developer-Edition ceiling).
"""

from __future__ import annotations

import datetime
import json
import pathlib
import uuid
from typing import Any, Optional, Sequence

from ._audit import AuditTrail
from .scope_token import ScopeTokenError, now_seconds, require_secret, sign_scope_token

__all__ = ["Scope", "DevEditionCeiling", "AttenuationDenied", "DE_MAX_DEPTH"]

#: The Developer-Edition ceiling: sub-agent trees attenuate up to this depth. The
#: engine still runs the real strict-subset math at every level — this is the
#: product boundary where DE hands off to Enterprise (which removes the cap and
#: adds server-side enforcement, signed lineage, and fleet-wide revocation).
DE_MAX_DEPTH = 5

#: Human-readable message raised when a sub-agent tree reaches the DE depth
#: ceiling — explains the product boundary and where the cap is lifted.
_CEILING_NOTICE = (
    "Developer Edition governs sub-agent trees up to depth {cap}; this chain "
    "reached the ceiling at depth {depth}. In production, agents spawn deeper "
    "trees across a fleet — enforced server-side (the agent cannot route around "
    "it), signed into tamper-evident lineage, and revocable fleet-wide. "
    "Talk to us: sales@watchlight.ai · https://www.watchlight.ai"
)


class DevEditionCeiling(RuntimeError):
    """Raised when a sub-agent tree would exceed the Developer-Edition depth
    ceiling (:data:`DE_MAX_DEPTH`).

    This is **not** a policy denial — it is a product boundary. Every attenuation
    up to the ceiling was a real, engine-validated strict subset; Enterprise
    removes the cap and enforces it server-side.
    """

    def __init__(self, depth: int) -> None:
        self.depth = depth
        self.cap = DE_MAX_DEPTH
        super().__init__(_CEILING_NOTICE.format(cap=DE_MAX_DEPTH, depth=depth))


class AttenuationDenied(PermissionError):
    """Raised when a sub-agent requests authority its parent does not hold.

    The engine refuses to widen scope (strict-subset only). ``violations`` names
    the dimension(s) that overreached — e.g. ``AllowedTools``, ``AllowedIntents``,
    ``MaxDepth``, ``TimeBudget`` — so you can surface a precise error.
    """

    def __init__(self, violations: list[str], reason: str) -> None:
        self.violations = violations
        self.reason = reason
        dims = ", ".join(violations) or "scope"
        super().__init__(f"attenuation denied ({dims}): {reason}")


def _norm(x: Sequence[str] | None) -> list[str]:
    return list(x) if x else []


def _matchers(resources: Sequence[str]) -> list[dict[str, str]]:
    """The engine's resource dimension is a list of ``{"matcher": ...}`` structs
    (mirrors the TS lane); a Scope keeps the plain matcher strings."""
    return [{"matcher": r} for r in resources]


def _unmatchers(resources: Sequence[Any]) -> list[str]:
    return [r["matcher"] if isinstance(r, dict) else str(r) for r in resources]


class Scope:
    """A capability scope that can spawn strictly-narrower child scopes.

    Create the root with :meth:`watchlight.Watchlight.scope`; call
    :meth:`attenuate` to derive a sub-agent scope. Every ``attenuate`` runs the
    real engine strict-subset validation and is written to the audit trail, so it
    streams into ``watchlight dev``. The Developer Edition allows this up to depth
    :data:`DE_MAX_DEPTH`.
    """

    def __init__(
        self,
        *,
        engine: Any,
        audit_path: str | pathlib.Path,
        agent: str,
        allowed_tools: Sequence[str] | None,
        allowed_resources: Sequence[str] | None,
        allowed_intents: Sequence[str] | None,
        max_depth: int,
        time_budget_seconds: int,
        depth: int,
        parent_id: str | None = None,
        audit: Optional[AuditTrail] = None,
        parent: Optional["Scope"] = None,
        token_secret: Optional[bytes] = None,
        issued_at: Optional[int] = None,
    ) -> None:
        """``parent`` is the scope this one was attenuated from (``None`` for a
        root) — it lets :meth:`to_token` serialise the full chain for engine
        replay. ``token_secret`` is the HMAC key for :meth:`to_token`, inherited
        by children; unset ⇒ minting fails closed. Never logged or written.
        ``issued_at`` is the epoch second this scope came into force (now)."""
        self._engine = engine
        self._audit_path = pathlib.Path(audit_path)
        # The governor's audit trail (file + optional ``audit_sink``) — shared by
        # every scope in the tree, so attenuations report through the same sink.
        self._audit = audit if audit is not None else AuditTrail(self._audit_path)
        self.agent = agent
        self.allowed_tools = _norm(allowed_tools)
        self.allowed_resources = _norm(allowed_resources)
        self.allowed_intents = _norm(allowed_intents)
        self.max_depth = int(max_depth)
        self.time_budget_seconds = int(time_budget_seconds)
        self.depth = int(depth)
        #: A short id for this scope and its parent's — so `watchlight dev` can
        #: reconstruct the exact attenuation tree (siblings at the same depth stay
        #: distinct). ``parent_id`` is None for a root scope.
        self.node_id = uuid.uuid4().hex[:8]
        self.parent_id = parent_id
        self._parent = parent
        self._token_secret = token_secret
        #: Epoch seconds this scope came into force.
        self.issued_at = int(issued_at) if issued_at is not None else now_seconds()
        # A scope never outlives its parent, whatever its own budget says.
        self._expires_at = self.issued_at + self.time_budget_seconds
        if parent is not None:
            self._expires_at = min(self._expires_at, parent.expires_at)

    @property
    def expires_at(self) -> int:
        """Epoch seconds after which this scope is spent: ``issued_at +
        time_budget_seconds``, clamped to the parent's expiry (and, for a scope
        rebuilt from a token, to the token's ``exp``)."""
        return self._expires_at

    def _bind_expiry(self, exp: int) -> None:
        """Lower this scope's expiry (never raise it). Used when a scope is
        rebuilt from a token so it cannot outlive the token."""
        self._expires_at = min(self._expires_at, int(exp))

    def _step_claim(self) -> dict[str, Any]:
        """The engine-granted dimensions of this level, as a token claim."""
        return {
            "tools": list(self.allowed_tools),
            "resources": list(self.allowed_resources),
            "intents": list(self.allowed_intents),
            "time_budget_seconds": self.time_budget_seconds,
        }

    def to_token(self, *, ttl_seconds: Optional[int] = None) -> str:
        """Serialise this scope for another process: an HMAC-signed token carrying
        the root grant and the engine-granted scope at every level down to this
        one. The receiving :meth:`watchlight.Watchlight.scope_from_token` verifies
        the signature and time window, then re-runs the engine's strict-subset
        attenuation level by level — the token is integrity across processes
        sharing the secret, never authority. ``ttl_seconds`` defaults to — and
        is always capped at — the scope's remaining lifetime
        (:attr:`expires_at`). Fails closed with :class:`ScopeTokenError` when no
        ``token_secret`` was configured or the scope has no remaining lifetime.
        The token never carries argument values, audit paths, or the secret."""
        secret = require_secret(self._token_secret)
        now = now_seconds()
        remaining = self.expires_at - now
        if remaining <= 0:
            raise ScopeTokenError("expired", "scope has no remaining lifetime")
        ttl = remaining if ttl_seconds is None else ttl_seconds
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            raise ScopeTokenError("lifetime", "ttl_seconds must be a positive integer")
        exp = min(now + ttl, self.expires_at)

        # Walk to the root, collecting each level's GRANTED dimensions.
        levels: list[Scope] = []
        s: Optional[Scope] = self
        while s is not None:
            levels.insert(0, s)
            s = s._parent
        root = levels[0]._step_claim()
        root["max_depth"] = levels[0].max_depth
        chain = [lvl._step_claim() for lvl in levels[1:]]
        if len(chain) != self.depth:
            raise ScopeTokenError("mismatch", "scope lineage does not match its depth")
        claims = {"agent": self.agent, "root": root, "chain": chain, "depth": self.depth, "iat": now, "exp": exp}
        return sign_scope_token(claims, secret)

    # ── the primitive ───────────────────────────────────────────────

    def attenuate(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        time_budget_seconds: int | None = None,
    ) -> "Scope":
        """Derive a sub-agent scope — a **strict subset** of this one.

        Any dimension you omit inherits the parent's (and the engine clamps it
        regardless). Raises :class:`AttenuationDenied` if the request exceeds the
        parent, and :class:`DevEditionCeiling` at the Developer-Edition depth
        ceiling.
        """
        child_depth = self.depth + 1
        requested_tools = _norm(tools) if tools is not None else self.allowed_tools

        # The Developer-Edition ceiling — a product boundary, checked before the
        # engine. Everything up to here was a real, validated strict subset.
        if child_depth > DE_MAX_DEPTH:
            self._record(
                node_id=uuid.uuid4().hex[:8],
                parent_id=self.node_id,
                tools=requested_tools,
                resource=f"sub-agent depth {child_depth}",
                decision="Deny",
                depth=child_depth,
                reason=DevEditionCeiling(child_depth).args[0],
            )
            raise DevEditionCeiling(child_depth)

        parent = self._as_dict()
        request = {
            "allowed_tools": requested_tools,
            "allowed_resources": _matchers(_norm(resources) if resources is not None else self.allowed_resources),
            "allowed_intents": _norm(intents) if intents is not None else self.allowed_intents,
            "max_depth": max(0, self.max_depth - 1),
            "time_budget_seconds": (
                time_budget_seconds if time_budget_seconds is not None else self.time_budget_seconds
            ),
        }

        resp = json.loads(
            self._engine.attenuate_scope(json.dumps(parent), json.dumps(request))
        )
        if resp.get("decision") != "Allow":
            violations = resp.get("violations") or []
            reason = resp.get("reason") or "requested scope is not a strict subset of the parent"
            self._record(
                node_id=uuid.uuid4().hex[:8],
                parent_id=self.node_id,
                tools=requested_tools,
                resource=f"sub-agent depth {child_depth}",
                decision="Deny",
                depth=child_depth,
                reason=reason,
            )
            raise AttenuationDenied(violations, reason)

        # The engine returns the CLAMPED grant — never the child's raw request.
        granted = resp.get("granted_scope") or {}
        child = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            agent=self.agent,
            allowed_tools=granted.get("allowed_tools", request["allowed_tools"]),
            allowed_resources=_unmatchers(granted.get("allowed_resources", request["allowed_resources"])),
            allowed_intents=granted.get("allowed_intents", request["allowed_intents"]),
            max_depth=granted.get("max_depth", request["max_depth"]),
            time_budget_seconds=granted.get("time_budget_seconds", request["time_budget_seconds"]),
            depth=granted.get("depth", child_depth),
            parent_id=self.node_id,
            audit=self._audit,
            parent=self,
            token_secret=self._token_secret,
        )
        self._record(
            node_id=child.node_id,
            parent_id=self.node_id,
            tools=child.allowed_tools,
            resource=f"sub-agent depth {child.depth}",
            decision="Allow",
            depth=child.depth,
        )
        return child

    # ── internals ───────────────────────────────────────────────────

    def _as_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": self.allowed_tools,
            "allowed_resources": _matchers(self.allowed_resources),
            "allowed_intents": self.allowed_intents,
            "max_depth": self.max_depth,
            "time_budget_seconds": self.time_budget_seconds,
            "depth": self.depth,
        }

    def _emit_root(self) -> None:
        """Record this scope as the root of an attenuation tree (parent-less), so
        the console shows the authority the tree starts from."""
        self._record(
            node_id=self.node_id,
            parent_id=None,
            tools=self.allowed_tools,
            resource="root scope",
            decision="Allow",
            depth=self.depth,
        )

    def _record(
        self,
        *,
        node_id: str,
        parent_id: str | None,
        tools: Sequence[str],
        resource: str,
        decision: str,
        depth: int,
        reason: str = "",
    ) -> None:
        # Value-free by construction — a scope's dimensions are capability NAMES,
        # never argument values. Shape stays compatible with `watchlight dev`'s
        # decision table (ts/agent/intent/resource/decision) and adds
        # node_id/parent_id/tools/depth so it can also draw the attenuation TREE.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "intent": "attenuate",
            "event": "attenuation",
            "node_id": node_id,
            "resource": resource,
            "decision": decision,
            "depth": depth,
            "tools": list(tools),
        }
        if parent_id:
            record["parent_id"] = parent_id
        if reason:
            record["reason"] = reason
        # One funnel: the governor's file + optional sink (see watchlight._audit).
        self._audit.write(record)

    def __repr__(self) -> str:
        return (
            f"Scope(depth={self.depth}, tools={self.allowed_tools}, "
            f"intents={self.allowed_intents}, max_depth={self.max_depth})"
        )
