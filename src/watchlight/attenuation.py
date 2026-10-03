"""Sub-agent scope attenuation for the Developer Edition.

When an agent spawns a sub-agent, the child must receive a **strict subset** of
the parent's authority — never more. That strict-subset validation is performed
by the Watchlight engine (``watchlight_engine.attenuate_scope``): a child that
asks for a tool, intent, or resource the parent does not hold is denied, and a
valid request comes back **clamped** to what the parent actually has.

Every tree is bounded by ``max_delegation_depth`` — a governance control, like a
privilege-escalation depth limit in traditional IAM. It defaults to
:data:`DEFAULT_MAX_DELEGATION_DEPTH` (8), is set on the governor, and can be
lowered per root scope. A hop past it is a deny with reason code
:data:`DELEGATION_DEPTH_EXCEEDED`, recorded like any other refused attenuation.

    root = govern.scope(tools=["read", "write", "search"], intents=["research"])
    analyst = root.attenuate(tools=["read", "search"])   # depth 1  (strict subset)
    reader  = analyst.attenuate(tools=["read"])           # depth 2
    # ... a level past max_delegation_depth raises DelegationDepthExceeded.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import uuid
from typing import Any, NoReturn, Optional, Sequence

from . import principals
from ._audit import AuditTrail
from .scope_token import MAX_CHAIN_LENGTH, ScopeTokenError, now_seconds, sign_scope_token, signing_secret

__all__ = [
    "Scope",
    "ScopePreview",
    "AttenuationDenied",
    "DelegationDepthExceeded",
    "DEFAULT_MAX_DELEGATION_DEPTH",
    "DELEGATION_DEPTH_EXCEEDED",
]

#: Default ``max_delegation_depth``: how many attenuation hops a sub-agent tree may
#: go below its root (depth 0). A governance control, not an edition limit.
DEFAULT_MAX_DELEGATION_DEPTH = 8

#: Reason code on a refused attenuation that would exceed ``max_delegation_depth``.
DELEGATION_DEPTH_EXCEEDED = "DELEGATION_DEPTH_EXCEEDED"


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


class DelegationDepthExceeded(AttenuationDenied):
    """Raised when an attenuation would take a sub-agent tree deeper than its
    ``max_delegation_depth``. A deny like any other refused attenuation — the
    child is never created — with a distinct :attr:`code` so it can be told apart
    from a scope that is not a strict subset. ``depth`` is the depth the refused
    child would have had; ``limit`` is the limit it exceeded."""

    code = DELEGATION_DEPTH_EXCEEDED

    def __init__(self, depth: int, limit: int) -> None:
        self.depth = depth
        self.limit = limit
        super().__init__(["MaxDepth"], f"delegation depth {depth} exceeds max_delegation_depth {limit}")


#: Fixed message for a spent scope (never carries scope or token details).
_EXPIRED_SCOPE = "scope has expired"


def _norm(x: Sequence[str] | None) -> list[str]:
    return list(x) if x else []


def _matchers(resources: Sequence[str]) -> list[dict[str, str]]:
    """The engine's resource dimension is a list of ``{"matcher": ...}`` structs
    (mirrors the TS lane); a Scope keeps the plain matcher strings."""
    return [{"matcher": r} for r in resources]


def _unmatchers(resources: Sequence[Any]) -> list[str]:
    return [r["matcher"] if isinstance(r, dict) else str(r) for r in resources]


def _check_request(
    tools: Any, resources: Any, intents: Any, agent: Any, chain: Sequence[str], where: str
) -> tuple[Optional[list[str]], Optional[list[str]], Optional[list[str]], Any]:
    """The bounds on a child scope's request (see :mod:`watchlight.principals`):
    each list bounded in entries and bytes, the sub-agent's name a valid agent
    name, and the chain it extends within :data:`~watchlight.principals.MAX_ACTOR_CHAIN_BYTES`.
    Value-free ``TypeError``; nothing is decided or recorded. Returns the lists
    it checked, each read exactly once; the caller uses those, never the
    arguments again."""
    checked_tools = principals.assert_name_list(tools, "tools")
    checked_resources = principals.assert_name_list(resources, "resources")
    checked_intents = principals.assert_name_list(intents, "intents")
    # `str.__len__`: an empty name means "no new actor", and a str subclass
    # cannot claim to be empty while holding characters.
    if agent is not None and not (isinstance(agent, str) and str.__len__(agent) == 0):
        agent = principals.assert_agent_name(agent, where)
        principals.assert_actor_chain((*chain, agent), where)
    else:
        agent = None
    return checked_tools, checked_resources, checked_intents, agent


def _scope_label(depth: int, agent: str | None) -> str:
    """An attenuation record's ``resource``: the sub-agent the scope is for, when
    one is named, else the depth."""
    return f"scope for {agent}" if agent else f"sub-agent depth {depth}"


def _attenuation_outcome(
    parent: Any,
    *,
    tools: Sequence[str] | None,
    resources: Sequence[str] | None,
    intents: Sequence[str] | None,
    time_budget_seconds: int | None,
) -> dict[str, Any]:
    """Run the engine's strict-subset check for a child of ``parent`` (a
    :class:`Scope` or a :class:`ScopePreview`). Creates and records nothing: the
    one decision both :meth:`Scope.attenuate` and the previews act on, so the two
    cannot disagree.

    Returns ``{"kind": "depth" | "deny" | "allow", ...}``."""
    child_depth = parent.depth + 1
    requested_tools = _norm(tools) if tools is not None else parent.allowed_tools

    # max_delegation_depth — a governance control, checked before the engine.
    if child_depth > parent.max_delegation_depth:
        return {"kind": "depth", "requested_tools": requested_tools, "child_depth": child_depth}

    request = {
        "allowed_tools": requested_tools,
        "allowed_resources": _matchers(_norm(resources) if resources is not None else parent.allowed_resources),
        "allowed_intents": _norm(intents) if intents is not None else parent.allowed_intents,
        "max_depth": max(0, parent.max_depth - 1),
        "time_budget_seconds": (
            time_budget_seconds if time_budget_seconds is not None else parent.time_budget_seconds
        ),
    }
    resp = json.loads(parent._engine.attenuate_scope(json.dumps(parent._as_dict()), json.dumps(request)))
    if resp.get("decision") != "Allow":
        violations = resp.get("violations") or []
        if "MaxDepth" in violations and parent.max_depth <= 0:
            # The engine's own depth budget is spent — the same deny.
            return {"kind": "depth", "requested_tools": requested_tools, "child_depth": child_depth}
        return {
            "kind": "deny",
            "requested_tools": requested_tools,
            "child_depth": child_depth,
            "violations": violations,
            "reason": resp.get("reason") or "requested scope is not a strict subset of the parent",
        }

    # The engine returns the CLAMPED grant — never the child's raw request.
    granted = resp.get("granted_scope") or {}
    return {
        "kind": "allow",
        "child_depth": child_depth,
        "grant": {
            "allowed_tools": granted.get("allowed_tools", request["allowed_tools"]),
            "allowed_resources": _unmatchers(granted.get("allowed_resources", request["allowed_resources"])),
            "allowed_intents": granted.get("allowed_intents", request["allowed_intents"]),
            "max_depth": granted.get("max_depth", request["max_depth"]),
            "time_budget_seconds": granted.get("time_budget_seconds", request["time_budget_seconds"]),
            "depth": granted.get("depth", child_depth),
        },
    }


class Scope:
    """A capability scope that can spawn strictly-narrower child scopes.

    Create the root with :meth:`watchlight.Watchlight.scope`; call
    :meth:`attenuate` to derive a sub-agent scope. Every ``attenuate`` runs the
    real engine strict-subset validation and is written to the audit trail, so it
    streams into ``watchlight dev``. The tree is bounded by
    :attr:`max_delegation_depth`.
    """

    def __init__(
        self,
        *,
        engine: Any,
        audit_path: str | pathlib.Path | None,
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
        signing_secrets: Optional[list[bytes]] = None,
        issued_at: Optional[int] = None,
        actor_chain: Sequence[str] | None = None,
        max_delegation_depth: int | None = None,
    ) -> None:
        """``parent`` is the scope this one was attenuated from (``None`` for a
        root) — it lets :meth:`to_token` serialise the full chain for engine
        replay. ``signing_secrets`` are the keys for :meth:`to_token` (newest
        first: the first signs, every one verifies), inherited
        by children; unset ⇒ minting fails closed. Never logged or written.
        ``issued_at`` is the epoch second this scope came into force (now)."""
        self._engine = engine
        # ``None`` when the governor writes no local file (``audit_file=False``).
        self._audit_path = pathlib.Path(audit_path) if audit_path is not None else None
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
        #: The deepest any scope in this tree may be (the root is depth 0). Set
        #: on the root from the governor's ``max_delegation_depth`` and inherited
        #: by every child.
        # Never past the structural bound, however the scope was constructed.
        self.max_delegation_depth = min(
            int(max_delegation_depth) if max_delegation_depth is not None else self.depth + self.max_depth,
            MAX_CHAIN_LENGTH,
        )
        #: A short id for this scope and its parent's — so `watchlight dev` can
        #: reconstruct the exact attenuation tree (siblings at the same depth stay
        #: distinct). ``parent_id`` is None for a root scope.
        self.node_id = uuid.uuid4().hex[:8]
        self.parent_id = parent_id
        #: The ordered delegation chain a call made through this scope acts
        #: under, root first — ``["flight-booker", "seat-picker"]`` for a
        #: seat-picker spawned by a flight-booker. The last entry is the acting
        #: (leaf) agent. A root scope's chain is just the governor's agent; each
        #: :meth:`attenuate` that names an ``agent`` appends one entry, so the
        #: chain is at most ``max_delegation_depth + 1`` long.
        self.actor_chain: tuple[str, ...] = tuple(actor_chain if actor_chain is not None else [agent])
        self._parent = parent
        self._signing_secrets = signing_secrets
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

    @property
    def expired(self) -> bool:
        """True once this scope is past :attr:`expires_at`."""
        return now_seconds() >= self._expires_at

    def assert_active(self) -> None:
        """Fail closed on a spent scope: raises :class:`ScopeTokenError`
        (``expired``) once the scope is past :attr:`expires_at`. Called by
        :meth:`attenuate` and :meth:`to_token`; call it yourself before acting
        under a scope you hold across time (e.g. a scope rebuilt from a token in
        a long-running worker)."""
        if self.expired:
            raise ScopeTokenError("expired", _EXPIRED_SCOPE)

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
        ``signing_secret`` was configured or the scope has no remaining lifetime.
        The token never carries argument values, audit paths, or the secret."""
        # The FIRST configured secret signs; the rest exist so a token signed
        # under a previous one still verifies while it is listed.
        secret = signing_secret(self._signing_secrets)
        self.assert_active()
        now = now_seconds()
        remaining = self.expires_at - now
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
        agent: str | None = None,
    ) -> "Scope":
        """Derive a sub-agent scope — a **strict subset** of this one.

        Any dimension you omit inherits the parent's (and the engine clamps it
        regardless). Raises :class:`AttenuationDenied` if the request exceeds the
        parent — or :class:`DelegationDepthExceeded`, a subclass, when the child
        would be deeper than :attr:`max_delegation_depth`.

        ``agent`` names the sub-agent this scope is spawned FOR, appending it to
        the child's :attr:`actor_chain` — what a delegated governor
        (:meth:`watchlight.Watchlight.delegate`) records and what a policy reads
        as ``context.actor_chain``. Omit it to narrow authority without naming a
        new actor: the child then inherits the parent's chain unchanged.
        """
        self.assert_active()  # a spent scope grants nothing further (fail-closed)
        # Bounded before the engine and before any record: the requested tools,
        # the sub-agent's name and the chain it extends are all written down.
        tools, resources, intents, agent = _check_request(
            tools, resources, intents, agent, self.actor_chain, "attenuate()"
        )
        # A named sub-agent's records carry the chain it would act under.
        named = (*self.actor_chain, agent) if agent else None
        out = _attenuation_outcome(
            self, tools=tools, resources=resources, intents=intents, time_budget_seconds=time_budget_seconds
        )
        if out["kind"] == "depth":
            # A hop past max_delegation_depth is a deny: the child is never created.
            self._deny_depth(out["requested_tools"], out["child_depth"], agent)
        if out["kind"] == "deny":
            self._record(
                node_id=uuid.uuid4().hex[:8],
                parent_id=self.node_id,
                tools=out["requested_tools"],
                resource=_scope_label(out["child_depth"], agent),
                decision="Deny",
                depth=out["child_depth"],
                reason=out["reason"],
                actor_chain=named,
            )
            raise AttenuationDenied(out["violations"], out["reason"])

        grant = out["grant"]
        child = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            agent=self.agent,
            allowed_tools=grant["allowed_tools"],
            allowed_resources=grant["allowed_resources"],
            allowed_intents=grant["allowed_intents"],
            max_depth=grant["max_depth"],
            time_budget_seconds=grant["time_budget_seconds"],
            depth=grant["depth"],
            max_delegation_depth=self.max_delegation_depth,
            parent_id=self.node_id,
            audit=self._audit,
            parent=self,
            signing_secrets=self._signing_secrets,
            # Naming the sub-agent this scope is spawned for extends the
            # delegation chain; narrowing without a name leaves the acting
            # identity unchanged.
            actor_chain=named if named else self.actor_chain,
        )
        self._record(
            node_id=child.node_id,
            parent_id=self.node_id,
            tools=child.allowed_tools,
            resource=_scope_label(child.depth, agent),
            decision="Allow",
            depth=child.depth,
            actor_chain=named,
        )
        return child

    def preview_attenuate(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        time_budget_seconds: int | None = None,
        agent: str | None = None,
    ) -> "ScopePreview":
        """What :meth:`attenuate` would grant, without granting it or recording
        anything — for showing a sub-agent's effective authority. Runs the same
        engine check and returns a :class:`ScopePreview`: the clamped grant, or
        the violations and reason it would be refused with. A preview is data,
        never a scope: it cannot authorize, delegate, or mint a token."""
        self.assert_active()
        tools, resources, intents, agent = _check_request(
            tools, resources, intents, agent, self.actor_chain, "preview_attenuate()"
        )
        return _preview_child(
            self, tools=tools, resources=resources, intents=intents,
            time_budget_seconds=time_budget_seconds, agent=agent,
        )

    def _deny_depth(self, requested_tools: Sequence[str], child_depth: int, agent: str | None = None) -> NoReturn:
        """Refuse a hop past :attr:`max_delegation_depth`: record the deny — the
        observed depth and the limit — then raise. The child is never created."""
        err = DelegationDepthExceeded(child_depth, self.max_delegation_depth)
        self._record(
            node_id=uuid.uuid4().hex[:8],
            parent_id=self.node_id,
            tools=requested_tools,
            resource=_scope_label(child_depth, agent),
            decision="Deny",
            depth=child_depth,
            reason=err.reason,
            reason_code=DELEGATION_DEPTH_EXCEEDED,
            max_delegation_depth=self.max_delegation_depth,
            actor_chain=(*self.actor_chain, agent) if agent else None,
        )
        raise err

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
        reason_code: str = "",
        max_delegation_depth: int | None = None,
        actor_chain: Sequence[str] | None = None,
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
        if reason_code:
            record["reason_code"] = reason_code
        if max_delegation_depth is not None:
            record["max_delegation_depth"] = max_delegation_depth
        # The named sub-agent the scope is for, and the chain it acts under.
        if actor_chain:
            record["actor_chain"] = list(actor_chain)
        # One funnel: the governor's file + optional sink (see watchlight._audit).
        self._audit.write(record)

    def __repr__(self) -> str:
        return (
            f"Scope(depth={self.depth}, tools={self.allowed_tools}, "
            f"intents={self.allowed_intents}, max_depth={self.max_depth})"
        )


class ScopePreview:
    """What a scope would be granted — the engine's answer, as data, with nothing
    recorded.

    Returned by :meth:`watchlight.Watchlight.preview_scope` and
    :meth:`Scope.preview_attenuate`, for showing an agent's effective authority
    without writing to the audit trail. It runs the same engine strict-subset
    check as :meth:`Scope.attenuate`, but it is not a grant: it has no
    ``attenuate``, cannot authorize, delegate or mint a token, and nothing is
    recorded. :meth:`preview_attenuate` previews the next level down.

    ``allowed`` says whether the scope would be granted. When it would not,
    ``violations`` and ``reason`` say why (``reason_code`` is
    ``DELEGATION_DEPTH_EXCEEDED`` for a hop past the depth limit) and ``tools``
    is the requested set.
    """

    def __init__(
        self,
        *,
        engine: Any,
        allowed: bool,
        tools: Sequence[str] | None,
        resources: Sequence[str] | None,
        intents: Sequence[str] | None,
        max_depth: int,
        time_budget_seconds: int,
        depth: int,
        max_delegation_depth: int,
        actor_chain: Sequence[str],
        violations: Sequence[str] = (),
        reason: str = "",
        reason_code: str | None = None,
    ) -> None:
        self._engine = engine
        self.allowed = bool(allowed)
        self.allowed_tools = _norm(tools)
        self.allowed_resources = _norm(resources)
        self.allowed_intents = _norm(intents)
        self.max_depth = int(max_depth)
        self.time_budget_seconds = int(time_budget_seconds)
        self.depth = int(depth)
        self.max_delegation_depth = min(int(max_delegation_depth), MAX_CHAIN_LENGTH)
        self.actor_chain: tuple[str, ...] = tuple(actor_chain)
        self.violations = list(violations)
        self.reason = reason
        self.reason_code = reason_code

    def _as_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": self.allowed_tools,
            "allowed_resources": _matchers(self.allowed_resources),
            "allowed_intents": self.allowed_intents,
            "max_depth": self.max_depth,
            "time_budget_seconds": self.time_budget_seconds,
            "depth": self.depth,
        }

    def preview_attenuate(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        time_budget_seconds: int | None = None,
        agent: str | None = None,
    ) -> "ScopePreview":
        """Preview the next level down, exactly as :meth:`Scope.attenuate`
        would decide it. Below a preview that would be refused, nothing would be
        granted either."""
        tools, resources, intents, agent = _check_request(
            tools, resources, intents, agent, self.actor_chain, "preview_attenuate()"
        )
        if not self.allowed:
            return ScopePreview(
                engine=self._engine,
                allowed=False,
                tools=_norm(tools) if tools is not None else self.allowed_tools,
                resources=(),
                intents=(),
                max_depth=0,
                time_budget_seconds=0,
                depth=self.depth + 1,
                max_delegation_depth=self.max_delegation_depth,
                actor_chain=(*self.actor_chain, agent) if agent else self.actor_chain,
                violations=self.violations,
                reason="its parent scope would not be granted",
                reason_code=self.reason_code,
            )
        return _preview_child(
            self, tools=tools, resources=resources, intents=intents,
            time_budget_seconds=time_budget_seconds, agent=agent,
        )

    def to_dict(self) -> dict[str, Any]:
        """The preview as plain data — for a template or a JSON response."""
        out: dict[str, Any] = {
            "allowed": self.allowed,
            "tools": list(self.allowed_tools),
            "resources": list(self.allowed_resources),
            "intents": list(self.allowed_intents),
            "depth": self.depth,
            "max_depth": self.max_depth,
            "time_budget_seconds": self.time_budget_seconds,
            "actor_chain": list(self.actor_chain),
        }
        if not self.allowed:
            out["violations"] = list(self.violations)
            out["reason"] = self.reason
            if self.reason_code:
                out["reason_code"] = self.reason_code
        return out

    def __repr__(self) -> str:
        if not self.allowed:
            return f"ScopePreview(allowed=False, depth={self.depth}, violations={self.violations})"
        return f"ScopePreview(depth={self.depth}, tools={self.allowed_tools}, intents={self.allowed_intents})"


def _preview_child(
    parent: Any,
    *,
    tools: Sequence[str] | None,
    resources: Sequence[str] | None,
    intents: Sequence[str] | None,
    time_budget_seconds: int | None,
    agent: str | None,
) -> ScopePreview:
    """The :class:`ScopePreview` of a child of ``parent`` — nothing recorded."""
    out = _attenuation_outcome(
        parent, tools=tools, resources=resources, intents=intents, time_budget_seconds=time_budget_seconds
    )
    chain = (*parent.actor_chain, agent) if agent else tuple(parent.actor_chain)
    if out["kind"] == "allow":
        g = out["grant"]
        return ScopePreview(
            engine=parent._engine,
            allowed=True,
            tools=g["allowed_tools"],
            resources=g["allowed_resources"],
            intents=g["allowed_intents"],
            max_depth=g["max_depth"],
            time_budget_seconds=g["time_budget_seconds"],
            depth=g["depth"],
            max_delegation_depth=parent.max_delegation_depth,
            actor_chain=chain,
        )
    if out["kind"] == "depth":
        err = DelegationDepthExceeded(out["child_depth"], parent.max_delegation_depth)
        violations, reason, code = list(err.violations), err.reason, DELEGATION_DEPTH_EXCEEDED
    else:
        violations, reason, code = out["violations"], out["reason"], None
    return ScopePreview(
        engine=parent._engine,
        allowed=False,
        tools=out["requested_tools"],
        resources=(),
        intents=(),
        max_depth=0,
        time_budget_seconds=0,
        depth=out["child_depth"],
        max_delegation_depth=parent.max_delegation_depth,
        actor_chain=chain,
        violations=violations,
        reason=reason,
        reason_code=code,
    )
