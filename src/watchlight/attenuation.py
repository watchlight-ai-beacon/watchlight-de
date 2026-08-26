"""Sub-agent scope attenuation — a Developer-Edition taste of the real thing.

When an agent spawns a sub-agent, the child must receive a **strict subset** of
the parent's authority — never more. That strict-subset validation is done here
by the **real** Watchlight engine (``watchlight_engine.attenuate_scope``): a child
that asks for a tool, intent, or resource the parent does not hold is denied, and
a valid request comes back **clamped** to what the parent actually has.

The Developer Edition governs these trees up to **depth 5** (:data:`DE_MAX_DEPTH`).
Deeper trees — and the server-side enforcement, signed lineage, and fleet-wide
revocation that make attenuation a *guarantee* rather than a convention — are the
Enterprise plane. The math you feel here is real; the ceiling is where DE hands
off.

    root = govern.scope(tools=["read", "write", "search"], intents=["research"])
    analyst = root.attenuate(tools=["read", "search"])   # depth 1  (strict subset)
    reader  = analyst.attenuate(tools=["read"])           # depth 2
    # ... a sixth level raises DevEditionCeiling → the upgrade moment.
"""

from __future__ import annotations

import datetime
import json
import pathlib
from typing import Any, Sequence

__all__ = ["Scope", "DevEditionCeiling", "AttenuationDenied", "DE_MAX_DEPTH"]

#: The Developer-Edition ceiling: sub-agent trees attenuate up to this depth. The
#: engine still runs the real strict-subset math at every level — this is the
#: product boundary where DE hands off to Enterprise (which removes the cap and
#: adds server-side enforcement, signed lineage, and fleet-wide revocation).
DE_MAX_DEPTH = 5

_UPSELL = (
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
        super().__init__(_UPSELL.format(cap=DE_MAX_DEPTH, depth=depth))


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
    ) -> None:
        self._engine = engine
        self._audit_path = pathlib.Path(audit_path)
        self.agent = agent
        self.allowed_tools = _norm(allowed_tools)
        self.allowed_resources = _norm(allowed_resources)
        self.allowed_intents = _norm(allowed_intents)
        self.max_depth = int(max_depth)
        self.time_budget_seconds = int(time_budget_seconds)
        self.depth = int(depth)

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

        # The Developer-Edition ceiling — a product boundary, checked before the
        # engine. Everything up to here was a real, validated strict subset.
        if child_depth > DE_MAX_DEPTH:
            self._audit(
                resource=f"sub-agent depth {child_depth}",
                decision="Deny",
                reason=DevEditionCeiling(child_depth).args[0],
                depth=child_depth,
            )
            raise DevEditionCeiling(child_depth)

        parent = self._as_dict()
        request = {
            "allowed_tools": _norm(tools) if tools is not None else self.allowed_tools,
            "allowed_resources": _norm(resources) if resources is not None else self.allowed_resources,
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
            self._audit(
                resource=f"sub-agent depth {child_depth}",
                decision="Deny",
                reason=reason,
                depth=child_depth,
            )
            raise AttenuationDenied(violations, reason)

        # The engine returns the CLAMPED grant — never the child's raw request.
        granted = resp.get("granted_scope") or {}
        child = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            agent=self.agent,
            allowed_tools=granted.get("allowed_tools", request["allowed_tools"]),
            allowed_resources=granted.get("allowed_resources", request["allowed_resources"]),
            allowed_intents=granted.get("allowed_intents", request["allowed_intents"]),
            max_depth=granted.get("max_depth", request["max_depth"]),
            time_budget_seconds=granted.get("time_budget_seconds", request["time_budget_seconds"]),
            depth=granted.get("depth", child_depth),
        )
        self._audit(
            resource=f"sub-agent depth {child.depth} · tools {child.allowed_tools}",
            decision="Allow",
            reason="",
            depth=child.depth,
        )
        return child

    # ── internals ───────────────────────────────────────────────────

    def _as_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": self.allowed_tools,
            "allowed_resources": self.allowed_resources,
            "allowed_intents": self.allowed_intents,
            "max_depth": self.max_depth,
            "time_budget_seconds": self.time_budget_seconds,
            "depth": self.depth,
        }

    def _audit(self, *, resource: str, decision: str, reason: str, depth: int) -> None:
        # Value-free by construction — the scope's dimensions are capability
        # names, never argument values. Shape is compatible with `watchlight dev`
        # (ts/agent/intent/resource/decision), plus `depth`/`event` for a tree view.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "intent": "attenuate",
            "resource": resource,
            "decision": decision,
            "depth": depth,
            "event": "attenuation",
        }
        if reason:
            record["reason"] = reason
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            # Audit is best-effort in dev mode; never let it break the app.
            pass

    def __repr__(self) -> str:
        return (
            f"Scope(depth={self.depth}, tools={self.allowed_tools}, "
            f"intents={self.allowed_intents}, max_depth={self.max_depth})"
        )
