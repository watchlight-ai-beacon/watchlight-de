"""watchlight — Developer Edition.

Govern an AI agent in-process, with zero infrastructure. Decorate a tool with
an *intent*, load a local policy, run your script, and the policy engine
authorizes every call — allowing what a policy permits and refusing everything
else **before the tool body runs**.

    from watchlight import govern, Denied

    govern.load("watchlight.policy.json")     # or govern.allow("permit(...);")

    @govern.tool(intent="research")
    def web_search(query: str) -> str:
        ...

The engine is the Watchlight authorization engine (Cedar evaluation plus the
surrounding pipeline) embedded via the ``watchlight-engine`` extension — the
same authorization model that runs in production, in-process. Point it at a
networked policy service to run the same code against a remote APDP.

Guarantees that are identical to production and MUST NOT be relaxed here:
  * **Fail-closed** — no matching policy denies; an unreachable decision denies.
  * **Explicit intent** — a tool is governed by the intent you declare, never
    inferred from its name or body.
  * **Value-free audit** — argument *values* never enter the trail; only who,
    what intent, which resource, and the decision.
"""

from __future__ import annotations

import datetime
import functools
import json
import os
import pathlib
from typing import Any, Callable, Sequence, TypeVar

import watchlight_engine as _engine

from .attenuation import DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling, Scope

__all__ = [
    "Watchlight",
    "Denied",
    "govern",
    "Scope",
    "AttenuationDenied",
    "DevEditionCeiling",
    "DE_MAX_DEPTH",
]

_F = TypeVar("_F", bound=Callable[..., Any])


class Denied(PermissionError):
    """Raised when the policy engine refuses a governed tool call (fail-closed).

    The decorated function's body never runs — the refusal happens *before* the
    side effect.
    """

    def __init__(self, tool: str, intent: str, reason: str) -> None:
        self.tool = tool
        self.intent = intent
        self.reason = reason
        super().__init__(f"watchlight denied intent '{intent}' on tool/{tool}: {reason}")


class Watchlight:
    """An in-process policy decision point for a single agent.

    Wraps the ``watchlight-engine`` in-process authorization core. Policies are
    loaded from a local file or added inline; each governed tool call is
    authorized against them.
    """

    def __init__(self, agent: str | None = None, audit_dir: str | os.PathLike[str] = ".watchlight") -> None:
        self._engine = _engine.PolicyEngine()
        self.agent = agent or os.environ.get("WATCHLIGHT_AGENT", "my-agent")
        self._audit_path = pathlib.Path(audit_dir) / "audit.jsonl"
        self._announced = False
        self._policy_count = 0

    # ── policy loading ──────────────────────────────────────────────

    def allow(self, cedar_code: str, name: str | None = None) -> "Watchlight":
        """Add one Cedar policy inline. Returns self for chaining."""
        self._engine.add_policy(
            json.dumps({"name": name or f"policy-{self._policy_count}", "code": cedar_code})
        )
        self._policy_count += 1
        return self

    def load(self, path: str | os.PathLike[str]) -> "Watchlight":
        """Load policies from a JSON file — a list of ``{"name", "code"}`` objects
        (or ``{"policies": [...]}``). Fail-closed: a missing file loads nothing,
        so every governed call is denied until a policy permits it."""
        p = pathlib.Path(path)
        if not p.exists():
            return self
        data = json.loads(p.read_text())
        entries = data if isinstance(data, list) else data.get("policies", [])
        for entry in entries:
            self.allow(entry["code"], entry.get("name"))
        return self

    # ── sub-agent scope attenuation ─────────────────────────────────

    def scope(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        max_depth: int = DE_MAX_DEPTH,
        time_budget_seconds: int = 3600,
    ) -> Scope:
        """Create a root capability scope for this agent, from which sub-agent
        scopes are attenuated (strict-subset).

        The Developer Edition governs the tree up to depth
        :data:`~watchlight.attenuation.DE_MAX_DEPTH` (5); Enterprise removes the
        ceiling and enforces it server-side. See
        :class:`~watchlight.attenuation.Scope`.
        """
        root = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            agent=self.agent,
            allowed_tools=tools,
            allowed_resources=resources,
            allowed_intents=intents,
            max_depth=min(int(max_depth), DE_MAX_DEPTH),
            time_budget_seconds=time_budget_seconds,
            depth=0,
        )
        root._emit_root()  # record the tree's starting authority for `watchlight dev`
        return root

    # ── governing tools ─────────────────────────────────────────────

    def tool(self, intent: str) -> Callable[[_F], _F]:
        """Decorate a function as a governed tool with the given *intent*.

        On every call the engine authorizes ``(agent, intent, tool/<name>)``.
        On ALLOW the function runs; on anything else a :class:`Denied` is raised
        and the body never executes.
        """

        def decorator(fn: _F) -> _F:
            resource = f"tool/{fn.__name__}"

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                decision, reason = self._authorize(intent, resource)
                self._audit(intent, resource, decision, reason)
                if decision != "Allow":
                    raise Denied(fn.__name__, intent, reason or "no matching policy")
                return fn(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        return decorator

    # ── internals ───────────────────────────────────────────────────

    def _authorize(self, intent: str, resource: str) -> tuple[str, str]:
        response = json.loads(
            self._engine.authorize(
                json.dumps(
                    {
                        "principal": self.agent,
                        "action": intent,
                        "resource": resource,
                        "context": {},
                    }
                )
            )
        )
        return response.get("decision", "Deny"), response.get("reason", "")

    def _announce(self) -> None:
        if not self._announced:
            print(f"watchlight: governing '{self.agent}' (dev mode, in-process engine)")
            self._announced = True

    def _audit(self, intent: str, resource: str, decision: str, reason: str) -> None:
        self._announce()
        allowed = decision == "Allow"
        tag = "ALLOW" if allowed else "DENY"
        trailer = "" if allowed else f"     {reason or 'no matching policy'}"
        print(f"watchlight: {tag:5} {intent:9} {resource}{trailer}")
        # Value-free audit: argument VALUES never enter the trail — only the
        # governance decision. This mirrors the production audit contract.
        record = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "intent": intent,
            "resource": resource,
            "decision": decision,
        }
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            # Audit is best-effort in dev mode; never let it break the app.
            pass


# A ready-to-use default governor so `from watchlight import govern` just works.
# It starts with NO policies — fail-closed by default — until you `govern.load(...)`
# a policy file or `govern.allow(...)` a policy inline.
govern = Watchlight()
