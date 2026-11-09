"""Uniform governed-spawn routing primitive (SubagentRegistry).

Every framework that exposes a *native* sub-agent primitive
(deepagents, LangGraph, Pydantic AI, the Claude Agent SDK, ADK,
Bedrock, …) needs the SAME thing when a child agent is created: route
the spawn through the governed ``spawn_subagent`` chokepoint so that
wl-apdp attests the spawn (server-side strict-subset attenuation)
and emits the authoritative ``agent_spawn_observed`` lineage event, and
so that the child's subsequent tool calls are authorized under the
child's OWN per-run ``sst_`` credential — never the shared tenant
bearer, never the root's handle.

Before this primitive, each plugin hand-rolled that routing. The
reference implementation is the TypeScript Claude Agent plugin
(``onSubagentStart`` / ``SubagentStop`` hooks). This module extracts
that pattern into ONE reusable helper so every framework wiring is a
thin adapter over identical, audited semantics.

What lives HERE, once, instead of per-plugin:

* **Parent-resolution ladder** — resolve the spawner handle as
  ``explicit parent_key`` → ``top of the active stack`` → ``root``.
  Spawning against the *direct* parent (never the root) is what lets
  the server bound a grandchild by the parent's GRANTED scope: a
  depth-2 grandchild is attenuated against depth-1's grant, not the
  root's full agent-record scope. Depth is NOT special-cased here — the
  server enforces the ``max_depth`` strict decrement.

  An **explicit** ``parent_key`` resolves ONLY to that named parent:
  if the named parent is itself fail-closed (denied) or unknown,
  the child fails CLOSED rather than being re-parented onto a laxer
  ancestor — a denied parent's subtree must never execute under
  root-derived authority. Only the **implicit** case (no ``parent_key``)
  walks the stack-top → root ladder. Framework wirings SHOULD therefore
  pass an explicit ``parent_key``; the implicit stack-top heuristic is a
  best-effort fallback that can mis-attribute under concurrent /
  interleaved spawns (documented, not relied on).

* **Fail-closed semantics** — an operator ``default_subagent_scope``
  supplies the requested scope when a framework surfaces no per-spawn
  scope. An EMPTY default is the deliberate, locked default: the child
  is registered but can call no tools until scoped. When the server
  DENIES the spawn (:class:`ScopeAttenuationDenied` /
  :class:`RunHandleInvalidated`, or any other spawn error, which then
  propagates) the registry records a fail-closed marker so
  :meth:`resolve` returns ``None`` — and the caller MUST deny the tool
  call (the ungoverned-request gate default). No bucket, no ungoverned
  execution. A refused child stays on the spawn stack until
  :meth:`on_stop`, so an implicit spawn under it fails closed instead
  of being re-parented onto a sibling or the root.

The registry stores ONLY the governed child handle keyed by an
opaque, framework-supplied ``child_key`` (the framework's own
sub-agent id). Event emission, action counters, and per-run state stay
in the plugin adapter — the registry is the spawn/lifecycle chokepoint,
not a replacement for the plugin's bookkeeping.

The TypeScript SDK ships a wire-identical mirror of this module.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Set

from .errors import RunHandleInvalidated, ScopeAttenuationDenied
from .log import get_logger
from .scope import plugin_child_intent
from .run_handle import BaseRunHandle

__all__ = [
    "SubagentRegistry",
    "DEFAULT_SUBAGENT_SCOPE_ENV_VAR",
    "default_subagent_scope_from_env",
]

logger = get_logger("watchlight_core.subagent_registry")

#: Operator env var carrying the fallback per-spawn scope as a JSON
#: object. Used when a framework surfaces no explicit per-spawn scope
#: AND the constructor was given no ``default_subagent_scope``.
DEFAULT_SUBAGENT_SCOPE_ENV_VAR = "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE"

# Canonical ``RequestedScope`` kwargs accepted by
# :meth:`BaseRunHandle.spawn_subagent`. camelCase aliases are tolerated
# on the env-var path so a JSON blob copy-pasted from the TypeScript
# lane still resolves.
_SCOPE_KEY_ALIASES: Dict[str, str] = {
    "allowed_tools": "allowed_tools",
    "allowedtools": "allowed_tools",
    "allowed_resources": "allowed_resources",
    "allowedresources": "allowed_resources",
    "allowed_intents": "allowed_intents",
    "allowedintents": "allowed_intents",
    "max_depth": "max_depth",
    "maxdepth": "max_depth",
    "time_budget_seconds": "time_budget_seconds",
    "timebudgetseconds": "time_budget_seconds",
}


def _normalize_scope(scope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize a scope mapping into canonical ``spawn_subagent``
    kwargs, tolerating camelCase keys (for env-var / cross-lane copy).

    Unknown keys are dropped (fail-closed on typos rather than
    forwarding a bogus kwarg that would raise ``TypeError`` at spawn
    time). An empty / ``None`` input yields ``{}`` — the deliberate
    fail-closed default.
    """
    if not scope:
        return {}
    out: Dict[str, Any] = {}
    for key, value in scope.items():
        canonical = _SCOPE_KEY_ALIASES.get(str(key).strip().lower())
        if canonical is not None:
            out[canonical] = value
    return out


def default_subagent_scope_from_env(
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Parse the fallback per-spawn scope from
    :data:`DEFAULT_SUBAGENT_SCOPE_ENV_VAR`.

    Returns a canonical ``spawn_subagent`` kwargs dict. When the var is
    unset, empty, malformed, or not a JSON object, returns ``{}`` — the
    fail-closed default (an operator misconfiguration must never widen
    a child's authority; the worst case is a child that can call no
    tools until correctly scoped). Parse failures are logged loudly
    (no secret values are ever present in this var, but we still never
    echo raw contents beyond the JSON error).
    """
    source = env if env is not None else os.environ
    raw = source.get(DEFAULT_SUBAGENT_SCOPE_ENV_VAR)
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as exc:
        logger.warning(
            "%s: invalid JSON — falling back to an EMPTY (fail-closed) "
            "default sub-agent scope. Fix the JSON so sub-agents receive "
            "the intended scope. (%s)",
            DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
            exc,
        )
        return {}
    if not isinstance(parsed, dict):
        logger.warning(
            "%s: expected a JSON object, got %s — falling back to an EMPTY "
            "(fail-closed) default sub-agent scope.",
            DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
            type(parsed).__name__,
        )
        return {}
    return _normalize_scope(parsed)


def _denial_class(exc: ScopeAttenuationDenied) -> str:
    """Coarse refusal class for a server scope-attenuation denial."""
    code = (getattr(exc, "reason_code", None) or "").upper()
    if code == "DELEGATION_DEPTH_EXCEEDED":
        return "delegation_depth"
    if code == "UNSATISFIABLE_SCOPE":
        return "unsatisfiable_scope"
    return "scope_attenuation"


class SubagentRegistry:
    """Route a framework's native sub-agent creation through the
    governed ``spawn_subagent`` chokepoint.

    Construct once per governed root run with the root
    :class:`BaseRunHandle` and an operator ``default_subagent_scope``
    (the fallback requested scope when a framework surfaces no
    per-spawn scope). Then drive it from the framework's lifecycle
    hooks:

    * :meth:`on_spawn` when the framework opens a child agent — routes
      the spawn through the direct parent's handle, stores the governed
      child, returns it (or ``None`` when the server denies).
    * :meth:`resolve` on every tool call — returns the governed child
      handle to authorize against, or ``None`` (caller MUST deny).
    * :meth:`on_stop` when the framework closes the child — pops the
      stack, completes the child handle, drops the entry.

    Thread/async model: the registry mutates plain in-memory maps and a
    LIFO stack; it is intended to be driven from a single framework
    event loop (the lifecycle hooks fire serially). It performs no
    locking of its own.
    """

    def __init__(
        self,
        root_handle: BaseRunHandle,
        default_subagent_scope: Optional[Dict[str, Any]] = None,
        child_intent_category: Optional[str] = None,
    ) -> None:
        """
        Parameters
        ----------
        root_handle:
            The governed root run's handle. Depth-1 spawns (and any
            spawn with no in-flight sub-agent on the stack) attenuate
            against this handle's scope.
        default_subagent_scope:
            Fallback requested scope (canonical ``spawn_subagent``
            kwargs, e.g. ``{"allowed_tools": [...], "max_depth": 1}``)
            used when :meth:`on_spawn` is called with
            ``requested_scope=None``. When ``None``, the value is read
            from :data:`DEFAULT_SUBAGENT_SCOPE_ENV_VAR`. An EMPTY scope
            is the deliberate fail-closed default — the child is
            registered but authorizes no tools until scoped.
        child_intent_category:
            The intent category declared for a child when :meth:`on_spawn`
            names no ``child_intent``. ``None``: the spawner's own derived
            category, else
            :data:`~watchlight_core.scope.DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY`.
            wl-apdp refuses a category outside the parent's intent bounds.
        """
        self._root: BaseRunHandle = root_handle
        self._child_intent_category: Optional[str] = child_intent_category
        self._default_scope: Dict[str, Any] = (
            _normalize_scope(default_subagent_scope)
            if default_subagent_scope is not None
            else default_subagent_scope_from_env()
        )
        # child_key -> governed child handle (successful spawns only).
        self._children: Dict[str, BaseRunHandle] = {}
        # child_key marked fail-closed: server denied the spawn, so
        # ``resolve`` returns None and the caller denies the tool call.
        self._failed: Set[str] = set()
        # child_key -> refusal class (see ``refusal_class``).
        self._refusal_class: Dict[str, str] = {}
        # LIFO stack of live child_keys — top is the most-recently
        # spawned, not-yet-stopped sub-agent (the direct parent for a
        # deeper spawn when no explicit parent_key is supplied).
        self._stack: List[str] = []

    @property
    def default_subagent_scope(self) -> Dict[str, Any]:
        """The resolved fallback scope (canonical kwargs). Read-only
        copy so callers can't mutate registry state."""
        return dict(self._default_scope)

    def _register_fail_closed(self, child_key: str, cause: str) -> None:
        """Mark ``child_key`` fail-closed: drop any live bucket and set
        the deny marker so :meth:`resolve` returns ``None``. A later
        successful :meth:`on_spawn` clears the marker. ``cause`` is the
        refusal class :meth:`refusal_class` reports."""
        self._children.pop(child_key, None)
        self._failed.add(child_key)
        self._refusal_class[child_key] = cause
        # Keep the refused child on the active stack until ``on_stop``:
        # while it is open, an IMPLICIT spawn may be its grandchild and
        # must fail closed rather than run under a sibling or the root.
        if child_key not in self._stack:
            self._stack.append(child_key)

    def _remove_from_stack(self, child_key: str) -> None:
        for idx in range(len(self._stack) - 1, -1, -1):
            if self._stack[idx] == child_key:
                del self._stack[idx]
                break

    def refusal_class(self, child_key: str) -> Optional[str]:
        """Why ``child_key``'s spawn failed closed, as a coarse class a
        framework can turn into an instructive message without repeating
        the server's decision detail:

        * ``"scope_attenuation"`` — the requested scope is not a strict
          subset of the parent's granted scope;
        * ``"delegation_depth"`` — the tree is at its depth limit;
        * ``"unsatisfiable_scope"`` — the grant would authorize nothing;
        * ``"parent_invalidated"`` — the parent's run handle is no longer
          valid;
        * ``"parent_refused"`` / ``"parent_unknown"`` — the named parent
          was itself refused, or is not a live sub-agent (for an implicit
          spawn: a refused child is still open on the stack);
        * ``"spawn_failed"`` — the spawn raised an unexpected error (the
          error propagated to the caller).

        ``None`` when ``child_key`` is not fail-closed.
        """
        if child_key not in self._failed:
            return None
        return self._refusal_class.get(child_key)

    def _resolve_implicit_spawner(self) -> Optional[BaseRunHandle]:
        """Resolve the spawner for the IMPLICIT case (no explicit
        ``parent_key``): top of the active stack → root.

        Only the implicit case walks this ladder. An EXPLICIT
        ``parent_key`` is resolved in :meth:`on_spawn` and fails CLOSED
        when the named parent is denied or unknown — it never falls
        through to a laxer ancestor here. See the explicit-parent
        handling described in the module docstring.

        Spawning against the DIRECT parent (top of stack) — never the
        root — is what makes the server bound a grandchild by the
        parent's granted scope.

        Returns ``None`` (fail closed) when the stack top is a refused
        child that is still open: the new spawn may be its descendant.
        """
        for key in reversed(self._stack):
            if key in self._failed:
                return None
            handle = self._children.get(key)
            if handle is not None:
                return handle
        return self._root

    async def on_spawn(
        self,
        *,
        child_key: str,
        child_slug: str,
        requested_scope: Optional[Dict[str, Any]] = None,
        parent_key: Optional[str] = None,
        child_intent: Optional[Any] = None,
        objective: Optional[str] = None,
    ) -> Optional[BaseRunHandle]:
        """Route a native sub-agent creation through the governed
        ``spawn_subagent`` chokepoint.

        Steps: (1) resolve the spawner handle via the parent-resolution
        ladder; (2) call ``spawner.spawn_subagent(child_slug, **scope)``
        — this is what makes wl-apdp attest the spawn and emit the
        authoritative ``agent_spawn_observed``; (3) on success, store
        the child handle keyed by ``child_key``, push ``child_key`` on
        the active stack, and return the handle; (4) on a server denial
        (:class:`ScopeAttenuationDenied` / :class:`RunHandleInvalidated`)
        record a fail-closed marker so :meth:`resolve` returns ``None``,
        log loudly (no token values), and return ``None``.

        Parameters
        ----------
        child_key:
            Opaque, framework-supplied id for the child sub-agent (the
            framework's own agent/thread id). The key used by
            :meth:`resolve` and :meth:`on_stop`.
        child_slug:
            The child agent's slug / UUID passed to
            ``spawn_subagent`` as the child principal.
        requested_scope:
            Per-spawn requested scope (canonical ``spawn_subagent``
            kwargs). When ``None``, the operator
            ``default_subagent_scope`` is used.
        parent_key:
            Explicit spawner ``child_key`` when the framework surfaces
            the parent. Framework wirings SHOULD pass this. When it is
            supplied but names a DENIED or UNKNOWN parent, the child
            fails CLOSED — it is NOT re-parented onto a laxer
            ancestor. When ``None`` (implicit), the ladder falls to the
            top of the stack, then the root.
        child_intent:
            The child's intent and goal (``ChildIntent`` or its dict form).
            When ``None``, the registry derives one with
            :func:`~watchlight_core.scope.plugin_child_intent` from
            ``objective`` (the framework's delegation text) and the
            configured category. Every spawn carries one.
        objective:
            The task text the framework hands the child, used only when
            ``child_intent`` is ``None``.

        Returns
        -------
        Optional[BaseRunHandle]
            The governed child handle on success, or ``None`` when the
            spawn failed closed (server denial, or an explicit
            denied/unknown ``parent_key``). The caller MUST deny the
            child's tool calls in the ``None`` case.
        """
        # A ``child_key`` already live in ``_children`` must not be
        # re-spawned: overwriting would LEAK the prior handle and
        # double-push the stack (corrupting the parent-resolution
        # ladder). Return the existing governed handle unchanged
        # (idempotent) — the safe disposition. A key that is only
        # fail-closed-marked (not live) is NOT a duplicate; it may
        # re-spawn and clear its marker.
        existing = self._children.get(child_key)
        if existing is not None:
            logger.warning(
                "SubagentRegistry: on_spawn called for an already-live "
                "child_key=%s — returning the existing governed handle "
                "without re-spawning (no duplicate spawn / stack push).",
                child_key,
            )
            return existing

        # A fail-closed key being retried replaces its own stack entry
        # (it must not block itself as an implicit parent).
        if child_key in self._failed:
            self._remove_from_stack(child_key)

        # An EXPLICIT parent_key resolves ONLY to its named parent.
        # A denied or unknown explicit parent fails CLOSED: the child's
        # subtree must not execute under a laxer ancestor (stack-top
        # sibling / root) than the parent the framework named. Only the
        # IMPLICIT case (parent_key is None) uses the stack-top → root
        # ladder.
        if parent_key is not None:
            if parent_key in self._failed:
                self._register_fail_closed(child_key, "parent_refused")
                logger.warning(
                    "SubagentRegistry: spawn FAILED CLOSED for child_key=%s "
                    "slug=%s — explicit parent_key=%s is itself fail-closed "
                    "(denied). Refusing to re-parent the child onto a laxer "
                    "ancestor; a denied parent's subtree must not execute.",
                    child_key,
                    child_slug,
                    parent_key,
                )
                return None
            spawner = self._children.get(parent_key)
            if spawner is None:
                self._register_fail_closed(child_key, "parent_unknown")
                logger.warning(
                    "SubagentRegistry: spawn FAILED CLOSED for child_key=%s "
                    "slug=%s — explicit parent_key=%s is unknown (never "
                    "spawned / already stopped). Refusing to substitute "
                    "another ancestor.",
                    child_key,
                    child_slug,
                    parent_key,
                )
                return None
        else:
            implicit = self._resolve_implicit_spawner()
            if implicit is None:
                self._register_fail_closed(child_key, "parent_refused")
                logger.warning(
                    "SubagentRegistry: spawn FAILED CLOSED for child_key=%s "
                    "slug=%s — a refused sub-agent is still open on the "
                    "spawn stack and this implicit spawn may be its "
                    "descendant. Pass an explicit parent_key.",
                    child_key,
                    child_slug,
                )
                return None
            spawner = implicit

        scope_kwargs = (
            _normalize_scope(requested_scope)
            if requested_scope is not None
            else dict(self._default_scope)
        )
        # A scope that pins exactly one intent names the category: wl-apdp
        # requires ``allowed_intents`` to be empty or exactly the category.
        scoped_intents = list(scope_kwargs.get("allowed_intents") or [])
        declared_intent = (
            child_intent
            if child_intent is not None
            else plugin_child_intent(
                objective,
                category=(
                    scoped_intents[0]
                    if len(scoped_intents) == 1
                    else self._child_intent_category
                ),
                parent=spawner,
                fallback_objective=f"Delegated task for sub-agent {child_slug}",
            )
        )
        try:
            child = await spawner.spawn_subagent(
                child_slug, child_intent=declared_intent, **scope_kwargs
            )
        except ScopeAttenuationDenied as exc:
            # Server refused: requested scope ⊄ parent effective scope.
            # Fail closed — record the marker, keep no bucket. The
            # ``violations`` list carries the offending dimensions; no
            # token/credential values appear in the exception.
            self._register_fail_closed(child_key, _denial_class(exc))
            logger.warning(
                "SubagentRegistry: spawn DENIED (scope_attenuation) for "
                "child_key=%s slug=%s — violations=%s reason=%s. "
                "Child registered fail-closed: its tool calls will be "
                "DENIED until an operator narrows the requested scope to a "
                "strict subset of the parent's granted scope.",
                child_key,
                child_slug,
                [v.value for v in exc.violations],
                exc.reason,
            )
            return None
        except RunHandleInvalidated as exc:
            # Parent handle no longer valid (revoke race / kill cascade).
            # Fail closed — no delegation from an invalidated parent.
            self._register_fail_closed(child_key, "parent_invalidated")
            logger.warning(
                "SubagentRegistry: spawn ABORTED (run_handle_invalidated) "
                "for child_key=%s slug=%s — reason=%s. Child registered "
                "fail-closed: its tool calls will be DENIED. Re-establish a "
                "fresh parent run before spawning.",
                child_key,
                child_slug,
                exc.reason,
            )
            return None
        except Exception as exc:
            # Any other failure (transport, missing child credential, a
            # run-ending decision on the spawner, ...) also leaves a
            # fail-closed marker, then propagates so the caller sees it.
            self._register_fail_closed(child_key, "spawn_failed")
            logger.warning(
                "SubagentRegistry: spawn FAILED for child_key=%s slug=%s "
                "(%s). Child registered fail-closed.",
                child_key,
                child_slug,
                type(exc).__name__,
            )
            raise

        # Success — clear any stale fail-closed marker, store, push.
        self._failed.discard(child_key)
        self._refusal_class.pop(child_key, None)
        self._children[child_key] = child
        self._remove_from_stack(child_key)
        self._stack.append(child_key)
        return child

    def resolve(self, child_key: str) -> Optional[BaseRunHandle]:
        """Return the governed child handle for ``child_key``, or
        ``None``.

        ``None`` means the caller MUST deny the child's tool call — the
        ungoverned-request-gate default. A ``child_key`` with a
        fail-closed marker (a server-denied spawn) returns ``None``.
        """
        if child_key in self._failed:
            return None
        return self._children.get(child_key)

    async def on_stop(self, child_key: str) -> None:
        """Close out a sub-agent: pop the stack, complete the child
        handle, drop the entry.

        Idempotent and out-of-order safe — a long-running parent that
        finishes after a quick child it spawned removes by last
        occurrence rather than popping blindly from the top. A
        ``child_key`` that was never registered (or was fail-closed) is
        simply cleared.
        """
        self._failed.discard(child_key)
        self._refusal_class.pop(child_key, None)
        # Remove the LAST occurrence from the stack (out-of-order safe).
        self._remove_from_stack(child_key)
        child = self._children.pop(child_key, None)
        if child is None:
            return
        try:
            await child.complete()
        except Exception as exc:  # noqa: BLE001 — close is best-effort
            # The framework MUST be able to release its sub-agent even
            # when observability / the APDP round-trip is degraded.
            logger.warning(
                "SubagentRegistry: on_stop close failed for child_key=%s "
                "(%s)",
                child_key,
                exc,
            )
