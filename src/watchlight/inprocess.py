"""In-process governance backend for Watchlight framework plugins.

The Developer Edition runs the Watchlight framework plugins
(``watchlight-langgraph``, ``watchlight-pydantic-ai``, ``watchlight-claude-agent``,
…) against the compiled authorization engine **in-process**, with zero
infrastructure. The seam is one object: a ``GovernanceBackend``.

- **Production**: the plugin talks to a networked policy service over TLS
  (``ApdpClient``).
- **Developer Edition**: the plugin talks to :func:`in_process_backend` — the
  ``watchlight-engine`` (Cedar) embedded in your process, writing a local,
  value-free audit trail.

``WATCHLIGHT_APDP_URL`` selects between the two (see :func:`_select_backend_kwargs`).

**What the in-process backend records.** Every authorization decision a plugin
asks it for (``handle.authorize_action`` and everything built on it) writes one
value-free decision record — the same record, built by the same function
(:func:`watchlight._audit.decision_record`) and written through the same
:class:`~watchlight._audit.AuditTrail`, as :meth:`watchlight.Watchlight.authorize`.
A sub-agent's decision names the sub-agent as ``agent`` and carries the
delegation chain, root first, as ``actor_chain``. The run's
``execution_started`` / ``execution_completed`` lifecycle lines and the
sub-agent ``attenuation`` lines are written by the SDK's client, to the same
file, as before. A ``preflight_step`` is an advisory, read-only what-if (it does
not count toward the run's budget and gates nothing) and writes no record; the
gate is ``authorize_action``.

Once a run is quarantined or severed, the plugin's handle refuses every later
call itself, without asking the backend. A plugin built by ``governed_plugin``
hands out run handles that record those refusals too (:class:`_AuditedRunHandle`),
including the children it spawns and the Claude Agent SDK's native Task
sub-agents. Two routes do not record those self-made refusals: a handle read
from ``watchlight_core.current_subagent_handle()`` (the SDK's own handle), and a
plugin you construct yourself around :func:`in_process_backend`. Both still
record every decision the backend makes.

    from watchlight.inprocess import in_process_backend
    from watchlight_langgraph import WatchlightLangGraphPlugin

    plugin = WatchlightLangGraphPlugin(
        governance=in_process_backend("watchlight.policy.json")
    )

Most users never import this directly — the per-framework helpers
(``watchlight.langgraph.governed_plugin`` etc.) call it for you.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from . import principals
from ._audit import (
    _SMALL_FIELD_BYTES,
    UNCONFIGURED_AGENT,
    AuditSink,
    AuditTrail,
    _error_kind,
    _marker,
    decision_record,
)

# A local policy source: a path to a JSON policy file, or an in-memory list of
# ``{"name", "code"}`` Cedar policy objects. ``None`` loads no policies —
# fail-closed, so every action is denied until a policy permits it.
Policies = Optional[Union[str, "os.PathLike[str]", List[Dict[str, Any]]]]


def in_process_backend(
    policies: Policies = None,
    *,
    audit_path: Optional[str] = ".watchlight/audit.jsonl",
    audit_sink: Optional[AuditSink] = None,
    audit_sink_batch: Optional[int] = None,
    audit_sink_interval: Optional[float] = None,
) -> Any:
    """Build an in-process ``GovernanceBackend`` over the compiled engine.

    :param policies: a path to a JSON policy file (a list of
        ``{"name", "code"}`` objects, or ``{"policies": [...]}``), or that list
        in memory. ``None`` → no policies (fail-closed: everything denies).
    :param audit_path: local JSONL audit file. Value-free — argument VALUES
        never enter the trail, only the governance decision. Pass ``None`` to
        disable the local audit file.
    :param audit_sink: an additional destination for every DECISION record,
        with exactly the semantics of ``Watchlight(audit_sink=...)``: it receives
        its own copy of the fields the file line carries, after the file append;
        a failure is reported once on stderr and never changes a decision. A
        synchronous sink runs INSIDE the decision and adds its own time to it —
        and on this path the decision is made on the event loop, so a slow
        synchronous sink also blocks every other task on that loop. Use an
        async sink (an awaitable it returns is scheduled on the running loop,
        never awaited inline) or batching. The run lifecycle and attenuation
        lines go to the file only.
    :param audit_sink_batch: as ``Watchlight(audit_sink_batch=...)`` — hand the
        sink lists from a background worker, off the decision path.
    :param audit_sink_interval: as ``Watchlight(audit_sink_interval=...)``.
    :returns: a ``watchlight_core.InProcessClient`` — pass it to any Watchlight
        framework plugin via ``governance=``. Every ``authorize`` it answers
        writes one decision record (see the module docstring).

    Requires the Watchlight SDK (installed transitively by any framework extra,
    e.g. ``pip install 'watchlight[langgraph]'``).
    """
    trail = AuditTrail(
        audit_path,
        audit_sink,
        sink_batch=audit_sink_batch,
        sink_interval=audit_sink_interval,
        no_destination_message=(
            "watchlight: audit_path is None and no audit_sink is configured — the plugin's "
            "decision records are discarded. Configure `audit_sink`, or pass an `audit_path`."
        ),
    )
    return _audited_client_class()(policies, audit_path=audit_path, trail=trail)


#: Record fields are stored exactly as given, as the direct path stores them:
#: ``json.dumps`` escapes every control character, and U+2028 / U+2029, so no
#: value can break or forge a line, and a field stored in full is one
#: ``counters()`` can match exactly. Agent names — the root's, passed to
#: ``start_run``, and a sub-agent's, often chosen by the framework or the model
#: — are recorded as given.

@functools.lru_cache(maxsize=None)
def _refused_marker(value: Any) -> Dict[str, Any]:
    """The value-free stand-in for a plugin term that broke a name rule: its
    length in bytes and, as the audit funnel does, a digest only for a value
    longer than 256 bytes — a short name is never digested. A non-string has
    neither."""
    if not isinstance(value, str):
        return {"omitted": "refused"}
    size = len(str.encode(value, "utf-8", "surrogatepass"))
    if size <= _SMALL_FIELD_BYTES:
        return {"omitted": "refused", "bytes": size}
    return _marker(value, "refused")


def _short_circuit_errors() -> Tuple[type, ...]:
    """The refusals a plugin's handle makes WITHOUT asking the backend: a handle
    that is quarantined or severed refuses every later call itself. The handle
    wrapper records each one (see :class:`_AuditedRunHandle`)."""
    from watchlight_core import AgentQuarantinedError, SubtreeSeveredError

    return (AgentQuarantinedError, SubtreeSeveredError)

#: Set by the handle wrapper for the duration of one call; the backend marks it
#: when it answers. A short-circuit refusal is one the backend never saw.
_CALL_MARKER: "contextvars.ContextVar[Optional[Dict[str, bool]]]" = contextvars.ContextVar(
    "watchlight_plugin_call", default=None
)


@functools.lru_cache(maxsize=None)
def _audited_client_class() -> Any:
    """The SDK's ``InProcessClient``, with one decision record per decision.

    Built on first use, because the SDK is an optional dependency: ``import
    watchlight`` must never require it."""
    try:
        from watchlight_core import InProcessClient
    except ImportError as exc:  # pragma: no cover - import-guard message
        raise ImportError(
            "in_process_backend requires the Watchlight SDK. Install a framework "
            "extra, e.g. `pip install 'watchlight[langgraph]'`, or the SDK "
            "directly: `pip install watchlight-agent-sdk`."
        ) from exc

    class AuditedInProcessClient(InProcessClient):  # type: ignore[misc, valid-type]
        """``InProcessClient`` that records every decision it makes.

        Only PUBLIC ``GovernanceBackend`` methods are overridden, and each calls
        the SDK's own implementation for the behaviour — the decision itself is
        never computed here. The overrides only observe: the agent's name
        (``resolve_agent``), which agent a session belongs to
        (``create_session``, ``spawn_subagent``), and the verdict
        (``authorize``). ``tests/integrations/test_plugin_decision_audit.py``
        lists the SDK client's public methods, so one added in a later SDK
        release fails a test until it is classified here."""

        def __init__(self, policies: Any = None, *, audit_path: Optional[str], trail: AuditTrail) -> None:
            super().__init__(policies, audit_path=audit_path)
            self._wl_trail = trail
            # agent id -> the name the run was started with, so a record names
            # the agent as the developer did ("research-agent"), like the direct
            # path's `agent`, rather than as its derived id.
            self._wl_agent_names: Dict[str, str] = {}
            # session id -> the delegation chain of agent ids, root first. A
            # root run's chain is its own agent; a sub-agent's is its parent's
            # chain plus itself.
            self._wl_sessions: Dict[str, Tuple[str, ...]] = {}
            # child run-handle id -> its chain, so a grandchild finds its parent.
            self._wl_handles: Dict[str, Tuple[str, ...]] = {}
            self._wl_warned_record = False

        # ── observation: who is acting ───────────────────────────────

        async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
            agent = await super().resolve_agent(slug)
            if isinstance(agent, dict) and agent.get("id"):
                self._wl_agent_names[str(agent["id"])] = slug
            return agent

        async def create_session(self, agent_id: str, *args: Any, **kwargs: Any) -> Optional[Dict[str, Any]]:
            response = await super().create_session(agent_id, *args, **kwargs)
            session = (response or {}).get("session") if isinstance(response, dict) else None
            if isinstance(session, dict) and session.get("id"):
                self._wl_sessions[str(session["id"])] = (str(agent_id),)
            return response

        async def spawn_subagent(
            self, request_body: Dict[str, Any], session_token: Optional[str] = None
        ) -> Dict[str, Any]:
            response = await super().spawn_subagent(request_body, session_token=session_token)
            try:
                parent_handle = str(request_body["parent_run_handle_id"])
                parent_chain = self._wl_handles.get(parent_handle) or (
                    str(request_body["parent_agent_id"]),
                )
                chain = parent_chain + (str(request_body["child_agent_id"]),)
                child_handle = str(response["child_run_handle_id"])
                # The session the SDK's handle uses for the child: the one the
                # backend returned, else `ses_<child run handle>` — the SDK's
                # own derivation, in the base handle and in every plugin.
                child_session = response.get("child_session_id") or f"ses_{child_handle}"
                self._wl_handles[child_handle] = chain
                self._wl_sessions[str(child_session)] = chain
            except Exception as exc:  # noqa: BLE001 — observing never changes the spawn
                self._wl_report_record_failure(exc)
            return response

        async def complete_session(self, session_id: str) -> bool:
            self._wl_forget(session_id)
            return await super().complete_session(session_id)

        async def terminate_session(self, session_id: str, reason: str = "manual") -> bool:
            self._wl_forget(session_id)
            return await super().terminate_session(session_id, reason)

        def _wl_forget(self, session_id: str) -> None:
            self._wl_sessions.pop(session_id, None)
            if isinstance(session_id, str) and session_id.startswith("ses_"):
                self._wl_handles.pop(session_id[4:], None)

        # ── the decision ─────────────────────────────────────────────

        async def authorize(
            self,
            principal: str,
            action: str,
            resource: str,
            context: Optional[Dict[str, Any]] = None,
            execution_id: Optional[str] = None,
            session_id: Optional[str] = None,
            intent: Optional[Dict[str, Any]] = None,
            session_token: Optional[str] = None,
        ) -> Dict[str, Any]:
            marker = _CALL_MARKER.get()
            if marker is not None:
                marker["reached"] = True
            # The direct path's bounds (see watchlight.principals), applied
            # before the engine and before the trail: a term that breaks a rule
            # raises TypeError (value-free) and nothing is decided or recorded,
            # exactly as Watchlight.authorize does. Only here, at the decision —
            # never in start_run or resolve_agent, where a framework's
            # instrumentation could swallow the error.
            principal = principals.assert_principal(principal)
            action = principals.assert_name(action, "action")
            resource = principals.assert_name(resource, "resource")
            if execution_id is not None:
                execution_id = principals.assert_name(execution_id, "execution_id")
            try:
                result = await super().authorize(
                    principal,
                    action,
                    resource,
                    context,
                    execution_id=execution_id,
                    session_id=session_id,
                    intent=intent,
                    session_token=session_token,
                )
            except Exception:
                # The direct path's rule: a request the engine cannot evaluate
                # is a refusal like any other — recorded, then raised as itself.
                self._wl_record(session_id, None, principal, action, resource, "Deny", execution_id)
                raise
            # The verdict the plugin acts on. The SDK reads it the same way —
            # case- and space-insensitively — and anything but an Allow is a
            # refusal (a Deny, a Quarantine, a Terminate, a SeverSubtree, …).
            verdict = result.get("decision") if isinstance(result, dict) else None
            allowed = str(verdict).strip().lower() == "allow"
            self._wl_record(
                session_id, None, principal, action, resource,
                "Allow" if allowed else "Deny", execution_id,
            )
            return result

        def _wl_record_refusal(self, handle: Any, action: Any, resource: Any, principal: Any) -> None:
            """Record a refusal the plugin's handle made without asking us."""
            try:
                agent_id = str(getattr(handle, "agent_uuid", "") or "")
                session_id = getattr(handle, "session_id", None)
                execution_id = getattr(handle, "execution_id", None)
            except Exception as exc:  # noqa: BLE001
                self._wl_report_record_failure(exc)
                return
            self._wl_record(
                session_id,
                agent_id or None,
                principal or (f'Agent::"{agent_id}"' if agent_id else ""),
                action,
                resource,
                "Deny",
                execution_id,
            )

        def _wl_record(
            self,
            session_id: Optional[str],
            agent_id: Optional[str],
            principal: Any,
            action: Any,
            resource: Any,
            decision: str,
            execution_id: Optional[str],
        ) -> None:
            # Names only: the principal, the action and the resource label, as
            # the engine received them. The Cedar `context` and the declared
            # `intent` — where a call's values travel — are never read here.
            # Everything, the lookups included, is inside the try: building the
            # record must never alter, delay or replace a decision.
            try:
                chain = self._wl_sessions.get(session_id or "") or (
                    (agent_id,) if agent_id else ()
                )
                # Stored IN FULL, as the direct path stores them: a quota
                # matches these fields exactly, so a cut or rewritten term
                # would be a decision no count could find. A term that breaks
                # the direct path's bounds is never written: it is replaced by
                # a value-free marker and the record is marked oversized, which
                # the counters count toward every query — so it can never make
                # a quota under-count. (`authorize` refuses such terms before
                # deciding; this covers the refusals the handle makes itself.)
                broken = False

                def bounded(value: Any, check: Any) -> Any:
                    nonlocal broken
                    try:
                        return check(value)
                    except Exception:  # noqa: BLE001 — any rule broken
                        broken = True
                        return _refused_marker(value)

                # Agent names come from `start_run` / `spawn_subagent` and are
                # never refused (a framework's instrumentation could swallow
                # the error); they are recorded as given, JSON escaping what
                # needs escaping, and only bounded in length.
                names = [
                    bounded(
                        str(self._wl_agent_names.get(a, a)),
                        lambda v: principals.assert_name_length(
                            v, "agent", TypeError, principals.MAX_AGENT_NAME_BYTES
                        ),
                    )
                    for a in chain
                ]
                record = decision_record(
                    agent=names[-1] if names else UNCONFIGURED_AGENT,
                    actor_chain=names if len(names) > 1 else None,
                    principal=bounded(principal, principals.assert_principal),
                    intent=bounded(action, lambda v: principals.assert_name(v, "action")),
                    resource=bounded(resource, lambda v: principals.assert_name(v, "resource")),
                    decision=decision,
                    execution_id=(
                        bounded(execution_id, lambda v: principals.assert_name(v, "execution_id"))
                        if execution_id
                        else None
                    ),
                )
                if broken:
                    record["oversized"] = True
            except Exception as exc:  # noqa: BLE001 — never let auditing alter a decision
                self._wl_report_record_failure(exc)
                return
            self._wl_trail.write(record)

        def _wl_report_record_failure(self, exc: BaseException) -> None:
            # A record that could not be built is a hole in the trail; said
            # once, by error type only, the way a failing sink is reported.
            if self._wl_warned_record:
                return
            self._wl_warned_record = True
            print(
                f"watchlight: a framework-plugin decision could not be recorded ({_error_kind(exc)}); "
                "further failures are suppressed",
                file=sys.stderr,
            )

    return AuditedInProcessClient


class _AuditedRunHandle:
    """The run handle a governed plugin hands out, recording every refusal.

    A plugin's handle refuses some calls ITSELF, without asking the backend: once
    a run is quarantined or severed, every later ``authorize_action`` raises at
    once. Those refusals never reach :class:`AuditedInProcessClient`, so this
    wrapper records them. Everything else is the SDK's handle, unchanged: every
    attribute and method is delegated, and the decision is always the handle's.

    A refusal is recorded here only when the backend did NOT answer the call —
    one it answered is already recorded — so each decision is recorded once.

    It is a wrapper, not a subclass: ``isinstance(handle, BaseRunHandle)`` is
    ``False`` for a handle a governed plugin hands out. The SDK's own handle is
    never exposed by name, and code that needs the handle's type should use the
    handle's methods instead.

    One route is not covered. ``watchlight_core.current_subagent_handle()``
    returns the SDK's own child handle, set inside the SDK, not this wrapper. A
    refusal that handle makes on its own after a quarantine or a sever is not
    recorded; use the handle ``spawn_subagent`` returned instead."""

    __slots__ = ("_wl_inner", "_wl_backend", "__weakref__")

    def __init__(self, inner: Any, backend: Any) -> None:
        object.__setattr__(self, "_wl_inner", inner)
        object.__setattr__(self, "_wl_backend", backend)

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._wl_inner, name)
        if name == "guarded_tool" and callable(value):
            return self._wl_guarded_tool(value)
        return value

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._wl_inner, name, value)

    def __repr__(self) -> str:
        return repr(self._wl_inner)

    async def __aenter__(self) -> "_AuditedRunHandle":
        await self._wl_inner.__aenter__()
        return self

    async def __aexit__(self, *exc_info: Any) -> Any:
        return await self._wl_inner.__aexit__(*exc_info)

    async def authorize_action(self, *args: Any, **kwargs: Any) -> Any:
        method = self._wl_inner.authorize_action
        return await self._wl_watch(method, args, kwargs)

    async def authorize_action_detailed(self, *args: Any, **kwargs: Any) -> Any:
        method = self._wl_inner.authorize_action_detailed
        return await self._wl_watch(method, args, kwargs)

    async def spawn_subagent(self, *args: Any, **kwargs: Any) -> Any:
        child = await self._wl_inner.spawn_subagent(*args, **kwargs)
        return _AuditedRunHandle(child, self._wl_backend)

    async def _wl_watch(self, method: Any, args: tuple, kwargs: dict) -> Any:
        try:
            bound = inspect.signature(method).bind(*args, **kwargs).arguments
        except (TypeError, ValueError):
            bound = {}
        return await self._wl_run(
            method(*args, **kwargs),
            bound.get("action"),
            bound.get("resource"),
            bound.get("principal"),
        )

    async def _wl_run(self, call: Any, action: Any, resource: Any, principal: Any) -> Any:
        marker: Dict[str, bool] = {"reached": False}
        token = _CALL_MARKER.set(marker)
        try:
            return await call
        except Exception as exc:
            if not marker["reached"] and isinstance(exc, _short_circuit_errors()):
                self._wl_backend._wl_record_refusal(self._wl_inner, action, resource, principal)
            raise
        finally:
            _CALL_MARKER.reset(token)

    def _wl_guarded_tool(self, guarded_tool: Any) -> Any:
        """A framework's tool decorator (Pydantic AI's ``guarded_tool``) calls
        the SDK handle's own ``authorize_action``, not this wrapper's, so the
        decorated tool is watched here instead."""

        @functools.wraps(guarded_tool)
        def factory(*args: Any, **kwargs: Any) -> Any:
            try:
                action = inspect.signature(guarded_tool).bind(*args, **kwargs).arguments.get(
                    "action", "execute"
                )
            except (TypeError, ValueError):
                action = None
            inner_decorator = guarded_tool(*args, **kwargs)

            def decorator(fn: Any) -> Any:
                governed = inner_decorator(fn)
                resource = getattr(fn, "__name__", None)

                @functools.wraps(governed)
                async def watched(*a: Any, **k: Any) -> Any:
                    return await self._wl_run(governed(*a, **k), action, resource, None)

                return watched

            return decorator

        return factory


def _rebind_subagent_registry(inner: Any, wrapped: "_AuditedRunHandle") -> None:
    """Point a run's native sub-agent registry at the wrapped handle.

    The Claude Agent SDK plugin attaches a ``SubagentRegistry`` to the root
    handle inside ``start_run``, so it spawns every native Task sub-agent from
    the SDK's own handle and hands back unwrapped children. Rebuilt here with
    the wrapped handle as its root, it spawns through the wrapper, and every
    child it returns — from ``on_subagent_start`` and ``resolve_subagent`` — is
    wrapped too. ``start_run`` returns the registry before anything has been
    spawned through it, so nothing is lost by rebuilding it."""
    registry = getattr(inner, "subagent_registry", None)
    if registry is None:
        return
    from watchlight_core import SubagentRegistry

    if type(registry) is not SubagentRegistry:
        # A registry type this code does not know: leave it as the plugin
        # built it rather than replace it with something it is not.
        return
    wrapped.subagent_registry = SubagentRegistry(
        wrapped, default_subagent_scope=registry.default_subagent_scope
    )


@functools.lru_cache(maxsize=None)
def _audited_plugin_class(plugin_cls: type) -> type:
    """``plugin_cls``, handing out run handles that record every refusal.

    A subclass, not a patch: nothing in the SDK or the plugin is modified. Its
    one override, ``start_run``, wraps the handle the plugin returns in
    :class:`_AuditedRunHandle` when the plugin is governed by the in-process
    backend; with any other backend the handle is returned as it is."""

    class AuditedPlugin(plugin_cls):  # type: ignore[misc, valid-type]
        async def start_run(self, *args: Any, **kwargs: Any) -> Any:
            handle = await super().start_run(*args, **kwargs)
            backend = getattr(self, "apdp", None)
            if not callable(getattr(backend, "_wl_record_refusal", None)):
                return handle
            wrapped = _AuditedRunHandle(handle, backend)
            _rebind_subagent_registry(handle, wrapped)
            return wrapped

    AuditedPlugin.__name__ = plugin_cls.__name__
    AuditedPlugin.__qualname__ = plugin_cls.__qualname__
    AuditedPlugin.__doc__ = plugin_cls.__doc__
    return AuditedPlugin


# Terms a ``governed_plugin`` factory cannot take, and what to do instead. A
# framework plugin is constructed once and then governs many calls, so a term
# that belongs to ONE call is not a constructor argument. All three ARE
# expressible — on the run handle, per call. Forwarded blindly, each would
# surface as a TypeError naming a plugin constructor the caller never wrote;
# named here, the message says where the term actually goes.
_PER_CALL_TERMS: Dict[str, str] = {
    "principal": (
        "the acting subject is a per-call term: pass it on the run handle — "
        "`await handle.authorize_action(action, resource, "
        "principal='User::\"u-1\"')`. Omitted, it defaults to the agent that "
        "runs. Requires watchlight-agent-sdk 0.7.0 or later."
    ),
    "context": (
        "Cedar `context` is a per-call term: pass it on the run handle — "
        "`await handle.authorize_action(action, resource, context={...})` — "
        "and the policy reads it as `context.*`."
    ),
    "resource": (
        "the resource is a per-call term: pass it on the run handle — "
        "`await handle.authorize_action(action, resource)`."
    ),
}


def _reject_per_call_terms(plugin_kwargs: Dict[str, Any]) -> None:
    """Refuse a governance term a plugin constructor cannot carry.

    Fail loudly and by name rather than forward it: a term the caller believes
    is reaching the decision, and is not, is a policy that silently never
    matches.
    """
    for term, guidance in _PER_CALL_TERMS.items():
        if term in plugin_kwargs:
            raise TypeError(f"governed_plugin() does not take `{term}` — {guidance}")


def _select_backend_kwargs(
    policies: Policies,
    audit_path: Optional[str],
    plugin_kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute the constructor kwargs for a framework plugin: production when
    ``WATCHLIGHT_APDP_URL`` is set (networked APDP), in-process otherwise.

    One environment variable flips dev↔prod with no code change — the shared
    logic behind every ``watchlight.<framework>.governed_plugin`` helper.

    Governance terms that belong to a single call — ``principal``, ``context``,
    ``resource`` — are refused here rather than forwarded into a constructor
    that has no place for them (see :data:`_PER_CALL_TERMS`).
    """
    _reject_per_call_terms(plugin_kwargs)
    # The audit-sink options configure OUR trail, not the plugin: they are taken
    # out here and never forwarded to a constructor that has no place for them.
    remaining = dict(plugin_kwargs)
    audit_options = {key: remaining.pop(key) for key in _AUDIT_SINK_KEYS if key in remaining}
    apdp_url = os.getenv("WATCHLIGHT_APDP_URL")
    if apdp_url:
        # Production: the plugin builds its own networked ApdpClient (which
        # enforces channel safety). We only pass the URL through. Decisions are
        # recorded by the policy service; there is no local trail to sink.
        if any(value is not None for value in audit_options.values()):
            _warn_sink_unused_networked()
        return {"apdp_url": apdp_url, **remaining}
    # Developer Edition: in-process engine, zero infra.
    return {
        "governance": in_process_backend(policies, audit_path=audit_path, **audit_options),
        **remaining,
    }


#: Keywords a ``governed_plugin`` factory accepts for its audit trail, with the
#: meaning they have on :class:`watchlight.Watchlight`. Consumed by
#: :func:`_select_backend_kwargs`, never forwarded to the plugin.
_AUDIT_SINK_KEYS = ("audit_sink", "audit_sink_batch", "audit_sink_interval")

_warned_sink_unused = False


def _warn_sink_unused_networked() -> None:
    global _warned_sink_unused
    if _warned_sink_unused:
        return
    _warned_sink_unused = True
    print(
        "watchlight: WATCHLIGHT_APDP_URL is set, so this plugin is governed by the networked "
        "policy service, which records its decisions itself — the audit_sink options passed "
        "to governed_plugin() are not used.",
        file=sys.stderr,
    )
