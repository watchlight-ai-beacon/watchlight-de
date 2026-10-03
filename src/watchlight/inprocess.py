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
The run's ``execution_started`` / ``execution_completed`` lifecycle lines and
the sub-agent ``attenuation`` lines are written by the SDK's client, to the same
file, as before. A ``preflight_step`` is a read-only what-if (it does not count
toward the run's budget) and writes no record.

    from watchlight.inprocess import in_process_backend
    from watchlight_langgraph import WatchlightLangGraphPlugin

    plugin = WatchlightLangGraphPlugin(
        governance=in_process_backend("watchlight.policy.json")
    )

Most users never import this directly — the per-framework helpers
(``watchlight.langgraph.governed_plugin`` etc.) call it for you.
"""

from __future__ import annotations

import functools
import os
import sys
from typing import Any, Dict, List, Optional, Union

from ._audit import UNCONFIGURED_AGENT, AuditSink, AuditTrail, decision_record

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
        an awaitable it returns is scheduled on the running loop, never awaited
        inline; a failure is reported once on stderr and never changes or delays
        a decision. The run lifecycle and attenuation lines go to the file only.
    :param audit_sink_batch: as ``Watchlight(audit_sink_batch=...)`` — hand the
        sink lists from a background worker.
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
    )
    return _audited_client_class()(policies, audit_path=audit_path, trail=trail)


@functools.lru_cache(maxsize=None)
def _audited_client_class() -> Any:
    """The SDK's ``InProcessClient``, with one decision record per ``authorize``.

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
        (``create_session``), and the verdict (``authorize``)."""

        def __init__(self, policies: Any = None, *, audit_path: Optional[str], trail: AuditTrail) -> None:
            super().__init__(policies, audit_path=audit_path)
            self._wl_trail = trail
            # agent id -> the slug the run was started with, so a record names
            # the agent as the developer did ("research-agent"), like the direct
            # path's `agent`, rather than as its derived id.
            self._wl_agent_names: Dict[str, str] = {}
            # session id -> agent id, for the record's `agent`.
            self._wl_session_agents: Dict[str, str] = {}

        async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
            agent = await super().resolve_agent(slug)
            if isinstance(agent, dict) and agent.get("id"):
                self._wl_agent_names[str(agent["id"])] = slug
            return agent

        async def create_session(self, agent_id: str, *args: Any, **kwargs: Any) -> Optional[Dict[str, Any]]:
            response = await super().create_session(agent_id, *args, **kwargs)
            session = (response or {}).get("session") if isinstance(response, dict) else None
            if isinstance(session, dict) and session.get("id"):
                self._wl_session_agents[str(session["id"])] = str(agent_id)
            return response

        async def complete_session(self, session_id: str) -> bool:
            self._wl_session_agents.pop(session_id, None)
            return await super().complete_session(session_id)

        async def terminate_session(self, session_id: str, reason: str = "manual") -> bool:
            self._wl_session_agents.pop(session_id, None)
            return await super().terminate_session(session_id, reason)

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
                self._wl_record(principal, action, resource, "Deny", execution_id, session_id)
                raise
            # The verdict the plugin acts on: only an engine "Allow" lets the
            # call proceed; anything else is a refusal, and is recorded as one.
            verdict = result.get("decision") if isinstance(result, dict) else None
            self._wl_record(
                principal, action, resource,
                "Allow" if verdict == "Allow" else "Deny",
                execution_id, session_id,
            )
            return result

        def _wl_record(
            self,
            principal: Any,
            action: Any,
            resource: Any,
            decision: str,
            execution_id: Optional[str],
            session_id: Optional[str],
        ) -> None:
            # Names only: the principal, the action and the resource label, as
            # the engine received them. The Cedar `context` and the declared
            # `intent` — where a call's values travel — are never read here.
            agent_id = self._wl_session_agents.get(session_id or "")
            agent = (
                self._wl_agent_names.get(agent_id, agent_id)
                if agent_id
                else UNCONFIGURED_AGENT
            )
            # AuditTrail.write never raises, but the record is built here; the
            # direct path's guarantee is that auditing never changes a decision.
            try:
                record = decision_record(
                    agent=str(agent),
                    principal=str(principal),
                    intent=str(action),
                    resource=str(resource),
                    decision=decision,
                    execution_id=str(execution_id) if execution_id else None,
                )
            except Exception:  # noqa: BLE001 — never let auditing alter a decision
                return
            self._wl_trail.write(record)

    return AuditedInProcessClient


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
