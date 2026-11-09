"""Cross-process pattern for Bedrock multi-agent collaborators.

# Why this module exists

Bedrock's multi-agent orchestration runs a *collaborator* agent as a
SEPARATE Bedrock agent — typically in its own action-group Lambda, in
its own process, invoked internally by Bedrock's server-side planner.
Unlike LangGraph / ADK / Pydantic-AI (where a sub-agent is spawned
*in-process* and the orchestrator's :class:`RunHandle` can call
:meth:`spawn_subagent` directly), the Bedrock orchestrator plugin has
**no in-process hook** on the collaborator: by the time the
collaborator's Lambda runs, we are in a different process with a
different call stack. The orchestrator physically cannot wrap it.

Consequently there is **no way to counterfeit in-process governance** of a
Bedrock collaborator. The honest, consistent model is:

    Every collaborator is itself a governed run that calls
    ``spawn_subagent`` against the PARENT's run handle, from inside
    its OWN Lambda, at the start of its own run.

# KNOWN LIMITATION — governed spawn is deferred

A *governed* cross-process spawn (server-attested ``agent_spawn_observed``
+ strict-subset scope attenuation of the collaborator) requires the
parent run to AUTHENTICATE ``POST /v1/spawn_subagent``. Today that
endpoint authenticates with the parent run's per-run ``sst_`` credential
(the shared tenant bearer is refused on that path). The only way to make
that authentication happen from the collaborator's Lambda would be to
carry the ``sst_`` credential across the Bedrock boundary via
``sessionState.sessionAttributes`` — which routes a run credential
through the AWS control plane (CloudTrail-visible). That is **below our
security bar**, so we DO NOT do it.

Until a **single-use, spawn-only, short-TTL spawn-authorization token**
(minted by a forthcoming wl-apdp endpoint) exists, there is **no
credential we are willing to cross**, and therefore **no governed
cross-process spawn**. This module ships the *pattern* and the
NON-SENSITIVE reference plumbing (run-handle id + agent id, which already
cross today) so the wiring is in place; :func:`spawn_collaborator_subagent`
is the fail-closed integration point where the future token will plug in.

Until then, Bedrock collaborators are governed at the **ACTION layer
only** — per-invocation trust + tool policy-enforcement via
:func:`watchlight_bedrock.watchlight_bedrock_action` — NOT
spawn-scope-attenuated, and the orchestrator does **not** fabricate a
spawn. This is a documented limitation, not a gap being papered over.

# What crosses the boundary (all NON-sensitive)

The orchestrator threads the parent reference through Bedrock
``sessionState.sessionAttributes``:

- :data:`SESSION_ATTR_PARENT_AGENT_ID` (``watchlight_agent_id``) — already
  crossed today by :meth:`RunHandle.bedrock_agent_runtime`.
- :data:`SESSION_ATTR_PARENT_SESSION_ID` (``watchlight_session_id``) —
  already crossed today.
- :data:`SESSION_ATTR_PARENT_RUN_HANDLE_ID` — the parent run-handle id, a
  non-sensitive identifier (it is NOT a credential; it cannot authenticate
  anything on its own).

**No credential ever crosses.** There is deliberately no session-attribute
key for the ``sst_`` token.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Sequence

from watchlight_core import WatchlightError, get_logger

logger = get_logger("watchlight_bedrock")


# ─── Session-attribute keys (all NON-sensitive) ───────────────────────
#
# The parent reference is threaded through Bedrock
# ``sessionState.sessionAttributes`` (a flat ``Dict[str, str]``). Two of
# these keys are the ones :meth:`RunHandle.bedrock_agent_runtime` adds
# on every ``invoke_agent``; the ``parent_run_handle_id`` key is added by
# ``invoke_agent(collaborator=True)``. NONE of them
# is a credential — there is intentionally NO key for the ``sst_`` token.

#: Parent agent UUID. Reused verbatim from the Watchlight
#: session attributes ``bedrock_agent_runtime()`` adds.
SESSION_ATTR_PARENT_AGENT_ID = "watchlight_agent_id"

#: Parent session id. Reused verbatim from the Watchlight
#: session attributes ``bedrock_agent_runtime()`` adds.
SESSION_ATTR_PARENT_SESSION_ID = "watchlight_session_id"

#: Parent run-handle id — a non-sensitive identifier (the
#: ``parent_run_handle_id`` field on the canonical ``SpawnSubagentRequest``
#: envelope). It cannot authenticate a spawn on its own.
SESSION_ATTR_PARENT_RUN_HANDLE_ID = "watchlight_parent_run_handle_id"


#: Env knob: a JSON object carrying the collaborator's default requested
#: sub-agent scope, used by :func:`requested_scope_from_env` when the
#: caller does not pass an explicit scope. Fail-closed empty when unset
#: or malformed.
ENV_DEFAULT_SUBAGENT_SCOPE = "WATCHLIGHT_BEDROCK_DEFAULT_SUBAGENT_SCOPE"


# ─── Errors ───────────────────────────────────────────────────────────


class CollaboratorGovernanceUnavailable(WatchlightError):
    """Raised when a collaborator cannot open a GOVERNED spawn.

    Fail-closed signal. Two causes:

    - No usable parent reference was handed across the Bedrock boundary
      (the hand-off did not happen).
    - Governed cross-process spawn is not yet available at all — the
      single-use spawn-authorization token mechanism is not yet
      implemented.

    In both cases the collaborator MUST NOT proceed as a spawn-scope-
    attenuated run; it is governed at the action layer only (per-invocation
    trust + tool PEP via :func:`watchlight_bedrock.watchlight_bedrock_action`).
    """


# ─── Requested scope ──────────────────────────────────────────────────


@dataclass(frozen=True)
class RequestedCollaboratorScope:
    """The attenuated scope a collaborator would request for ITS OWN run.

    Mirrors the five canonical ``spawn_subagent`` dimensions. Every
    field is fail-closed by default: an empty scope means the child may
    do nothing until wl-apdp grants (a subset of the parent's) scope.
    The collaborator derives this from what IT knows in its own Lambda —
    its own action-group tool names (:func:`scope_from_action_group_tools`)
    or the :data:`ENV_DEFAULT_SUBAGENT_SCOPE` env knob
    (:func:`requested_scope_from_env`).

    This is retained plumbing for the deferred governed-spawn path:
    once the spawn-authorization token endpoint ships, this is the
    scope the collaborator will request. Today it is not sent
    anywhere (no governed spawn is possible), but the derivation helpers
    are shipped and unit-tested so the wiring is ready.
    """

    allowed_tools: List[str] = field(default_factory=list)
    allowed_resources: List[str] = field(default_factory=list)
    allowed_intents: List[str] = field(default_factory=list)
    #: Further spawn depth the child may use. ``0`` = the child cannot
    #: spawn descendants (fail-closed default).
    max_depth: int = 0
    #: Per-spawn time budget in seconds. ``None`` (the default) names no
    #: budget: the child inherits the parent's remaining time, bounded by
    #: the parent's deadline and never wider. ``0`` is refused as
    #: unsatisfiable.
    time_budget_seconds: Optional[int] = None

    def is_empty(self) -> bool:
        """True when no privilege at all is requested."""
        return not (
            self.allowed_tools
            or self.allowed_resources
            or self.allowed_intents
            or self.max_depth
            or self.time_budget_seconds
        )


def scope_from_action_group_tools(
    tool_names: Sequence[str],
    *,
    allowed_resources: Optional[Sequence[str]] = None,
    allowed_intents: Optional[Sequence[str]] = None,
    max_depth: int = 0,
    time_budget_seconds: Optional[int] = None,
) -> RequestedCollaboratorScope:
    """Build a requested scope from the collaborator's OWN action-group
    tool names.

    A collaborator's Lambda knows exactly which action-group tools it
    exposes. Pass each one by its full action URI,
    ``bedrock://agent/<agentId>/action/<actionGroup><apiPath>``: wl-apdp
    grants a Bedrock action only by that URI, never by the bare
    ``{actionGroup}/{apiPath}`` slug. Passing that list here
    yields a least-privilege request whose ``allowed_tools`` is exactly
    the collaborator's surface — never wider than what the parent grants,
    because wl-apdp's strict-subset validator still intersects it against
    the parent's effective scope (once the governed-spawn path lands).
    """
    return RequestedCollaboratorScope(
        allowed_tools=list(dict.fromkeys(str(t) for t in tool_names if t)),
        allowed_resources=list(allowed_resources or []),
        allowed_intents=list(allowed_intents or []),
        max_depth=int(max_depth or 0),
        time_budget_seconds=time_budget_seconds,
    )


def requested_scope_from_env(
    env: Optional[Mapping[str, str]] = None,
) -> RequestedCollaboratorScope:
    """Parse :data:`ENV_DEFAULT_SUBAGENT_SCOPE` into a requested scope.

    The env value is a JSON object, e.g.::

        {"allowed_tools": ["bedrock://agent/A1/action/research/search"],
         "allowed_intents": ["summarize_public_docs"],
         "max_depth": 0, "time_budget_seconds": 300}

    Fail-closed: absent, empty, non-object, or malformed JSON yields an
    EMPTY scope (a warning is logged, no exception is raised — a
    misconfigured env var must never widen privilege, and must never
    crash the collaborator's Lambda). Only the five canonical keys are
    read; unknown keys are ignored.
    """
    env = env if env is not None else os.environ
    raw = env.get(ENV_DEFAULT_SUBAGENT_SCOPE)
    if not raw or not raw.strip():
        return RequestedCollaboratorScope()
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning(
            "%s is not valid JSON; failing closed to an EMPTY requested "
            "scope (collaborator would request no privilege).",
            ENV_DEFAULT_SUBAGENT_SCOPE,
        )
        return RequestedCollaboratorScope()
    if not isinstance(parsed, dict):
        logger.warning(
            "%s must be a JSON object; got %s. Failing closed to an EMPTY "
            "requested scope.",
            ENV_DEFAULT_SUBAGENT_SCOPE,
            type(parsed).__name__,
        )
        return RequestedCollaboratorScope()

    def _str_list(value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        return [str(v) for v in value if isinstance(v, (str, int))]

    def _int(value: Any) -> int:
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0

    def _budget(value: Any) -> Optional[int]:
        # Absent: inherit the parent's remaining time. Present but not a
        # whole number: 0, which is refused (fail closed, never wider).
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            return 0
        return value

    return RequestedCollaboratorScope(
        allowed_tools=_str_list(parsed.get("allowed_tools")),
        allowed_resources=_str_list(parsed.get("allowed_resources")),
        allowed_intents=_str_list(parsed.get("allowed_intents")),
        max_depth=_int(parsed.get("max_depth")),
        time_budget_seconds=_budget(parsed.get("time_budget_seconds")),
    )


# ─── Parent reference (NON-sensitive) ─────────────────────────────────


@dataclass(frozen=True)
class CollaboratorSpawnRef:
    """A NON-sensitive parent run-handle reference handed to a
    collaborator's Lambda.

    Reconstructed from Bedrock ``sessionAttributes`` on the collaborator
    side. It carries only identifiers — the parent agent id, session id,
    and run-handle id. It deliberately carries **no credential**: none of
    these fields can authenticate a spawn on its own, so crossing them
    through the AWS control plane is safe (the agent id + session id
    already cross today).

    A governed spawn under this reference is NOT possible until the
    single-use spawn-authorization token mechanism ships. This type
    exists so the non-sensitive plumbing is in place and unit-tested
    ahead of that follow-up.
    """

    parent_agent_id: Optional[str] = None
    parent_session_id: Optional[str] = None
    parent_run_handle_id: Optional[str] = None

    @property
    def has_parent_reference(self) -> bool:
        """True iff this reference identifies a parent run (agent id AND
        run-handle id present).

        NOTE: a complete reference is necessary but NOT sufficient for a
        governed spawn — that additionally requires the deferred
        spawn-authorization token. This property only reports
        whether the non-sensitive hand-off happened.
        """
        return bool(self.parent_agent_id and self.parent_run_handle_id)


def _session_attributes_from_event(
    event_or_attrs: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Return the ``sessionAttributes`` map from either a raw Bedrock
    event or an already-extracted attributes dict.

    Mirrors the precedence :mod:`watchlight_bedrock.plugin` uses:
    ``sessionState.sessionAttributes`` first, then a top-level
    ``sessionAttributes``. If neither key is present, the input is
    assumed to already BE the attributes map.
    """
    session_state = event_or_attrs.get("sessionState")
    if isinstance(session_state, Mapping):
        attrs = session_state.get("sessionAttributes")
        if isinstance(attrs, Mapping):
            return attrs
    attrs = event_or_attrs.get("sessionAttributes")
    if isinstance(attrs, Mapping):
        return attrs
    return event_or_attrs


def extract_collaborator_spawn_ref(
    event_or_attrs: Mapping[str, Any],
) -> Optional[CollaboratorSpawnRef]:
    """Parse a :class:`CollaboratorSpawnRef` from a Bedrock event or its
    ``sessionAttributes`` map.

    Accepts either the raw Bedrock Lambda ``event`` dict or a plain
    attributes mapping. Returns ``None`` when NOTHING identifying a
    parent run is present (no agent id and no run-handle id) — the
    unambiguous "no hand-off happened" case. Otherwise returns the
    non-sensitive reference.
    """
    attrs = _session_attributes_from_event(event_or_attrs)

    def _get(key: str) -> Optional[str]:
        value = attrs.get(key)
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    parent_agent_id = _get(SESSION_ATTR_PARENT_AGENT_ID)
    parent_session_id = _get(SESSION_ATTR_PARENT_SESSION_ID)
    parent_run_handle_id = _get(SESSION_ATTR_PARENT_RUN_HANDLE_ID)

    # No parent reference at all → the hand-off did not happen.
    if not parent_agent_id and not parent_run_handle_id:
        return None

    return CollaboratorSpawnRef(
        parent_agent_id=parent_agent_id,
        parent_session_id=parent_session_id,
        parent_run_handle_id=parent_run_handle_id,
    )


async def spawn_collaborator_subagent(
    plugin: Any,
    ref: Optional[CollaboratorSpawnRef],
    child_slug: str,
    *,
    requested_scope: Optional[RequestedCollaboratorScope] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Any:
    """Integration point for the (deferred) governed cross-process spawn.

    This is where a Bedrock collaborator's Lambda WILL open a governed
    sub-agent run under the parent, once the single-use spawn-
    authorization token endpoint ships.

    **Today it always fails closed.** A governed cross-process spawn
    requires the parent run to authenticate ``POST /v1/spawn_subagent``,
    and the only credential that could do so from the collaborator's
    Lambda is the parent run's ``sst_`` — which we refuse to cross the
    Bedrock boundary (AWS control plane / CloudTrail exposure, below our
    security bar). No non-sensitive reference can authenticate a spawn.
    So this raises :class:`CollaboratorGovernanceUnavailable` rather than
    fabricating a spawn or crossing a credential.

    The signature (``requested_scope`` / ``env``) is the stable forward
    contract: when the spawn-authorization token lands, the orchestrator
    will mint a single-use, spawn-only, short-TTL token bound to
    ``(parent_run_handle, child_agent, scope)``, cross ONLY that token,
    and this function will present it to obtain the attenuated child
    handle. The scope-derivation helpers (:func:`scope_from_action_group_tools`,
    :func:`requested_scope_from_env`) are shipped and unit-tested against
    that future contract.

    Parameters
    ----------
    plugin:
        The collaborator's :class:`WatchlightBedrockPlugin`.
    ref:
        The non-sensitive parent reference parsed via
        :func:`extract_collaborator_spawn_ref`, or ``None``.
    child_slug:
        The collaborator's OWN registered agent slug.
    requested_scope / env:
        Forward-contract scope inputs (see above). Currently unused
        because the call fails closed before a spawn is attempted.

    Raises
    ------
    CollaboratorGovernanceUnavailable
        Always, until the spawn-authorization token endpoint ships. The
        message distinguishes "no parent reference" from "governed spawn
        not yet available". The collaborator MUST fall back to
        action-layer governance (it is not spawn-scope-attenuated).
    """
    # Reference the forward-contract inputs so readers see they are part
    # of the stable signature, without computing anything the fail-closed
    # path would discard.
    _ = (plugin, requested_scope, env, child_slug)

    if ref is None or not ref.has_parent_reference:
        raise CollaboratorGovernanceUnavailable(
            "No Watchlight parent reference in Bedrock sessionAttributes; "
            "the collaborator was invoked without a governed-spawn hand-off. "
            "Failing closed — the collaborator is not spawn-scope-attenuated "
            "and must rely on action-layer governance "
            "(watchlight_bedrock_action). To run this agent as an independent "
            "governed root when it is invoked standalone (no Watchlight "
            "attributes at all), set fallback_agent_slug together with an "
            "explicit fallback_allowed_actions scope on watchlight_bedrock_action."
        )

    # A complete NON-sensitive reference is present, but a governed spawn
    # is still not possible: it needs the single-use spawn-authorization
    # token, which is deferred. We DELIBERATELY do not cross the
    # parent ``sst_`` credential to authenticate a spawn. Fail closed.
    raise CollaboratorGovernanceUnavailable(
        "Governed cross-process spawn for Bedrock collaborators is not yet "
        "available: it requires a single-use, spawn-only, short-TTL "
        "spawn-authorization token. The parent run credential (sst_) is "
        "deliberately NEVER crossed through Bedrock session attributes, so "
        "until that token mechanism is available the collaborator is governed "
        "at the action layer only (per-invocation trust + tool policy "
        "enforcement) and is NOT spawn-scope-attenuated. Failing closed."
    )
