"""Install once at the root: credential-bound root runs and labelled sub-agents.

A Watchlight plugin is installed once, at the root of an agent system, and
governs everything beneath it. Two primitives make that work without naming
agents in code:

**A root run with no slug.** :func:`open_root_session` (and every backend's
``create_session(agent_id=None)``) opens the root run as the agent the
caller's verified credential is bound to. wl-apdp decides which agent that
is (an agent API key today, and an AWS workload role mapping once that lands
in wl-apdp); the SDK adopts the agent the server names. A credential bound to
no single agent is refused with :class:`~watchlight_core.CredentialBindsNoAgent`:
nothing guesses and there is no default agent. Naming the agent is still
supported as an optional override, and wl-apdp refuses it when it does not
match the credential's agent.

**A sub-agent that is not a registered agent.**
``BaseRunHandle.spawn_subagent(child_label="research-agent", ...)`` spawns a
child identified by its parent run and a label (a deepagents or Claude
``subagent_type``, an ADK ``agent.name``, a Strands node id). The child is
always attenuated to a strict subset of its parent's scope, under every
existing rule (a named time budget above what the parent has is refused,
depth is limited). The label is recorded in lineage and reaches policy as
``context.subagent_label``; it is evidence only and never an authority. An
operator may map a label to a registered agent for one tenant; the child
then runs as that agent, still spawned and attenuated under its parent.
Without a mapping the child runs as its parent's agent ("anonymous").

The label rule is the one wl-apdp applies (``wl_core::subagent_label``), so
a label this module accepts is never refused for its shape by the server.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from .backend import SessionInfo
from .errors import AgentNotRegistered, GovernanceUnavailable

__all__ = [
    "CHILD_IDENTITIES",
    "CHILD_IDENTITY_ANONYMOUS",
    "CHILD_IDENTITY_MAPPED",
    "CHILD_IDENTITY_REGISTERED",
    "MAX_CHILD_LABEL_BYTES",
    "SUBAGENT_LABEL_CONTEXT_KEY",
    "open_root_session",
    "validate_child_label",
]

#: The longest label accepted, in bytes (``wl_core::subagent_label::MAX_LABEL_BYTES``).
MAX_CHILD_LABEL_BYTES = 128

#: The authorization-context key wl-apdp sets, from the child's verified run
#: credential, to the label of the sub-agent run that is acting.
SUBAGENT_LABEL_CONTEXT_KEY = "subagent_label"

#: A child spawned by agent id.
CHILD_IDENTITY_REGISTERED = "registered"
#: A child spawned by label that an operator mapped to a registered agent.
CHILD_IDENTITY_MAPPED = "mapped"
#: A child spawned by label with no mapping: it runs as its parent's agent.
CHILD_IDENTITY_ANONYMOUS = "anonymous"
CHILD_IDENTITIES = (
    CHILD_IDENTITY_REGISTERED,
    CHILD_IDENTITY_MAPPED,
    CHILD_IDENTITY_ANONYMOUS,
)

_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._:/@-]{0,127}", re.ASCII)


def validate_child_label(label: Any) -> str:
    """Return ``label`` unchanged when it is a valid sub-agent label.

    A label is 1 to 128 bytes, starts with an ASCII letter or digit, and
    uses only letters, digits, space and ``. _ : / @ -``. It is taken
    exactly as given (no trimming or case folding), so the label in
    lineage is the label the plugin sent.

    Raises :class:`ValueError` otherwise, before anything is sent.
    """
    if not isinstance(label, str) or not label:
        raise ValueError("spawn_subagent: child_label must be a non-empty string")
    if len(label.encode("utf-8")) > MAX_CHILD_LABEL_BYTES:
        raise ValueError("spawn_subagent: child_label is longer than 128 bytes")
    if not _LABEL_RE.fullmatch(label):
        raise ValueError(
            "spawn_subagent: child_label must start with a letter or digit and use "
            "only letters, digits, space and . _ : / @ -"
        )
    return label


async def open_root_session(
    backend: Any,
    *,
    agent_slug: Optional[str] = None,
    agent_id: Optional[str] = None,
    **session_kwargs: Any,
) -> SessionInfo:
    """Open a governed root run on ``backend`` and return its session.

    The default is to name no agent: the run is opened as the agent the
    caller's verified credential is bound to (in the Developer Edition, the
    process's configured identity), and the returned
    ``SessionInfo.agent_id`` is the agent the backend chose.

    ``agent_slug`` (resolved through ``backend.resolve_agent``) or
    ``agent_id`` name the agent explicitly, as plugins did before. The
    backend then confirms it: wl-apdp refuses a name that does not match an
    agent-bound credential, and this function refuses a session that names
    any other agent than the one asked for.

    Other keyword arguments (``goal_id``, ``max_actions``, ``ttl_seconds``,
    ``metadata``, ``subject_token``, ``application_id``) go to
    ``backend.create_session`` unchanged.

    Raises
    ------
    CredentialBindsNoAgent
        No agent was named and the credential is bound to no single agent.
    AgentNotRegistered
        ``agent_slug`` is not registered.
    GovernanceUnavailable
        The backend did not open the run, or opened it for another agent.
    """
    if agent_slug is not None and agent_id is not None:
        raise ValueError("open_root_session: name the agent by agent_slug or agent_id, not both")
    requested: Optional[str] = agent_id
    if agent_slug is not None:
        resolved = await backend.resolve_agent(agent_slug)
        if not resolved or not isinstance(resolved.get("id"), str) or not resolved["id"]:
            raise AgentNotRegistered(
                f"Agent '{agent_slug}' is not registered with Watchlight. "
                "Register the agent, or open the run without a slug to run as the "
                "agent your credential is bound to."
            )
        requested = resolved["id"]
    session = await backend.create_session(agent_id=requested, **session_kwargs)
    if session is None:
        raise GovernanceUnavailable(
            "The governance backend did not open the run. Check that it is "
            "reachable and that the credential may open a run for this agent."
        )
    problem: Optional[str] = None
    if not isinstance(session.agent_id, str) or not session.agent_id:
        problem = "opened a run without naming its agent"
    elif requested is not None and session.agent_id != requested:
        problem = "opened the run for another agent than the one named"
    if problem is not None:
        # The run is never used: release it (best effort) and refuse.
        try:
            await backend.terminate_session(session.run, "root_identity_refused")
        except Exception:  # noqa: BLE001 — the refusal is what the caller sees
            pass
        raise GovernanceUnavailable(f"The governance backend {problem}; refusing it.")
    return session
