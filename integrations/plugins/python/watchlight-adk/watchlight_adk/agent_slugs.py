"""ADK agent object → registered Watchlight slug.

A governed identity is **configuration**, never something derived from a
framework object's display name. ADK's ``agent.name`` is a display name
the host picked for its own orchestration (it is what
``transfer_to_agent`` addresses); the Watchlight slug is the registry key
the platform mints and an operator registers policy against. The two are
independent strings that happen to look alike in the examples.

Deriving one from the other is not a convenience, it is an identity
decision taken by whoever names a Python object. A derived candidate that
happens to resolve hands the run another agent's UUID, trust state,
session, tool allowlist, policies and lineage attribution — so this module
derives nothing, at any level of configuration. There is no fallback and
no opt-in switch: the plugin takes both strings explicitly, mirroring
:mod:`watchlight_deepagents` (``agent_slug=`` + ``subagent_slugs=``), and
refuses an ADK agent it has no mapping for.

* ``agent_slug`` — the registered slug of the ROOT agent of the run.
* ``root_agent_name`` — the ADK ``agent.name`` that ``agent_slug``
  belongs to. The slug is bound to an IDENTITY, not to lifecycle
  position: without this, any agent that happened to start an invocation
  would authorize as the root.
* ``subagent_slugs`` — ADK ``agent.name`` → registered slug, for every
  other agent in the tree.

An ADK agent with no mapping is a DEPLOYMENT error, not a policy
decision, and the plugin refuses it as such — see :func:`configured_slug`
returning ``None``.
"""

from __future__ import annotations

from typing import Dict, Mapping, Optional

#: wl-registry's ``slugify_agent_name``
#: prefixes every slug it mints with ``agent-``: an agent registered
#: under the NAME ``adk-orchestrator`` carries the SLUG
#: ``agent-adk-orchestrator``. Documented here because operators read
#: slugs off the registry; the plugin never constructs one.
REGISTRY_SLUG_PREFIX = "agent-"


def configured_slug(
    agent_name: str,
    *,
    agent_slug: Optional[str],
    subagent_slugs: Optional[Mapping[str, str]],
    root_agent_name: Optional[str],
    is_root: bool,
    governed_reentry: bool = False,
) -> Optional[str]:
    """The configured Watchlight slug for one ADK agent, or ``None``.

    ``None`` means "not configured", and the caller refuses the agent. It
    never means "not registered": that is wl-apdp's answer to a slug, and
    the two are reported differently so an operator can tell a missing
    ``subagent_slugs`` entry from a missing registration.

    ``agent_slug`` is returned only for the ADK agent it was declared
    for — ``agent_name == root_agent_name`` AND this invocation is the
    run's root. Matching on ``is_root`` alone would let any unmapped
    agent that opens an invocation (a different entrypoint, a re-entered
    tree, a newly added agent) authorize under the root's identity
    instead of being refused. Symmetrically, a ``subagent_slugs`` entry
    is returned only for a NESTED invocation: a sub-agent that opens an
    invocation as the run's root is refused, never run as a root.

    Args:
        agent_name: ADK's ``agent.name`` for the agent being started.
        agent_slug: The configured ROOT slug.
        subagent_slugs: ADK ``agent.name`` → registered slug.
        root_agent_name: The ADK ``agent.name`` ``agent_slug`` belongs to.
        is_root: Whether this invocation is the run's root agent (the
            plugin derives this from its own lifecycle state — an ADK
            sub-agent transfer fires ``before_agent_callback`` while a
            parent run is live).
        governed_reentry: The agent is the target of a ``transfer_to_agent``
            and will run as a GOVERNED SPAWN under the transferring agent,
            narrowed to the transferor's grant. Only then does the root
            agent's own name, on a nested invocation, get ``agent_slug``:
            re-entering the root through a transfer never restores the
            root's authority.
    """
    if is_root:
        # Only the configured root agent may OPEN a run. A mapped
        # sub-agent reaching here opened an invocation of its own — for
        # example ADK routing the next user turn to the sub-agent that
        # authored the last event — with no governed spawn. Handing it its
        # slug would open a ROOT session under its full agent-record
        # scope, unattenuated; a sub-agent's authority only ever comes
        # from a spawn under its parent.
        if agent_slug and root_agent_name and agent_name == root_agent_name:
            return agent_slug
        return None
    slug = (subagent_slugs or {}).get(agent_name) or None
    if (
        slug is None
        and governed_reentry
        and agent_slug
        and root_agent_name
        and agent_name == root_agent_name
    ):
        return agent_slug
    return slug


def normalize_subagent_slugs(
    subagent_slugs: Optional[Mapping[str, str]],
    *,
    agent_slug: Optional[str] = None,
) -> Dict[str, str]:
    """Validate and copy a ``subagent_slugs`` mapping.

    Fail loud at construction rather than at run start: every rejection
    here is a deployment typo that would otherwise surface as a refused
    agent — or, worse, as the wrong identity — in production.

    Rejects:

    * a blank key or value (a typo);
    * two ADK agents mapped to ONE governed identity — attenuation and
      attribution are per-identity, so collapsing two agents onto one
      slug makes a sub-agent's scope indistinguishable from its
      sibling's and its lineage indistinguishable from its sibling's;
    * a value equal to ``agent_slug`` — a child running as the root
      makes the governed-spawn strict-subset check compare a scope to
      itself, so it can never attenuate.

    Keys AND values are stripped. Stripping only values let a key with a
    leading space never match ``agent.name``, and the operator was then
    told to add a mapping that is visibly already in their config.

    The copy keeps the plugin's view immutable against a caller mutating
    the dict it passed in.
    """
    if not subagent_slugs:
        return {}
    root = (agent_slug or "").strip()
    normalized: Dict[str, str] = {}
    by_slug: Dict[str, str] = {}
    for raw_name, raw_slug in subagent_slugs.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError(
                "subagent_slugs keys must be non-empty ADK agent names "
                "(agent.name), e.g. {'adk_researcher': 'agent-adk-researcher'}"
            )
        name = raw_name.strip()
        if not isinstance(raw_slug, str) or not raw_slug.strip():
            raise ValueError(
                f"subagent_slugs['{name}'] must be a non-empty registered "
                "Watchlight slug"
            )
        slug = raw_slug.strip()
        if name in normalized:
            raise ValueError(
                f"subagent_slugs has two keys that name the same ADK agent "
                f"'{name}' once whitespace is stripped; remove the duplicate"
            )
        if slug in by_slug:
            raise ValueError(
                f"subagent_slugs maps both '{by_slug[slug]}' and '{name}' to "
                f"the governed identity '{slug}'. Two ADK agents cannot share "
                "one Watchlight identity: scope attenuation and lineage "
                "attribution are per-identity. Register an agent per ADK agent."
            )
        if root and slug == root:
            raise ValueError(
                f"subagent_slugs['{name}'] is the root's own slug '{slug}'. A "
                "sub-agent cannot run as the root agent — its requested scope "
                "would be checked against itself and could never attenuate. "
                "Register a separate agent for it."
            )
        normalized[name] = slug
        by_slug[slug] = name
    return normalized


__all__ = [
    "REGISTRY_SLUG_PREFIX",
    "configured_slug",
    "normalize_subagent_slugs",
]
