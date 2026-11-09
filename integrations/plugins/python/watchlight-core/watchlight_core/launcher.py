"""Workload launchers: open a Beacon run bound to the workload it runs in.

A launcher starts an agent inside an isolated runtime workload (an NVIDIA
OpenShell sandbox today). It runs OUTSIDE the workload, holds a Beacon
service credential (``wlsa_``) with the ``workload:bind`` capability, and:

1. creates the workload with immutable labels naming the run
   (``watchlight.ai/tenant-id``, ``agent-id``, ``application-id``,
   ``launch-id``, ``governed=true``); how the labels are set is specific to
   each runtime;
2. calls :func:`open_bound_run` with the workload's id: wl-apdp opens the
   session in the launcher credential's tenant, records the binding (with
   ``bound_by`` = the launcher, taken from its verified credential), binds
   it into the run credential (``wref``) and stamps it on every lineage
   event of the run;
3. hands the agent ONLY the returned :class:`~watchlight_core.run_grant.RunGrant`
   (on the agent process's stdin) — never its own credential and never a
   plugin token.

The binding contract is described in the Watchlight Beacon documentation on
workload binding.
"""

from __future__ import annotations

import re
import secrets
from typing import Any, Dict, Mapping, Optional

from .apdp_client import ApdpClient
from .errors import AgentNotRegistered, GovernanceUnavailable
from .run_grant import RunGrant

__all__ = [
    "WORKLOAD_KINDS",
    "LABEL_TENANT",
    "LABEL_AGENT",
    "LABEL_APPLICATION",
    "LABEL_LAUNCH",
    "LABEL_GOVERNED",
    "new_launch_id",
    "workload_ref",
    "workload_labels",
    "open_bound_run",
]

#: Runtime kinds wl-apdp accepts (mirrors ``wl_lineage::workload::WORKLOAD_KINDS``).
WORKLOAD_KINDS = ("openshell",)

#: Immutable workload labels the launcher sets at creation. They are a
#: cross-check of the server-side binding, never the binding itself.
LABEL_TENANT = "watchlight.ai/tenant-id"
LABEL_AGENT = "watchlight.ai/agent-id"
LABEL_APPLICATION = "watchlight.ai/application-id"
LABEL_LAUNCH = "watchlight.ai/launch-id"
LABEL_GOVERNED = "watchlight.ai/governed"

# The same bounds wl-apdp enforces (``WorkloadRef::validate``); checked here
# too so a launcher fails before it creates anything it cannot bind.
_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,47}$")
_WORKLOAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LAUNCH_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def new_launch_id() -> str:
    """A fresh per-launch nonce (``lnch_`` + 32 hex chars)."""
    return "lnch_" + secrets.token_hex(16)


def workload_ref(
    *,
    kind: str,
    source_id: str,
    workload_id: str,
    launch_id: Optional[str] = None,
    workload_name: Optional[str] = None,
) -> Dict[str, Any]:
    """A ``workload_ref`` for ``POST /sessions``, checked against wl-apdp's
    bounds. ``bound_by`` is never sent: wl-apdp takes it from the launcher's
    verified credential."""
    if kind not in WORKLOAD_KINDS:
        raise ValueError("workload_ref.kind is not valid")
    if not _SOURCE_ID.match(source_id or ""):
        raise ValueError("workload_ref.source_id is not valid")
    if not _WORKLOAD_ID.match(workload_id or ""):
        raise ValueError("workload_ref.workload_id is not valid")
    ref: Dict[str, Any] = {"kind": kind, "source_id": source_id, "workload_id": workload_id}
    if launch_id is not None:
        if not _LAUNCH_ID.match(launch_id):
            raise ValueError("workload_ref.launch_id is not valid")
        ref["launch_id"] = launch_id
    if workload_name is not None:
        if not _NAME.match(workload_name):
            raise ValueError("workload_ref.workload_name is not valid")
        ref["workload_name"] = workload_name
    return ref


def workload_labels(
    *,
    tenant_id: str,
    agent_id: str,
    launch_id: str,
    application_id: Optional[str] = None,
) -> Dict[str, str]:
    """The immutable labels a launcher sets on the workload at creation."""
    labels = {
        LABEL_TENANT: tenant_id,
        LABEL_AGENT: agent_id,
        LABEL_LAUNCH: launch_id,
        LABEL_GOVERNED: "true",
    }
    if application_id:
        labels[LABEL_APPLICATION] = application_id
    return labels


async def resolve_agent_id(client: ApdpClient, agent_slug: str) -> str:
    """The canonical agent id for a slug, in the launcher credential's tenant."""
    resolved = await client.resolve_agent(agent_slug)
    if not resolved or not isinstance(resolved.get("id"), str):
        raise AgentNotRegistered(
            f"Agent '{agent_slug}' is not registered in the launcher credential's tenant."
        )
    return resolved["id"]


async def open_bound_run(
    client: ApdpClient,
    *,
    agent_id: str,
    workload: Mapping[str, Any],
    application_id: Optional[str] = None,
    goal_id: Optional[str] = None,
    ttl_seconds: int = 3600,
    max_actions: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> RunGrant:
    """Open a Beacon run bound to ``workload`` and return its run grant.

    ``client`` must authenticate with the launcher's ``workload:bind``
    service credential. ``workload`` is built with :func:`workload_ref`.
    Fails closed: any refusal raises :class:`GovernanceUnavailable` (wl-apdp
    logs the reason; the refusal on the wire is opaque by design), and a
    response whose run credential does not carry the binding is refused
    here too.
    """
    credential = client.credential
    if credential is None or getattr(credential, "kind", None) != "service":
        raise GovernanceUnavailable(
            "open_bound_run needs the launcher's workload:bind service credential (wlsa_)"
        )
    if "bound_by" in workload:
        raise ValueError("workload_ref.bound_by is set by wl-apdp, never by the launcher")
    grant = await client.create_run_grant(
        agent_id=agent_id,
        goal_id=goal_id,
        max_actions=max_actions,
        ttl_seconds=ttl_seconds,
        metadata=metadata,
        application_id=application_id,
        workload_ref=dict(workload),
    )
    if grant is None:
        raise GovernanceUnavailable(
            "wl-apdp refused the bound session. Check that the launcher credential "
            "holds workload:bind on the agent's tenant (wl-apdp logs the reason)."
        )
    bound = grant.workload_ref or {}
    if bound.get("workload_id") != workload.get("workload_id") or bound.get(
        "source_id"
    ) != workload.get("source_id"):
        raise GovernanceUnavailable(
            "the run credential does not carry the requested workload binding"
        )
    if grant.agent_id != agent_id:
        raise GovernanceUnavailable("the run credential names another agent")
    return grant
