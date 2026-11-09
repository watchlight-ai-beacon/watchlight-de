"""Environment-variable readers for shared governance config."""

import os
from typing import Any, Optional

from .errors import GovernanceUnavailable
from .log import get_logger

logger = get_logger("watchlight_core.env")

#: Env var selecting plan-governance mode. ``strict`` is the default.
PLAN_GOVERNANCE_MODE_ENV_VAR = "WATCHLIGHT_PLAN_GOVERNANCE_MODE"


def governance_mode() -> str:
    """Read ``WATCHLIGHT_PLAN_GOVERNANCE_MODE`` from the environment.

    Returns ``"degrade"`` only when the env var is explicitly set to
    ``degrade`` (case-insensitive, stripped); that opt-in is logged at
    WARNING every time it is read. Anything else, including unset and
    typos, returns ``"strict"``: an unexpected failure in the
    governance pipeline (for example a missing constraint manifest)
    refuses the run rather than silently dropping plan-time
    enforcement.

    Same reader semantics across every framework plugin — do not
    introduce framework-specific variants.
    """
    raw = os.getenv(PLAN_GOVERNANCE_MODE_ENV_VAR, "").strip().lower()
    if raw == "degrade":
        logger.warning(
            "%s=degrade: plan governance runs in DEGRADED mode by explicit "
            "operator opt-in. A run without a constraint manifest will "
            "proceed without plan-time enforcement. Do not use this in "
            "production.",
            PLAN_GOVERNANCE_MODE_ENV_VAR,
        )
        return "degrade"
    if raw and raw != "strict":
        logger.warning(
            "%s=%r is not a recognised mode; using 'strict'.",
            PLAN_GOVERNANCE_MODE_ENV_VAR,
            raw,
        )
    return "strict"


def require_manifest(manifest: Optional[Any], *, agent_id: str) -> str:
    """Gate a run on its pre-flight constraint manifest.

    Returns ``"strong"`` when a manifest is present. When it is missing
    (``None``, or not an object), raises :class:`GovernanceUnavailable`
    unless the operator explicitly opted into ``degrade`` mode, in
    which case it logs a WARNING and returns ``"degraded"``.

    Plugins call this right after ``ApdpClient.get_manifest`` and set
    ``last_governance_mode`` from the result.
    """
    if isinstance(manifest, dict):
        return "strong"
    if governance_mode() == "degrade":
        logger.warning(
            "no constraint manifest for agent %s; continuing in DEGRADED "
            "governance mode (%s=degrade)",
            agent_id,
            PLAN_GOVERNANCE_MODE_ENV_VAR,
        )
        return "degraded"
    raise GovernanceUnavailable(
        f"No constraint manifest could be obtained for agent {agent_id}; "
        "refusing the run (plan governance is strict). Set "
        f"{PLAN_GOVERNANCE_MODE_ENV_VAR}=degrade only for development."
    )
