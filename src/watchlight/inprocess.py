"""In-process governance backend for Watchlight framework plugins.

The Developer Edition runs the *same* framework plugins you ship to production
(``watchlight-langgraph``, ``watchlight-pydantic-ai``, ``watchlight-claude-agent``,
…) — but against the compiled authorization engine **in-process**, with zero
infrastructure. The seam is one object: a ``GovernanceBackend``.

- **Production**: the plugin talks to a running policy service over TLS
  (``ApdpClient``).
- **Developer Edition**: the plugin talks to :func:`in_process_backend` — the
  real ``watchlight-engine`` (the Watchlight authorization engine, Cedar)
  embedded in your process, writing a local, value-free audit trail.

Same plugin, same agent code. Going to production is pointing at a policy
service — not a rewrite.

    from watchlight.inprocess import in_process_backend
    from watchlight_langgraph import WatchlightLangGraphPlugin

    plugin = WatchlightLangGraphPlugin(
        governance=in_process_backend("watchlight.policy.json")
    )

Most users never import this directly — the per-framework helpers
(``watchlight.langgraph.governed_plugin`` etc.) call it for you.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Union

# A local policy source: a path to a JSON policy file, or an in-memory list of
# ``{"name", "code"}`` Cedar policy objects. ``None`` loads no policies —
# fail-closed, so every action is denied until a policy permits it.
Policies = Optional[Union[str, "os.PathLike[str]", List[Dict[str, Any]]]]


def in_process_backend(
    policies: Policies = None,
    *,
    audit_path: Optional[str] = ".watchlight/audit.jsonl",
) -> Any:
    """Build an in-process ``GovernanceBackend`` over the compiled engine.

    :param policies: a path to a JSON policy file (a list of
        ``{"name", "code"}`` objects, or ``{"policies": [...]}``), or that list
        in memory. ``None`` → no policies (fail-closed: everything denies).
    :param audit_path: local JSONL lineage sink. Value-free — argument VALUES
        never enter the trail, only the governance decision. Pass ``None`` to
        disable the local audit file.
    :returns: a ``watchlight_core.InProcessClient`` — pass it to any Watchlight
        framework plugin via ``governance=``.

    Requires the Watchlight SDK (installed transitively by any framework extra,
    e.g. ``pip install 'watchlight[langgraph]'``).
    """
    try:
        from watchlight_core import InProcessClient
    except ImportError as exc:  # pragma: no cover - import-guard message
        raise ImportError(
            "in_process_backend requires the Watchlight SDK. Install a framework "
            "extra, e.g. `pip install 'watchlight[langgraph]'`, or the SDK "
            "directly: `pip install watchlight-agent-sdk`."
        ) from exc
    return InProcessClient(policies, audit_path=audit_path)


def _select_backend_kwargs(
    policies: Policies,
    audit_path: Optional[str],
    plugin_kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute the constructor kwargs for a framework plugin: production when
    ``WATCHLIGHT_APDP_URL`` is set (networked APDP), in-process otherwise.

    One environment variable flips dev↔prod with no code change — the shared
    logic behind every ``watchlight.<framework>.governed_plugin`` helper.
    """
    apdp_url = os.getenv("WATCHLIGHT_APDP_URL")
    if apdp_url:
        # Production: the plugin builds its own networked ApdpClient (which
        # enforces channel safety). We only pass the URL through.
        return {"apdp_url": apdp_url, **plugin_kwargs}
    # Developer Edition: in-process engine, zero infra.
    return {
        "governance": in_process_backend(policies, audit_path=audit_path),
        **plugin_kwargs,
    }
