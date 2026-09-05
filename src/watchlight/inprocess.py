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
