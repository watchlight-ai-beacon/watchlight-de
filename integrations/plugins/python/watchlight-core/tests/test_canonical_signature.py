"""Cross-plugin assertion that every shipped Python plugin's
``spawn_subagent`` accepts the canonical attenuation kwargs.

The plugin overrides each accept the same five canonical kwargs
plus plugin-specific plumbing. This test inspects each plugin's
``RunHandle.spawn_subagent`` signature and asserts the kwargs are
present (kwonly) so a future plugin author who omits one fails CI
loudly. The signature CONTENT is the load-bearing contract;
each plugin's deeper behaviour is exercised by its own
``test_subagent_spawn_propagation.py`` suite (or, for plugins that
inherit the base implementation unchanged, by
``test_spawn_subagent.py`` in this directory).

Plugins covered:

  * ``watchlight_core.BaseRunHandle`` — the canonical reference.
  * ``watchlight_langgraph.RunHandle`` — explicit-primitives plugin.
  * ``watchlight_pydantic_ai.RunHandle`` — auto-instrumented plugin.

Plugins NOT covered here:

  * ``watchlight_bedrock`` / ``watchlight_adk`` /
    ``watchlight_claude_agent`` / ``watchlight_msaf`` /
    ``watchlight_openclaw`` — these plugins do NOT override
    ``spawn_subagent``; they inherit it verbatim from
    :class:`watchlight_core.BaseRunHandle`. The base assertion
    therefore covers them transitively.
"""

from __future__ import annotations

import inspect

import pytest

from watchlight_core.run_handle import BaseRunHandle


_M43_CANONICAL_SCOPE_KWARGS = (
    "allowed_tools",
    "allowed_resources",
    "allowed_intents",
    "max_depth",
    "time_budget_seconds",
)


def _assert_signature_carries_m43_canonical_kwargs(method) -> None:
    """Every plugin override accepts the five canonical kwargs
    as keyword-only parameters."""
    sig = inspect.signature(method)
    for kwarg in _M43_CANONICAL_SCOPE_KWARGS:
        assert kwarg in sig.parameters, (
            f"{method.__qualname__} is missing the canonical "
            f"kwarg {kwarg!r}. Every plugin's spawn_subagent override "
            f"MUST accept the five canonical attenuation kwargs "
            f"(sub-agent scope attenuation invariant #1)."
        )
        param = sig.parameters[kwarg]
        assert param.kind == inspect.Parameter.KEYWORD_ONLY, (
            f"{method.__qualname__}.{kwarg} must be keyword-only "
            f"(currently {param.kind!r}). The kwonly contract is "
            f"the readability gate — operators reading the call "
            f"site SEE the scope dimensions named at the call."
        )


def test_base_run_handle_spawn_subagent_has_m43_canonical_signature() -> None:
    _assert_signature_carries_m43_canonical_kwargs(
        BaseRunHandle.spawn_subagent
    )


def test_langgraph_run_handle_spawn_subagent_has_m43_canonical_signature() -> None:
    pytest.importorskip("watchlight_langgraph")
    from watchlight_langgraph import RunHandle  # noqa: PLC0415

    _assert_signature_carries_m43_canonical_kwargs(RunHandle.spawn_subagent)


def test_pydantic_ai_run_handle_spawn_subagent_has_m43_canonical_signature() -> None:
    pytest.importorskip("watchlight_pydantic_ai")
    from watchlight_pydantic_ai import RunHandle  # noqa: PLC0415

    _assert_signature_carries_m43_canonical_kwargs(RunHandle.spawn_subagent)


def test_no_plugin_carries_delegation_scope_as_a_required_kwarg() -> None:
    """``delegation_scope`` is DEPRECATED. It may remain on a plugin's
    override for backward-compat, but it MUST be optional (default
    ``None``) so customer call sites that migrate to the canonical
    kwargs don't need to thread a ``delegation_scope=None`` through
    every spawn. A future PR removes the kwarg entirely; until then,
    the optional default is the structural guarantee that the legacy
    surface is on a deprecation path, not a maintained API.
    """
    targets = [BaseRunHandle.spawn_subagent]
    try:
        from watchlight_langgraph import RunHandle as _LG  # noqa: PLC0415

        targets.append(_LG.spawn_subagent)
    except ImportError:
        pass
    try:
        from watchlight_pydantic_ai import RunHandle as _PA  # noqa: PLC0415

        targets.append(_PA.spawn_subagent)
    except ImportError:
        pass

    for method in targets:
        sig = inspect.signature(method)
        if "delegation_scope" not in sig.parameters:
            # The base RunHandle's spawn_subagent does NOT carry the
            # legacy kwarg — that's correct, it's the canonical path.
            continue
        param = sig.parameters["delegation_scope"]
        assert param.default is None, (
            f"{method.__qualname__}.delegation_scope must default "
            f"to None on the deprecation path "
            f"(currently default={param.default!r})."
        )
