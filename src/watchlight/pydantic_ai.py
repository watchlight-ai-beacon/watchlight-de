"""Govern a Pydantic AI agent in-process, with zero infrastructure.

    from watchlight.pydantic_ai import governed_plugin

    plugin = governed_plugin("watchlight.policy.json")
    async with await plugin.start_run("research-agent") as handle:
        if not await handle.authorize_action("read", "tool/web_search"):
            raise PermissionError("denied before it executed")
        ...  # run the tool

The returned object is a standard ``WatchlightPydanticAIPlugin`` wired to the
in-process engine (local Cedar policies, local value-free audit). Set
``WATCHLIGHT_APDP_URL`` to a networked policy service and the same code runs
against a remote APDP.

Requires the Pydantic AI extra: ``pip install 'watchlight[pydantic-ai]'``.
"""

from __future__ import annotations

from typing import Any, Optional  # noqa: F401  (kept: names this module has always exposed)

from .inprocess import Policies, _select_backend_kwargs  # noqa: F401  (kept, as above)

# The implementation lives in ``watchlight.integrations.pydantic_ai``, on the
# framework-integration contract; this module is its stable public name.
from .integrations.pydantic_ai import governed_plugin
