"""Manifest-driven toolset for Google ADK.

Wraps a static list of tools and filters them at runtime by the
`tool_allowlist` derived from the agent's constraint manifest. The
manifest is fetched by `WatchlightPlugin.before_run_callback` and
stored on the InvocationContext under
`ctx.state["wl_governance"]["manifest"]`; this toolset reads it back
out of the same slot.

Customers register this toolset on their agent so that the LLM is
never offered a tool it isn't allowed to call. This is defence in
depth — `before_tool_callback` will still veto unauthorized calls
even if the LLM somehow names a filtered tool — but filtering at
the toolset layer is the cleanest UX (the model isn't tempted by
forbidden capabilities).

Usage::

    from google.adk.tools import FunctionTool
    from watchlight_adk import ManifestDrivenToolset

    toolset = ManifestDrivenToolset([
        FunctionTool(get_market_data),
        FunctionTool(send_email),  # filtered out if not in manifest
        FunctionTool(execute_trade),
    ])

    agent = LlmAgent(
        name="research_agent",
        tools=[toolset],
        ...
    )
"""

from typing import Any, Optional

from watchlight_core import get_logger

logger = get_logger("watchlight_adk")

try:  # pragma: no cover — import-shape compatibility across ADK versions
    from google.adk.tools.base_toolset import BaseToolset
    from google.adk.tools.base_tool import BaseTool
except ImportError:  # pragma: no cover
    BaseToolset = object  # type: ignore[assignment,misc]
    BaseTool = object  # type: ignore[assignment,misc]


class ManifestDrivenToolset(BaseToolset):
    """Filters a wrapped list of tools by the manifest tool_allowlist.

    Falls back to surfacing every tool when no manifest is on the
    context — so an agent run that bypassed `before_run_callback`
    (for any reason) still works. The plugin's `before_tool_callback`
    remains the authoritative gate.
    """

    def __init__(self, tools: list[Any], strict: bool = False):
        """Construct.

        Args:
            tools: The full list of `BaseTool` instances the agent
                might use.
            strict: When True, an empty manifest tool_allowlist hides
                ALL tools (fail-closed). When False (default), an empty
                allowlist passes every tool through, treating the
                missing manifest as 'unknown' rather than 'all forbidden'.
        """
        self._tools = list(tools)
        self._strict = strict

    @property
    def tools(self) -> list[Any]:
        """All wrapped tools regardless of context (for ADK's __init__-time
        introspection)."""
        return self._tools

    async def get_tools(
        self,
        ctx: Optional[Any] = None,
    ) -> list[Any]:
        """ADK calls this to determine which tools to advertise to the
        LLM for a given invocation context."""
        allowlist = self._allowlist_from_ctx(ctx)
        if allowlist is None:
            # No manifest on ctx — degrade to surfacing everything
            # unless strict mode is enabled.
            if self._strict:
                logger.warning(
                    "ManifestDrivenToolset: no manifest on ctx; strict mode → 0 tools"
                )
                return []
            return list(self._tools)

        if not allowlist:
            logger.info("manifest tool_allowlist is empty — surfacing 0 tools")
            return []

        filtered = [t for t in self._tools if self._tool_name(t) in allowlist]
        dropped = [self._tool_name(t) for t in self._tools if self._tool_name(t) not in allowlist]
        if dropped:
            logger.info(
                "ManifestDrivenToolset: hiding %d tool(s) outside allowlist: %s",
                len(dropped),
                dropped,
            )
        return filtered

    @staticmethod
    def _allowlist_from_ctx(ctx: Optional[Any]) -> Optional[list[str]]:
        if ctx is None:
            return None
        # ADK contexts vary across versions: try `.state`, then attr,
        # then the old `temp_data` slot. All paths are best-effort.
        candidates: list[Any] = []
        for attr in ("state", "session_state", "temp_data"):
            if hasattr(ctx, attr):
                candidates.append(getattr(ctx, attr))
        for src in candidates:
            try:
                gov = src.get("wl_governance") if hasattr(src, "get") else None
            except Exception:
                gov = None
            if isinstance(gov, dict):
                manifest = gov.get("manifest")
                if isinstance(manifest, dict):
                    allow = manifest.get("tool_allowlist")
                    if isinstance(allow, list):
                        return [str(x) for x in allow]
        return None

    @staticmethod
    def _tool_name(tool: Any) -> str:
        # ADK tools expose `.name` (BaseTool); fall back to class name.
        return getattr(tool, "name", None) or type(tool).__name__

    async def close(self) -> None:  # pragma: no cover
        """ADK BaseToolset cleanup hook — no resources to release."""
        return None
