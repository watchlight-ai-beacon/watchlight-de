"""The third line of the session guard: watch the message stream.

Layers 1 and 2 (``session_guard``) are checked before a tool runs. Some
managed settings cannot be read before the session starts (settings the
server delivers at startup), and those could switch both layers off.
The watcher catches that from the messages the session reports:

* Watchlight's ``UserPromptSubmit`` hook runs before Claude Code reports
  that a session started (its ``init`` system message), and both carry
  the session id. An ``init`` for a session the hook never ran for means
  the hooks are not running in it.
* Every tool result must belong to a call the ``PreToolUse`` gate
  decided (allowed or denied). A result for any other call means a tool
  ran without Watchlight.

This **detects**; it does not prevent. Claude Code runs the model turn
and its tools inside its own process whether or not this code has read
the messages, and the SDK reads ahead of it, so by the time the watcher
sees ``init`` or a tool result, tools may already have run. Layers 1 and
2 carry the guarantee; the watcher limits how long a session that lost
them can go on.

On either finding the message source is closed (which stops the Claude
Code process), the run is terminated with a ``governance_bypass``
reason, and :class:`~watchlight_claude_agent.session_guard.GovernanceBypassDetected`
is raised.
"""

from __future__ import annotations

from typing import Any, AsyncIterable, AsyncIterator, Optional

from watchlight_core import BaseRunHandle, get_logger

from .session_guard import GovernanceBypassDetected

logger = get_logger("watchlight_claude_agent.stream_guard")


def _bypass_in(gate: Any, message: Any) -> Optional[str]:
    """Why ``message`` shows the session running without Watchlight, or
    ``None``."""
    from claude_agent_sdk import SystemMessage, ToolResultBlock, UserMessage

    if isinstance(message, SystemMessage) and message.subtype == "init":
        data = message.data if isinstance(message.data, dict) else {}
        if not gate.prompted(data.get("session_id")):
            return "the session started without Watchlight's hooks"
        return None
    if isinstance(message, UserMessage) and isinstance(message.content, list):
        for block in message.content:
            if isinstance(block, ToolResultBlock) and not gate.decided(block.tool_use_id):
                return "a tool ran that Watchlight did not decide"
    return None


async def guard_messages(
    gate: Any, handle: BaseRunHandle, messages: AsyncIterable[Any]
) -> AsyncIterator[Any]:
    """Yield ``messages``, ending the session at the first sign that it
    runs without Watchlight."""
    iterator = messages.__aiter__()
    try:
        async for message in iterator:
            reason = _bypass_in(gate, message)
            if reason is None:
                yield message
                continue
            logger.error("watchlight_claude_agent: %s; ending the session.", reason)
            await _close(iterator)
            try:
                await handle.terminate(f"governance_bypass: {reason}")
            except Exception as exc:  # noqa: BLE001 - the refusal below still stands
                logger.warning(
                    "watchlight_claude_agent: could not terminate the run after a "
                    "governance bypass (%s).",
                    type(exc).__name__,
                )
            raise GovernanceBypassDetected(
                f"Watchlight ended the Claude Code session: {reason}."
            )
    finally:
        await _close(iterator)


async def _close(iterator: Any) -> None:
    aclose = getattr(iterator, "aclose", None)
    if aclose is None:
        return
    try:
        await aclose()
    except Exception:  # noqa: BLE001 - closing is best effort; the run is ended anyway
        pass


__all__ = ["guard_messages"]
