"""Shipped enforcement hooks for the Claude Agent SDK.

:meth:`WatchlightClaudeAgentSDKPlugin.governance_hooks` returns the
hook map built here. Pass it to ``ClaudeAgentOptions(hooks=...)`` (or
use :meth:`WatchlightClaudeAgentSDKPlugin.governed_options`) and every
tool call the agent makes goes through Watchlight before it runs:

* **Sub-agent spawns.** A ``PreToolUse`` call to the ``Task`` or
  ``Agent`` tool performs the governed ``spawn_subagent`` round-trip on
  the spawning agent's handle *before* the tool runs. When the spawn is
  refused, or anything about it is uncertain (unregistered sub-agent,
  unknown spawner, transport error), the hook returns a ``deny``
  decision. The tool never runs, so the sub-agent never starts and
  never gets a model turn.
* **Every other tool.** The hook authorizes the call on the handle of
  the agent that made it: the sub-agent's own handle when the call
  comes from a sub-agent, the root handle otherwise. A deny, a
  needs-approval decision, or any error returns ``deny``.
* ``SubagentStart`` binds the SDK's sub-agent id to the governed spawn
  that the ``Task``/``Agent`` gate opened. A sub-agent with no matching
  governed spawn stays unbound and all of its tool calls are denied.
* ``SubagentStop`` closes the sub-agent's governed handle.
* ``PostToolUse`` / ``PostToolUseFailure`` on ``Task``/``Agent`` and
  ``Stop`` close any governed spawn whose sub-agent never started (for
  example a later hook or a permission prompt refused the launch), so a
  stale spawn never lingers or binds to a later sub-agent.

A sub-agent binds to its spawn by tool-use id when the SDK provides one,
otherwise by sub-agent type. Because the SDK's ``SubagentStart`` input
carries no tool-use id, a second spawn of a type that already has a
spawn waiting to start is refused: two pending spawns of one type could
not be told apart.

Every gate runs under a deadline well inside the SDK's hook timeout and
denies when it expires.

The hooks never send raw tool arguments to the backend: only argument
names and value types. Token values are never logged.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from watchlight_core import (
    BaseRunHandle,
    get_logger,
    plugin_child_intent,
    should_inject_synthetic_tool,
)

from .subagents import derive_requested_scope, task_objective_from_tool_input
from .synthetic_tools import DECLARE_INTENT_TOOL_NAME, intercept_tool_call
from .traces import URI_SCHEME
from .tool_classes import (
    CLASSIFIED_CLI_VERSION,
    REMOTE_DISPATCH_REFUSED,
    UNCLASSIFIED_TOOL,
    classify_tool,
    isolation_refusal,
)

if TYPE_CHECKING:  # pragma: no cover
    from .plugin import WatchlightClaudeAgentSDKPlugin

logger = get_logger("watchlight_claude_agent.hooks")

#: Tool names the Claude Agent SDK uses to launch a sub-agent. ``Task``
#: is the historical name; newer releases call it ``Agent``.
SUBAGENT_TOOL_NAMES = frozenset({"Task", "Agent"})

_MAX_ARG_NAMES = 32

#: Allowed tool-use ids kept for the permission callback at most; the
#: oldest are dropped (a dropped call is refused, never allowed). The same
#: bound applies to the decided ids kept for the session watcher.
MAX_ALLOWED_TOOL_USES = 1024


def input_digest(tool_input: Any) -> Optional[str]:
    """A canonical digest of a tool call's input, or ``None`` when it is
    not plain JSON (such a call is never allowed by the permission
    callback)."""
    try:
        text = json.dumps(
            tool_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

#: Timeout set on every Watchlight ``HookMatcher`` (the SDK's default).
HOOK_TIMEOUT_SECONDS = 60.0

#: Deadline for one ``PreToolUse`` gate decision, well inside
#: :data:`HOOK_TIMEOUT_SECONDS`. A gate that has not decided by then
#: denies the call instead of letting the SDK's own hook timeout decide.
GATE_DEADLINE_SECONDS = 45.0

#: A governed spawn whose sub-agent has not started within this many
#: seconds is closed; a sub-agent that starts later is unbound and all
#: of its tool calls are denied.
PENDING_SPAWN_TTL_SECONDS = 120.0

_SCOPE_KEYS = (
    "allowed_tools",
    "allowed_resources",
    "allowed_intents",
    "max_depth",
    "time_budget_seconds",
)


@dataclass
class _HookMatcherFallback:
    """Structural stand-in for ``claude_agent_sdk.HookMatcher`` when the
    SDK is not importable (same attribute names)."""

    matcher: Optional[str] = None
    hooks: List[Any] = field(default_factory=list)
    timeout: Optional[float] = None


def _hook_matcher(
    matcher: Optional[str], hooks: List[Any], timeout: float = HOOK_TIMEOUT_SECONDS
) -> Any:
    try:  # pragma: no cover - depends on the optional framework install
        from claude_agent_sdk import HookMatcher  # type: ignore

        return HookMatcher(matcher=matcher, hooks=hooks, timeout=timeout)
    except Exception:  # noqa: BLE001 - SDK absent or older shape
        return _HookMatcherFallback(matcher=matcher, hooks=hooks, timeout=timeout)


@dataclass
class _PendingSpawn:
    """A governed spawn the gate allowed, waiting for its SubagentStart."""

    agent_type: str
    #: ``None`` while the gate is still performing the governed spawn: the
    #: slot is reserved synchronously so a parallel same-type launch sees
    #: it, but it can never be claimed.
    child: Optional[BaseRunHandle]
    created_at: float


def deny_output(reason: str) -> Dict[str, Any]:
    """The Claude Agent SDK ``PreToolUse`` deny shape."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def is_deny_output(output: Any) -> bool:
    """True when ``output`` is a ``PreToolUse`` deny."""
    if not isinstance(output, dict):
        return False
    spec = output.get("hookSpecificOutput")
    return isinstance(spec, dict) and spec.get("permissionDecision") == "deny"


def _arg_metadata(tool_input: Any) -> Dict[str, Any]:
    """Value-free description of the tool arguments: names and types."""
    if isinstance(tool_input, dict):
        items = list(tool_input.items())[:_MAX_ARG_NAMES]
        return {
            "arg_count": len(tool_input),
            "arg_names": sorted(str(k) for k, _ in items),
            "arg_types": {str(k): type(v).__name__ for k, v in items},
        }
    return {"arg_count": 0 if tool_input is None else 1, "arg_names": []}


def _str_field(data: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _agent_id_of(data: Dict[str, Any]) -> Optional[str]:
    """The SDK sub-agent id the hook fired in, if any (``None`` = root)."""
    return _str_field(data, "agent_id", "agentId", "subagent_id", "subagentId")


class GovernanceHookGate:
    """Per-run enforcement state behind the shipped hooks.

    Holds the governed sub-agent handles opened by the ``Task``/``Agent``
    gate, keyed by the SDK sub-agent id once ``SubagentStart`` binds
    them. One gate per root run handle.
    """

    def __init__(
        self, plugin: "WatchlightClaudeAgentSDKPlugin", root: BaseRunHandle
    ) -> None:
        self._plugin = plugin
        self._root = root
        self._gate_deadline = GATE_DEADLINE_SECONDS
        self._pending_ttl = PENDING_SPAWN_TTL_SECONDS
        # Governed spawns waiting for their SubagentStart, by tool-use id
        # (insertion ordered).
        self._pending: Dict[str, _PendingSpawn] = {}
        # SDK sub-agent id -> governed child handle.
        self._bound: Dict[str, BaseRunHandle] = {}
        # SDK sub-agent ids that started without a governed spawn.
        self._unbound: set = set()
        # Closes of child runs whose gate was cancelled mid-spawn (kept
        # referenced until done).
        self._orphan_closes: set = set()
        # Tool-use ids this gate allowed, waiting for the permission
        # callback (insertion ordered, bounded). The callback allows a
        # tool call only when its id is here.
        # Each entry keeps the call's tool, an input digest, and the
        # permission mode and working directory Claude Code reported for it.
        self._allowed_tool_uses: Dict[str, Dict[str, Any]] = {}
        # Tool-use ids the PreToolUse gate decided, allowed or denied
        # (insertion ordered, bounded), and the session ids Watchlight's
        # UserPromptSubmit hook ran for: what the session watcher checks.
        self._decided_tool_uses: Dict[str, None] = {}
        self._prompted_sessions: Dict[str, None] = {}

    # ── handle resolution ────────────────────────────────────────────

    def resolve(self, agent_id: str) -> Optional[BaseRunHandle]:
        """Governed handle bound to the SDK sub-agent ``agent_id``."""
        return self._bound.get(agent_id)

    def _live_subagents(self) -> bool:
        started_spawns = any(p.child is not None for p in self._pending.values())
        return bool(self._bound or started_spawns or self._unbound)

    async def _close_pending(self, key: str, reason: str) -> None:
        """Drop a spawn whose sub-agent never started and close its run."""
        entry = self._pending.get(key)
        if entry is None or entry.child is None:
            # Missing, or a reservation whose gate is still running (the
            # gate drops or fills it itself).
            return
        del self._pending[key]
        try:
            await entry.child.terminate(reason=reason)
        except Exception as exc:  # noqa: BLE001 - close is best effort
            logger.warning(
                "watchlight_claude_agent: closing an unstarted sub-agent "
                "spawn failed (%s).",
                type(exc).__name__,
            )

    async def _expire_stale_pending(self) -> None:
        now = time.monotonic()
        for key in [
            k
            for k, v in self._pending.items()
            if v.child is not None and now - v.created_at > self._pending_ttl
        ]:
            logger.warning(
                "watchlight_claude_agent: a governed spawn of %r never "
                "started; closing it.",
                self._pending[key].agent_type,
            )
            await self._close_pending(key, "subagent_never_started")

    async def _acting_handle(
        self, data: Dict[str, Any]
    ) -> Tuple[Optional[BaseRunHandle], Optional[str]]:
        """Handle the call must run under, or ``(None, reason)``."""
        await self._expire_stale_pending()
        agent_id = _agent_id_of(data)
        if agent_id is None:
            if self._live_subagents():
                # The SDK did not say which agent made this call while a
                # sub-agent is live: we cannot tell the root's calls from
                # the sub-agent's, so we refuse rather than run a
                # sub-agent's call on the root's credential.
                return None, (
                    "Watchlight cannot tell which agent made this call while "
                    "a sub-agent is running; refusing it."
                )
            return self._root, None
        handle = self._bound.get(agent_id)
        if handle is None:
            return None, (
                "This sub-agent has no governed Watchlight handle (its spawn "
                "was refused or never governed); its tool calls are denied."
            )
        return handle, None

    # ── PreToolUse ───────────────────────────────────────────────────

    async def pre_tool_use(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        try:
            output = await asyncio.wait_for(
                self._pre_tool_use(input_data, tool_use_id),
                timeout=self._gate_deadline,
            )
            if not is_deny_output(output):
                self._record_allowed(tool_use_id, input_data)
            else:
                self._record_decided(tool_use_id, input_data)
            return output
        except asyncio.TimeoutError:
            self._record_decided(tool_use_id, input_data)
            logger.warning(
                "watchlight_claude_agent: tool gate did not decide within "
                "%.0fs; denying the tool call.",
                self._gate_deadline,
            )
            return deny_output(
                "Watchlight could not authorize this call in time; it was refused."
            )
        except Exception as exc:  # noqa: BLE001 - fail closed on anything
            self._record_decided(tool_use_id, input_data)
            logger.warning(
                "watchlight_claude_agent: tool gate failed (%s); denying the "
                "tool call.",
                type(exc).__name__,
            )
            return deny_output(
                "Watchlight could not authorize this call; it was refused."
            )

    @staticmethod
    def _tool_use_id(tool_use_id: Optional[str], input_data: Any) -> Optional[str]:
        if not tool_use_id and isinstance(input_data, dict):
            tool_use_id = _str_field(input_data, "tool_use_id")
        return tool_use_id or None

    def _record_decided(self, tool_use_id: Optional[str], input_data: Any) -> None:
        tool_use_id = self._tool_use_id(tool_use_id, input_data)
        if not tool_use_id:
            return
        self._decided_tool_uses.pop(tool_use_id, None)
        self._decided_tool_uses[tool_use_id] = None
        while len(self._decided_tool_uses) > MAX_ALLOWED_TOOL_USES:
            self._decided_tool_uses.pop(next(iter(self._decided_tool_uses)))

    def _record_allowed(self, tool_use_id: Optional[str], input_data: Any) -> None:
        self._record_decided(tool_use_id, input_data)
        tool_use_id = self._tool_use_id(tool_use_id, input_data)
        if not tool_use_id:
            return
        data = input_data if isinstance(input_data, dict) else {}
        digest = input_digest(data.get("tool_input"))
        self._allowed_tool_uses.pop(tool_use_id, None)
        if digest is None:
            return
        self._allowed_tool_uses[tool_use_id] = {
            "tool_name": data.get("tool_name"),
            "input_digest": digest,
            "permission_mode": data.get("permission_mode"),
            "cwd": data.get("cwd") if isinstance(data.get("cwd"), str) else None,
        }
        while len(self._allowed_tool_uses) > MAX_ALLOWED_TOOL_USES:
            self._allowed_tool_uses.pop(next(iter(self._allowed_tool_uses)))

    def decided(self, tool_use_id: Any) -> bool:
        """Whether the ``PreToolUse`` gate decided this tool-use id."""
        return isinstance(tool_use_id, str) and tool_use_id in self._decided_tool_uses

    def prompted(self, session_id: Any) -> bool:
        """Whether Watchlight's ``UserPromptSubmit`` hook ran for this
        session."""
        return isinstance(session_id, str) and session_id in self._prompted_sessions

    # ── UserPromptSubmit: proof the hooks are live ────────────────────

    async def user_prompt_submit(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        """Records the session: Claude Code runs this before it reports the
        session started, so the session watcher knows the hooks are live in
        that session."""
        session_id = _str_field(input_data, "session_id") if isinstance(input_data, dict) else None
        if session_id:
            self._prompted_sessions.pop(session_id, None)
            self._prompted_sessions[session_id] = None
            while len(self._prompted_sessions) > MAX_ALLOWED_TOOL_USES:
                self._prompted_sessions.pop(next(iter(self._prompted_sessions)))
        return {}

    def can_use_tool(self, permissions: Any, user_callback: Any = None) -> Any:
        """The SDK ``can_use_tool`` callback that proves the gate ran.

        The session's settings make Claude Code ask it before every tool
        call. It refuses (and ends the session) a call this gate's
        ``PreToolUse`` did not allow first: same tool-use id (each id
        once), same tool, same input. For a call the gate allowed, it
        allows only what the session's own configuration would have run
        without a prompt (``permissions``, a ``SessionPermissions``), so a
        Watchlight allow never widens it. Any other call goes to
        ``user_callback`` (your own ``can_use_tool``), or is denied, as
        Claude Code denies a prompt in the SDK when no callback is set. An
        allow from ``user_callback`` that changes permissions or the input
        is refused.
        """

        async def callback(tool_name: str, tool_input: Any, context: Any) -> Any:
            from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny

            tool_use_id = getattr(context, "tool_use_id", None)
            record = self._allowed_tool_uses.pop(tool_use_id, None) if tool_use_id else None
            if record is None:
                logger.warning(
                    "watchlight_claude_agent: tool %r reached the permission check "
                    "with no Watchlight decision (the hooks did not run); refused.",
                    tool_name,
                )
                return PermissionResultDeny(
                    message="Refused by Watchlight: this call was not authorized.",
                    interrupt=True,
                )
            digest = record["input_digest"]
            if record["tool_name"] != tool_name or input_digest(tool_input) != digest:
                logger.warning(
                    "watchlight_claude_agent: tool %r reached the permission check "
                    "with another tool or input than Watchlight authorized; refused.",
                    tool_name,
                )
                return PermissionResultDeny(
                    message="Refused by Watchlight: this call differs from the one authorized.",
                    interrupt=True,
                )
            try:
                unprompted = permissions.would_run_unprompted(
                    tool_name, tool_input, record["permission_mode"], record["cwd"]
                )
            except Exception:  # noqa: BLE001 - fail closed
                unprompted = False
            if unprompted:
                return PermissionResultAllow()
            if user_callback is None:
                return PermissionResultDeny(
                    message="This tool call needs permission, and no permission handler is configured."
                )
            result = await user_callback(tool_name, tool_input, context)
            if isinstance(result, PermissionResultDeny):
                return result
            if not isinstance(result, PermissionResultAllow):
                return PermissionResultDeny(message="The permission handler gave no decision.")
            if result.updated_permissions:
                return PermissionResultDeny(
                    message="Refused by Watchlight: a permission handler may not change permissions."
                )
            if result.updated_input is not None and input_digest(result.updated_input) != digest:
                return PermissionResultDeny(
                    message="Refused by Watchlight: a permission handler may not change the input."
                )
            return result

        return callback

    async def _pre_tool_use(
        self, input_data: Any, tool_use_id: Optional[str]
    ) -> Dict[str, Any]:
        if not isinstance(input_data, dict):
            return deny_output("Watchlight received a malformed tool call.")
        tool_name = input_data.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return deny_output("Watchlight received a tool call with no name.")
        tool_use_id = tool_use_id or _str_field(input_data, "tool_use_id")

        isolation = (
            isolation_refusal(input_data.get("tool_input")) if tool_name in SUBAGENT_TOOL_NAMES else None
        )
        if isolation is not None:
            # A remote sub-agent runs elsewhere: these hooks never see its
            # tool calls, so it would run ungoverned. An isolation value
            # this plugin does not know is refused the same way.
            return await self._refuse_before_decision(
                input_data,
                isolation,
                "Watchlight starts sub-agents only in this process: a remote "
                "sub-agent's tool calls cannot be governed here.",
            )
        if tool_name in SUBAGENT_TOOL_NAMES:
            return await self._gate_spawn(input_data, tool_use_id)

        handle, reason = await self._acting_handle(input_data)
        if handle is None:
            return deny_output(reason or "Refused by Watchlight.")

        if tool_name == DECLARE_INTENT_TOOL_NAME and should_inject_synthetic_tool(
            getattr(self._plugin, "intent_enforcement_mode", None)
        ):
            # The plugin's own synthetic declare_intent tool (offered only
            # in greenfield mode) records intent on the acting handle; it
            # is not itself an authorized action. Any other tool with a
            # look-alike name is authorized like every other tool.
            intercept_tool_call(handle, {"hook": "PreToolUse", **input_data})
            return {}

        # A tool that starts work outside these hooks (a remote
        # session), or one this plugin version has not classified, is
        # refused before any decision, whatever the policy says. The
        # refusal is a recorded Deny.
        tool_class = classify_tool(tool_name)
        if tool_class == "refused":
            return await self._refuse_before_decision(
                input_data,
                REMOTE_DISPATCH_REFUSED,
                "Watchlight does not start remote sessions: their tool calls "
                "cannot be governed here.",
            )
        if tool_class is None:
            return await self._refuse_before_decision(
                input_data,
                UNCLASSIFIED_TOOL,
                "Watchlight refused this tool: this plugin version has not "
                f"classified it (checked against Claude Code {CLASSIFIED_CLI_VERSION}).",
            )

        result = await handle.authorize_action_detailed(
            action="execute",
            resource=tool_name,
            context={"tool_args": _arg_metadata(input_data.get("tool_input"))},
        )
        if result.is_allow():
            return {}
        if result.needs_approval():
            return deny_output(
                "This call needs human approval in Watchlight before it can run."
            )
        # Opaque deny: the agent sees a generic refusal; the server's
        # reason stays in its audit trail.
        return deny_output("Denied by Watchlight policy.")

    async def _refuse_before_decision(
        self, input_data: Dict[str, Any], reason: str, message: str
    ) -> Dict[str, Any]:
        """Deny with no authorize call, recorded as a ``Deny`` under the
        acting handle with a value-free ``metadata.refusal_reason``. The
        call is refused whether or not the record is sent."""
        tool_name = input_data.get("tool_name")
        handle, _ = await self._acting_handle(input_data)
        logger.warning(
            "watchlight_claude_agent: PreToolUse %s -> DENY (%s) before any decision.",
            tool_name,
            reason,
        )
        if handle is not None:
            try:
                await handle.publish_observation(
                    "tool_call_observed",
                    {
                        "tool": {
                            "resource_type": "tool",
                            "identifier": tool_name,
                            "endpoint": f"{URI_SCHEME}://tool/{tool_name}",
                        },
                        "action": {"action": "execute"},
                        "decision": "Deny",
                    },
                    extra_metadata={"refusal_reason": reason},
                )
            except Exception as exc:  # noqa: BLE001 - the refusal stands
                logger.warning(
                    "watchlight_claude_agent: could not record the refusal (%s).",
                    type(exc).__name__,
                )
        return deny_output(message)

    async def _gate_spawn(
        self, input_data: Dict[str, Any], tool_use_id: Optional[str]
    ) -> Dict[str, Any]:
        if not tool_use_id:
            return deny_output(
                "Watchlight cannot govern a sub-agent launch with no tool-use id."
            )
        if tool_use_id in self._pending:
            return deny_output(
                "Watchlight already governs a sub-agent launch with this "
                "tool-use id; refusing the duplicate."
            )
        tool_input = input_data.get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = {}
        agent_type = _str_field(
            tool_input, "subagent_type", "agent_type", "subagentType", "agentType"
        ) or "general-purpose"

        if any(p.agent_type == agent_type for p in self._pending.values()):
            # SubagentStart names the sub-agent's type but no tool-use id,
            # so two pending spawns of one type could bind to each other's
            # handles. Refuse rather than guess.
            return deny_output(
                f"Another {agent_type!r} sub-agent is still starting; Watchlight "
                "refused this launch. Start it after the first one is running."
            )
        # Reserve the slot before the first await, so a parallel launch of
        # the same type (gated concurrently) is refused by the check
        # above. The reservation is dropped unless the spawn succeeds.
        slot = _PendingSpawn(agent_type=agent_type, child=None, created_at=time.monotonic())
        self._pending[tool_use_id] = slot
        granted = False
        try:
            result = await self._spawn_into_slot(
                input_data, tool_input, agent_type, slot
            )
            granted = slot.child is not None and not is_deny_output(result)
            return result
        finally:
            if not granted and self._pending.get(tool_use_id) is slot:
                del self._pending[tool_use_id]

    async def _spawn_into_slot(
        self,
        input_data: Dict[str, Any],
        tool_input: Dict[str, Any],
        agent_type: str,
        slot: "_PendingSpawn",
    ) -> Dict[str, Any]:
        spawner, reason = await self._acting_handle(input_data)
        if spawner is None:
            return deny_output(reason or "Refused by Watchlight.")

        child_uuid = await self._plugin._resolve_subagent_principal(agent_type)
        if child_uuid is None:
            logger.warning(
                "watchlight_claude_agent: sub-agent type %r is not a "
                "registered Watchlight agent; refusing to launch it.",
                agent_type,
            )
            return deny_output(
                f"Sub-agent {agent_type!r} is not a registered Watchlight "
                "agent; it was not started."
            )
        try:
            uuid.UUID(str(child_uuid))
        except (ValueError, TypeError):
            return deny_output(
                f"Sub-agent {agent_type!r} has no valid Watchlight identity; "
                "it was not started."
            )

        requested = derive_requested_scope({"tool_input": tool_input})
        if requested is None:
            requested = self._plugin.default_subagent_scope
        scope_kwargs = {k: v for k, v in requested.items() if k in _SCOPE_KEYS}
        # The child's intent derives from the task the parent hands it: the
        # Task tool's description (else its prompt) is the objective. A
        # scope that pins exactly one intent names the category (wl-apdp
        # requires ``allowed_intents`` to be empty or exactly that category).
        scoped_intents = list(scope_kwargs.get("allowed_intents") or [])
        child_intent = plugin_child_intent(
            task_objective_from_tool_input(tool_input),
            category=(
                scoped_intents[0]
                if len(scoped_intents) == 1
                else getattr(self._plugin, "child_intent_category", None)
            ),
            parent=spawner,
            fallback_objective=f"Task sub-agent {agent_type}",
        )

        # The spawn runs as its own task, shielded from the gate deadline:
        # when the deadline cancels the gate while the server is minting
        # the child, the child run that arrives afterwards is ended, so its
        # credential never stays valid for a launch that was refused.
        spawn_task = asyncio.ensure_future(
            spawner.spawn_subagent(child_uuid, child_intent=child_intent, **scope_kwargs)
        )
        try:
            child = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            spawn_task.add_done_callback(self._end_orphaned_spawn)
            raise
        except Exception as exc:  # noqa: BLE001 - every failure refuses
            logger.warning(
                "watchlight_claude_agent: governed spawn of %r refused (%s); "
                "the sub-agent was not started.",
                agent_type,
                type(exc).__name__,
            )
            return deny_output(
                f"Watchlight refused to start sub-agent {agent_type!r}."
            )
        if child is None:
            return deny_output(
                f"Watchlight refused to start sub-agent {agent_type!r}."
            )
        slot.child = child
        slot.created_at = time.monotonic()
        return {}

    def _end_orphaned_spawn(self, task: "asyncio.Future") -> None:
        """Done-callback for a spawn whose gate was cancelled: end the
        child run the server minted (the launch was refused)."""
        if task.cancelled() or task.exception() is not None:
            return
        child = task.result()
        if child is None:
            return
        logger.warning(
            "watchlight_claude_agent: a governed spawn finished after its gate "
            "was cancelled; ending the orphaned child run."
        )
        closing = asyncio.ensure_future(
            child.terminate(reason="spawn_gate_cancelled")
        )
        self._orphan_closes.add(closing)
        closing.add_done_callback(self._orphan_closes.discard)

    # ── SubagentStart / SubagentStop ─────────────────────────────────

    def _claim_pending(
        self, data: Dict[str, Any]
    ) -> Optional[BaseRunHandle]:
        """The pending spawn this starting sub-agent belongs to.

        By tool-use id when the SDK provides one (and nothing else);
        otherwise by sub-agent type, only when exactly one pending spawn
        has that type. Anything ambiguous claims nothing, so the
        sub-agent stays unbound and its tool calls are denied.
        """
        explicit = _str_field(
            data, "tool_use_id", "parent_tool_use_id", "toolUseId"
        )
        if explicit is not None:
            entry = self._pending.get(explicit)
            if entry is None or entry.child is None:
                return None
            del self._pending[explicit]
            return entry.child
        agent_type = _str_field(
            data, "agent_type", "subagent_type", "agentType", "subagentType"
        )
        if agent_type is None:
            return None
        candidates = [k for k, v in self._pending.items() if v.agent_type == agent_type]
        if any(self._pending[k].child is None for k in candidates):
            # A launch of this type is still being governed: nothing to
            # claim yet.
            return None
        if len(candidates) != 1:
            if candidates:
                logger.warning(
                    "watchlight_claude_agent: %d pending spawns of %r and no "
                    "tool-use id; the starting sub-agent is left unbound.",
                    len(candidates),
                    agent_type,
                )
            return None
        return self._pending.pop(candidates[0]).child

    async def subagent_start(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        if not isinstance(input_data, dict):
            return {}
        agent_id = _agent_id_of(input_data)
        if agent_id is None:
            return {}
        child = self._claim_pending(input_data)
        if child is None:
            self._unbound.add(agent_id)
            logger.warning(
                "watchlight_claude_agent: sub-agent %r started without a "
                "governed spawn; all of its tool calls will be denied.",
                agent_id,
            )
            return {}
        self._bound[agent_id] = child
        return {}

    async def subagent_stop(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        if not isinstance(input_data, dict):
            return {}
        agent_id = _agent_id_of(input_data)
        if agent_id is None:
            return {}
        self._unbound.discard(agent_id)
        child = self._bound.pop(agent_id, None)
        if child is not None:
            try:
                await child.complete()
            except Exception as exc:  # noqa: BLE001 - close is best effort
                logger.warning(
                    "watchlight_claude_agent: closing sub-agent %r failed (%s).",
                    agent_id,
                    type(exc).__name__,
                )
        return {}

    # ── PostToolUse / PostToolUseFailure / Stop ──────────────────────

    async def post_tool_use(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        """A ``Task``/``Agent`` call that finished (or failed) while its
        governed spawn is still pending never started its sub-agent:
        close that spawn so it cannot bind to a later sub-agent."""
        if not isinstance(input_data, dict):
            return {}
        if input_data.get("tool_name") not in SUBAGENT_TOOL_NAMES:
            return {}
        key = tool_use_id or _str_field(input_data, "tool_use_id")
        if key is not None and key in self._pending:
            await self._close_pending(key, "subagent_never_started")
        return {}

    async def stop(
        self, input_data: Any, tool_use_id: Optional[str], context: Any = None
    ) -> Dict[str, Any]:
        """The turn ended: no pending spawn can still start."""
        for key in list(self._pending):
            await self._close_pending(key, "subagent_never_started")
        return {}

    # ── hook map ─────────────────────────────────────────────────────

    def hooks(self) -> Dict[str, List[Any]]:
        return {
            "UserPromptSubmit": [_hook_matcher(None, [self.user_prompt_submit])],
            "PreToolUse": [_hook_matcher(None, [self.pre_tool_use])],
            "PostToolUse": [_hook_matcher(None, [self.post_tool_use])],
            "PostToolUseFailure": [_hook_matcher(None, [self.post_tool_use])],
            "SubagentStart": [_hook_matcher(None, [self.subagent_start])],
            "SubagentStop": [_hook_matcher(None, [self.subagent_stop])],
            "Stop": [_hook_matcher(None, [self.stop])],
        }


__all__ = [
    "GATE_DEADLINE_SECONDS",
    "GovernanceHookGate",
    "HOOK_TIMEOUT_SECONDS",
    "SUBAGENT_TOOL_NAMES",
    "deny_output",
    "input_digest",
    "is_deny_output",
]
