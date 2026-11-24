"""Governed-tool-call helper integrating LangGraph's ``interrupt`` /
``Command`` primitives with Watchlight's APDP human-approval path.

The contract:

* On Allow → invoke the tool implementation and return its result.
* On Deny → raise :class:`ToolDenied` carrying APDP's reason string.
* On needs_approval → call :func:`langgraph.types.interrupt` with a
  structured payload the dashboard can render; LangGraph persists
  the graph state via the compiled checkpointer (``MemorySaver`` for
  the demo, ``PostgresSaver`` for production) and returns control
  to the caller. When an operator approves via
  ``POST /approvals/:id/approve`` and the workflow is resumed with
  :class:`langgraph.types.Command(resume=...)`, control re-enters
  the same node, the helper retries ``authorize_action`` with
  ``intent.approval_token`` set, and proceeds.

Security model — production callers must:

* Mount the checkpointer behind a tenant-scoped Postgres role; the
  in-memory variant exists only for single-process demos.
* Treat the ``approval_request_id`` as a bearer token: never log it
  at info-level, never embed it in error messages surfaced to
  untrusted callers. An approval is single-use and bound to the
  request it was minted for (principal, action, resource and the
  intent's objective), so it cannot release a different call or be
  replayed once redeemed.
* Bind the resume action behind the dashboard's admin auth so the
  approver identity matches the operator-of-record on the audit
  chain (segregation of duties from the requester).
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from typing import Any, Awaitable, Callable, Dict, Optional

try:
    from langgraph.types import interrupt as _lg_interrupt
except ImportError as exc:  # pragma: no cover — langgraph is a required dep
    raise ImportError(
        "watchlight-langgraph governed_tool_call requires LangGraph >= 0.2 "
        "(langgraph.types.interrupt). Upgrade your LangGraph install."
    ) from exc

from watchlight_core import AuthorizeResult, get_logger
from watchlight_core import langchain_tool_backstop as backstop

from . import RunHandle
from .tool_gate import publish_tool_gate_refusals

logger = get_logger("watchlight_langgraph.governance")


class ToolDenied(Exception):
    """Raised when ``authorize_action`` returns Deny.

    Carries APDP's reason verbatim (typically a Cedar policy id or
    an IntentValidator message) so the workflow's error path has a
    machine-readable handle on which policy fired.

    Distinct from ``Exception("approval not granted")`` — Deny is
    terminal for this attempt; the operator must either change the
    request shape or update policy.
    """

    def __init__(self, tool_name: str, reason: str):
        # Opaque deny: the message (which LangGraph's ToolNode hands to
        # the model) is a generic refusal. ``reason`` stays available to
        # the workflow's own code; do not forward it to the model.
        super().__init__(f"{tool_name}: denied by Watchlight policy")
        self.tool_name = tool_name
        self.reason = reason


async def governed_tool_call(
    handle: RunHandle,
    tool_name: str,
    *,
    intent: Dict[str, Any],
    context: Dict[str, Any],
    impl: Callable[..., Any],
    **impl_kwargs: Any,
) -> Any:
    """Run ``impl(**impl_kwargs)`` under APDP authorization with
    automatic pause-on-approval-needed semantics.

    The function is sync / async-agnostic for ``impl``: a coroutine
    is awaited, a plain callable is called directly. This matches the
    shape of LangGraph nodes that wrap either ``def`` or ``async def``
    tool implementations.

    Returns whatever ``impl`` returns on Allow. Raises
    :class:`ToolDenied` on Deny.

    On ``needs_approval``:
      1. ``interrupt()`` is called with a structured payload (see
         :func:`build_interrupt_payload`). The caller's framework
         persists graph state at this point.
      2. When the workflow is resumed with
         ``Command(resume=<approval_request_id>)``, control re-enters
         this node and the call retries with
         ``intent.approval_token`` set.
      3. The retry's outcome is honored: Allow → run impl; anything
         else → raise ToolDenied with the retry's reason.

    Audit — every Allow / Deny / needs_approval transition is
    recorded server-side by APDP. The plugin's
    ``last_actions_allowed`` / ``last_actions_denied`` counters are
    incremented by the underlying ``authorize_action_detailed``
    call. The token leg on retry counts as a separate authz
    decision (replayable from the audit chain).
    """
    result = await handle.authorize_action_detailed(
        action="execute",
        resource=tool_name,
        intent=intent,
        context=context,
    )

    if result.is_allow():
        return await _run_granted(handle, tool_name, impl, impl_kwargs)

    if result.is_deny():
        raise ToolDenied(tool_name, result.reason or "policy denied")

    # ──── needs_approval ────────────────────────────────────────────
    if not result.approval_request_id:
        # APDP signalled escalation but didn't mint an id — shouldn't
        # happen if the server is current, but fail-closed is the
        # only safe behavior. Treat as a hard deny so the workflow
        # doesn't hang on a bogus interrupt.
        raise ToolDenied(
            tool_name,
            "needs_approval signalled but no approval_request_id was provided",
        )

    payload = build_interrupt_payload(
        tool_name=tool_name,
        intent=intent,
        result=result,
    )
    # The approval_request_id is a bearer value: log only a short,
    # one-way reference so the line can be correlated, never the id.
    logger.info(
        "tool %s requires human approval (approval_ref=%s) — interrupting workflow",
        tool_name,
        _approval_ref(result.approval_request_id),
    )

    # interrupt() persists graph state and returns when the
    # workflow is resumed via Command(resume=<value>). The resumed
    # value is whatever the operator-driven resume call passed —
    # by convention, the approval_request_id (the secret token) so
    # APDP recognizes the retry. The dashboard / CLI driver is the
    # source of this token.
    resumed_token = _lg_interrupt(payload)

    # Defensive validation — the resumed token should be a non-empty
    # string. If a caller resumes with junk we fail-closed.
    if not isinstance(resumed_token, str) or not resumed_token:
        raise ToolDenied(
            tool_name,
            "workflow resumed with an invalid approval_token; refusing the action",
        )

    intent_with_token = {**intent, "approval_token": resumed_token}
    retried = await handle.authorize_action_detailed(
        action="execute",
        resource=tool_name,
        intent=intent_with_token,
        context=context,
    )

    if retried.is_allow():
        logger.info(
            "tool %s approved (approval_ref=%s) — executing",
            tool_name,
            _approval_ref(result.approval_request_id),
        )
        return await _run_granted(handle, tool_name, impl, impl_kwargs)

    # The retry didn't pass — operator rejected, token expired,
    # principal/action drifted, etc. Surface the new reason.
    raise ToolDenied(
        tool_name,
        retried.reason
        or "approval token did not satisfy authz on retry",
    )


def build_interrupt_payload(
    *,
    tool_name: str,
    intent: Dict[str, Any],
    result: AuthorizeResult,
) -> Dict[str, Any]:
    """Construct the dict surfaced through ``interrupt(...)``.

    The dashboard's approvals page reads this payload to render
    ``Approve / Reject`` for the right tool call. Keep it small and
    operator-readable; no secrets beyond ``approval_request_id``
    (which IS the secret needed to satisfy the retry — guard the
    page's RBAC accordingly).
    """
    return {
        "type": "human_approval_required",
        "approval_request_id": result.approval_request_id,
        "tool_name": tool_name,
        "intent_category": intent.get("category"),
        "intent_objective": intent.get("objective"),
        "reason": result.reason,
    }


def _approval_ref(approval_request_id: str) -> str:
    """One-way, short reference to an approval request id for logs.

    The id itself is a bearer value and must never reach a log line.
    """
    return hashlib.sha256(approval_request_id.encode("utf-8")).hexdigest()[:12]


async def _run_granted(
    handle: RunHandle, tool_name: str, impl: Callable[..., Any], impl_kwargs: Dict[str, Any]
) -> Any:
    """Run an allowed ``impl`` with its one tool start granted (a tool
    started with no ``tool_call_id`` under ``tool_name``) and its body
    marked, so the shared backstop lets that start through and nothing
    else."""
    try:
        with backstop.grant_tool_start(None, tool_name, handle, body="binding"):
            return await _maybe_await(impl, **impl_kwargs)
    finally:
        await publish_tool_gate_refusals(handle)


async def _maybe_await(fn: Callable[..., Any], **kwargs: Any) -> Any:
    """Invoke ``fn``; await if coroutine-shaped, return directly otherwise."""
    out = fn(**kwargs)
    if inspect.isawaitable(out):
        return await out
    # Some sync implementations might return a future-like; respect it.
    if asyncio.iscoroutine(out):
        return await out
    return out
