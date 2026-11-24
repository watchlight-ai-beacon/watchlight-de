"""Kill-signal protocol for the HTTP interceptor lane.

This module is the Python sibling of `kill-signal.ts`. Plugins embed
[`InterceptorKillRegistry`][watchlight_core.kill_signal.InterceptorKillRegistry]
in their HTTP interceptor (the local CONNECT sidecar in
`connect_proxy.py` for the framework plugins; httpx-mounted clients
for direct integrations) so the operator-triggered (or APDP-triggered)
quarantine can interrupt in-flight LLM calls within ~2 seconds.

# Protocol

The protocol matches the TS lane exactly:

1. Interceptor calls
   [`InterceptorKillRegistry.register`][watchlight_core.kill_signal.InterceptorKillRegistry.register]
   when an HTTP request starts. Returns an opaque request id + an
   `asyncio.Event` the interceptor SHOULD await on a side-channel to
   detect the kill (the interceptor's primary mechanism remains the
   normal HTTP-client cancellation primitive — e.g. cancelling the
   `asyncio.Task` running the request).
2. Interceptor calls
   [`InterceptorKillRegistry.complete`][watchlight_core.kill_signal.InterceptorKillRegistry.complete]
   when the request lands (success or upstream error).
3. The plugin's run-handle calls
   [`InterceptorKillRegistry.cancel`][watchlight_core.kill_signal.InterceptorKillRegistry.cancel]
   to interrupt every in-flight request.

# Reporting honesty

This is COOPERATIVE enforcement: the registry aborts requests it was
told about, and the hard-kill escalation is self-directed. It is not a
server-initiated containment channel. Because of that, the one thing
this module owes an auditor is an accurate record of what it did:

- ``disposition`` says what happened to the CALL.
- ``escalation`` says what happened to the escalation ATTEMPT.

``proxy_hard_kill`` is a positive assertion that a socket was torn
down. It is stamped only when the kill endpoint confirms it. Every
other outcome is ``unconfirmed``. See :data:`DISPOSITIONS` and
:data:`ESCALATIONS`.

# Why this lives in `watchlight_core`

Every framework plugin (LangGraph, Pydantic AI, ADK, …) inherits the
same kill-signal plumbing.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from .log import get_logger

logger = get_logger("watchlight_core.kill_signal")

# ─── Constants mirrored from the Rust + TS lanes ───────────────────────

#: Graceful window in milliseconds. Lockstep with the equivalent
#: Rust and TypeScript constants. Bumping requires updating ALL three.
KILL_SIGNAL_GRACEFUL_WINDOW_MS: int = 2000

#: Canonical reason strings — keep in lockstep with the Rust + TS
#: constants. Operators grep on these in SIEM.
LLM_CALL_INTERRUPTED_REASON_QUARANTINE: str = "quarantine"
LLM_CALL_INTERRUPTED_REASON_SCOPE_VIOLATION: str = "scope_violation"
LLM_CALL_INTERRUPTED_REASON_MANUAL_TERMINATE: str = "manual_terminate"
LLM_CALL_INTERRUPTED_REASON_HARD_TIMEOUT: str = "hard_timeout"

#: Reason token for a *policy-driven* Terminate enforcement effect
#: (Halt/contain). This
#: is DISTINCT from ``manual_terminate`` (``LLM_CALL_INTERRUPTED_REASON_MANUAL_TERMINATE``):
#: ``manual_terminate`` is operator-driven (a human closes the run from
#: the dashboard), whereas ``policy_terminate`` is fired when a Cedar
#: policy carrying ``@enforcement_effect("terminate")`` determines the
#: decision. Both end the current run, but keeping them as separate
#: closed-set tokens lets SIEM rules distinguish operator action from
#: automated policy enforcement. Locked in lockstep across the Rust,
#: TS, and Python lanes.
LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE: str = "policy_terminate"

#: Reason token for a *policy-driven, multi-agent* SeverSubtree
#: enforcement effect (Halt/contain). Stamped on the kill signal for
#: EVERY RunHandle in the collapsed sub-agent spawn tree — the root
#: that received the ``SeverSubtree`` decision AND every descendant
#: severed transitively by the depth-first walk. DISTINCT from
#: ``policy_terminate`` (a single-run kill) so SIEM rules can tell a
#: tree-collapse (multi-agent containment) apart from a single-run kill
#: and from operator-driven ``manual_terminate``. Locked in lockstep
#: across the Rust, TS, and Python lanes.
LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE: str = "sever_subtree"

#: Reason token for a *policy-driven* Revoke enforcement effect
#: (Halt/contain) — the terminal, most-severe verb (ordinal 4): the
#: agent's identity TRUST is withdrawn. Stamped on the run-ending kill
#: signal so the in-flight LLM call aborts IMMEDIATELY rather than
#: waiting for the durable ``trust_state=Revoked`` write (owned by the
#: registry service) to propagate. DISTINCT from ``quarantine``
#: (durable, liftable agent bag), ``policy_terminate`` (single-run
#: kill), and ``sever_subtree`` (multi-agent tree collapse): a revoke
#: is TERMINAL for the agent's identity — every subsequent authorize is
#: denied by wl-apdp's pre-Cedar trust gate until an operator
#: re-trusts. Locked in lockstep across the Rust, TS, and Python lanes.
LLM_CALL_INTERRUPTED_REASON_REVOKE: str = "revoke"

#: Disposition strings — closed set. Match the Rust serde
#: discriminator.
#:
#: ``proxy_hard_kill`` is a POSITIVE ASSERTION that wl-proxy tore the
#: upstream socket down. It MUST only be stamped when the kill
#: endpoint CONFIRMED containment. Anything weaker — escalation
#: skipped, transport failure, or the endpoint reporting that nothing
#: was registered — is recorded as ``unconfirmed``: the graceful
#: window elapsed and the call may still be in flight. Emitting
#: ``proxy_hard_kill`` for those cases put a kill that never happened
#: into the evidence trail.
DISPOSITION_GRACEFUL: str = "graceful"
DISPOSITION_PROXY_HARD_KILL: str = "proxy_hard_kill"
DISPOSITION_UNCONFIRMED: str = "unconfirmed"

#: The closed disposition vocabulary. Emitters MUST NOT invent values.
DISPOSITIONS: tuple[str, ...] = (
    DISPOSITION_GRACEFUL,
    DISPOSITION_PROXY_HARD_KILL,
    DISPOSITION_UNCONFIRMED,
)

#: Hard-kill escalation outcome — closed set, carried alongside the
#: disposition so an auditor can tell *why* a kill is unconfirmed
#: without correlating logs.
#:
#: - ``skipped``   — the escalation was never issued: no escalator is
#:   configured, or the request carries no CONNECT session id. Also
#:   used on the ``graceful`` path, where escalation is not reached.
#: - ``attempted`` — the escalation was issued and did not error, but
#:   the endpoint reported no outcome we can classify. Indeterminate.
#: - ``failed``    — the escalation was issued and errored (transport
#:   failure, timeout, or a non-2xx response).
#: - ``unknown``   — the endpoint answered, and answered that it had
#:   nothing registered under that session id. **Nothing was
#:   contained.**
#: - ``confirmed`` — the endpoint confirmed containment (the tunnel was
#:   killed, or was already dead). The ONLY outcome that licenses a
#:   ``proxy_hard_kill`` disposition.
ESCALATION_SKIPPED: str = "skipped"
ESCALATION_ATTEMPTED: str = "attempted"
ESCALATION_FAILED: str = "failed"
ESCALATION_UNKNOWN: str = "unknown"
ESCALATION_CONFIRMED: str = "confirmed"

#: The closed escalation vocabulary. Emitters MUST NOT invent values.
ESCALATIONS: tuple[str, ...] = (
    ESCALATION_SKIPPED,
    ESCALATION_ATTEMPTED,
    ESCALATION_FAILED,
    ESCALATION_UNKNOWN,
    ESCALATION_CONFIRMED,
)

#: Wire strings returned by wl-proxy's ``/internal/v1/connect/kill``
#: endpoint (``KillResult::status_str`` on the Rust side). Kept here so
#: the mapping from proxy answer → escalation token is one documented
#: function rather than scattered string comparisons.
KILL_ENDPOINT_STATUS_KILLED: str = "killed"
KILL_ENDPOINT_STATUS_ALREADY_DEAD: str = "already_dead"
KILL_ENDPOINT_STATUS_UNKNOWN: str = "unknown"


def classify_kill_endpoint_status(status: Optional[str]) -> str:
    """Map a wl-proxy kill-endpoint ``status`` to an escalation token.

    ``killed`` and ``already_dead`` both mean the tunnel is not live —
    containment is a fact, so both are ``confirmed``. ``unknown`` means
    the session id was not in the registry and **nothing was
    contained**. Anything else (including a missing or unparseable
    body) is ``attempted``: we issued the call and cannot prove the
    outcome, which is not the same as proving it worked.
    """
    if status in (KILL_ENDPOINT_STATUS_KILLED, KILL_ENDPOINT_STATUS_ALREADY_DEAD):
        return ESCALATION_CONFIRMED
    if status == KILL_ENDPOINT_STATUS_UNKNOWN:
        return ESCALATION_UNKNOWN
    return ESCALATION_ATTEMPTED

# Payload size caps — mirror the Rust validator.
_METHOD_MAX_LEN = 16
_HOST_MAX_LEN = 253
_PATH_MAX_LEN = 2048
_REASON_MAX_LEN = 64
_BYTES_MAX = 1 << 30
_DURATION_MAX_MS = 60 * 60 * 1000


class LlmCallInterruptedValidationError(ValueError):
    """Raised when an emitted payload would not validate at the Rust side."""


@dataclass(frozen=True)
class LlmCallInterruptedPayload:
    """Mirror of the Rust ``LlmCallInterruptedPayload`` event.

    Frozen so callers can't mutate after validation; the interceptor
    constructs once + emits once per cancelled request.
    """

    method: str
    host: str
    path: str
    bytes_sent: int
    bytes_received: int
    duration_ms: int
    reason: str
    disposition: str
    #: Hard-kill escalation outcome — one of :data:`ESCALATIONS`.
    #: Defaults to ``skipped`` so the field is always populated even
    #: for callers built before it existed; ``skipped`` is the honest
    #: default because "we never escalated" is the truth for any
    #: payload that does not say otherwise.
    escalation: str = ESCALATION_SKIPPED

    def validate(self) -> None:
        """Mirror of `LlmCallInterruptedPayload::validate` in Rust."""
        if not self.method:
            raise LlmCallInterruptedValidationError("method must be non-empty")
        if len(self.method) > _METHOD_MAX_LEN:
            raise LlmCallInterruptedValidationError(
                f"method too long ({len(self.method)})"
            )
        if not self.host:
            raise LlmCallInterruptedValidationError("host must be non-empty")
        if len(self.host) > _HOST_MAX_LEN:
            raise LlmCallInterruptedValidationError(
                f"host too long ({len(self.host)})"
            )
        if "/" in self.host or "://" in self.host:
            raise LlmCallInterruptedValidationError(
                "host must be a bare hostname (no scheme, no path)"
            )
        if not self.path:
            raise LlmCallInterruptedValidationError("path must be non-empty")
        if len(self.path) > _PATH_MAX_LEN:
            raise LlmCallInterruptedValidationError(
                f"path too long ({len(self.path)})"
            )
        if not self.path.startswith("/"):
            raise LlmCallInterruptedValidationError("path must start with '/'")
        if "?" in self.path:
            raise LlmCallInterruptedValidationError(
                "path must not include a query string"
            )
        if not 0 <= self.bytes_sent <= _BYTES_MAX:
            raise LlmCallInterruptedValidationError(
                f"bytes_sent out of range ({self.bytes_sent})"
            )
        if not 0 <= self.bytes_received <= _BYTES_MAX:
            raise LlmCallInterruptedValidationError(
                f"bytes_received out of range ({self.bytes_received})"
            )
        if not 0 <= self.duration_ms <= _DURATION_MAX_MS:
            raise LlmCallInterruptedValidationError(
                f"duration_ms out of range ({self.duration_ms})"
            )
        if not self.reason:
            raise LlmCallInterruptedValidationError("reason must be non-empty")
        if len(self.reason) > _REASON_MAX_LEN:
            raise LlmCallInterruptedValidationError(
                f"reason too long ({len(self.reason)})"
            )
        if self.disposition not in DISPOSITIONS:
            raise LlmCallInterruptedValidationError(
                "disposition must be one of: "
                f"{', '.join(DISPOSITIONS)} (got {self.disposition!r})"
            )
        if self.escalation not in ESCALATIONS:
            raise LlmCallInterruptedValidationError(
                "escalation must be one of: "
                f"{', '.join(ESCALATIONS)} (got {self.escalation!r})"
            )
        # Audit-integrity invariant: `proxy_hard_kill` is a positive
        # claim that containment happened. It is licensed by exactly
        # one escalation outcome and nothing else. Enforcing the
        # biconditional here means no future caller can reintroduce a
        # kill assertion that the escalation never earned.
        if self.disposition == DISPOSITION_PROXY_HARD_KILL:
            if self.escalation != ESCALATION_CONFIRMED:
                raise LlmCallInterruptedValidationError(
                    "disposition 'proxy_hard_kill' requires escalation "
                    f"'confirmed' (got {self.escalation!r}) — a hard kill "
                    "may only be asserted when the kill endpoint confirmed it"
                )
        elif self.escalation == ESCALATION_CONFIRMED:
            raise LlmCallInterruptedValidationError(
                "escalation 'confirmed' requires disposition "
                f"'proxy_hard_kill' (got {self.disposition!r})"
            )
        if (
            self.disposition == DISPOSITION_GRACEFUL
            and self.escalation != ESCALATION_SKIPPED
        ):
            raise LlmCallInterruptedValidationError(
                "disposition 'graceful' requires escalation 'skipped' "
                f"(got {self.escalation!r}) — escalation is only reached "
                "after the graceful window elapses"
            )

    def to_dict(self) -> dict[str, Any]:
        """Wire shape — matches the Rust serde output exactly."""
        return {
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "disposition": self.disposition,
            "escalation": self.escalation,
        }


# Emitter signature.
LlmCallInterruptedEmitter = Callable[[LlmCallInterruptedPayload], None]

# Hard-kill escalator signature — given (session_id, reason), returns
# an awaitable resolving to one of :data:`ESCALATIONS` describing what
# the kill endpoint actually reported. Pluggable so tests can inject a
# stub, and production can use httpx / aiohttp without coupling this
# module to a specific HTTP client.
#
# Raising is how an escalator reports ``failed``. Returning ``None`` is
# accepted for escalators written against the older ``-> None``
# signature and is recorded as ``attempted`` (we issued the call; the
# escalator told us nothing about the outcome) — never as a confirmed
# kill.
HardKillEscalator = Callable[[str, str], Awaitable[Optional[str]]]


@dataclass
class _TrackedRequest:
    """Internal — one in-flight request the registry watches.

    The two events serve distinct purposes:

    - ``cancel_requested`` is set by ``cancel()`` so the interceptor
      can race the upstream request against this event and bail out
      early when the kill switch fires.
    - ``completed_event`` is set by ``complete()`` and tells the
      cancellation watcher that the request ack'd (whether due to
      cancel-driven shutdown or natural completion).

    Splitting them avoids the original conflation where a single event
    couldn't unambiguously signal both "abort please" and "abort
    succeeded."
    """

    id: int
    method: str
    host: str
    path: str
    session_id: Optional[str]
    started_at_ms: int
    bytes_sent: int = 0
    bytes_received: int = 0
    cancel_requested: asyncio.Event = field(default_factory=asyncio.Event)
    completed_event: asyncio.Event = field(default_factory=asyncio.Event)
    fired: bool = False
    completed: bool = False


@dataclass
class KillSignalResult:
    """One request's cancellation outcome."""

    request_id: int
    disposition: str
    #: Hard-kill escalation outcome — one of :data:`ESCALATIONS`.
    escalation: str = ESCALATION_SKIPPED

    @property
    def killed(self) -> bool:
        """True only when a proxy-side hard kill was CONFIRMED.

        Callers that need to know whether containment actually
        happened MUST use this rather than testing the disposition
        string themselves.
        """
        return self.disposition == DISPOSITION_PROXY_HARD_KILL


@dataclass
class RegisterRequestOptions:
    """Metadata an interceptor stamps when registering a request."""

    method: str
    host: str
    path: str
    session_id: Optional[str] = None


class InterceptorKillRegistry:
    """Per-interceptor registry of in-flight LLM calls + the kill switch.

    Thread-safety: Python interceptors run on one asyncio event loop;
    this registry assumes single-threaded asyncio access (the normal
    pattern). Multi-process or thread-pool deployments need their own
    per-thread registry instance.
    """

    def __init__(
        self,
        *,
        graceful_window_ms: int = KILL_SIGNAL_GRACEFUL_WINDOW_MS,
        emit_event: Optional[LlmCallInterruptedEmitter] = None,
        hard_kill_escalator: Optional[HardKillEscalator] = None,
        now_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        self._graceful_window_ms = graceful_window_ms
        self._emit_event = emit_event
        self._hard_kill_escalator = hard_kill_escalator
        self._now_ms = now_ms or (lambda: int(time.monotonic() * 1000))
        self._in_flight: dict[int, _TrackedRequest] = {}
        self._next_id = 1
        self._cancel_in_progress = False
        # One-shot latches for the "containment is not actually
        # available here" warnings. Warned once per registry so a
        # long-running agent doesn't spam, but never silent: an
        # operator must never be able to believe the kill switch works
        # when it cannot.
        self._warned_no_escalator = False
        self._warned_no_interceptor = False

    @property
    def hard_kill_available(self) -> bool:
        """Whether proxy-side hard-kill escalation is configured.

        ``False`` means the ONLY containment this registry can perform
        is in-process cancellation; a request that ignores the abort
        will be recorded ``unconfirmed`` and nothing will have torn its
        socket down.
        """
        return self._hard_kill_escalator is not None

    # ─── Lifecycle methods (called by interceptor code) ──────────────

    def register(self, options: RegisterRequestOptions) -> tuple[int, asyncio.Event]:
        """Register a new in-flight request.

        Returns ``(id, cancel_requested_event)``. The interceptor
        SHOULD race its upstream request future against the
        ``cancel_requested`` event (e.g. via ``asyncio.wait`` with
        ``return_when=FIRST_COMPLETED``) so that when ``cancel()``
        fires, the request breaks out promptly.

        The interceptor MUST also call
        [`record_bytes`][watchlight_core.kill_signal.InterceptorKillRegistry.record_bytes]
        as bytes flow + [`complete`][watchlight_core.kill_signal.InterceptorKillRegistry.complete]
        when the request lands.
        """
        # Strip any query string defensively — never log
        # OAuth-style `?access_token=…` secrets.
        path = options.path.split("?", 1)[0] or "/"
        tracked = _TrackedRequest(
            id=self._next_id,
            method=options.method,
            host=options.host,
            path=path,
            session_id=options.session_id,
            started_at_ms=self._now_ms(),
        )
        self._next_id += 1
        self._in_flight[tracked.id] = tracked
        return tracked.id, tracked.cancel_requested

    def record_bytes(self, request_id: int, bytes_sent: int, bytes_received: int) -> None:
        """Update byte counts on a registered request."""
        tracked = self._in_flight.get(request_id)
        if tracked is None:
            return
        tracked.bytes_sent = bytes_sent
        tracked.bytes_received = bytes_received

    def complete(self, request_id: int) -> None:
        """Mark a request complete. Drops the entry unless cancel is in flight."""
        tracked = self._in_flight.get(request_id)
        if tracked is None:
            return
        tracked.completed = True
        tracked.completed_event.set()
        if not tracked.fired:
            # Normal completion — drop from registry.
            self._in_flight.pop(request_id, None)

    def size(self) -> int:
        """Count live (non-completed) requests."""
        return sum(1 for t in self._in_flight.values() if not t.completed)

    # ─── Kill switch ──────────────────────────────────────────────────

    async def cancel(self, reason: str) -> list[KillSignalResult]:
        """Cancel every in-flight request.

        Each request:
        1. Gets its ``abort_event`` set (the interceptor side responds).
        2. Has up to ``graceful_window_ms`` to ack via ``complete()``.
        3. On miss, escalates via ``hard_kill_escalator`` (when set + the
           request has a ``session_id``).
        4. Emits an ``llm_call_interrupted`` event recording what
           ACTUALLY happened — see :data:`DISPOSITIONS` and
           :data:`ESCALATIONS`.

        Idempotent: a second concurrent ``cancel()`` returns without
        re-firing aborts or double-emitting events.
        """
        if not reason:
            raise ValueError("cancel() requires a non-empty reason")
        if self._cancel_in_progress:
            logger.debug(
                "watchlight: kill-signal cancel() called while another is in flight; no-op"
            )
            return []
        self._cancel_in_progress = True
        try:
            live = [t for t in self._in_flight.values() if not t.completed and not t.fired]
            if not live:
                self._warn_no_interceptor_once()
                return []
            results = await asyncio.gather(
                *(self._cancel_one(t, reason) for t in live),
                return_exceptions=False,
            )
            return list(results)
        finally:
            self._cancel_in_progress = False

    async def _cancel_one(self, tracked: _TrackedRequest, reason: str) -> KillSignalResult:
        if tracked.fired:
            return KillSignalResult(tracked.id, DISPOSITION_GRACEFUL)
        tracked.fired = True

        # Signal the interceptor that a cancel is pending. The
        # interceptor races its upstream request future against this
        # event, so it bails out promptly and then calls
        # `complete()` to ack.
        tracked.cancel_requested.set()

        # Race the graceful window — completed_event is set by the
        # interceptor's `complete()` call.
        disposition, escalation = await self._settle(tracked, reason)
        duration_ms = self._now_ms() - tracked.started_at_ms

        try:
            payload = LlmCallInterruptedPayload(
                method=tracked.method,
                host=tracked.host,
                path=tracked.path,
                bytes_sent=tracked.bytes_sent,
                bytes_received=tracked.bytes_received,
                duration_ms=duration_ms,
                reason=reason,
                disposition=disposition,
                escalation=escalation,
            )
            payload.validate()
            if self._emit_event is not None:
                self._emit_event(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "watchlight: kill-signal event emission failed: %s", type(exc).__name__
            )

        self._in_flight.pop(tracked.id, None)
        return KillSignalResult(tracked.id, disposition, escalation)

    async def _settle(
        self, tracked: _TrackedRequest, reason: str
    ) -> tuple[str, str]:
        """Resolve the honest ``(disposition, escalation)`` for a request.

        The one rule this method exists to enforce: the returned
        disposition is ``proxy_hard_kill`` if and ONLY if the kill
        endpoint confirmed the kill. Every weaker outcome —
        escalation skipped, escalation failed, or the endpoint
        reporting it had nothing registered — resolves to
        ``unconfirmed``, because the in-flight call may still be
        running and the evidence trail must not claim otherwise.
        """
        graceful_window_s = self._graceful_window_ms / 1000.0
        try:
            await asyncio.wait_for(
                tracked.completed_event.wait(), timeout=graceful_window_s
            )
            # The interceptor acked inside the window. Escalation was
            # never reached, so it is honestly `skipped`.
            return DISPOSITION_GRACEFUL, ESCALATION_SKIPPED
        except asyncio.TimeoutError:
            pass

        escalation = await self._escalate(tracked, reason)
        if escalation == ESCALATION_CONFIRMED:
            return DISPOSITION_PROXY_HARD_KILL, ESCALATION_CONFIRMED
        logger.warning(
            "watchlight: in-flight LLM call to %s%s did NOT ack the abort and the "
            "hard kill was not confirmed (escalation=%s) — recording disposition "
            "'%s'; the call may still be running",
            tracked.host,
            tracked.path,
            escalation,
            DISPOSITION_UNCONFIRMED,
        )
        return DISPOSITION_UNCONFIRMED, escalation

    async def _escalate(self, tracked: _TrackedRequest, reason: str) -> str:
        """Issue the hard-kill escalation; report what really happened."""
        if not tracked.session_id or self._hard_kill_escalator is None:
            self._warn_no_escalator_once(tracked)
            return ESCALATION_SKIPPED
        try:
            outcome = await self._hard_kill_escalator(tracked.session_id, reason)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "watchlight: kill-signal hard-kill escalation failed for session %s: %s",
                tracked.session_id,
                exc,
            )
            return ESCALATION_FAILED
        if outcome is None:
            # Legacy `-> None` escalator: the POST returned without
            # raising, but told us nothing. Indeterminate, not success.
            return ESCALATION_ATTEMPTED
        if outcome not in ESCALATIONS:
            logger.warning(
                "watchlight: hard-kill escalator returned an unrecognised outcome "
                "%r; recording '%s' rather than trusting it",
                outcome,
                ESCALATION_ATTEMPTED,
            )
            return ESCALATION_ATTEMPTED
        if outcome == ESCALATION_UNKNOWN:
            logger.warning(
                "watchlight: hard-kill escalation for session %s reported that "
                "NOTHING was registered under that id — no socket was torn down",
                tracked.session_id,
            )
        return outcome

    # ─── Loud degradation notices ────────────────────────────────────

    def _warn_no_escalator_once(self, tracked: _TrackedRequest) -> None:
        if self._warned_no_escalator:
            return
        self._warned_no_escalator = True
        if self._hard_kill_escalator is None:
            why = "no hard_kill_escalator is configured on this registry"
        else:
            why = "the intercepted request carries no CONNECT session id"
        logger.warning(
            "watchlight: proxy-side hard-kill escalation is UNAVAILABLE (%s). "
            "In-flight LLM calls that ignore the in-process abort will NOT be "
            "torn down, and are recorded with disposition '%s'. Wire a "
            "hard_kill_escalator (see httpx_hard_kill_escalator) if you need "
            "proxy-enforced containment.",
            why,
            DISPOSITION_UNCONFIRMED,
        )

    def _warn_no_interceptor_once(self) -> None:
        if self._warned_no_interceptor:
            return
        self._warned_no_interceptor = True
        logger.warning(
            "watchlight: kill signal fired but NO in-flight request is registered "
            "with this registry. If no HTTP interceptor calls register(), "
            "in-flight LLM-call interruption is not active in this process and "
            "cancel() cannot contain anything."
        )


# ─── Pre-built hard-kill escalators ────────────────────────────────────


def httpx_hard_kill_escalator(
    proxy_url: str, internal_token: str, *, timeout_s: float = 5.0
) -> HardKillEscalator:
    """Build a hard-kill escalator that POSTs to wl-proxy via httpx.

    Pulled into the SDK rather than per-plugin so the wire format
    (URL shape, auth header, JSON body) is consistent across every
    framework lane. ``timeout_s`` defaults to 5s so a hung wl-proxy
    can't pin the asyncio event loop forever.

    ``proxy_url`` MUST point at the wl-proxy admin port (default
    ``http://localhost:8078``); ``internal_token`` MUST match
    ``WL_PROXY_INTERNAL_TOKEN``.

    Returns one of :data:`ESCALATIONS`, derived from the endpoint's
    own ``status`` field. A 2xx alone is NOT treated as a kill: the
    endpoint answers ``{"status":"unknown"}`` with a 200 when nothing
    was registered under that session id, and that case is reported as
    ``unknown`` so the lineage record cannot claim containment.
    """
    import httpx

    base = proxy_url.rstrip("/")

    async def escalator(session_id: str, reason: str) -> str:
        url = f"{base}/internal/v1/connect/kill"
        # trust_env=False: the internal token goes straight to wl-proxy's
        # admin port, never through the CONNECT sidecar named by HTTPS_PROXY.
        async with httpx.AsyncClient(timeout=timeout_s, trust_env=False) as client:
            res = await client.post(
                url,
                params={"session_id": session_id},
                headers={"Authorization": f"Bearer {internal_token}"},
                json={"reason": reason},
            )
            if res.status_code >= 400:
                # Raising is the contract for `failed`.
                raise RuntimeError(
                    f"wl-proxy kill endpoint returned {res.status_code}"
                )
            try:
                body = res.json()
            except Exception:  # noqa: BLE001 — unparseable body
                return ESCALATION_ATTEMPTED
            if not isinstance(body, dict):
                return ESCALATION_ATTEMPTED
            status = body.get("status")
            return classify_kill_endpoint_status(
                status if isinstance(status, str) else None
            )

    return escalator


def default_kill_signal_registry(
    *,
    hard_kill_escalator: Optional[HardKillEscalator] = None,
) -> InterceptorKillRegistry:
    """Build the registry every shipped plugin wires by default.

    In-process cancellation costs nothing until an interceptor
    registers a request, and the failure mode of leaving it unwired is
    SILENT non-enforcement — the run-handle's quarantine transition
    returns early and nothing anywhere says the kill switch was a
    no-op. So the shipped default is a live registry.

    Proxy-side escalation stays opt-in: no ``hard_kill_escalator``
    means no network calls and no credentials are needed, so an
    in-process / zero-infrastructure run is unaffected. When a request
    then ignores the abort, the registry says so loudly and records
    the honest ``unconfirmed`` disposition rather than asserting a
    kill it never made.
    """
    return InterceptorKillRegistry(hard_kill_escalator=hard_kill_escalator)
