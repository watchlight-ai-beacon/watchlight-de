"""Bounded retry and per-run delivery lanes for lineage and run-end reporting.

wl-apdp answers ``503 Service Unavailable`` (with ``Retry-After``) when a
replica cannot yet know a run's state (startup replay, store
unavailable), and ``429 Too Many Requests`` when a run-end budget is
spent. A gateway in front of it answers ``502`` / ``504`` while a
replica restarts. All are transient. Dropping a lineage batch on them
loses audit evidence, so the reporting calls
(:meth:`ApdpClient.publish_events`, :meth:`ApdpClient.complete_session`)
retry them here, within a bounded budget.

What is retried, and what is not:

* Retried: ``429``, ``502``, ``503``, ``504`` and transport errors
  (connect failures, timeouts, a dropped connection). ``Retry-After`` is
  honoured, capped. A retried batch is idempotent: every event carries
  its ``event_id``, which the event plane deduplicates (``Nats-Msg-Id``
  within the JetStream duplicate window, ``ON CONFLICT (event_id)`` in
  the consumers beyond it).
* Never retried: any other status. A ``4xx`` other than ``429`` is the
  server's authoritative refusal (a ``403`` stays a ``403``). A ``500``
  is a server fault that the same request reproduces, not a "try
  later", so it is final too. A ``2xx`` is delivered.
* Never retried or delayed: the governance decision path. ``authorize``
  does not go through this module, and lineage emitted on the decision
  path never waits (see :func:`lineage_decision_path`). The
  ``execution_started`` mint in front of ``authorize`` is one direct
  attempt that bypasses the lane, and authorize fails closed unless it
  was accepted (see :func:`lineage_direct_attempt`).

Bounds (both clamped, both overridable by environment):

* ``WATCHLIGHT_LINEAGE_RETRY_MAX_ATTEMPTS`` — total attempts including
  the first, default 6, clamped to ``[1, 20]``.
* ``WATCHLIGHT_LINEAGE_RETRY_MAX_WAIT_SECONDS`` — hard wall-clock budget
  for one delivery, request time included (each attempt's timeout is cut
  to what is left), default 30, clamped to ``[0, 300]``.

Ordering: each run (keyed by its run credential) has a delivery lane.
Awaited publishes for a run go out one at a time, in call order, and a
retried batch keeps its place. A decision-path publish never waits for
the lane: if the lane is busy it is queued behind the lane's work and
delivered in the background, so it can land after a batch that was
being retried when it was emitted; the lineage view orders events by
their ``timestamp``. After a run's batch exhausts its budget the lane is
*degraded*: later publishes for that run get one attempt and are then
queued for background delivery, until a delivery succeeds.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import math
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, Iterator, List, Optional

import httpx

from .log import get_logger

logger = get_logger("watchlight_core.apdp_client")

#: Statuses that mean "not yet, try again".
RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})

#: Events a run may hold queued for background delivery; beyond it new
#: events are refused (counted, logged once per run), never unbounded.
MAX_PENDING_EVENTS_PER_RUN = 1000
#: Idle degraded lanes kept to remember a run's degraded state.
MAX_IDLE_LANES = 1024

ENV_MAX_ATTEMPTS = "WATCHLIGHT_LINEAGE_RETRY_MAX_ATTEMPTS"
ENV_MAX_WAIT_SECONDS = "WATCHLIGHT_LINEAGE_RETRY_MAX_WAIT_SECONDS"

DEFAULT_MAX_ATTEMPTS = 6
DEFAULT_MAX_WAIT_SECONDS = 30.0
_MAX_ATTEMPTS_BOUNDS = (1, 20)
_MAX_WAIT_BOUNDS = (0.0, 300.0)

#: First backoff step and the cap on any single wait (backoff or
#: ``Retry-After``). A server asking for longer is still bounded by this.
BASE_DELAY_SECONDS = 0.25
MAX_SINGLE_DELAY_SECONDS = 10.0

# Set (via :func:`lineage_decision_path`) around a publish made on the
# governance decision path.
_decision_path: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_lineage_decision_path", default=False
)


@contextlib.contextmanager
def lineage_decision_path() -> Iterator[None]:
    """Mark publishes in this context as made on the decision path.

    Such a publish never waits: it gets one attempt when the run's lane
    is free, and is otherwise (lane busy, or a transient answer) queued
    for background delivery with the full retry budget; it returns
    ``True`` once delivered or queued. A context variable rather than a
    keyword so third-party backends with the published ``publish_events``
    signature keep working.
    """
    token = _decision_path.set(True)
    try:
        yield
    finally:
        _decision_path.reset(token)


def on_decision_path() -> bool:
    return _decision_path.get()


# Set (via :func:`lineage_direct_attempt`) around the ``execution_started``
# mint in front of ``authorize``.
_direct_attempt: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_lineage_direct_attempt", default=False
)


@contextlib.contextmanager
def lineage_direct_attempt() -> Iterator[None]:
    """Make publishes in this context one direct attempt.

    Used for the ``execution_started`` mint in front of ``authorize``,
    which must be accepted before the decision may proceed (wl-apdp does
    not check that ``execution_started`` exists, and wl-execution-graph
    drops an action whose execution was never started). The attempt
    bypasses the run's lane, so it never waits behind a retry, and is not
    retried inline. A transient failure also queues the batch for
    background delivery (harmless: the event plane deduplicates on
    ``event_id``), but the publish still returns ``False`` so the caller
    fails closed.
    """
    token = _direct_attempt.set(True)
    try:
        yield
    finally:
        _direct_attempt.reset(token)


def direct_attempt_in_context() -> bool:
    return _direct_attempt.get()


def _clamp(value: float, bounds: tuple) -> float:
    lo, hi = bounds
    return max(lo, min(hi, value))


@dataclass(frozen=True)
class LineageRetryPolicy:
    """Bounds for retrying lineage / run-end reporting."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    max_wait_seconds: float = DEFAULT_MAX_WAIT_SECONDS

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "max_attempts",
            int(_clamp(int(self.max_attempts), _MAX_ATTEMPTS_BOUNDS)),
        )
        wait = float(self.max_wait_seconds)
        if not math.isfinite(wait):
            wait = DEFAULT_MAX_WAIT_SECONDS
        object.__setattr__(self, "max_wait_seconds", _clamp(wait, _MAX_WAIT_BOUNDS))

    @classmethod
    def from_env(cls) -> "LineageRetryPolicy":
        """Read the two bounds from the environment; an unparsable value
        falls back to the default (logged once, value-free)."""
        attempts = DEFAULT_MAX_ATTEMPTS
        wait = DEFAULT_MAX_WAIT_SECONDS
        raw = os.environ.get(ENV_MAX_ATTEMPTS)
        if raw is not None and raw.strip():
            try:
                attempts = int(raw.strip())
            except ValueError:
                logger.warning(
                    "%s is not an integer; using the default (%d)",
                    ENV_MAX_ATTEMPTS,
                    DEFAULT_MAX_ATTEMPTS,
                )
        raw = os.environ.get(ENV_MAX_WAIT_SECONDS)
        if raw is not None and raw.strip():
            try:
                wait = float(raw.strip())
            except ValueError:
                logger.warning(
                    "%s is not a number; using the default (%s)",
                    ENV_MAX_WAIT_SECONDS,
                    DEFAULT_MAX_WAIT_SECONDS,
                )
        return cls(max_attempts=attempts, max_wait_seconds=wait)


def parse_retry_after(value: Optional[str], now: Optional[datetime] = None) -> Optional[float]:
    """``Retry-After`` as seconds (delta-seconds or HTTP-date), or ``None``."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        seconds = float(value)
        if math.isfinite(seconds) and seconds >= 0:
            return seconds
        return None
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0.0, (when - now).total_seconds())


@dataclass
class SendOutcome:
    """Result of :func:`send_with_retry`.

    ``response`` is the last response (``None`` when the last attempt
    failed in transport, ``error`` then names the exception class).
    ``exhausted`` is True when the last result was still transient.
    ``ambiguous_earlier`` is True when an earlier attempt failed in
    transport, so the server may have processed it. ``retry_delay`` is
    the wait (seconds) before a further attempt would be due — the
    capped ``Retry-After`` or the next backoff step; 0 when not
    transient.
    """

    response: Optional[httpx.Response]
    error: Optional[str]
    attempts: int
    exhausted: bool
    ambiguous_earlier: bool
    retry_delay: float = 0.0

    @property
    def last_result(self) -> str:
        """Value-free description of the last result, for logs."""
        if self.response is not None:
            return str(self.response.status_code)
        return self.error or "transport_error"


class RetryRunner:
    """Runs one request with the policy. Clock, sleep and jitter are
    attributes so tests can drive them without real waits."""

    def __init__(self, policy: LineageRetryPolicy) -> None:
        self.policy = policy
        self.sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
        self.clock: Callable[[], float] = time.monotonic
        self.random: Callable[[], float] = random.random

    def _backoff(self, retry_index: int) -> float:
        # Full jitter on an exponential step.
        ceiling = min(MAX_SINGLE_DELAY_SECONDS, BASE_DELAY_SECONDS * (2**retry_index))
        return ceiling * self.random()

    async def send(
        self,
        op: str,
        send: Callable[[float], Awaitable[httpx.Response]],
        *,
        client_timeout: float,
        single_attempt: bool = False,
        on_retry: Optional[Callable[[], None]] = None,
    ) -> SendOutcome:
        """Run ``send(timeout)`` until a non-transient result or the budget
        runs out. Each attempt's timeout is the client timeout cut to the
        time left in the budget, so the budget is a hard bound."""
        max_attempts = 1 if single_attempt else self.policy.max_attempts
        budget = self.policy.max_wait_seconds
        deadline = self.clock() + budget
        attempts = 0
        ambiguous = False
        while True:
            attempts += 1
            response: Optional[httpx.Response] = None
            error: Optional[str] = None
            timeout = client_timeout
            if budget > 0:
                timeout = max(0.001, min(client_timeout, deadline - self.clock()))
            try:
                response = await send(timeout)
            except httpx.TransportError as exc:
                error = type(exc).__name__
            transient = error is not None or (
                response is not None and response.status_code in RETRYABLE_STATUSES
            )
            if not transient:
                return SendOutcome(response, error, attempts, False, ambiguous)
            delay = self._backoff(attempts - 1)
            if response is not None:
                hinted = parse_retry_after(response.headers.get("retry-after"))
                if hinted is not None:
                    # Honour the server's hint, plus a little jitter so a
                    # fleet of clients does not return in lockstep.
                    delay = hinted + BASE_DELAY_SECONDS * self.random()
            delay = min(delay, MAX_SINGLE_DELAY_SECONDS)
            remaining = deadline - self.clock()
            if attempts >= max_attempts or remaining <= 0:
                return SendOutcome(response, error, attempts, True, ambiguous, delay)
            delay = min(delay, remaining)
            if error is not None:
                ambiguous = True
            logger.debug(
                "%s: transient result %s on attempt %d; retrying in %.2fs",
                op,
                error or (response.status_code if response is not None else "?"),
                attempts,
                delay,
            )
            if on_retry is not None:
                on_retry()
            await self.sleep(delay)


class RunLane:
    """Delivery state for one run's reporting.

    ``lock`` serialises the run's sends. ``users`` counts awaited
    publishes holding or waiting for it. ``pending`` holds batches queued
    for background delivery, drained in order by one ``worker`` task.
    ``degraded`` is set when a delivery exhausted its budget and cleared
    by the next delivery that succeeds.
    """

    __slots__ = (
        "lock",
        "users",
        "pending",
        "pending_count",
        "worker",
        "degraded",
        "overflow_logged",
        "token",
    )

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.users = 0
        self.pending: Deque[List[Dict[str, Any]]] = deque()
        self.pending_count = 0
        self.worker: Optional["asyncio.Task[None]"] = None
        self.degraded = False
        self.overflow_logged = False
        # The run credential the queued batches are sent under.
        self.token: Optional[str] = None

    def worker_active(self) -> bool:
        return self.worker is not None and not self.worker.done()

    def busy(self) -> bool:
        return self.users > 0 or bool(self.pending) or self.worker_active() or self.lock.locked()

    def idle(self) -> bool:
        return not self.busy()
