"""``@watchlight`` decorator — drop-in lineage emission for custom agents.

# Why this exists

The framework plugins (``watchlight-langgraph``, ``watchlight-adk``,
``watchlight-bedrock``) cover the three frameworks we ship adapters
for. Customers writing custom agents — vanilla Python loops, FastAPI
endpoints, Celery tasks, scripts — need a path that's as low-friction
as the framework decorators while still emitting the same canonical
``ExecutionEvent`` shape.

``@watchlight`` is that path. Decorate a function; lineage emission
is automatic. The decorator handles the three root-event types
(``execution_started`` / ``execution_completed`` / ``execution_failed``);
inside the function body the customer can use the ``ApdpClient``
directly for ``tool_call_observed`` / ``api_request_observed``
events when they need them.

# Usage

    from watchlight_core import watchlight, ApdpClient, OtlpConfig, WatchlightOtlpExporter

    client = ApdpClient(base_url="http://localhost:8081")
    otlp = WatchlightOtlpExporter(OtlpConfig.from_env())

    @watchlight(
        agent_id="research-analyst",
        apdp_client=client,
        otlp_exporter=otlp,  # optional
    )
    async def run_research(query: str) -> str:
        # ... agent logic; emit child events as needed via client ...
        return "result"

    result = await run_research("market analysis")

# Two emission destinations

The decorator always emits to **APDP** (the Watchlight lineage stream,
foundation for drift, ABR, audit). If an ``otlp_exporter`` is passed,
the SAME three events are ALSO translated to OpenTelemetry signals
for customer observability. The OTLP path is opt-in; APDP is always-on.

# Failure semantics

If APDP publish fails: the wrapped function still runs; the failure
is logged at debug. We do NOT abort the customer's agent because
lineage emission failed — that would couple their availability to ours.

If the wrapped function raises: ``execution_failed`` is emitted with
the exception class + bounded message; the exception is then
re-raised to the caller. The decorator is a passthrough on the
exception path.

# Sync vs async

Both supported. ``functools.wraps`` is applied so introspection
(``__name__``, ``__doc__``) still works on the wrapped function.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional, TypeVar, Union

from .log import get_logger

logger = get_logger("watchlight_core.decorator")

F = TypeVar("F", bound=Callable[..., Any])


def watchlight(
    *,
    agent_id: str,
    apdp_client: Any,
    otlp_exporter: Optional[Any] = None,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Callable[[F], F]:
    """Wrap a Python function as an instrumented agent execution.

    Emits ``execution_started`` before the function runs,
    ``execution_completed`` on normal return, or ``execution_failed``
    on exception. Each call generates a fresh ``execution_id``.

    Args:
        agent_id: The registered agent identifier the function
            represents. Required — there is no implicit-identity fallback.
        apdp_client: An ``ApdpClient`` (or any object with the
            same ``publish_events`` interface). Required — without
            APDP, there is no lineage.
        otlp_exporter: Optional ``WatchlightOtlpExporter`` for
            also emitting OTel signals to a customer collector.
            ``None`` means no OTLP export (the default).
        session_id: Optional session identifier shared across
            multiple agent executions in the same business flow.
        tenant_id: Optional tenant identifier for multi-tenant
            deployments. Strongly recommended for any customer-
            isolating governance.
        parent_execution_id: Optional parent execution id for
            sub-agent / delegation chains. The runtime uses this
            to build the execution graph.
        metadata: Optional dict attached to every event's
            ``metadata`` field. Use for plugin-source attribution,
            ``authority_class``, etc.

    Returns:
        The wrapped function with identical signature and return type.
        Lineage emission happens before/after the wrapped call;
        the return value is passed through unchanged.

    The decorator detects async vs sync functions via
    :func:`inspect.iscoroutinefunction` and returns the matching
    wrapper. Mixing them (sync function used as awaitable, or
    vice versa) is a customer-side bug we cannot detect here.
    """
    base_metadata: Dict[str, Any] = {"source": "watchlight.decorator"}
    if metadata:
        base_metadata.update(metadata)

    def decorate(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                execution_id = f"exec_{uuid.uuid4()}"
                started_at = time.monotonic()
                await _emit_started(
                    apdp_client=apdp_client,
                    otlp_exporter=otlp_exporter,
                    execution_id=execution_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    tenant_id=tenant_id,
                    parent_execution_id=parent_execution_id,
                    metadata=base_metadata,
                )
                try:
                    result = await func(*args, **kwargs)
                except BaseException as exc:
                    await _emit_failed(
                        apdp_client=apdp_client,
                        otlp_exporter=otlp_exporter,
                        execution_id=execution_id,
                        agent_id=agent_id,
                        session_id=session_id,
                        tenant_id=tenant_id,
                        parent_execution_id=parent_execution_id,
                        metadata=base_metadata,
                        error=exc,
                        duration_ms=int((time.monotonic() - started_at) * 1000),
                    )
                    raise
                else:
                    await _emit_completed(
                        apdp_client=apdp_client,
                        otlp_exporter=otlp_exporter,
                        execution_id=execution_id,
                        agent_id=agent_id,
                        session_id=session_id,
                        tenant_id=tenant_id,
                        parent_execution_id=parent_execution_id,
                        metadata=base_metadata,
                        duration_ms=int((time.monotonic() - started_at) * 1000),
                    )
                    return result

            return async_wrapper  # type: ignore[return-value]

        # Sync function — emission helpers are async so we bridge
        # via asyncio.run (creating a fresh event loop). For sync
        # callers already inside an event loop (notebooks, Streamlit),
        # we schedule the emission as a fire-and-forget task instead.
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            execution_id = f"exec_{uuid.uuid4()}"
            started_at = time.monotonic()
            _emit_sync(
                _emit_started(
                    apdp_client=apdp_client,
                    otlp_exporter=otlp_exporter,
                    execution_id=execution_id,
                    agent_id=agent_id,
                    session_id=session_id,
                    tenant_id=tenant_id,
                    parent_execution_id=parent_execution_id,
                    metadata=base_metadata,
                )
            )
            try:
                result = func(*args, **kwargs)
            except BaseException as exc:
                _emit_sync(
                    _emit_failed(
                        apdp_client=apdp_client,
                        otlp_exporter=otlp_exporter,
                        execution_id=execution_id,
                        agent_id=agent_id,
                        session_id=session_id,
                        tenant_id=tenant_id,
                        parent_execution_id=parent_execution_id,
                        metadata=base_metadata,
                        error=exc,
                        duration_ms=int((time.monotonic() - started_at) * 1000),
                    )
                )
                raise
            else:
                _emit_sync(
                    _emit_completed(
                        apdp_client=apdp_client,
                        otlp_exporter=otlp_exporter,
                        execution_id=execution_id,
                        agent_id=agent_id,
                        session_id=session_id,
                        tenant_id=tenant_id,
                        parent_execution_id=parent_execution_id,
                        metadata=base_metadata,
                        duration_ms=int((time.monotonic() - started_at) * 1000),
                    )
                )
                return result

        return sync_wrapper  # type: ignore[return-value]

    return decorate


# ─── Emission helpers ─────────────────────────────────────────────────


def _build_envelope(
    *,
    event_type: str,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Build the canonical ExecutionEvent envelope shared by all
    three root event types.

    ``event_id`` and ``timestamp`` are REQUIRED by the wire envelope.
    Without them every
    ``POST /v1/events`` call APDP receives fails to deserialize the
    untagged ``IngestExecutionEventsRequest`` enum and returns 422 —
    NATS never sees the event, and downstream consumers
    (wl-execution-graph, wl-drift) starve. Generate them here so the
    decorator path matches the explicit ``_publish_event`` helper
    every plugin already uses.
    """
    import uuid as _uuid
    from datetime import datetime as _dt, timezone as _tz

    event: Dict[str, Any] = {
        "event_id": f"evt_{_uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": _dt.now(_tz.utc).isoformat(),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "metadata": dict(metadata),
    }
    if session_id is not None:
        event["session_id"] = session_id
    if tenant_id is not None:
        event["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        event["parent_execution_id"] = parent_execution_id
    return event


async def _emit_started(
    *,
    apdp_client: Any,
    otlp_exporter: Optional[Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    metadata: Dict[str, Any],
) -> None:
    event = _build_envelope(
        event_type="execution_started",
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        metadata=metadata,
    )
    event["payload"] = {}
    await _emit([event], apdp_client, otlp_exporter)


async def _emit_completed(
    *,
    apdp_client: Any,
    otlp_exporter: Optional[Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    metadata: Dict[str, Any],
    duration_ms: int,
) -> None:
    event = _build_envelope(
        event_type="execution_completed",
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        metadata=metadata,
    )
    event["payload"] = {"duration_ms": duration_ms}
    await _emit([event], apdp_client, otlp_exporter)


async def _emit_failed(
    *,
    apdp_client: Any,
    otlp_exporter: Optional[Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    metadata: Dict[str, Any],
    error: BaseException,
    duration_ms: int,
) -> None:
    # Value-free: an exception message can carry argument values,
    # response bodies or credentials, so only its class is recorded.
    from .events_schema import redacted_error_summary

    bounded = redacted_error_summary(error)
    event = _build_envelope(
        event_type="execution_failed",
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        metadata=metadata,
    )
    event["payload"] = {
        "duration_ms": duration_ms,
        # ``ExecutionFailedPayload`` models the error CATEGORY as
        # ``error_type``; ``error_code`` is not a field on the server
        # struct, so serde dropped it silently.
        "error_type": error.__class__.__name__,
        "error": bounded,
    }
    await _emit([event], apdp_client, otlp_exporter)


async def _emit(
    events: list,
    apdp_client: Any,
    otlp_exporter: Optional[Any],
) -> None:
    """Push events to APDP, and optionally to OTLP. Best-effort."""
    # APDP — always
    try:
        await apdp_client.publish_events(None, events)
    except Exception as exc:  # noqa: BLE001
        logger.debug("watchlight decorator APDP publish failed: %s", type(exc).__name__)

    # OTLP — opt-in
    if otlp_exporter is not None:
        try:
            otlp_exporter.export_events(events)
        except Exception as exc:  # noqa: BLE001
            logger.debug("watchlight decorator OTLP export failed: %s", type(exc).__name__)


def _emit_sync(coro: Awaitable[None]) -> None:
    """Run an awaitable emission helper from a sync context.

    Three scenarios:

    1. No event loop running on this thread → ``asyncio.run`` works
       cleanly. Fresh loop, runs, closed.
    2. Event loop already running (e.g. inside a notebook,
       Streamlit's runner, an outer ``async def``) → ``asyncio.run``
       would raise ``RuntimeError``. We fall back to scheduling
       the coroutine on the running loop as a task and forgetting
       about it. The emission becomes eventually-consistent rather
       than synchronous.
    3. Exception inside emission → swallowed at debug, never
       propagated. Lineage emission must not interrupt the
       customer's agent.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop — safe to run synchronously
        try:
            asyncio.run(coro)
        except Exception as exc:  # noqa: BLE001
            logger.debug("watchlight decorator sync-emit failed: %s", type(exc).__name__)
        return

    # Already inside a running loop — schedule as a task
    try:
        loop.create_task(coro)
    except Exception as exc:  # noqa: BLE001
        logger.debug("watchlight decorator task schedule failed: %s", type(exc).__name__)
