"""Execution lineage event emission for the Watchlight execution graph.

Events are batched during an agent execution and flushed to APDP in a
single HTTP call at execution end. APDP publishes them to NATS, keeping
the message bus infrastructure hidden from application code.

# Why the emitter delegates to the translator

The canonical-shape logic lives in :mod:`watchlight_adk.traces` —
:func:`translate_adk_event` is the single source of truth for the
wire contract. The emitter methods here thinly wrap that translator,
which gives three properties for free:

1. **Provenance source tag** — every emitted event carries
   ``metadata.source = "adk.callback"`` so downstream consumers can
   attribute events to this plugin and detect fabrication. The
   cross-plugin conformance test asserts this matches the sibling
   tags ``"langgraph.callback"`` / ``"bedrock.agentTrace"``.
2. **Bounded per-event size** — input summaries truncated at 120
   chars; error messages at 512. Matches the other framework plugins'
   limits so downstream consumers can rely on a uniform cap.
3. **Cross-plugin conformance** — the LangGraph and Bedrock
   translators share the same envelope shape; pinning it in one
   place per framework lets the conformance suite enforce parity
   across all plugins.

# Failure modes

``flush()`` is best-effort: a publish failure is logged at debug
and the batch is cleared so it doesn't accumulate unboundedly on
sustained APDP unavailability. Errors do NOT propagate to the
caller — lineage is observability, not control plane. A failure in
a governance-observability mechanism must degrade gracefully.
"""

from __future__ import annotations

import uuid
from collections import OrderedDict
from typing import Any, List, Optional, TYPE_CHECKING

from watchlight_core import get_logger

from .traces import translate_adk_event

if TYPE_CHECKING:
    from .apdp_client import ApdpClient

logger = get_logger("watchlight_adk")


def _execution_id() -> str:
    """Fresh execution_id matching ``exec_<uuid>`` convention used
    across all Watchlight framework plugins."""
    return f"exec_{uuid.uuid4().hex}"


class LineageEmitter:
    """Batches ADK callback captures and flushes them as canonical
    :class:`ExecutionEvent` dicts to APDP.

    Captures accumulate in memory during an agent execution; the
    plugin calls :meth:`flush` (or :meth:`close`) at execution end
    to publish them via APDP's ``POST /v1/events`` endpoint. APDP
    forwards to NATS for the execution-graph service.

    No direct NATS dependency in the plugin.

    Emitter methods enqueue **captures** (dicts
    keyed by ``hook``), and :meth:`flush` translates them to
    canonical events via :func:`translate_adk_event` at publish
    time. This separation keeps the wire contract under
    :mod:`traces` (testable as pure functions) and the batching
    logic here.
    """

    def __init__(
        self,
        apdp_client: "ApdpClient",
        *,
        otlp_exporter: Optional[Any] = None,
    ):
        self._apdp = apdp_client
        # Optional `WatchlightOtlpExporter`; when present, flush() also
        # routes the translated events through OTLP for customer-facing
        # observability. APDP emission remains the source of truth for
        # Watchlight lineage; OTLP is opt-in customer observability.
        self._otlp = otlp_exporter
        # We store raw capture dicts; translation happens at flush
        # time. Lets unit tests inspect the captured callbacks
        # without going through translation, and lets us decide
        # to drop a capture late if needed.
        self._captures: List[dict] = []
        # Events that never reached wl-apdp: a refused or failed publish,
        # or a capture with no execution/agent id. Lineage publish is
        # non-blocking: a failed publish is logged at WARNING and counted
        # here, and never stops a run; a lost terminal event leaves a run open in
        # lineage and must be visible.
        self.lost_event_count: int = 0

    async def connect(self) -> None:
        """No-op — retained for backward compatibility with code
        that called ``await emitter.connect()`` before this
        module published directly to NATS."""
        pass

    # ── Capture API (used by the plugin's callbacks) ────────────

    async def emit(
        self,
        *,
        hook: str,
        execution_id: str,
        agent_id: str,
        run: Optional[str] = None,
        **fields: Any,
    ) -> None:
        """Enqueue a callback capture. Translation happens later
        on flush.

        The ``hook`` value MUST match one of the strings the
        translator recognizes (see :mod:`traces` for the full
        list). Unknown hooks are buffered but produce no event
        at flush time — logged at debug.

        ``run`` is the run reference the events are published under at
        flush time; the backend authenticates them with that run's own
        ``sst_`` credential (execution-lineage identity binding). It is
        bound per-capture so the buffer can serve nested runs that each
        opened their own session.
        """
        capture = {
            "hook": hook,
            # The translator routes these through every event;
            # binding them at capture time lets the same emitter
            # serve nested executions with different IDs.
            "_execution_id": execution_id,
            "_agent_id": agent_id,
            # The run the flush groups + publishes under.
            "_run": run,
            **fields,
        }
        self._captures.append(capture)
        logger.debug(
            "[lineage] buffered %s agent=%s exec=%s",
            hook,
            agent_id,
            execution_id,
        )

    # ── Typed convenience emitters (used by the plugin's
    #    callbacks; preserved as the public API for backward
    #    compatibility — but they go through emit() now). ────────

    async def emit_execution_started(
        self,
        execution_id: str,
        agent_id: str,
        depth: int = 0,
        *,
        intent_category: Optional[str] = None,
        intent_objective: Optional[str] = None,
        intent_provenance: Optional[str] = None,
        agent_name: Optional[str] = None,
        **envelope: Any,
    ) -> None:
        # ``intent_provenance`` rides through to the translator
        # alongside ``intent_objective``. ``None`` means "infer from the
        # objective" in the translator (declared vs plugin-derived vs
        # absent precedence). Callers that already know the provenance
        # (e.g. the customer passed ``start_run(intent_objective=...)``
        # — the declared path) can pass the explicit string.
        await self.emit(
            hook="before_agent_callback",
            execution_id=execution_id,
            agent_id=agent_id,
            depth=depth,
            intent_category=intent_category,
            intent_objective=intent_objective,
            intent_provenance=intent_provenance,
            agent_name=agent_name,
            **envelope,
        )

    async def emit_execution_completed(
        self,
        execution_id: str,
        agent_id: str,
        duration_ms: int,
        actions_taken: int,
        actions_denied: int = 0,
        *,
        outcome: Optional[str] = None,
        **envelope: Any,
    ) -> None:
        await self.emit(
            hook="after_agent_callback",
            execution_id=execution_id,
            agent_id=agent_id,
            duration_ms=duration_ms,
            actions_taken=actions_taken,
            actions_denied=actions_denied,
            outcome=outcome,
            **envelope,
        )

    async def emit_execution_failed(
        self,
        execution_id: str,
        agent_id: str,
        error: BaseException,
        *,
        hook: str = "on_tool_error_callback",
        **envelope: Any,
    ) -> None:
        """Emit an ExecutionFailed event. `hook` should be either
        `on_tool_error_callback` or `on_model_error_callback` —
        the translator routes both the same way (both are
        ExecutionFailed); the hook value lands in metadata for
        operator forensics."""
        await self.emit(
            hook=hook,
            execution_id=execution_id,
            agent_id=agent_id,
            error=error,
            **envelope,
        )

    async def emit_tool_call(
        self,
        execution_id: str,
        agent_id: str,
        tool_name: str,
        action: str,
        decision: Optional[str],
        *,
        duration_ms: Optional[int] = None,
        arg_key_summary: Optional[str] = None,
        phase: str = "completed",
        outcome: Optional[str] = None,
        **envelope: Any,
    ) -> None:
        """Emit a ToolCallObserved event.

        ``decision`` has no default: it is the decision the call actually
        got (``None`` when unknown), never an assumed Allow.
        ``outcome`` is ``"failed"`` for an allowed call whose tool raised;
        it is carried in ``metadata.outcome``.

        ``phase`` is ``"completed"`` for after_tool_callback (the
        default) or ``"planned"`` for before_tool_callback. The
        translator chooses the right ADK hook based on this.

        ``arg_key_summary`` is the sorted, comma-joined argument KEYS
        (never values) — the behavioural feature Watchlight's drift
        detector consumes for arg-shape scoring. Computed by the caller via
        :func:`watchlight_core.summarize_arg_keys`.
        """
        hook = "after_tool_callback" if phase == "completed" else "before_tool_callback"
        await self.emit(
            hook=hook,
            execution_id=execution_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action_verb=action,
            decision=decision,
            duration_ms=duration_ms,
            arg_key_summary=arg_key_summary,
            outcome=outcome,
            **envelope,
        )

    async def emit_api_request(
        self,
        execution_id: str,
        agent_id: str,
        model: str,
        *,
        prompt_summary: Optional[str] = None,
        **envelope: Any,
    ) -> None:
        """Emit an ApiRequestObserved event for an LLM call. Fired
        from before_model_callback so we capture model choice and
        bounded prompt-summary for drift detection and cost
        attribution downstream."""
        await self.emit(
            hook="before_model_callback",
            execution_id=execution_id,
            agent_id=agent_id,
            model=model,
            prompt_summary=prompt_summary,
            **envelope,
        )

    # NOTE: there is deliberately no ``emit_policy_decision`` here.
    # ``policy_decision_made`` is SERVER-attested only — wl-apdp is
    # the sole decision authority and the class is BLOCKED at ``/v1/events``
    # ingest. A plugin MUST NOT emit policy decisions.

    # ── Publish API (called at execution end) ───────────────────

    def buffered_count(self) -> int:
        """Current number of captures awaiting flush."""
        return len(self._captures)

    def snapshot(self) -> List[dict]:
        """Return a copy of the current capture buffer WITHOUT
        draining. Used by tests."""
        return list(self._captures)

    async def flush(self) -> int:
        """Translate all buffered captures into canonical
        :class:`ExecutionEvent` dicts and publish them to APDP.
        Returns the count of events emitted.

        Execution-lineage identity binding.
        wl-apdp's ``/v1/events`` gate binds every event to the run its
        per-run ``sst_`` credential opened. The buffer can hold captures
        from MULTIPLE runs (a root agent plus nested sub-agents, each of
        which opened its OWN session with its OWN token), so events are
        GROUPED by their bound ``run`` and each group is published under
        that run (the backend attaches the run's own token). Batching
        cross-run events under one run would make the gate refuse
        whichever events don't match.

        Best-effort: a refused or failed publish is logged at WARNING
        with the event types it lost, and counted on
        :attr:`lost_event_count`. The buffer is always cleared, even on
        failure, so it doesn't accumulate unboundedly on sustained APDP
        unavailability.
        """
        if not self._captures:
            return 0

        captures = self._captures
        self._captures = []

        # Preserve emission order within each run group, and the order
        # in which runs first appear, for deterministic (order-stable)
        # publishing.
        grouped: "OrderedDict[Optional[str], List[dict]]" = OrderedDict()
        all_events: List[dict] = []
        for cap in captures:
            # The capture-time helpers stash the per-call execution_id +
            # agent_id + per-run credential under `_execution_id` /
            # `_agent_id` / `_run`. Lift them out into the
            # translator's named args, leaving the rest of the capture
            # fields for the per-hook builder to consume.
            exec_id = cap.pop("_execution_id", None)
            agent_id = cap.pop("_agent_id", None)
            run = cap.pop("_run", None)
            envelope_extras = {
                "session_id": cap.pop("session_id", None),
                "tenant_id": cap.pop("tenant_id", None),
                "parent_execution_id": cap.pop("parent_execution_id", None),
                "root_execution_id": cap.pop("root_execution_id", None),
            }
            if not exec_id or not agent_id:
                self.lost_event_count += 1
                logger.warning(
                    "[lineage] dropping capture %s: no execution_id/agent_id",
                    cap.get("hook"),
                )
                continue
            translated = translate_adk_event(
                capture=cap,
                execution_id=exec_id,
                agent_id=agent_id,
                **envelope_extras,
            )
            if translated is not None:
                grouped.setdefault(run, []).append(translated)
                all_events.append(translated)

        if not all_events:
            return 0

        published = 0
        for run, group in grouped.items():
            try:
                # Each run's events ride that run's own `sst_` credential.
                # ``publish_events`` returns False (it does not raise) on a
                # missing credential, a transport failure or a non-2xx.
                ok = await self._apdp.publish_events(run, group)
            except Exception as exc:  # noqa: BLE001 - best-effort lineage
                ok = False
                logger.warning("lineage publish raised: %s", type(exc).__name__)
            if ok is False:
                self.lost_event_count += len(group)
                logger.warning(
                    "Failed to publish %d lineage event(s) (types: %s); they "
                    "are lost and the run's lineage is incomplete",
                    len(group),
                    ", ".join(sorted({str(e.get("event_type", "?")) for e in group})),
                )
                continue
            published += len(group)
            logger.debug(
                "Flushed %d lineage events to APDP (run-bound=%s)",
                len(group),
                run is not None,
            )

        if published == 0:
            return 0

        # Optional OTLP export. Runs only when an exporter is wired.
        # OTLP failure does not affect the APDP outcome we report back
        # — OTLP is opt-in customer obs, lineage is the always-on
        # source of truth.
        if self._otlp is not None:
            try:
                self._otlp.export_events(all_events)
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "Failed to export %d events to OTLP: %s", len(all_events), exc
                )
        return published

    async def close(self) -> None:
        """Flush remaining captures before shutdown. Same best-
        effort semantics as :meth:`flush`."""
        await self.flush()
