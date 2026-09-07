"""The value-free audit trail — the ONE funnel every audit record passes through.

All five record kinds end up here — decisions (:meth:`Watchlight.authorize`),
sanitizations (:meth:`Watchlight.sanitize`), screenings (:meth:`Watchlight.screen`),
egress dispositions (a governed tool's ``on_result`` hook) and attenuations
(:meth:`Scope.attenuate`). Their shapes are the ``TypedDict`` classes
below. Two destinations:

1. the local ``.watchlight/audit.jsonl`` file (on by default, best-effort;
   ``audit_file=False`` turns it off and makes the sink the sole destination), and
2. an optional application-supplied ``audit_sink`` callable, which receives
   exactly the fields the file line carries — nothing more.

With BOTH destinations off a record has nowhere to go; the trail says so once
rather than discarding records silently.

The sink is ADDITIVE and FIRE-AND-FORGET: it is called synchronously after the
file append, an awaitable it returns is scheduled on the running event loop (never
awaited inline), and any failure — an exception, a rejected awaitable, or an
awaitable returned with no loop to run it on — is captured and reported once. It
can never block, delay or alter a governance decision, and the file keeps being
written.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import atexit
import pathlib
import queue
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Literal, Optional, TypedDict, Union

__all__ = [
    "AttenuationRecord",
    "AuditRecord",
    "AuditRecordBase",
    "AuditSink",
    "AuditTrail",
    "DecisionRecord",
    "EgressRecord",
    "SanitizationRecord",
    "ScreeningRecord",
    "UnknownAuditRecord",
]

# ── the record kinds ─────────────────────────────────────────────────────────
#
# Five kinds go through this funnel, and a sink sees exactly the fields the
# ``audit.jsonl`` line carries. They are DISCRIMINATED BY ``event``: a decision
# record has no ``event`` key at all; the other four name themselves in it. That
# is not a tidier restatement of the shape — it is the shape, and it is what
# :func:`watchlight.count_audit_records` already keys on to tell a decision from
# the rest.
#
# Each kind is written by exactly one function, and this is the whole list:
#
#   decision      ``Watchlight.authorize`` (and so every governed tool call)
#   sanitization  ``Watchlight.sanitize``
#   screening     ``Watchlight.screen``
#   egress        the ``on_result`` hook of a governed tool
#   attenuation   ``Watchlight.scope`` (the root) and every ``Scope.attenuate``
#
# These mirror the TypeScript lane's ``AuditRecord`` union field for field, and
# the field reference both mirror — one table per kind, checked against a real
# trail — is ``examples/showcase/audit-forensics/README.md``.
#
# TWO LIMITS, so a sink author is not misled about what these buy:
#
#  1. The discriminant is an ABSENT key on a decision record. ``TypedDict``
#     unions narrow on a literal tag, and there is no literal to read when the
#     key is missing, so a type checker will not narrow the decision case for
#     you the way TypeScript's ``event === undefined`` does. Test it at runtime
#     — ``if "event" not in record:`` — and ``cast`` if your checker needs the
#     hint. The runtime test itself is exact.
#  2. The distribution is not marked ``py.typed``. Checkers that read a
#     library's source anyway (pyright's default) resolve these; ones that
#     require the marker (mypy) do not, and see the package as untyped.


class AuditRecordBase(TypedDict):
    """The fields every audit record carries, whatever its kind."""

    #: ISO-8601 UTC timestamp.
    ts: str
    #: The governor's agent identity.
    agent: str
    #: The action, label, or (for an attenuation) the fixed word ``attenuate``.
    intent: str
    #: The resource, label or scope description the record is about.
    resource: str


class _DecisionRequired(AuditRecordBase):
    #: The acting principal, e.g. ``User::"alice"``; defaults to ``Agent::"<agent>"``.
    principal: str
    decision: Literal["Allow", "Deny", "NeedsApproval"]


class DecisionRecord(_DecisionRequired, total=False):
    """A governance decision — written by ``authorize()``, and so by every
    governed tool call. The ONLY kind with no ``event`` key: that absence is the
    discriminant. An approved action is two records — the ``NeedsApproval`` hold,
    then an ``Allow`` carrying ``approved: True`` under a new ``decision_id``. The
    reason is never written; callers see a uniform, non-revealing one."""

    #: The ordered delegation chain, root first. Present ONLY on a record written
    #: through a ``delegate()``d governor, whose chain is longer than one name.
    actor_chain: List[str]
    #: The engine's per-decision correlation id — the join key.
    decision_id: str
    #: Present, and always ``True``, only when a valid approval token downgraded
    #: a ``NeedsApproval``.
    approved: Literal[True]


class _SanitizationRequired(AuditRecordBase):
    event: Literal["sanitization"]
    #: ``tag``, ``mask`` or ``hash``. Unlike ``screen``'s, this one is not
    #: validated, so a caller can put another string here.
    mode: str
    #: Detector version, e.g. ``de-rules-2``.
    detector: str
    #: Redactions per PII type, e.g. ``{"SSN": 1}``.
    counts: Dict[str, int]
    total: int


class SanitizationRecord(_SanitizationRequired, total=False):
    """A PII redaction pass — written by ``sanitize()``. Value-free: counts per
    type and the mode, never the values."""

    actor_chain: List[str]
    #: Present only when the caller passed the read's ``decision_id`` to
    #: ``sanitize`` — that is what joins this record to its decision.
    decision_id: str
    #: Present only when the caller passed ``principal`` to ``sanitize``.
    principal: str


class _ScreeningRequired(AuditRecordBase):
    event: Literal["screening"]
    mode: Literal["report", "redact"]
    #: Detector version, e.g. ``de-screen-1``.
    detector: str
    #: Matches per rule family, e.g. ``{"PROMPT_LEAK": 1}``.
    counts: Dict[str, int]
    total: int
    #: ``total > 0``.
    flagged: bool


class ScreeningRecord(_ScreeningRequired, total=False):
    """A prompt-injection / content screening pass — written by ``screen()``.
    Value-free: counts per rule family, never the text."""

    actor_chain: List[str]
    #: Present only when the caller passed ``decision_id`` to ``screen``.
    decision_id: str
    #: Present only when the caller passed ``principal`` to ``screen``.
    principal: str


class _EgressRequired(AuditRecordBase):
    event: Literal["egress"]
    #: The principal of the call whose result was inspected.
    principal: str
    #: ``True`` when the hook returned a value that replaced the payload.
    replaced: bool


class EgressRecord(_EgressRequired, total=False):
    """The disposition of a governed tool's payload — written after the
    ``on_result`` hook runs. Value-free: the disposition only, never the payload
    or anything derived from it. A denied call has no egress record; the body
    never ran."""

    actor_chain: List[str]
    #: The id of the decision that let the body run. Absent on a framework
    #: adapter call that carries no id of its own.
    decision_id: str
    #: Present, and always ``True``, when the hook raised or outran its deadline
    #: (``on_result_timeout_ms``, 8 s by default, enforced on an async tool body;
    #: ``on_result_timeout_ms`` is refused on a synchronous one, which cannot be
    #: interrupted) — the payload was never released. ``replaced`` is then
    #: ``False``. Which of the two it was is not recorded: the line carries the
    #: disposition of the payload, and the cause reaches the caller as the
    #: exception.
    withheld: Literal[True]


class _AttenuationRequired(AuditRecordBase):
    event: Literal["attenuation"]
    #: Always the fixed word ``attenuate``.
    intent: Literal["attenuate"]
    #: This scope's id. A refused request gets a fresh id that heads no chain.
    node_id: str
    decision: Literal["Allow", "Deny"]
    #: 0 for the root.
    depth: int
    #: The GRANTED tool set (the engine's clamped grant); on a ``Deny``, the
    #: requested set.
    tools: List[str]


class AttenuationRecord(_AttenuationRequired, total=False):
    """One node of a sub-agent scope tree — written by ``scope()`` for the root
    and by every ``attenuate()``, granted or refused. Carries capability NAMES
    only. Unlike the other kinds it has no ``principal`` and no ``actor_chain``."""

    #: Absent on the root.
    parent_id: str
    #: Present on a ``Deny``: the violated dimension, or the depth-ceiling notice.
    reason: str


#: One value-free audit record, as delivered to an :data:`AuditSink` — the same
#: fields the ``.watchlight/audit.jsonl`` line carries, and never argument
#: values, PII, or secrets. A union over the five kinds, discriminated by the
#: ``event`` key (absent on a decision, a literal on every other kind), so a sink
#: reads a kind's fields by name and a rename or a removal is a type error rather
#: than a ``None`` nobody notices. See the two limits noted above.
AuditRecord = Union[
    DecisionRecord,
    SanitizationRecord,
    ScreeningRecord,
    EgressRecord,
    AttenuationRecord,
]

#: The escape hatch: an audit record with nothing said about its fields. A sink
#: annotated with this still satisfies :data:`AuditSink`, so a sink that only
#: forwards records — or one that must survive a kind it does not know about —
#: needs no narrowing. This is the shape a sink was given before the record kinds
#: were typed, and it is unchanged.
UnknownAuditRecord = Dict[str, Any]

#: An application-supplied destination for audit records (``audit_sink=`` on
#: :class:`watchlight.Watchlight`). Called once per record, after the local file
#: append, with its own copy of the record (a plain ``dict`` with exactly the
#: fields the ``audit.jsonl`` line carries). May return an awaitable, which is
#: scheduled fire-and-forget on the running event loop. Failures are reported
#: once per governor and never reach the caller.
#:
#: EITHER form is accepted: a sink that narrows on the record kinds
#: (``def sink(record: AuditRecord) -> None``) or one written against the
#: untyped dict it has always been given (``def sink(record: dict) -> None``).
#: A ``TypedDict`` is not interchangeable with ``Dict[str, Any]`` for a type
#: checker, so both are spelled out here rather than one standing in for the
#: other.
AuditSink = Union[Callable[[AuditRecord], Any], Callable[[UnknownAuditRecord], Any]]


def _error_kind(exc: BaseException) -> str:
    """A safe label for a sink failure: the class name of a *built-in* exception
    (a plain identifier, <= 64 chars), else the literal ``Error``. A user-defined
    class name is sink-controlled text — it could be identifier-shaped and still
    carry record content — so it is never echoed."""
    cls = type(exc)
    name = cls.__name__
    builtin = getattr(cls, "__module__", None) == "builtins"
    return name if builtin and isinstance(name, str) and len(name) <= 64 and name.isidentifier() else "Error"


#: Records held for the background sink worker before the oldest are dropped.
#: A bounded queue is the point: an audit destination that stops responding must
#: not become unbounded memory growth in the application it is auditing.
DEFAULT_SINK_QUEUE_MAX = 10_000
#: Records per call to a batching sink.
DEFAULT_SINK_BATCH = 100
#: Seconds a partial batch waits before it is handed over anyway.
DEFAULT_SINK_INTERVAL = 2.0


async def _await(awaitable: Any) -> None:
    """Await one awaitable — the body of the `asyncio.run` a batching worker
    uses when the sink returns a coroutine."""
    await awaitable


class AuditTrail:
    """The audit trail shared by a governor and every scope derived from it."""

    def __init__(
        self,
        path: str | pathlib.Path | None,
        sink: Optional[AuditSink] = None,
        *,
        sink_batch: Optional[int] = None,
        sink_interval: Optional[float] = None,
        sink_queue_max: int = DEFAULT_SINK_QUEUE_MAX,
    ) -> None:
        #: The local file every record is appended to, or ``None`` when the file
        #: is disabled (``audit_file=False``) and the sink is the sole destination.
        self.path = pathlib.Path(path) if path is not None else None
        self._sink = sink
        self._warned_no_destination = False
        # Sanitized error kinds already reported — one warning per kind, so a
        # "no running loop" condition never silences a later real failure.
        self._warned_kinds: set[str] = set()
        # Strong references to in-flight sink tasks: asyncio holds tasks weakly,
        # and a GC'd task would drop the record silently mid-await.
        self._tasks: set[asyncio.Future[Any]] = set()
        # ── batching (off unless sink_batch or sink_interval is given) ──
        # A durable destination — a database, an object store, a log service —
        # is too slow to call on the request path. With batching configured the
        # record is queued and a background worker hands the sink a LIST.
        self._batching = sink is not None and (sink_batch is not None or sink_interval is not None)
        self._batch_max = max(1, sink_batch if sink_batch is not None else DEFAULT_SINK_BATCH)
        self._batch_interval = (
            sink_interval if sink_interval is not None else DEFAULT_SINK_INTERVAL
        )
        if self._batching and self._batch_interval <= 0:
            raise ValueError("audit_sink_interval must be greater than zero")
        self._queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=max(1, sink_queue_max))
        self._dropped = 0
        self._warned_dropped = False
        self._worker: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        if self._batching:
            self._start_worker()

    @property
    def dropped(self) -> int:
        """Records the batching queue has dropped. Non-zero means the trail has
        holes, and where they are is not recoverable — watch it."""
        return self._dropped

    @property
    def has_sink(self) -> bool:
        """True when an application-supplied sink is attached to this trail."""
        return self._sink is not None

    def write(self, record: dict[str, Any]) -> None:
        """Append ``record`` to the local file, then hand the same fields to the sink."""
        if self.path is None and self._sink is None:
            self._warn_no_destination()
            return
        # The funnel can never raise out of authorize/sanitize/attenuate —
        # including for a record that fails to serialize.
        try:
            line = json.dumps(record)
        except (TypeError, ValueError):
            return
        # 1. The file, first — the sink can never influence what lands on disk.
        #    Skipped entirely when the file is disabled: nothing is created.
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError:
                # Audit is best-effort in dev mode; never let it break the app.
                pass
        # 2. The sink, fire-and-forget. It receives a fresh copy built from the
        #    exact serialized line, so it sees precisely the file's fields and
        #    cannot mutate the caller's record.
        if self._sink is None:
            return
        if self._batching:
            self._enqueue(json.loads(line))
            return
        try:
            result = self._sink(json.loads(line))
            if inspect.isawaitable(result):
                self._schedule(result)
        except Exception as exc:  # noqa: BLE001 — a sink must never break a decision
            self._warn_once(exc)

    # ── batching worker ─────────────────────────────────────────────

    def _start_worker(self) -> None:
        self._worker = threading.Thread(
            target=self._drain_forever, name="watchlight-audit-sink", daemon=True
        )
        self._worker.start()
        # A daemon thread is killed at interpreter exit wherever it happens to
        # be, so the last partial batch would be lost. Flushing here is what
        # makes "records queued" mean "records delivered" for a process that
        # ends normally.
        atexit.register(self.flush)

    def _enqueue(self, record: dict[str, Any]) -> None:
        """Queue a record for the worker. Never raises, never blocks the caller."""
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            # Drop the OLDEST: under sustained pressure the newest records are
            # the ones an operator is looking at. Dropping silently would be an
            # audit gap, so it is counted and reported once.
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                pass
            self._dropped += 1
            self._warn_dropped_once()
            try:
                self._queue.put_nowait(record)
            except queue.Full:
                pass

    def _drain_forever(self) -> None:
        while not self._stopping.is_set():
            batch = self._collect(timeout=self._batch_interval)
            if batch:
                self._deliver(batch)

    def _collect(self, timeout: float) -> list[dict[str, Any]]:
        """Up to ``_batch_max`` records, waiting at most ``timeout`` for the first."""
        batch: list[dict[str, Any]] = []
        try:
            batch.append(self._queue.get(timeout=timeout))
        except queue.Empty:
            return batch
        while len(batch) < self._batch_max:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _deliver(self, batch: list[dict[str, Any]]) -> None:
        """Hand a batch to the sink. A sink that raises must never take the
        worker down with it, or the trail stops for the life of the process."""
        try:
            result = self._sink(batch)  # type: ignore[misc]
            if inspect.isawaitable(result):
                # Off the request path already, and on a thread with no event
                # loop: run it to completion here rather than dropping it.
                asyncio.run(_await(result))
        except Exception as exc:  # noqa: BLE001 — a sink must never break the trail
            self._warn_once(exc)
        finally:
            for _ in batch:
                self._queue.task_done()

    def flush(self, timeout: float = 5.0) -> None:
        """Deliver everything queued, and wait for it. Called at interpreter
        exit, and worth calling yourself before a deliberate shutdown.

        The drain happens HERE, in the caller, rather than inside the worker's
        own shutdown path: a worker that has been told to stop cannot reliably
        finish one more round of work, and a final flush written into its exit
        handler is the kind that looks correct and never runs.
        """
        if not self._batching:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            batch = self._collect(timeout=0.0)
            if not batch:
                break
            self._deliver(batch)

    # ── internals ───────────────────────────────────────────────────

    def _schedule(self, awaitable: Any) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None:
            # Nothing to run it on, and awaiting inline would put the sink on
            # the decision path. Drop it (closing a coroutine avoids the
            # "never awaited" warning) and say so once.
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            self._warn_once(RuntimeError("async audit sink called outside a running event loop"))
            return
        task = asyncio.ensure_future(awaitable, loop=loop)
        self._tasks.add(task)
        task.add_done_callback(self._on_done)

    def _on_done(self, task: "asyncio.Future[Any]") -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self._warn_once(exc)

    def _warn_no_destination(self) -> None:
        # Both destinations are off, so this record has nowhere to go. Said once
        # — a discarded trail is a configuration mistake, never a silent one.
        if self._warned_no_destination:
            return
        self._warned_no_destination = True
        print(
            "watchlight: the audit file is disabled and no audit_sink is configured — "
            "audit records are discarded. Configure `audit_sink`, or leave `audit_file` on.",
            file=sys.stderr,
        )

    def _warn_once(self, exc: BaseException) -> None:
        # Only the error TYPE is reported — never the record, never a message
        # that could carry one. The class name is sink-controlled text, so it is
        # accepted only when it is a plain identifier; anything else logs `Error`.
        kind = _error_kind(exc)
        if kind in self._warned_kinds:
            return
        self._warned_kinds.add(kind)
        tail = (
            " — the local audit file is still written"
            if self.path is not None
            else " — the local audit file is disabled, so these records are lost"
        )
        print(
            f"watchlight: audit sink failed ({kind}); further sink failures "
            f"are suppressed{tail}",
            file=sys.stderr,
        )

    def _warn_dropped_once(self) -> None:
        """Report a full queue once. The count is ours, not the sink's, so
        unlike a sink failure it is safe to print — and it must be printed: a
        dropped record is a hole in the audit trail, and a hole nobody is told
        about is the worst kind."""
        if self._warned_dropped:
            return
        self._warned_dropped = True
        print(
            f"watchlight: the audit sink queue is full — records are being dropped, oldest "
            f"first, because the sink is slower than the rate records are produced. Raise "
            f"audit_sink_batch, or make the sink faster. Further drops are not reported; "
            f"AuditTrail.dropped counts them.",
            file=sys.stderr,
        )
