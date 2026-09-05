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
import pathlib
import sys
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
    #: — the payload was never released. ``replaced`` is then ``False``.
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


class AuditTrail:
    """The audit trail shared by a governor and every scope derived from it."""

    def __init__(self, path: str | pathlib.Path | None, sink: Optional[AuditSink] = None) -> None:
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
        try:
            result = self._sink(json.loads(line))
            if inspect.isawaitable(result):
                self._schedule(result)
        except Exception as exc:  # noqa: BLE001 — a sink must never break a decision
            self._warn_once(exc)

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
        print(
            f"watchlight: audit sink failed ({kind}); further sink failures "
            "are suppressed — the local audit file is still written",
            file=sys.stderr,
        )
