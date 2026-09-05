"""The value-free audit trail — the ONE funnel every audit record passes through.

Decisions (:meth:`Watchlight.authorize`), sanitizations (:meth:`Watchlight.sanitize`)
and attenuations (:meth:`Scope.attenuate`) all end up here. Two destinations:

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
from typing import Any, Callable, Optional

__all__ = ["AuditSink", "AuditTrail"]

#: An application-supplied destination for audit records (``audit_sink=`` on
#: :class:`watchlight.Watchlight`). Called once per record, after the local file
#: append, with its own copy of the record (a plain ``dict`` with exactly the
#: fields the ``audit.jsonl`` line carries). May return an awaitable, which is
#: scheduled fire-and-forget on the running event loop. Failures are reported
#: once per governor and never reach the caller.
AuditSink = Callable[[dict[str, Any]], Any]


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
