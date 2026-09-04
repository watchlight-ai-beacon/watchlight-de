"""The value-free audit trail — the ONE funnel every audit record passes through.

Decisions (:meth:`Watchlight.authorize`), sanitizations (:meth:`Watchlight.sanitize`)
and attenuations (:meth:`Scope.attenuate`) all end up here. Two destinations:

1. the local ``.watchlight/audit.jsonl`` file (always on, best-effort), and
2. an optional application-supplied ``audit_sink`` callable, which receives
   exactly the fields the file line carries — nothing more.

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


class AuditTrail:
    """The audit trail shared by a governor and every scope derived from it."""

    def __init__(self, path: str | pathlib.Path, sink: Optional[AuditSink] = None) -> None:
        self.path = pathlib.Path(path)
        self._sink = sink
        self._sink_warned = False

    def write(self, record: dict[str, Any]) -> None:
        """Append ``record`` to the local file, then hand the same fields to the sink."""
        line = json.dumps(record)
        # 1. The file, first — the sink can never influence what lands on disk.
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
        task.add_done_callback(self._on_done)

    def _on_done(self, task: "asyncio.Future[Any]") -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self._warn_once(exc)

    def _warn_once(self, exc: BaseException) -> None:
        if self._sink_warned:
            return
        self._sink_warned = True
        # Only the error TYPE is reported — never the record, never a message
        # that could carry one. The trail is value-free; keep the log that way.
        print(
            f"watchlight: audit sink failed ({type(exc).__name__}); further sink failures "
            "are suppressed — the local audit file is still written",
            file=sys.stderr,
        )
