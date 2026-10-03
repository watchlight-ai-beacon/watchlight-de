"""Counters over the local audit trail — the input to a quota policy.

Cedar is stateless and ``context`` is entirely application-supplied, so a quota
("100 reads per hour per user") needs a number the caller can put in
``context``. :func:`count_audit_records` folds ``.watchlight/audit.jsonl`` —
every decision the governor has already made — into exactly that number::

    c = govern.counters(principal='User::"u1"', intent="read", window="1h")
    govern.authorize(action="read", principal='User::"u1"',
                     context={"reads_this_hour": c["count"]})

What counts (identical in the TypeScript package):

* only DECISION records — a line with a string ``decision`` whose ``event`` is
  ``"decision"`` or absent (written before 0.13.0). ``sanitization``,
  ``screening``, ``egress`` and ``attenuation`` records never count.
* ``outcome`` selects which decisions: ``"allowed"`` (default) = ``decision ==
  "Allow"``, including approved ones; ``"denied"`` = every decision that did not
  let the body run (``Deny`` and ``NeedsApproval`` holds); ``"all"`` = both. So
  ``allowed + denied == all``.
* ``principal`` (required), ``intent`` and ``resource`` (optional) match the
  record's fields by exact string equality — no prefixes, no globs. A record
  without a ``principal`` matches no principal.
* the window is ``(end - window, end]`` — start exclusive, end inclusive — on
  the record's own ``ts`` (ISO-8601 with a zone), never on file order. ``end``
  defaults to now. Records timestamped after ``end`` do not count.

Fail-closed and value-free: nothing about a line is ever echoed or logged. A
line the scan cannot fully read can never LOWER a count:

* a line that cannot be read at all — longer than ``MAX_COUNTERS_LINE_BYTES``,
  not UTF-8, nested too deeply, not JSON, or not a JSON object — might be any
  record, so it counts toward ``count`` in every query, whatever the principal,
  filters, outcome or window;
* a decision (a string ``decision``, ``event`` absent or ``"decision"``) whose
  ``ts`` cannot be read counts when its principal, intent, resource and outcome
  match, as if it were inside the window;
* a record carrying ``"oversized": true`` — one the audit funnel shortened
  because it was too long (``watchlight._audit.bounded_line``) — counts toward
  every query, like a line that cannot be read, since a field it replaced might
  be the one a query matches on.

All three are counted in ``unreadable`` (so ``count`` minus ``unreadable`` is the
number of well-formed matching decisions) and in ``skipped``. A well-formed
object that is not a decision — no string ``decision``, like a framework run's
lifecycle line — is counted in ``skipped`` only and never counts. Because an
unreadable line counts in every outcome, ``allowed + denied == all`` holds for
well-formed decisions only.

The SDK never writes a line that cannot be read. Every name it records is
bounded (see :mod:`watchlight.principals`), and the largest record its entry
points can produce measures under 400,000 bytes, about 38% of the line limit
(``tests/test_record_bounds.py`` builds it). Behind those checks, the audit
funnel shortens any record over ``MAX_AUDIT_RECORD_BYTES`` (512 KiB) and marks it
``"oversized": true``, so the trail never holds a line over the limit. An
unreadable line therefore means a damaged or foreign trail, and an oversized
record means an entry point let through a name it should have refused. Neither
ages out of a window: until the file is repaired or rotated each costs the quota
one call, which is the fail-closed direction. ``watchlight audit check`` lists
every line that could count this way, by number and reason, with the same reader
(:func:`find_unreadable_lines`).

A missing file is zero counts; a file that exists but cannot be read raises
:class:`AuditTrailUnreadable`.

Bounded read: the file is streamed in 64 KiB chunks, never loaded whole. At most
``max_bytes`` (default 64 MiB) are scanned, taken from the END of the file (the
newest records — the ones inside any recent window). When the file is larger,
``truncated`` is ``True`` and ``count`` is a lower bound; a fail-closed caller
treats that as the quota being exceeded, or raises ``max_bytes``. A single line
longer than 1 MiB, or nested deeper than 32 levels, is counted as unreadable
without being buffered or parsed — one oversized line cannot cost more than the
cap. When the scan starts inside the file, the partial first line it cuts into
is dropped and not counted; ``truncated`` already says the count is partial.
"""

from __future__ import annotations

import calendar
import datetime
import inspect
import json
import os
import pathlib
import re
import time
from typing import Any, Callable, Iterator, Optional, Union

from . import principals

__all__ = [
    "AuditTrailUnreadable",
    "CounterSource",
    "CounterSourceError",
    "MAX_COUNTER_VALUE",
    "count_from_source",
    "count_from_source_async",
    "DEFAULT_COUNTERS_MAX_BYTES",
    "MAX_COUNTERS_LINE_BYTES",
    "MAX_COUNTERS_NESTING",
    "MAX_COUNTERS_WINDOW_SECONDS",
    "count_audit_records",
    "find_unreadable_lines",
    "parse_window_seconds",
    "UNREADABLE_REASONS",
]


class AuditTrailUnreadable(RuntimeError):
    """The audit file exists but could not be read (permissions, a directory,
    an I/O error). A MISSING file is not an error — it yields zero counts."""

    def __init__(self, audit_path: Union[str, os.PathLike]) -> None:
        super().__init__("audit trail is not readable")
        #: The file that could not be read. Kept off the message deliberately.
        self.path = str(audit_path)


#: The read-side counterpart of an ``audit_sink``: given the query dict below,
#: return how many DECISION records match it in your durable store — the same
#: records the sink wrote there. Configured via ``Watchlight(counter_source=...)``.
#:
#: The query is ``{"principal", "outcome", "window": {"seconds", "start",
#: "end"}}`` plus ``"intent"`` / ``"resource"`` WHEN the caller filtered on them
#: — the validated, resolved form of the caller's arguments, key-for-key
#: identical to what the TypeScript lane passes. ``window["start"]`` is exclusive
#: and ``window["end"]`` inclusive, both ISO-8601 UTC, so the source can
#: translate them straight into a range query; ``intent`` / ``resource`` match by
#: exact string equality, like the local scan.
#:
#: Must return a non-negative ``int`` no larger than :data:`MAX_COUNTER_VALUE`,
#: or an awaitable of one (an async source is read with ``counters_async``).
#: Fail-closed: an exception, or anything that is not a count, raises
#: :class:`CounterSourceError` — the read never falls back to the local file,
#: because a silently local count is a quota that under-counts without saying so.
CounterSource = Callable[[dict], Any]


class CounterSourceError(RuntimeError):
    """A configured :data:`CounterSource` could not produce a count. Fail-closed:
    the quota read fails rather than returning a number from somewhere else. The
    message is fixed and value-free; the source's own exception is the
    ``__cause__``."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"counter source failed (fail-closed): {detail}")


DEFAULT_COUNTERS_MAX_BYTES = 64 * 1024 * 1024
#: A line longer than this is not buffered or parsed: it is counted as unreadable
#: (fail-closed, see the module docstring). A typical audit record is a few
#: hundred bytes; the largest the SDK can write is under 400,000.
MAX_COUNTERS_LINE_BYTES = 1024 * 1024
#: A line nested deeper than this (objects/arrays) is counted as unreadable
#: without being parsed. Audit records nest two levels at most.
MAX_COUNTERS_NESTING = 32
#: Longest accepted window, in seconds (366 days).
MAX_COUNTERS_WINDOW_SECONDS = 366 * 86_400

_OUTCOMES = ("allowed", "denied", "all")
_WINDOW_RE = re.compile(r"(\d{1,12})([smhd])?", re.ASCII)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3_600, "d": 86_400}
_WINDOW_HELP = (
    'window must be a positive duration such as "15m", "1h", "24h", "7d", '
    "or a number of seconds (at most 366 days)"
)


def parse_window_seconds(window: Union[str, int]) -> int:
    """Parse a window spec into whole seconds. Raises ``ValueError`` on anything else."""
    if isinstance(window, bool):
        raise ValueError(_WINDOW_HELP)
    if isinstance(window, int):
        seconds = window
    elif isinstance(window, str):
        m = _WINDOW_RE.fullmatch(window)
        if not m:
            raise ValueError(_WINDOW_HELP)
        seconds = int(m.group(1)) * _UNIT_SECONDS[m.group(2) or "s"]
    else:
        raise ValueError(_WINDOW_HELP)
    if seconds <= 0 or seconds > MAX_COUNTERS_WINDOW_SECONDS:
        raise ValueError(_WINDOW_HELP)
    return seconds


# ── timestamps ──────────────────────────────────────────────────────────────
# A strict ISO-8601 subset, parsed with integer arithmetic so both language
# packages accept exactly the same strings and land on the same millisecond:
#   YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)
# The fraction is truncated to milliseconds. Anything else — a missing zone, a
# space separator, a lowercase `z`, an out-of-range field — is rejected.
_TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})",
    re.ASCII,
)


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _parse_iso_millis(value: Any) -> Optional[int]:
    """Epoch milliseconds for a strict ISO-8601 timestamp, or ``None``."""
    if not isinstance(value, str):
        return None
    m = _TS_RE.fullmatch(value)
    if not m:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if year < 1970 or month < 1 or month > 12 or day < 1 or day > _days_in_month(year, month):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    frac = m.group(7)
    millis = int((frac + "00")[:3]) if frac else 0
    zone = m.group(8)
    offset_minutes = 0
    if zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        oh, om = int(zone[1:3]), int(zone[4:6])
        if oh > 23 or om > 59:
            return None
        offset_minutes = sign * (oh * 60 + om)
    base = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    return base * 1000 + millis - offset_minutes * 60_000


_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _format_millis(ms: int) -> str:
    dt = _EPOCH + datetime.timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _resolve_now(now: Union[None, datetime.datetime, str]) -> int:
    if now is None:
        return time.time_ns() // 1_000_000
    if isinstance(now, datetime.datetime):
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must be a timezone-aware datetime")
        return (now - _EPOCH) // datetime.timedelta(milliseconds=1)
    if isinstance(now, str):
        t = _parse_iso_millis(now)
        if t is None:
            raise ValueError("now must be an ISO-8601 timestamp with a zone")
        return t
    raise ValueError("now must be a timezone-aware datetime or an ISO-8601 string")


# ── the scan ────────────────────────────────────────────────────────────────

_CHUNK = 64 * 1024


def _reject_constant(_name: str) -> Any:
    # ``NaN`` / ``Infinity`` are not JSON; the TS side rejects them too.
    raise ValueError("not JSON")


#: The longest integer literal a line may carry, in digits: Python's default
#: ``int`` conversion limit. Checked here rather than left to the interpreter,
#: whose limit an environment variable can change, so both lanes classify
#: exactly the same lines.
MAX_COUNTERS_INT_DIGITS = 4300


def _bounded_int(literal: str) -> int:
    if len(literal.lstrip("-")) > MAX_COUNTERS_INT_DIGITS:
        raise ValueError("not JSON")
    # The counter never reads a number — every field it matches is a string —
    # so the value is not converted.
    return 0


def _nested_too_deep(text: str) -> bool:
    """True when ``text`` nests objects/arrays deeper than ``MAX_COUNTERS_NESTING``.
    A single linear pass that only tracks string boundaries — no parsing."""
    depth = 0
    in_string = False
    escaped = False
    for c in text:
        if in_string:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "{[":
            depth += 1
            if depth > MAX_COUNTERS_NESTING:
                return True
        elif c in "}]":
            depth -= 1
    return False


#: Why a line cannot be read — the reasons :func:`find_unreadable_lines` reports.
#: Value-free: a reason says what is wrong with a line, never what it holds.
UNREADABLE_REASONS = {
    "oversized": f"longer than {MAX_COUNTERS_LINE_BYTES} bytes",
    "not-utf8": "not valid UTF-8",
    "too-deep": f"nested deeper than {MAX_COUNTERS_NESTING} levels",
    "not-json": "not JSON",
    "not-an-object": "not a JSON object",
    "unreadable-ts": "a decision whose ts cannot be read",
    "oversized-record": "a record the SDK shortened because it was too long",
}


def _classify(raw: Optional[bytes]) -> tuple[str, Optional[dict]]:
    """What ONE line is, and its record when it is one. ``raw`` is ``None`` for a
    line the reader already found to be over the line limit. Returns
    ``("blank", None)``, ``(<reason>, None)`` for a line that cannot be read at
    all (a key of :data:`UNREADABLE_REASONS`), or ``("record", rec)``. The ONE
    classification both the counters and ``watchlight audit check`` use."""
    if raw is None or len(raw) > MAX_COUNTERS_LINE_BYTES:
        return "oversized", None
    try:
        text = raw.decode("utf-8").strip(" \t\r\n\f\v")  # ASCII whitespace only, as in TS
    except UnicodeDecodeError:
        return "not-utf8", None
    if not text:
        return "blank", None
    if _nested_too_deep(text):
        return "too-deep", None
    try:
        rec = json.loads(text, parse_constant=_reject_constant, parse_int=_bounded_int)
    except (ValueError, RecursionError):
        return "not-json", None
    if not isinstance(rec, dict):
        return "not-an-object", None
    return "record", rec


def _is_decision(rec: dict) -> bool:
    """A decision record: ``event`` absent or ``"decision"``, and a string
    ``decision``."""
    return rec.get("event", "decision") == "decision" and isinstance(rec.get("decision"), str)


def _iter_lines(fh: Any, drop_partial: bool = False) -> Iterator[Optional[bytes]]:
    """Every line from ``fh``'s current position, without its newline: ``bytes``,
    or ``None`` for a line longer than ``MAX_COUNTERS_LINE_BYTES``. Streamed in
    64 KiB chunks; never more than the line limit is held — past it the line's
    bytes are discarded as they arrive. ``drop_partial`` drops the first line
    unread (the reader started inside it). A final line without a newline is
    yielded too."""
    carry: list[bytes] = []
    carry_bytes = 0
    oversized = False
    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            break
        at = 0
        while True:
            nl = chunk.find(b"\n", at)
            if nl == -1:
                break
            tail = chunk[at:nl]
            if drop_partial:
                drop_partial = False
            elif oversized or carry_bytes + len(tail) > MAX_COUNTERS_LINE_BYTES:
                yield None
            else:
                carry.append(tail)
                yield carry[0] if len(carry) == 1 else b"".join(carry)
            carry = []
            carry_bytes = 0
            oversized = False
            at = nl + 1
        if at < len(chunk) and not drop_partial and not oversized:
            carry_bytes += len(chunk) - at
            if carry_bytes > MAX_COUNTERS_LINE_BYTES:
                oversized = True
                carry = []
                carry_bytes = 0
            else:
                carry.append(chunk[at:])
    if not drop_partial:
        if oversized:
            yield None
        elif carry:
            yield b"".join(carry)


class _Tally:
    __slots__ = ("count", "records", "skipped", "unreadable")

    def __init__(self) -> None:
        self.count = 0
        self.records = 0
        self.skipped = 0
        self.unreadable = 0


def _tally_line(raw: Optional[bytes], f: dict, t: _Tally) -> None:
    """Classify and tally ONE line. Blank lines are ignored entirely."""
    kind, rec = _classify(raw)
    if kind == "blank":
        return
    if rec is None or rec.get("oversized") is True:
        # A line that cannot be read at all might be any record, including a
        # matching Allow: it counts toward every query (fail-closed). So does a
        # record the audit funnel shortened (`"oversized": true`): a field it
        # replaced might have been the one a query matches on.
        t.skipped += 1
        t.unreadable += 1
        t.count += 1
        return
    # Records whose `event` names another kind (sanitization, egress,
    # attenuation) are well-formed but are not decisions. A decision's `event` is
    # "decision"; one written by an earlier release has none.
    if rec.get("event", "decision") != "decision":
        t.records += 1
        return
    # A framework plugin's run lifecycle line (`execution_started`,
    # `execution_completed`) names its kind in `event_type` and carries neither
    # `event` nor `decision`. It is well-formed and not a decision — not a
    # malformed line, so it is not counted as skipped.
    if "event" not in rec and "decision" not in rec and isinstance(rec.get("event_type"), str):
        t.records += 1
        return
    decision = rec.get("decision")
    if not isinstance(decision, str):
        # Not a decision: no verdict to count (a framework run's lifecycle line,
        # say). Never counts.
        t.skipped += 1
        return
    outcome = f["outcome"]
    allowed = decision == "Allow"
    matches = (
        rec.get("principal") == f["principal"]
        and (f["intent"] is None or rec.get("intent") == f["intent"])
        and (f["resource"] is None or rec.get("resource") == f["resource"])
        and ((outcome == "allowed" and allowed) or (outcome == "denied" and not allowed) or outcome == "all")
    )
    ts = _parse_iso_millis(rec.get("ts"))
    if ts is None:
        # A decision whose time cannot be read cannot be shown to be outside the
        # window, so a matching one counts (fail-closed).
        t.skipped += 1
        if matches:
            t.unreadable += 1
            t.count += 1
        return
    t.records += 1
    if matches and f["start"] < ts <= f["end"]:
        t.count += 1


def _prepare_counters(
    principal: str,
    intent: Optional[str] = None,
    resource: Optional[str] = None,
    window: Union[str, int] = "1h",
    *,
    outcome: str = "allowed",
    now: Union[None, datetime.datetime, str] = None,
    max_bytes: int = DEFAULT_COUNTERS_MAX_BYTES,
) -> tuple[dict, dict]:
    """Validate the arguments and resolve the window ONCE — shared by the local
    scan and by a :data:`CounterSource`, so both are asked exactly the same
    question and reject exactly the same inputs. Internal."""
    # The ONE principal rule, so a filter cannot be a shape a decision record
    # could never carry.
    principals.assert_principal(principal)
    if intent is not None and not isinstance(intent, str):
        raise TypeError("intent must be a string")
    if resource is not None and not isinstance(resource, str):
        raise TypeError("resource must be a string")
    # A filter longer than any name a record can carry could never match.
    principals.assert_name_length(intent, "intent")
    principals.assert_name_length(resource, "resource")
    if outcome not in _OUTCOMES:
        raise ValueError('outcome must be "allowed", "denied" or "all"')
    seconds = parse_window_seconds(window)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    end = _resolve_now(now)
    start = end - seconds * 1000
    f = {
        "principal": principal,
        "intent": intent,
        "resource": resource,
        "outcome": outcome,
        "start": start,
        "end": end,
    }
    result: dict[str, Any] = {
        "count": 0,
        "principal": principal,
        "intent": intent,
        "resource": resource,
        "outcome": outcome,
        "window": {"seconds": seconds, "start": _format_millis(start), "end": _format_millis(end)},
        "records": 0,
        "skipped": 0,
        "unreadable": 0,
        "truncated": False,
        "source": "local",
    }
    return f, result


def _query_of(result: dict) -> dict:
    """The query dict a :data:`CounterSource` is handed for these arguments.

    ``intent`` / ``resource`` are OMITTED when the caller did not filter on them
    — never present as ``None`` — so the dict is key-for-key what the TypeScript
    lane passes (and serialises to the same JSON): one shared counting service
    must not have to recognise two shapes. Read them with ``query.get("intent")``.
    """
    query = {
        "principal": result["principal"],
        "outcome": result["outcome"],
        "window": dict(result["window"]),
    }
    for key in ("intent", "resource"):
        if result[key] is not None:
            query[key] = result[key]
    return query


#: Largest count a source may return: the same bound as TypeScript's
#: ``Number.isSafeInteger``, so both lanes accept exactly the same values. A
#: larger integer would survive Python and then fail inside the engine when it
#: reached Cedar ``context``, instead of failing at the source that produced it.
MAX_COUNTER_VALUE = 2**53 - 1


def _counters_from_source_value(count: Any, result: dict) -> dict:
    """Turn a source's return value into a counters dict, or fail closed."""
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        or count > MAX_COUNTER_VALUE
    ):
        raise CounterSourceError("a counter source must return a non-negative integer count")
    result["count"] = count
    return result


def count_from_source(source: CounterSource, /, **kwargs: Any) -> dict:
    """Count via a :data:`CounterSource`, synchronously. The source is validated
    the same way the local scan is, and an awaitable is refused rather than
    resolved behind the caller's back: a synchronous caller cannot silently get
    a stale or local number. An async source belongs on an async path —
    ``counters_async``, awaited inside an ``async def`` ``context`` binding."""
    _f, result = _prepare_counters(**kwargs)
    result["source"] = "external"
    try:
        count = source(_query_of(result))
    except Exception as exc:  # noqa: BLE001 — fail-closed
        raise CounterSourceError("the counter source raised") from exc
    if inspect.isawaitable(count):
        close = getattr(count, "close", None)
        if callable(close):
            close()  # never surfaces as "never awaited": the caller gets an error
        raise CounterSourceError(
            "the counter source is asynchronous — read it with counters_async()"
        )
    return _counters_from_source_value(count, result)


async def count_from_source_async(source: CounterSource, /, **kwargs: Any) -> dict:
    """:func:`count_from_source` for a source that may return an awaitable."""
    _f, result = _prepare_counters(**kwargs)
    result["source"] = "external"
    try:
        count = source(_query_of(result))
        if inspect.isawaitable(count):
            count = await count
    except Exception as exc:  # noqa: BLE001 — fail-closed
        raise CounterSourceError("the counter source raised") from exc
    return _counters_from_source_value(count, result)


def count_audit_records(
    audit_path: Union[str, os.PathLike],
    principal: str,
    intent: Optional[str] = None,
    resource: Optional[str] = None,
    window: Union[str, int] = "1h",
    *,
    outcome: str = "allowed",
    now: Union[None, datetime.datetime, str] = None,
    max_bytes: int = DEFAULT_COUNTERS_MAX_BYTES,
) -> dict:
    """Count decision records in the audit file at ``audit_path``. See the module
    docstring for exactly what counts.

    :param principal: Cedar principal exactly as written on the record, e.g. ``User::"u1"``.
    :param intent: match only decisions with this intent (the Cedar action). Exact.
    :param resource: match only decisions on this resource. Exact.
    :param window: ``"15m"``, ``"1h"``, ``"24h"``, ``"7d"``, a bare number of
        seconds as a string, or an ``int`` of seconds. Positive, at most 366 days.
    :param outcome: ``"allowed"`` (default), ``"denied"`` or ``"all"``.
    :param now: the inclusive end of the window — a timezone-aware ``datetime``
        or an ISO-8601 string with a zone. Default: now. Clocks across the
        processes that wrote the trail are the caller's concern.
    :param max_bytes: scan at most this many bytes from the end of the file.
    :returns: ``{"count", "principal", "intent", "resource", "outcome",
        "window": {"seconds", "start", "end"}, "records", "skipped",
        "unreadable", "truncated", "source"}``. ``count`` includes the
        ``unreadable`` lines (fail-closed; see the module docstring).
    """
    f, result = _prepare_counters(
        principal, intent, resource, window, outcome=outcome, now=now, max_bytes=max_bytes
    )
    path = pathlib.Path(audit_path)
    try:
        fh = path.open("rb")
    except FileNotFoundError:
        return result  # no trail yet → zero
    except OSError:
        raise AuditTrailUnreadable(path) from None
    t = _Tally()
    try:
        with fh:
            size = os.fstat(fh.fileno()).st_size
            pos = 0
            # Only the newest `max_bytes` are scanned. When cutting into the file
            # the first (partial) line is dropped without being counted as skipped.
            drop_partial = False
            if size > max_bytes:
                pos = size - max_bytes
                result["truncated"] = True
                # If the cut lands exactly on a line boundary there is nothing partial.
                fh.seek(pos - 1)
                drop_partial = fh.read(1) != b"\n"
            fh.seek(pos)
            for raw in _iter_lines(fh, drop_partial):
                _tally_line(raw, f, t)
    except OSError:
        raise AuditTrailUnreadable(path) from None
    result["count"] = t.count
    result["records"] = t.records
    result["skipped"] = t.skipped
    result["unreadable"] = t.unreadable
    return result


def find_unreadable_lines(
    audit_path: Union[str, os.PathLike], *, limit: int = 100
) -> dict:
    """Find the lines of an audit file that the counters cannot read — the lines
    that count toward every quota (see the module docstring) — using exactly the
    counters' own reader and classification, so the two never disagree. Behind
    ``watchlight audit check``.

    Value-free: each finding is a 1-based line number and a reason code from
    :data:`UNREADABLE_REASONS`, never the line's content. The whole file is
    streamed; at most ``limit`` findings are returned, and ``total`` counts them
    all. A missing file has no findings; a file that cannot be read raises
    :class:`AuditTrailUnreadable`.

    :returns: ``{"lines": int, "total": int, "findings": [{"line", "reason"}],
        "truncated": bool}`` — ``truncated`` is ``True`` when ``total`` exceeds
        ``limit``.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError("limit must be a non-negative integer")
    path = pathlib.Path(audit_path)
    out: dict[str, Any] = {"lines": 0, "total": 0, "findings": [], "truncated": False}
    try:
        fh = path.open("rb")
    except FileNotFoundError:
        return out
    except OSError:
        raise AuditTrailUnreadable(path) from None
    try:
        with fh:
            for number, raw in enumerate(_iter_lines(fh), start=1):
                out["lines"] = number
                kind, rec = _classify(raw)
                if kind == "blank":
                    continue
                if rec is not None:
                    if rec.get("oversized") is True:
                        kind = "oversized-record"
                    elif not _is_decision(rec) or _parse_iso_millis(rec.get("ts")) is not None:
                        continue
                    else:
                        kind = "unreadable-ts"
                out["total"] += 1
                if len(out["findings"]) < limit:
                    out["findings"].append({"line": number, "reason": kind})
    except OSError:
        raise AuditTrailUnreadable(path) from None
    out["truncated"] = out["total"] > len(out["findings"])
    return out
