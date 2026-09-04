"""Counters over the local audit trail — the input to a quota policy.

Cedar is stateless and ``context`` is entirely application-supplied, so a quota
("100 reads per hour per user") needs a number the caller can put in
``context``. :func:`count_audit_records` folds ``.watchlight/audit.jsonl`` —
every decision the governor has already made — into exactly that number::

    c = govern.counters(principal='User::"u1"', intent="read", window="1h")
    govern.authorize(action="read", principal='User::"u1"',
                     context={"reads_this_hour": c["count"]})

What counts (identical in the TypeScript package):

* only DECISION records — a line with a string ``decision`` and no ``event``
  field. ``sanitization``, ``egress`` and ``attenuation`` records never count.
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

Fail-closed and value-free: a line that is not a well-formed decision record is
skipped and counted in ``skipped`` — nothing about it is echoed or logged. A
missing file is zero counts; a file that exists but cannot be read raises
:class:`AuditTrailUnreadable`.

Bounded read: the file is streamed in 64 KiB chunks, never loaded whole. At most
``max_bytes`` (default 64 MiB) are scanned, taken from the END of the file (the
newest records — the ones inside any recent window). When the file is larger,
``truncated`` is ``True`` and ``count`` is a lower bound; a fail-closed caller
treats that as the quota being exceeded, or raises ``max_bytes``. A single line
longer than 1 MiB, or nested deeper than 32 levels, is skipped without being
buffered or parsed — one oversized line cannot cost more than the cap.
"""

from __future__ import annotations

import calendar
import datetime
import json
import os
import pathlib
import re
import time
from typing import Any, Optional, Union

__all__ = [
    "AuditTrailUnreadable",
    "DEFAULT_COUNTERS_MAX_BYTES",
    "MAX_COUNTERS_LINE_BYTES",
    "MAX_COUNTERS_NESTING",
    "MAX_COUNTERS_WINDOW_SECONDS",
    "count_audit_records",
    "parse_window_seconds",
]


class AuditTrailUnreadable(RuntimeError):
    """The audit file exists but could not be read (permissions, a directory,
    an I/O error). A MISSING file is not an error — it yields zero counts."""

    def __init__(self, audit_path: Union[str, os.PathLike]) -> None:
        super().__init__("audit trail is not readable")
        #: The file that could not be read. Kept off the message deliberately.
        self.path = str(audit_path)


DEFAULT_COUNTERS_MAX_BYTES = 64 * 1024 * 1024
#: A line longer than this is skipped (and counted in ``skipped``) without being
#: buffered or parsed. Audit records are a few hundred bytes.
MAX_COUNTERS_LINE_BYTES = 1024 * 1024
#: A line nested deeper than this (objects/arrays) is skipped without being
#: parsed. Audit records nest two levels at most.
MAX_COUNTERS_NESTING = 32
#: Longest accepted window, in seconds (366 days).
MAX_COUNTERS_WINDOW_SECONDS = 366 * 86_400

_OUTCOMES = ("allowed", "denied", "all")
_WINDOW_RE = re.compile(r"^(\d{1,12})([smhd])?$")
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
        m = _WINDOW_RE.match(window)
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
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$"
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
    m = _TS_RE.match(value)
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


class _Tally:
    __slots__ = ("count", "records", "skipped")

    def __init__(self) -> None:
        self.count = 0
        self.records = 0
        self.skipped = 0


def _tally_line(raw: bytes, f: dict, t: _Tally) -> None:
    """Classify and tally ONE line. Blank lines are ignored entirely."""
    if len(raw) > MAX_COUNTERS_LINE_BYTES:
        t.skipped += 1
        return
    try:
        text = raw.decode("utf-8").strip(" \t\r\n\f\v")  # ASCII whitespace only, as in TS
    except UnicodeDecodeError:
        t.skipped += 1
        return
    if not text:
        return
    if _nested_too_deep(text):
        t.skipped += 1
        return
    try:
        rec = json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        t.skipped += 1
        return
    if not isinstance(rec, dict):
        t.skipped += 1
        return
    # Records that carry an `event` (sanitization, egress, attenuation) are
    # well-formed but are not decisions.
    if "event" in rec:
        t.records += 1
        return
    decision = rec.get("decision")
    ts = _parse_iso_millis(rec.get("ts"))
    if not isinstance(decision, str) or ts is None:
        t.skipped += 1
        return
    t.records += 1
    if ts <= f["start"] or ts > f["end"]:
        return
    if rec.get("principal") != f["principal"]:
        return
    if f["intent"] is not None and rec.get("intent") != f["intent"]:
        return
    if f["resource"] is not None and rec.get("resource") != f["resource"]:
        return
    allowed = decision == "Allow"
    outcome = f["outcome"]
    if (outcome == "allowed" and allowed) or (outcome == "denied" and not allowed) or outcome == "all":
        t.count += 1


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
        "window": {"seconds", "start", "end"}, "records", "skipped", "truncated"}``.
    """
    if not isinstance(principal, str) or not principal:
        raise TypeError("principal must be a non-empty string")
    if intent is not None and not isinstance(intent, str):
        raise TypeError("intent must be a string")
    if resource is not None and not isinstance(resource, str):
        raise TypeError("resource must be a string")
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
        "truncated": False,
    }
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
            # Pending bytes of the current (unterminated) line: a list of
            # chunks, joined once at the newline. Never more than
            # MAX_COUNTERS_LINE_BYTES are held — past that the line is
            # `oversized`, its bytes are discarded as they arrive, and it is
            # counted once in `skipped` when its newline is found.
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
                        t.skipped += 1
                    else:
                        carry.append(tail)
                        _tally_line(carry[0] if len(carry) == 1 else b"".join(carry), f, t)
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
                    t.skipped += 1
                elif carry:
                    _tally_line(b"".join(carry), f, t)
    except OSError:
        raise AuditTrailUnreadable(path) from None
    result["count"] = t.count
    result["records"] = t.records
    result["skipped"] = t.skipped
    return result
