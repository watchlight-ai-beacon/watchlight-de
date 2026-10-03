// Counters over the local audit trail — the input to a quota policy.
//
// Cedar is stateless and `context` is entirely application-supplied, so a
// quota ("100 reads per hour per user") needs a number the caller can put in
// `context`. `countAuditRecords` folds `.watchlight/audit.jsonl` — every
// decision the governor has already made — into exactly that number:
//
//   const c = govern.counters({ principal: 'User::"u1"', intent: "read", window: "1h" });
//   await govern.authorize({ action: "read", principal: 'User::"u1"',
//                            context: { reads_this_hour: c.count } });
//
// What counts (identical in the Python package):
//   * only DECISION records — a line with a string `decision` whose `event` is
//     "decision" or absent (written before 0.13.0). `sanitization`,
//     `screening`, `egress` and `attenuation` records never count.
//   * `outcome` selects which decisions: `allowed` (default) = `decision ==
//     "Allow"`, including approved ones; `denied` = every decision that did not
//     let the body run (`Deny` and `NeedsApproval` holds); `all` = both. So
//     `allowed + denied == all`.
//   * `principal` (required), `intent` and `resource` (optional) match the
//     record's fields by exact string equality — no prefixes, no globs. A
//     record without a `principal` matches no principal.
//   * the window is `(end - window, end]` — start exclusive, end inclusive —
//     on the record's own `ts` (ISO-8601 with a zone), never on file order.
//     `end` defaults to now. Records timestamped after `end` do not count.
//
// Fail-closed and value-free: nothing about a line is ever echoed or logged. A
// line the scan cannot fully read can never LOWER a count:
//   * a line that cannot be read at all — longer than `MAX_COUNTERS_LINE_BYTES`,
//     not UTF-8, nested too deeply, not JSON, or not a JSON object — might be
//     any record, so it counts toward `count` in every query, whatever the
//     principal, filters, outcome or window;
//   * a decision (a string `decision`, `event` absent or "decision") whose `ts`
//     cannot be read counts when its principal, intent, resource and outcome
//     match, as if it were inside the window.
// Both are counted in `unreadable` (so `count - unreadable` is the number of
// well-formed matching decisions) and in `skipped`. A well-formed object that
// is not a decision — no string `decision`, like a framework run's lifecycle
// line — is counted in `skipped` only and never counts. Because an unreadable
// line counts in every outcome, `allowed + denied == all` holds for well-formed
// decisions only.
//
// The SDK never writes such a line. Every name it records is bounded (see
// `principals.ts`), and the largest record it can write measures under 400,000
// bytes in Python and under 270,000 here, at most about 38% of the line limit
// (`ts/test/counters.test.mjs` builds it). One therefore means a damaged or
// foreign trail. It never ages out of a window: until the file is repaired or
// rotated it costs the quota one call per line, which is the fail-closed
// direction. `watchlight audit check` lists such lines by number and reason,
// with the same reader (`findUnreadableLines`).
//
// A missing file is zero counts; a file that exists but cannot be read raises
// `AuditTrailUnreadable`.
//
// Bounded read: the file is streamed in 64 KiB chunks, never loaded whole. At
// most `maxBytes` (default 64 MiB) are scanned, taken from the END of the file
// (the newest records — the ones inside any recent window). When the file is
// larger, `truncated` is `true` and `count` is a lower bound; a fail-closed
// caller treats that as the quota being exceeded, or raises `maxBytes`. A single
// line longer than 1 MiB, or nested deeper than 32 levels, is counted as
// unreadable without being buffered or parsed — one oversized line cannot cost
// more than the cap. When the scan starts inside the file, the partial first
// line it cuts into is dropped and not counted; `truncated` already says the
// count is partial.

import * as fs from "node:fs";
import { assertNameLength, assertPrincipal } from "./principals";

export type CounterOutcome = "allowed" | "denied" | "all";

export interface CountersOptions {
  /** Cedar principal exactly as written on the decision record, e.g. `User::"u1"`. */
  principal: string;
  /** Match only decisions with this intent (the Cedar action). Exact match. */
  intent?: string;
  /** Match only decisions on this resource. Exact match. */
  resource?: string;
  /** How far back to count: `"15m"`, `"1h"`, `"24h"`, `"7d"`, a bare number of
   *  seconds as a string, or a number of seconds. Positive, at most 366 days.
   *  Default `"1h"`. */
  window?: string | number;
  /** Which decisions count. Default `"allowed"`. */
  outcome?: CounterOutcome;
  /** The end of the window (inclusive). A `Date`, epoch milliseconds, or an
   *  ISO-8601 string with a zone. Default: now. Clocks across the processes
   *  that wrote the trail are the caller's concern. */
  now?: Date | number | string;
  /** Scan at most this many bytes from the end of the file. Default 64 MiB. */
  maxBytes?: number;
}

export interface CounterWindow {
  seconds: number;
  /** ISO-8601 UTC, millisecond precision. Exclusive. */
  start: string;
  /** ISO-8601 UTC, millisecond precision. Inclusive. */
  end: string;
}

export interface Counters {
  /** Matching decision records inside the window — put this in `context`. */
  count: number;
  principal: string;
  intent?: string;
  resource?: string;
  outcome: CounterOutcome;
  window: CounterWindow;
  /** Well-formed records read, of every kind (decisions and `event` records). */
  records: number;
  /** Lines that were not a well-formed record. Never echoed. Includes the
   *  `unreadable` ones. */
  skipped: number;
  /** Lines counted in `count` although they could not be read (fail-closed):
   *  every line that cannot be read at all, and every matching decision whose
   *  `ts` cannot be read. `count - unreadable` is the number of well-formed
   *  matching decisions. A non-zero value means a damaged trail. */
  unreadable: number;
  /** True when the file was larger than `maxBytes` and only its tail was
   *  scanned — `count` is then a lower bound. */
  truncated: boolean;
  /** Where `count` came from: `"local"` (the audit file) or `"external"` (a
   *  configured {@link CounterSource}). On `"external"`, `records`, `skipped`
   *  and `unreadable` describe the local scan that did not happen and are `0`. */
  source: CounterSourceKind;
}

/** Which side produced a {@link Counters}. */
export type CounterSourceKind = "local" | "external";

/** The query a {@link CounterSource} is asked to answer — the validated,
 *  resolved form of the caller's {@link CountersOptions}. `window.start` is
 *  exclusive and `window.end` inclusive, both ISO-8601 UTC, so the source can
 *  translate them straight into a range query. `intent` / `resource` are absent
 *  when the caller did not filter on them; when present they match by exact
 *  string equality, like the local scan. */
export interface CounterQuery {
  principal: string;
  intent?: string;
  resource?: string;
  outcome: CounterOutcome;
  window: CounterWindow;
}

/**
 * The read-side counterpart of an `auditSink`: given a {@link CounterQuery},
 * return how many DECISION records match it in your durable store — the same
 * records the sink wrote there. Configured via `WatchlightOptions.counterSource`.
 *
 * Must return a non-negative safe integer, or a promise of one (an async source
 * is read with `countersAsync`). Fail-closed: a throw, a rejection, or anything
 * that is not a count raises {@link CounterSourceError} — the read never falls
 * back to the local file, because a silently local count is a quota that under-
 * counts without saying so.
 */
export type CounterSource = (query: CounterQuery) => number | Promise<number>;

/** A configured {@link CounterSource} could not produce a count. Fail-closed:
 *  the quota read fails rather than returning a number from somewhere else. The
 *  message is fixed and value-free; the source's own error is on `cause`. */
export class CounterSourceError extends Error {
  constructor(detail: string, options?: { cause?: unknown }) {
    super(`counter source failed (fail-closed): ${detail}`);
    this.name = "CounterSourceError";
    if (options && "cause" in options) (this as { cause?: unknown }).cause = options.cause;
  }
}

/** The audit file exists but could not be read (permissions, a directory, an
 *  I/O error). A MISSING file is not an error — it yields zero counts. */
export class AuditTrailUnreadable extends Error {
  /** The file that could not be read. Kept off the message deliberately. */
  readonly path: string;
  constructor(auditPath: string) {
    super("audit trail is not readable");
    this.name = "AuditTrailUnreadable";
    this.path = auditPath;
  }
}

export const DEFAULT_COUNTERS_MAX_BYTES = 64 * 1024 * 1024;
/** A line longer than this is not buffered or parsed: it is counted as
 *  unreadable (fail-closed, see the module header). Audit records are a few
 *  hundred bytes, and names are bounded by `MAX_NAME_BYTES`. */
export const MAX_COUNTERS_LINE_BYTES = 1024 * 1024;
/** A line nested deeper than this (objects/arrays) is counted as unreadable
 *  without being parsed. Audit records nest two levels at most. */
export const MAX_COUNTERS_NESTING = 32;
/** Longest accepted window, in seconds (366 days). */
export const MAX_COUNTERS_WINDOW_SECONDS = 366 * 86_400;

const WINDOW_RE = /^(\d{1,12})([smhd])?$/;
const UNIT_SECONDS: Record<string, number> = { s: 1, m: 60, h: 3_600, d: 86_400 };
const WINDOW_HELP =
  'window must be a positive duration such as "15m", "1h", "24h", "7d", or a number of seconds (at most 366 days)';

/** Parse a window spec into whole seconds. Throws `RangeError` on anything else. */
export function parseWindowSeconds(window: string | number): number {
  let seconds: number;
  if (typeof window === "number") {
    if (!Number.isSafeInteger(window)) throw new RangeError(WINDOW_HELP);
    seconds = window;
  } else if (typeof window === "string") {
    const m = WINDOW_RE.exec(window);
    if (!m) throw new RangeError(WINDOW_HELP);
    seconds = Number(m[1]) * (UNIT_SECONDS[m[2] ?? "s"] as number);
  } else {
    throw new RangeError(WINDOW_HELP);
  }
  if (seconds <= 0 || seconds > MAX_COUNTERS_WINDOW_SECONDS) throw new RangeError(WINDOW_HELP);
  return seconds;
}

// ── timestamps ──────────────────────────────────────────────────────────────
// A strict ISO-8601 subset, parsed with integer arithmetic so both language
// packages accept exactly the same strings and land on the same millisecond:
//   YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)
// The fraction is truncated to milliseconds. Anything else — a missing zone, a
// space separator, a lowercase `z`, an out-of-range field — is rejected.
const TS_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

function daysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/** Epoch milliseconds for a strict ISO-8601 timestamp, or `undefined`. @internal */
export function parseIsoMillis(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const m = TS_RE.exec(value);
  if (!m) return undefined;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return undefined;
  if (hour > 23 || minute > 59 || second > 59) return undefined;
  const millis = m[7] ? Number((m[7] + "00").slice(0, 3)) : 0;
  let offsetMinutes = 0;
  if (m[8] !== "Z") {
    const sign = m[8][0] === "-" ? -1 : 1;
    const oh = Number(m[8].slice(1, 3));
    const om = Number(m[8].slice(4, 6));
    if (oh > 23 || om > 59) return undefined;
    offsetMinutes = sign * (oh * 60 + om);
  }
  return Date.UTC(year, month - 1, day, hour, minute, second, millis) - offsetMinutes * 60_000;
}

function resolveNow(now: CountersOptions["now"]): number {
  if (now === undefined) return Date.now();
  if (now instanceof Date) {
    const t = now.getTime();
    if (!Number.isFinite(t)) throw new RangeError("now must be a valid Date");
    return t;
  }
  if (typeof now === "number") {
    if (!Number.isSafeInteger(now)) throw new RangeError("now must be integer epoch milliseconds");
    return now;
  }
  const t = parseIsoMillis(now);
  if (t === undefined) throw new RangeError("now must be an ISO-8601 timestamp with a zone");
  return t;
}

// ── the scan ────────────────────────────────────────────────────────────────

const CHUNK = 64 * 1024;
const NEWLINE = 0x0a;
// `ignoreBOM` keeps a leading U+FEFF in the text (so the line then fails to parse
// and is counted as unreadable, as in Python) instead of silently swallowing it.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ASCII_WS = /^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g;

type Tally = { count: number; records: number; skipped: number; unreadable: number };

/** The longest integer literal a line may carry, in digits: Python's default
 *  `int` conversion limit, applied here too so both lanes classify exactly the
 *  same lines. */
const MAX_COUNTERS_INT_DIGITS = 4300;

/** True when `text` nests objects/arrays deeper than `MAX_COUNTERS_NESTING`.
 *  A single linear pass that only tracks string boundaries — no parsing. */
function nestedTooDeep(text: string): boolean {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (escaped) escaped = false;
      else if (c === 0x5c) escaped = true; // backslash
      else if (c === 0x22) inString = false; // quote
      continue;
    }
    if (c === 0x22) inString = true;
    else if (c === 0x7b || c === 0x5b) {
      if (++depth > MAX_COUNTERS_NESTING) return true; // { [
    } else if (c === 0x7d || c === 0x5d) depth--; // } ]
  }
  return false;
}

const isDigit = (c: number): boolean => c >= 0x30 && c <= 0x39;

/** True when `text` holds an integer literal (no fraction, no exponent) of more
 *  than `MAX_COUNTERS_INT_DIGITS` digits outside a string — a line Python's
 *  parser refuses. A single linear pass, no parsing. */
function integerTooLong(text: string): boolean {
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (escaped) escaped = false;
      else if (c === 0x5c) escaped = true;
      else if (c === 0x22) inString = false;
      continue;
    }
    if (c === 0x22) {
      inString = true;
      continue;
    }
    if (c !== 0x2d && !isDigit(c)) continue;
    // A number: [-]digits[.digits][(e|E)[+-]digits]. Consume all of it.
    let j = c === 0x2d ? i + 1 : i;
    const start = j;
    while (j < text.length && isDigit(text.charCodeAt(j))) j++;
    const digits = j - start;
    let isFloat = false;
    if (text.charCodeAt(j) === 0x2e) {
      isFloat = true;
      j++;
      while (j < text.length && isDigit(text.charCodeAt(j))) j++;
    }
    if (text.charCodeAt(j) === 0x65 || text.charCodeAt(j) === 0x45) {
      isFloat = true;
      j++;
      if (text.charCodeAt(j) === 0x2b || text.charCodeAt(j) === 0x2d) j++;
      while (j < text.length && isDigit(text.charCodeAt(j))) j++;
    }
    if (!isFloat && digits > MAX_COUNTERS_INT_DIGITS) return true;
    i = Math.max(i, j - 1);
  }
  return false;
}

/** Why a line cannot be read — the reasons {@link findUnreadableLines} reports.
 *  Value-free: a reason says what is wrong with a line, never what it holds. */
export const UNREADABLE_REASONS = {
  oversized: `longer than ${MAX_COUNTERS_LINE_BYTES} bytes`,
  "not-utf8": "not valid UTF-8",
  "too-deep": `nested deeper than ${MAX_COUNTERS_NESTING} levels`,
  "not-json": "not JSON",
  "not-an-object": "not a JSON object",
  "unreadable-ts": "a decision whose ts cannot be read",
} as const;

/** A reason code from {@link UNREADABLE_REASONS}. */
export type UnreadableReason = keyof typeof UNREADABLE_REASONS;

type Classified =
  | { kind: "blank" }
  | { kind: Exclude<UnreadableReason, "unreadable-ts"> }
  | { kind: "record"; rec: Record<string, unknown> };

/** What ONE line is, and its record when it is one. `bytes` is `null` for a
 *  line the reader already found to be over the line limit. The ONE
 *  classification both the counters and `watchlight audit check` use. */
function classify(bytes: Buffer | null): Classified {
  if (bytes === null || bytes.length > MAX_COUNTERS_LINE_BYTES) return { kind: "oversized" };
  let text: string;
  try {
    // ASCII whitespace only (not `trim()`, which also eats a BOM and Unicode
    // spaces) so both language packages classify exactly the same lines.
    text = utf8.decode(bytes).replace(ASCII_WS, "");
  } catch {
    return { kind: "not-utf8" };
  }
  if (text.length === 0) return { kind: "blank" };
  if (nestedTooDeep(text)) return { kind: "too-deep" };
  if (integerTooLong(text)) return { kind: "not-json" };
  let rec: unknown;
  try {
    rec = JSON.parse(text);
  } catch {
    return { kind: "not-json" };
  }
  if (typeof rec !== "object" || rec === null || Array.isArray(rec)) return { kind: "not-an-object" };
  return { kind: "record", rec: rec as Record<string, unknown> };
}

/** A decision record: `event` absent or "decision", and a string `decision`. */
function isDecision(r: Record<string, unknown>): boolean {
  return (!("event" in r) || r.event === "decision") && typeof r.decision === "string";
}

/** Every line from `fd` starting at `pos`, without its newline: a `Buffer`, or
 *  `null` for a line longer than `MAX_COUNTERS_LINE_BYTES`. Streamed in 64 KiB
 *  chunks; never more than the line limit is held — past it the line's bytes
 *  are discarded as they arrive. `dropPartial` drops the first line unread (the
 *  reader started inside it). A final line without a newline is yielded too. */
function* iterLines(fd: number, pos: number, dropPartial: boolean): Generator<Buffer | null> {
  const buf = Buffer.allocUnsafe(CHUNK);
  const carry: Buffer[] = [];
  let carryBytes = 0;
  let oversized = false;
  for (;;) {
    const n = fs.readSync(fd, buf, 0, CHUNK, pos);
    if (n === 0) break;
    pos += n;
    let from = 0;
    for (;;) {
      const nl = buf.indexOf(NEWLINE, from);
      if (nl === -1 || nl >= n) break;
      const tail = buf.subarray(from, nl);
      if (dropPartial) {
        dropPartial = false;
      } else if (oversized || carryBytes + tail.length > MAX_COUNTERS_LINE_BYTES) {
        yield null;
      } else {
        carry.push(tail);
        // Copied when it is the only piece: `buf` is reused on the next read.
        yield carry.length === 1 ? Buffer.from(carry[0]) : Buffer.concat(carry);
      }
      carry.length = 0;
      carryBytes = 0;
      oversized = false;
      from = nl + 1;
    }
    if (from < n && !dropPartial && !oversized) {
      carryBytes += n - from;
      if (carryBytes > MAX_COUNTERS_LINE_BYTES) {
        oversized = true;
        carry.length = 0;
        carryBytes = 0;
      } else {
        carry.push(Buffer.from(buf.subarray(from, n))); // copy: `buf` is reused
      }
    }
  }
  if (!dropPartial) {
    if (oversized) yield null;
    else if (carry.length > 0) yield Buffer.concat(carry);
  }
}

/** Classify and tally ONE line. Blank lines are ignored entirely. */
function tallyLine(bytes: Buffer | null, filter: Filter, t: Tally): void {
  const c = classify(bytes);
  if (c.kind === "blank") return;
  if (c.kind !== "record") {
    // A line that cannot be read at all might be any record, including a
    // matching Allow: it counts toward every query (fail-closed).
    t.skipped += 1;
    t.unreadable += 1;
    t.count += 1;
    return;
  }
  const r = c.rec;
  // Records whose `event` names another kind (sanitization, egress,
  // attenuation) are well-formed but are not decisions. A decision's `event` is
  // "decision"; one written by an earlier release has none.
  if ("event" in r && r.event !== "decision") {
    t.records += 1;
    return;
  }
  // A framework plugin's run lifecycle line (`execution_started`,
  // `execution_completed`) names its kind in `event_type` and carries neither
  // `event` nor `decision`. It is well-formed and not a decision — not a
  // malformed line, so it is not counted as skipped.
  if (!("event" in r) && !("decision" in r) && typeof r.event_type === "string") {
    t.records += 1;
    return;
  }
  const decision = r.decision;
  if (typeof decision !== "string") {
    // Not a decision: no verdict to count (a framework run's lifecycle line,
    // say). Never counts.
    t.skipped += 1;
    return;
  }
  const allowed = decision === "Allow";
  const matches =
    r.principal === filter.principal &&
    (filter.intent === undefined || r.intent === filter.intent) &&
    (filter.resource === undefined || r.resource === filter.resource) &&
    (filter.outcome === "allowed" ? allowed : filter.outcome === "denied" ? !allowed : true);
  const ts = parseIsoMillis(r.ts);
  if (ts === undefined) {
    // A decision whose time cannot be read cannot be shown to be outside the
    // window, so a matching one counts (fail-closed).
    t.skipped += 1;
    if (matches) {
      t.unreadable += 1;
      t.count += 1;
    }
    return;
  }
  t.records += 1;
  if (matches && ts > filter.start && ts <= filter.end) t.count += 1;
}

type Filter = {
  principal: string;
  intent?: string;
  resource?: string;
  outcome: CounterOutcome;
  start: number;
  end: number;
};

/** Validate the options and resolve the window ONCE — shared by the local scan
 *  and by a {@link CounterSource}, so both are asked exactly the same question
 *  and reject exactly the same inputs. @internal */
function prepareCounters(opts: CountersOptions): { filter: Filter; result: Counters; maxBytes: number } {
  // The ONE principal rule, so a filter cannot be a shape a decision record
  // could never carry.
  assertPrincipal(opts?.principal);
  if (opts.intent !== undefined && typeof opts.intent !== "string") throw new TypeError("intent must be a string");
  if (opts.resource !== undefined && typeof opts.resource !== "string") {
    throw new TypeError("resource must be a string");
  }
  // A filter longer than any name a record can carry could never match.
  assertNameLength(opts.intent, "intent");
  assertNameLength(opts.resource, "resource");
  const outcome = opts.outcome ?? "allowed";
  if (outcome !== "allowed" && outcome !== "denied" && outcome !== "all") {
    throw new RangeError('outcome must be "allowed", "denied" or "all"');
  }
  const seconds = parseWindowSeconds(opts.window ?? "1h");
  const maxBytes = opts.maxBytes ?? DEFAULT_COUNTERS_MAX_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new RangeError("maxBytes must be a positive integer");
  const end = resolveNow(opts.now);
  const start = end - seconds * 1000;
  const filter = { principal: opts.principal, intent: opts.intent, resource: opts.resource, outcome, start, end };

  const result: Counters = {
    count: 0,
    principal: opts.principal,
    outcome,
    window: { seconds, start: new Date(start).toISOString(), end: new Date(end).toISOString() },
    records: 0,
    skipped: 0,
    unreadable: 0,
    truncated: false,
    source: "local",
  };
  if (opts.intent !== undefined) result.intent = opts.intent;
  if (opts.resource !== undefined) result.resource = opts.resource;
  return { filter, result, maxBytes };
}

/** The {@link CounterQuery} a source is handed for these options. @internal */
function queryOf(result: Counters): CounterQuery {
  const query: CounterQuery = {
    principal: result.principal,
    outcome: result.outcome,
    window: { ...result.window },
  };
  if (result.intent !== undefined) query.intent = result.intent;
  if (result.resource !== undefined) query.resource = result.resource;
  return query;
}

/** Turn a source's return value into a `Counters`, or fail closed. @internal */
function countersFromSourceValue(count: unknown, result: Counters): Counters {
  if (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0) {
    throw new CounterSourceError("a counter source must return a non-negative integer count");
  }
  result.count = count;
  return result;
}

/**
 * Count via a {@link CounterSource}, synchronously. The source is validated the
 * same way the local scan is, and a promise is refused rather than resolved
 * behind the caller's back: a synchronous caller cannot silently get a stale or
 * local number. An async source belongs on an async path — `countersAsync`,
 * awaited inside an async `context` binding.
 */
export function countFromSource(source: CounterSource, opts: CountersOptions): Counters {
  const { result } = prepareCounters(opts);
  result.source = "external";
  let count: unknown;
  try {
    count = source(queryOf(result));
  } catch (err) {
    throw new CounterSourceError("the counter source threw", { cause: err });
  }
  if (count !== null && typeof count === "object" && typeof (count as Promise<number>).then === "function") {
    // Never leave it unhandled: the caller is getting an error, not this value.
    (count as Promise<number>).then(undefined, () => {});
    throw new CounterSourceError(
      "the counter source is asynchronous — read it with countersAsync()"
    );
  }
  return countersFromSourceValue(count, result);
}

/** {@link countFromSource} for a source that may return a promise. */
export async function countFromSourceAsync(
  source: CounterSource,
  opts: CountersOptions
): Promise<Counters> {
  const { result } = prepareCounters(opts);
  result.source = "external";
  let count: unknown;
  try {
    count = await source(queryOf(result));
  } catch (err) {
    throw new CounterSourceError("the counter source threw", { cause: err });
  }
  return countersFromSourceValue(count, result);
}

/**
 * Count decision records in the audit file at `auditPath`. See the module
 * header for exactly what counts. Synchronous — it is meant to run inside a
 * `context` binding, right before the decision it feeds.
 */
export function countAuditRecords(auditPath: string, opts: CountersOptions): Counters {
  const { filter, result, maxBytes } = prepareCounters(opts);

  let fd: number;
  try {
    fd = fs.openSync(auditPath, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return result; // no trail yet → zero
    throw new AuditTrailUnreadable(auditPath);
  }
  const tally: Tally = { count: 0, records: 0, skipped: 0, unreadable: 0 };
  try {
    const size = fs.fstatSync(fd).size;
    let pos = 0;
    // Only the newest `maxBytes` are scanned. When cutting into the file the
    // first (partial) line is dropped without being counted as skipped.
    let dropPartial = false;
    if (size > maxBytes) {
      pos = size - maxBytes;
      result.truncated = true;
      // If the cut lands exactly on a line boundary there is nothing partial.
      const one = Buffer.alloc(1);
      dropPartial = !(fs.readSync(fd, one, 0, 1, pos - 1) === 1 && one[0] === NEWLINE);
    }
    for (const line of iterLines(fd, pos, dropPartial)) tallyLine(line, filter, tally);
  } catch {
    throw new AuditTrailUnreadable(auditPath);
  } finally {
    fs.closeSync(fd);
  }
  result.count = tally.count;
  result.records = tally.records;
  result.skipped = tally.skipped;
  result.unreadable = tally.unreadable;
  return result;
}

/** What {@link findUnreadableLines} found. */
export interface UnreadableLines {
  /** Lines in the file. */
  lines: number;
  /** Unreadable lines found, all of them. */
  total: number;
  /** The first `limit` of them: a 1-based line number and a reason code. */
  findings: { line: number; reason: UnreadableReason }[];
  /** True when `total` exceeds the number listed. */
  truncated: boolean;
}

/**
 * Find the lines of an audit file that the counters cannot read — the lines
 * that count toward quotas (see the module header) — using exactly the
 * counters' own reader and classification, so the two never disagree. Behind
 * `watchlight audit check`. Value-free: each finding is a line number and a
 * reason code from {@link UNREADABLE_REASONS}, never the line's content. The
 * whole file is streamed; at most `limit` findings are listed. A missing file
 * has none; a file that cannot be read throws {@link AuditTrailUnreadable}.
 */
export function findUnreadableLines(auditPath: string, opts: { limit?: number } = {}): UnreadableLines {
  const limit = opts.limit ?? 100;
  if (!Number.isSafeInteger(limit) || limit < 0) throw new RangeError("limit must be a non-negative integer");
  const out: UnreadableLines = { lines: 0, total: 0, findings: [], truncated: false };
  let fd: number;
  try {
    fd = fs.openSync(auditPath, "r");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return out;
    throw new AuditTrailUnreadable(auditPath);
  }
  try {
    let number = 0;
    for (const line of iterLines(fd, 0, false)) {
      number += 1;
      out.lines = number;
      const c = classify(line);
      if (c.kind === "blank") continue;
      let reason: UnreadableReason;
      if (c.kind === "record") {
        if (!isDecision(c.rec) || parseIsoMillis(c.rec.ts) !== undefined) continue;
        reason = "unreadable-ts";
      } else {
        reason = c.kind;
      }
      out.total += 1;
      if (out.findings.length < limit) out.findings.push({ line: number, reason });
    }
  } catch {
    throw new AuditTrailUnreadable(auditPath);
  } finally {
    fs.closeSync(fd);
  }
  out.truncated = out.total > out.findings.length;
  return out;
}
