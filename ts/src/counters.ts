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
//   * only DECISION records — a line with a string `decision` and no `event`
//     field. `sanitization`, `egress` and `attenuation` records never count.
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
// Fail-closed and value-free: a line that is not a well-formed decision record
// is skipped and counted in `skipped` — nothing about it is echoed or logged. A
// missing file is zero counts; a file that exists but cannot be read raises
// `AuditTrailUnreadable`.
//
// Bounded read: the file is streamed in 64 KiB chunks, never loaded whole. At
// most `maxBytes` (default 64 MiB) are scanned, taken from the END of the file
// (the newest records — the ones inside any recent window). When the file is
// larger, `truncated` is `true` and `count` is a lower bound; a fail-closed
// caller treats that as the quota being exceeded, or raises `maxBytes`. A single
// line longer than 1 MiB, or nested deeper than 32 levels, is skipped without
// being buffered or parsed — one oversized line cannot cost more than the cap.

import * as fs from "node:fs";
import { assertPrincipal } from "./principals";

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
  /** Lines that were not a well-formed record and were ignored. Never echoed. */
  skipped: number;
  /** True when the file was larger than `maxBytes` and only its tail was
   *  scanned — `count` is then a lower bound. */
  truncated: boolean;
  /** Where `count` came from: `"local"` (the audit file) or `"external"` (a
   *  configured {@link CounterSource}). On `"external"`, `records` and
   *  `skipped` describe the local scan that did not happen and are `0`. */
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
/** A line longer than this is skipped (and counted in `skipped`) without being
 *  buffered or parsed. Audit records are a few hundred bytes. */
export const MAX_COUNTERS_LINE_BYTES = 1024 * 1024;
/** A line nested deeper than this (objects/arrays) is skipped without being
 *  parsed. Audit records nest two levels at most. */
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
// and is skipped, as in Python) instead of silently swallowing it.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ASCII_WS = /^[ \t\r\n\f\v]+|[ \t\r\n\f\v]+$/g;

type Tally = { count: number; records: number; skipped: number };

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

/** Classify and tally ONE line. Blank lines are ignored entirely. */
function tallyLine(
  bytes: Buffer,
  filter: { principal: string; intent?: string; resource?: string; outcome: CounterOutcome; start: number; end: number },
  t: Tally
): void {
  if (bytes.length > MAX_COUNTERS_LINE_BYTES) {
    t.skipped += 1;
    return;
  }
  let text: string;
  try {
    // ASCII whitespace only (not `trim()`, which also eats a BOM and Unicode
    // spaces) so both language packages classify exactly the same lines.
    text = utf8.decode(bytes).replace(ASCII_WS, "");
  } catch {
    t.skipped += 1;
    return;
  }
  if (text.length === 0) return;
  if (nestedTooDeep(text)) {
    t.skipped += 1;
    return;
  }
  let rec: unknown;
  try {
    rec = JSON.parse(text);
  } catch {
    t.skipped += 1;
    return;
  }
  if (typeof rec !== "object" || rec === null || Array.isArray(rec)) {
    t.skipped += 1;
    return;
  }
  const r = rec as Record<string, unknown>;
  // Records that carry an `event` (sanitization, egress, attenuation) are
  // well-formed but are not decisions.
  if ("event" in r) {
    t.records += 1;
    return;
  }
  const decision = r.decision;
  const ts = parseIsoMillis(r.ts);
  if (typeof decision !== "string" || ts === undefined) {
    t.skipped += 1;
    return;
  }
  t.records += 1;
  if (ts <= filter.start || ts > filter.end) return;
  if (r.principal !== filter.principal) return;
  if (filter.intent !== undefined && r.intent !== filter.intent) return;
  if (filter.resource !== undefined && r.resource !== filter.resource) return;
  const allowed = decision === "Allow";
  if (filter.outcome === "allowed" ? allowed : filter.outcome === "denied" ? !allowed : true) {
    t.count += 1;
  }
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
  const tally: Tally = { count: 0, records: 0, skipped: 0 };
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
    const buf = Buffer.allocUnsafe(CHUNK);
    // Pending bytes of the current (unterminated) line: a list of copies,
    // joined once at the newline. Never more than MAX_COUNTERS_LINE_BYTES are
    // held — past that the line is `oversized`, its bytes are discarded as they
    // arrive, and it is counted once in `skipped` when its newline is found.
    const carry: Buffer[] = [];
    let carryBytes = 0;
    let oversized = false;
    const endLine = (tail: Buffer): void => {
      if (dropPartial) {
        dropPartial = false;
      } else if (oversized || carryBytes + tail.length > MAX_COUNTERS_LINE_BYTES) {
        tally.skipped += 1;
      } else {
        carry.push(tail);
        tallyLine(carry.length === 1 ? carry[0] : Buffer.concat(carry), filter, tally);
      }
      carry.length = 0;
      carryBytes = 0;
      oversized = false;
    };
    for (;;) {
      const n = fs.readSync(fd, buf, 0, CHUNK, pos);
      if (n === 0) break;
      pos += n;
      let from = 0;
      for (;;) {
        const nl = buf.indexOf(NEWLINE, from);
        if (nl === -1 || nl >= n) break;
        endLine(buf.subarray(from, nl));
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
      if (oversized) tally.skipped += 1;
      else if (carry.length > 0) tallyLine(Buffer.concat(carry), filter, tally);
    }
  } catch {
    throw new AuditTrailUnreadable(auditPath);
  } finally {
    fs.closeSync(fd);
  }
  result.count = tally.count;
  result.records = tally.records;
  result.skipped = tally.skipped;
  return result;
}
