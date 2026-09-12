// The value-free audit trail — the ONE funnel every audit record passes through.
//
// All five record kinds end up here — decisions (`Watchlight.authorize`),
// sanitizations (`Watchlight.sanitize`), screenings (`Watchlight.screen`),
// egress dispositions (a governed tool's `onResult` hook) and attenuations
// (`Scope.attenuate`). Their shapes are the discriminated union below. Two
// destinations:
//
//   1. the local `.watchlight/audit.jsonl` file (on by default, best-effort;
//      `auditFile: false` turns it off and makes the sink the sole
//      destination), and
//   2. an optional application-supplied `auditSink` callback, which receives
//      exactly the fields the file line carries — nothing more.
//
// With BOTH destinations off a record has nowhere to go; the trail says so once
// rather than discarding records silently.
//
// The sink is ADDITIVE and FIRE-AND-FORGET: it is invoked synchronously after the
// file append, its return value is never awaited, and any failure (a throw or a
// rejected promise) is captured and reported once — it can never block, delay
// or alter a governance decision, and the file keeps being written.

import * as fs from "node:fs";
import * as path from "node:path";
import type { PiiType, RedactMode } from "./sanitize";
import type { ScreenFamily, ScreenMode } from "./screen";

// ── the record kinds ──────────────────────────────────────────────────
//
// Five kinds go through this funnel, and a sink sees exactly the fields the
// `audit.jsonl` line carries. They are DISCRIMINATED BY `event`: a decision
// record has no `event` field at all; the other four name themselves in it.
// That is not a tidier restatement of the shape — it is the shape, and it is
// what `countAuditRecords` already keys on to tell a decision from the rest.
//
// Each kind is written by exactly one function, and this is the whole list:
//
//   decision      `Watchlight.authorize` (and so every governed tool call)
//   sanitization  `Watchlight.sanitize`
//   screening     `Watchlight.screen`
//   egress        the `onResult` hook of a governed tool
//   attenuation   `Watchlight.scope` (the root) and every `Scope.attenuate`
//
// The field reference these types mirror — one table per kind, checked against
// a real trail — is `examples/showcase/audit-forensics/README.md`.

/** The fields every audit record carries, whatever its kind. */
export type AuditRecordBase = {
  /** ISO-8601 UTC timestamp. */
  readonly ts: string;
  /** The governor's agent identity. */
  readonly agent: string;
  /** The action, label or (for an attenuation) the fixed word `attenuate`. */
  readonly intent: string;
  /** The resource, label or scope description the record is about. */
  readonly resource: string;
};

/** The ordered delegation chain, root first — present ONLY on a record written
 *  through a `delegate()`d governor, whose chain is longer than one name. A
 *  call outside any delegation carries no `actor_chain` at all. Never written
 *  on an `attenuation` record. */
type ActorChain = { readonly actor_chain?: readonly string[] };

/** A governance decision — written by `authorize()`, and so by every governed
 *  tool call. The ONLY kind with no `event` field: that absence is the
 *  discriminant. An approved action is two records — the `NeedsApproval` hold,
 *  then an `Allow` carrying `approved: true` under a new `decision_id`. The
 *  reason is never written; callers see a uniform, non-revealing one. */
export type DecisionRecord = AuditRecordBase &
  ActorChain & {
    /** Absent on a decision record. Present, and a literal, on every other kind. */
    readonly event?: undefined;
    /** The acting principal, e.g. `User::"alice"`; defaults to `Agent::"<agent>"`. */
    readonly principal: string;
    readonly decision: "Allow" | "Deny" | "NeedsApproval";
    /** The engine's per-decision correlation id — the join key. */
    readonly decision_id?: string;
    /** Present only when a valid approval token downgraded a `NeedsApproval`. */
    readonly approved?: true;
  };

/** A PII redaction pass — written by `sanitize()`. Value-free: counts per type
 *  and the mode, never the values. */
export type SanitizationRecord = AuditRecordBase &
  ActorChain & {
    readonly event: "sanitization";
    readonly mode: RedactMode;
    /** Detector version, e.g. `de-rules-2`. */
    readonly detector: string;
    /** Redactions per PII type, e.g. `{ SSN: 1 }`. */
    readonly counts: Readonly<Partial<Record<PiiType, number>>>;
    readonly total: number;
    /** Present only when the caller passed the read's `decisionId` to
     *  `sanitize` — that is what joins this record to its decision. */
    readonly decision_id?: string;
    /** Present only when the caller passed `principal` to `sanitize`. */
    readonly principal?: string;
  };

/** A prompt-injection / content screening pass — written by `screen()`.
 *  Value-free: counts per rule family, never the text. */
export type ScreeningRecord = AuditRecordBase &
  ActorChain & {
    readonly event: "screening";
    readonly mode: ScreenMode;
    /** Detector version, e.g. `de-screen-1`. */
    readonly detector: string;
    /** Matches per rule family, e.g. `{ PROMPT_LEAK: 1 }`. */
    readonly counts: Readonly<Partial<Record<ScreenFamily, number>>>;
    readonly total: number;
    /** `total > 0`. */
    readonly flagged: boolean;
    /** Present only when the caller passed `decisionId` to `screen`. */
    readonly decision_id?: string;
    /** Present only when the caller passed `principal` to `screen`. */
    readonly principal?: string;
  };

/** The disposition of a governed tool's payload — written after the `onResult`
 *  hook runs. Value-free: the disposition only, never the payload or anything
 *  derived from it. A denied call has no `egress` record; the body never ran. */
export type EgressRecord = AuditRecordBase &
  ActorChain & {
    readonly event: "egress";
    /** The principal of the call whose result was inspected. */
    readonly principal: string;
    /** `true` when the hook returned a value that replaced the payload. */
    readonly replaced: boolean;
    /** The id of the decision that let the body run. Absent on a framework
     *  adapter call that carries no id of its own. */
    readonly decision_id?: string;
    /** The hook threw, or outran its deadline (`onResultTimeoutMs`, 8 s by
     *  default — on `tool()`, on `governTool` / `governTools` and on
     *  `governedHooks` alike) — the payload was never released. `replaced` is
     *  then `false`. */
    readonly withheld?: true;
  };

/** One node of a sub-agent scope tree — written by `scope()` for the root and
 *  by every `attenuate()`, granted or refused. Carries capability NAMES only.
 *  Unlike the other kinds it has no `principal` and no `actor_chain`. */
export type AttenuationRecord = AuditRecordBase & {
  readonly event: "attenuation";
  /** Always the fixed word `attenuate`. */
  readonly intent: "attenuate";
  /** This scope's id. A refused request gets a fresh id that heads no chain. */
  readonly node_id: string;
  readonly decision: "Allow" | "Deny";
  /** 0 for the root. */
  readonly depth: number;
  /** The GRANTED tool set (the engine's clamped grant); on a `Deny`, the
   *  requested set. */
  readonly tools: readonly string[];
  /** Absent on the root. */
  readonly parent_id?: string;
  /** Present on a `Deny`: the violated dimension(s), or the depth limit. */
  readonly reason?: string;
  /** Present on a `Deny` from `maxDelegationDepth`: `DELEGATION_DEPTH_EXCEEDED`.
   *  `depth` is the refused child's depth. */
  readonly reason_code?: "DELEGATION_DEPTH_EXCEEDED";
  /** Present with `reason_code`: the limit the refused hop exceeded. */
  readonly max_delegation_depth?: number;
};

/**
 * One value-free audit record, as delivered to an {@link AuditSink}. Frozen —
 * the same fields the `.watchlight/audit.jsonl` line carries, and never
 * argument values, PII, or secrets.
 *
 * A discriminated union on `event`, so a sink narrows to one kind and reads its
 * fields by name. A field that is renamed or removed, or a sixth record kind,
 * then breaks the sink at COMPILE time — which is when its author wants to know,
 * rather than by printing a record in production:
 *
 * ```ts
 * const sink: AuditSink = (r) => {
 *   switch (r.event) {
 *     case undefined:      return store.decision(r.principal, r.decision, r.decision_id);
 *     case "sanitization": return store.redaction(r.counts, r.total);
 *     case "screening":    return store.screening(r.counts, r.flagged);
 *     case "egress":       return store.egress(r.replaced, r.withheld === true);
 *     case "attenuation":  return store.scopeNode(r.node_id, r.parent_id, r.tools);
 *   }
 * };
 * ```
 *
 * To opt OUT — to forward a record whole without naming its fields, or to keep
 * a sink compiling against a future version that adds a kind — annotate the
 * parameter {@link UnknownAuditRecord} instead. Both forms satisfy
 * {@link AuditSink}.
 */
export type AuditRecord =
  | DecisionRecord
  | SanitizationRecord
  | ScreeningRecord
  | EgressRecord
  | AttenuationRecord;

/**
 * The escape hatch: an audit record with nothing said about its fields. A sink
 * whose parameter is annotated with this (or with `Record<string, unknown>`)
 * still satisfies {@link AuditSink} — every {@link AuditRecord} is assignable to
 * it — so a sink that only forwards records, or one that must survive a kind it
 * does not know about, needs no narrowing.
 */
export type UnknownAuditRecord = Readonly<Record<string, unknown>>;

/** A record under construction, inside the SDK. The writers build one of these
 *  and hand it to {@link AuditTrail.write}, so a field added, renamed or dropped
 *  at a writer that is not also changed in its record type fails to compile —
 *  the types cannot drift from the lines they describe.
 *  @internal */
export type WritableAuditRecord<T extends AuditRecord> = { -readonly [K in keyof T]: T[K] };

/**
 * An application-supplied destination for audit records, configured via
 * `WatchlightOptions.auditSink`. Called once per record, after the local file
 * append, with a frozen deep copy of the record. May return a promise; the
 * promise is NOT awaited (fire-and-forget) so decision latency is unchanged.
 * A throw or a rejection is captured, reported once per governor, and never
 * reaches the caller.
 */
export type AuditSink = (record: AuditRecord) => void | Promise<void>;

/**
 * A sink under batching: it receives an ARRAY of records from a timer rather
 * than one record on the request path. Configuring `auditSinkBatch` or
 * `auditSinkInterval` selects this shape — the two are not interchangeable, and
 * a single-record sink handed an array would quietly write one malformed row.
 */
export type BatchAuditSink = (batch: readonly AuditRecord[]) => void | Promise<void>;

const ERROR_KIND = /^[A-Za-z_$][\w$]{0,63}$/;
// `err.name` is sink-controlled text (a subclass or `Object.assign` can make it
// anything, including an identifier-shaped string carrying record content), so
// only the standard built-in error names are ever echoed.
const STANDARD_ERRORS = new Set([
  "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError",
  "EvalError", "URIError", "AggregateError",
]);

/** A safe label for a sink failure: a standard built-in error name, else the
 *  literal `Error`. Never sink-chosen text. */
function sanitizeErrorKind(err: unknown): string {
  const name = err instanceof Error ? err.name : "";
  return typeof name === "string" && ERROR_KIND.test(name) && STANDARD_ERRORS.has(name) ? name : "Error";
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
  }
  return value;
}

/** The audit trail shared by a governor and every scope derived from it. */
/** Records held for the batching sink before the oldest are dropped. Bounded on
 *  purpose: an audit destination that stops responding must not become unbounded
 *  memory growth in the application it is auditing. */
export const DEFAULT_SINK_QUEUE_MAX = 10_000;
/** Records per call to a batching sink. */
export const DEFAULT_SINK_BATCH = 100;
/** Milliseconds a partial batch waits before it is handed over anyway. */
export const DEFAULT_SINK_INTERVAL = 2_000;

export class AuditTrail {
  /** The local file every record is appended to, or `null` when the file is
   *  disabled (`auditFile: false`) and the sink is the sole destination. */
  readonly path: string | null;
  private readonly _sink?: AuditSink | BatchAuditSink;
  /** Sanitized error kinds already reported — one warning per kind, so a
   *  "no running loop"-style condition never silences a later real failure. */
  private readonly _warnedKinds = new Set<string>();
  private _warnedNoDestination = false;
  // ── batching (off unless sinkBatch or sinkInterval is given) ──
  // A durable destination — a database, an object store, a log service — is too
  // slow to call on the request path. With batching configured the record is
  // queued and a timer hands the sink an ARRAY after the decision has returned.
  private readonly _batching: boolean;
  private readonly _batchMax: number;
  private readonly _batchInterval: number;
  private readonly _queueMax: number;
  private _queue: AuditRecord[] = [];
  private _timer: ReturnType<typeof setTimeout> | null = null;
  private _dropped = 0;
  private _warnedDropped = false;

  constructor(
    auditPath: string | null,
    sink?: AuditSink | BatchAuditSink,
    opts: { sinkBatch?: number; sinkInterval?: number; sinkQueueMax?: number } = {}
  ) {
    this.path = auditPath;
    this._sink = sink;
    this._batching = !!sink && (opts.sinkBatch !== undefined || opts.sinkInterval !== undefined);
    this._batchMax = Math.max(1, opts.sinkBatch ?? DEFAULT_SINK_BATCH);
    this._batchInterval = opts.sinkInterval ?? DEFAULT_SINK_INTERVAL;
    if (this._batching && !(this._batchInterval > 0)) {
      throw new Error("auditSinkInterval must be greater than zero");
    }
    this._queueMax = Math.max(1, opts.sinkQueueMax ?? DEFAULT_SINK_QUEUE_MAX);
  }

  /** Records the batching queue has dropped. Non-zero means the trail has
   *  holes, and where they are is not recoverable — watch it. */
  get dropped(): number {
    return this._dropped;
  }

  /** True when an application-supplied sink is attached to this trail. */
  get hasSink(): boolean {
    return !!this._sink;
  }

  /** Append `record` to the local file, then hand the same fields to the sink. */
  write(record: AuditRecord): void {
    if (this.path === null && !this._sink) {
      this._warnNoDestination();
      return;
    }
    // The funnel can never throw out of authorize/sanitize/attenuate — including
    // for a record that fails to serialize (nothing to write, nothing to send).
    let line: string;
    try {
      line = JSON.stringify(record);
    } catch {
      return;
    }
    // 1. The file, first — the sink can never influence what lands on disk.
    //    Skipped entirely when the file is disabled: nothing is created.
    if (this.path !== null) {
      try {
        fs.mkdirSync(path.dirname(this.path), { recursive: true });
        fs.appendFileSync(this.path, line + "\n", "utf8");
      } catch {
        // Audit is best-effort in dev mode; never let it break the app.
      }
    }
    // 2. The sink, fire-and-forget. It receives a frozen deep copy built from
    //    the exact serialized line, so it sees precisely the file's fields and
    //    cannot mutate the caller's record.
    if (!this._sink) return;
    if (this._batching) {
      this._enqueue(deepFreeze(JSON.parse(line) as Record<string, unknown>) as AuditRecord);
      return;
    }
    try {
      const copy = deepFreeze(JSON.parse(line) as Record<string, unknown>) as AuditRecord;
      const ret = (this._sink as AuditSink)(copy);
      if (ret && typeof (ret as Promise<void>).then === "function") {
        (ret as Promise<void>).then(undefined, (err) => this._warnOnce(err));
      }
    } catch (err) {
      this._warnOnce(err);
    }
  }

  /** Both destinations are off, so this record has nowhere to go. Said once —
   *  a discarded trail is a configuration mistake, never a silent one. */
  private _warnNoDestination(): void {
    if (this._warnedNoDestination) return;
    this._warnedNoDestination = true;
    // eslint-disable-next-line no-console
    console.warn(
      "watchlight: the audit file is disabled and no auditSink is configured — " +
        "audit records are discarded. Configure `auditSink`, or leave `auditFile` on."
    );
  }

  // ── batching worker ──

  private _enqueue(record: AuditRecord): void {
    if (this._queue.length >= this._queueMax) {
      // Drop the OLDEST: under sustained pressure the newest records are the
      // ones an operator is looking at.
      this._queue.shift();
      this._dropped += 1;
      this._warnDroppedOnce();
    }
    this._queue.push(record);
    if (this._queue.length >= this._batchMax) {
      this._deliverNow();
      return;
    }
    if (this._timer === null) {
      this._timer = setTimeout(() => this._deliverNow(), this._batchInterval);
      // Never hold the process open for a partial batch.
      (this._timer as unknown as { unref?: () => void }).unref?.();
    }
  }

  private _deliverNow(): void {
    if (this._timer !== null) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    while (this._queue.length) {
      const batch = this._queue.splice(0, this._batchMax);
      try {
        const ret = (this._sink as unknown as BatchAuditSink)(batch);
        if (ret && typeof (ret as Promise<void>).then === "function") {
          (ret as Promise<void>).then(undefined, (err) => this._warnOnce(err));
        }
      } catch (err) {
        // A sink that throws must never take the trail down with it, or the
        // trail stops for the life of the process.
        this._warnOnce(err);
      }
    }
  }

  /** Deliver everything queued, now. Worth calling before a deliberate
   *  shutdown: a partial batch is otherwise waiting on its timer, and the timer
   *  is unref'd so it will not hold the process open to fire. */
  flush(): void {
    if (!this._batching) return;
    this._deliverNow();
  }

  private _warnDroppedOnce(): void {
    // The count is ours, not the sink's, so unlike a sink failure it is safe to
    // print — and it must be printed: a dropped record is a hole in the audit
    // trail, and a hole nobody is told about is the worst kind.
    if (this._warnedDropped) return;
    this._warnedDropped = true;
    console.error(
      "watchlight: the audit sink queue is full — records are being dropped, oldest first, " +
        "because the sink is slower than the rate records are produced. Raise auditSinkBatch, " +
        "or make the sink faster. Further drops are not reported; AuditTrail.dropped counts them."
    );
  }

  private _warnOnce(err: unknown): void {
    // Only the error TYPE is reported — never the record, never a message that
    // could carry one. `err.name` is sink-controlled text, so it is accepted
    // only when it looks like an identifier; anything else logs as `Error`.
    const kind = sanitizeErrorKind(err);
    if (this._warnedKinds.has(kind)) return;
    this._warnedKinds.add(kind);
    // eslint-disable-next-line no-console
    console.warn(
      `watchlight: audit sink failed (${kind}); further sink failures are suppressed — ` +
        "the local audit file is still written"
    );
  }
}
