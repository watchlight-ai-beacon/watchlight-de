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
    /** The hook threw, or outran its deadline — the payload was never
     *  released. `replaced` is then `false`. */
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
  /** Present on a `Deny`: the violated dimension, or the depth-ceiling notice. */
  readonly reason?: string;
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
export class AuditTrail {
  /** The local file every record is appended to, or `null` when the file is
   *  disabled (`auditFile: false`) and the sink is the sole destination. */
  readonly path: string | null;
  private readonly _sink?: AuditSink;
  /** Sanitized error kinds already reported — one warning per kind, so a
   *  "no running loop"-style condition never silences a later real failure. */
  private readonly _warnedKinds = new Set<string>();
  private _warnedNoDestination = false;

  constructor(auditPath: string | null, sink?: AuditSink) {
    this.path = auditPath;
    this._sink = sink;
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
    try {
      const copy = deepFreeze(JSON.parse(line) as Record<string, unknown>) as AuditRecord;
      const ret = this._sink(copy);
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
