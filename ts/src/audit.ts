// The value-free audit trail — the ONE funnel every audit record passes through.
//
// Decisions (`Watchlight.authorize`), sanitizations (`Watchlight.sanitize`) and
// attenuations (`Scope.attenuate`) all end up here. Two destinations:
//
//   1. the local `.watchlight/audit.jsonl` file (always on, best-effort), and
//   2. an optional application-supplied `auditSink` callback, which receives
//      exactly the fields the file line carries — nothing more.
//
// The sink is ADDITIVE and FIRE-AND-FORGET: it is invoked synchronously after the
// file append, its return value is never awaited, and any failure (a throw or a
// rejected promise) is captured and reported once — it can never block, delay
// or alter a governance decision, and the file keeps being written.

import * as fs from "node:fs";
import * as path from "node:path";

/** One value-free audit record, as delivered to an {@link AuditSink}. Frozen —
 *  the same fields the `.watchlight/audit.jsonl` line carries, and never
 *  argument values, PII, or secrets. */
export type AuditRecord = Readonly<Record<string, unknown>>;

/**
 * An application-supplied destination for audit records, configured via
 * `WatchlightOptions.auditSink`. Called once per record, after the local file
 * append, with a frozen deep copy of the record. May return a promise; the
 * promise is NOT awaited (fire-and-forget) so decision latency is unchanged.
 * A throw or a rejection is captured, reported once per governor, and never
 * reaches the caller.
 */
export type AuditSink = (record: AuditRecord) => void | Promise<void>;

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
  }
  return value;
}

/** The audit trail shared by a governor and every scope derived from it. */
export class AuditTrail {
  readonly path: string;
  private readonly _sink?: AuditSink;
  private _sinkWarned = false;

  constructor(auditPath: string, sink?: AuditSink) {
    this.path = auditPath;
    this._sink = sink;
  }

  /** Append `record` to the local file, then hand the same fields to the sink. */
  write(record: Record<string, unknown>): void {
    const line = JSON.stringify(record);
    // 1. The file, first — the sink can never influence what lands on disk.
    try {
      fs.mkdirSync(path.dirname(this.path), { recursive: true });
      fs.appendFileSync(this.path, line + "\n", "utf8");
    } catch {
      // Audit is best-effort in dev mode; never let it break the app.
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

  private _warnOnce(err: unknown): void {
    if (this._sinkWarned) return;
    this._sinkWarned = true;
    // Only the error TYPE is reported — never the record, never a message that
    // could carry one. The trail itself is value-free; keep the log that way too.
    const kind = err instanceof Error ? err.name : typeof err;
    // eslint-disable-next-line no-console
    console.warn(
      `watchlight: audit sink failed (${kind}); further sink failures are suppressed — ` +
        "the local audit file is still written"
    );
  }
}
