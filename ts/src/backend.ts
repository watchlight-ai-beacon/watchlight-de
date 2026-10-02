// Governance backend seam — the one object that graduation swaps.
//
// The authorize request/response shape is IDENTICAL in both editions
// (`{principal, action, resource, context}` → `{decision, reason}`), so the same
// govern/tool/hook code works either way:
//
//   * Developer Edition (default) — InProcessBackend runs the compiled
//     @watchlight/engine wasm core in-process. Zero infrastructure.
//   * Enterprise — set WATCHLIGHT_APDP_URL and NetworkedBackend POSTs the same
//     request to the control plane's /authorize (signed lineage, cross-tenant
//     isolation, IdP/mTLS attestation live there). No policy or code change.
//
// Fail-closed everywhere: any transport/engine error resolves to Deny.

import { Engine } from "@watchlight/engine";

export interface AuthorizeRequest {
  principal: string;
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}

export interface Decision {
  decision: string;
  reason: string;
  /** Per-decision correlation id (the engine's `request_id`) — join to your own
   *  records. */
  decisionId?: string;
  /** True when a matched permit carries the `require_approval` enforcement
   *  effect: the action is permitted only after a human confirmation. */
  needsApproval?: boolean;
  /** Obligations the permitting policies attach to an `Allow` — see
   *  {@link Obligations}. Absent on Deny and when no permit declares any. */
  obligations?: Obligations;
}

/**
 * Obligations a `permit` declares via `@obligate_*` Cedar annotations —
 * constraints the caller MUST honour when acting on an `Allow`. Policy-authored
 * strings, echoed as-is; never derived from request or result values.
 *
 * - `@obligate_redact("ssn, card")` → `redact: ["ssn", "card"]` — field names to
 *   strip before the result reaches the caller or the model.
 * - `@obligate_max_items("8")` → `maxItems: 8` — an upper bound on how many
 *   items the caller may act on or return.
 * - `@obligate_log_values("false")` → `logValues: false` — whether the values
 *   handled under this decision may be logged.
 * - any other `@obligate_<name>("raw")` → `extra[name] = ["raw"]`, uninterpreted.
 *
 * Every source that carries the Allow — the engine's merged `details.obligations`
 * and each determining permit's `policy_results[].obligations` — is merged to
 * the strictest reading: `redact` is the union, `maxItems` the minimum,
 * `logValues` the logical AND. `extra` values are uninterpreted, so every
 * carrier's value is kept: `extra[name]` lists the distinct values (sorted),
 * and your code decides what a disagreement means. Every field is omitted when
 * unset; the whole object is omitted when empty. A known key the engine emits
 * in an unreadable form is not dropped — the decision fails closed with
 * {@link AuthorizeError}.
 */
export interface Obligations {
  redact?: string[];
  maxItems?: number;
  logValues?: boolean;
  /** Unknown `@obligate_*` keys, raw and uninterpreted: every distinct value the
   *  carrying permits declared for that name, sorted. */
  extra?: Record<string, string[]>;
}

/** Fixed, value-free message of {@link AuthorizeError}. */
export const OBLIGATIONS_INVALID_MESSAGE = "invalid obligations on an Allow decision";

/** Thrown when an `Allow` carries a known obligation (`redact`, `max_items`,
 *  `log_values`) the SDK cannot read — the constraint cannot be honoured, so
 *  the decision fails closed instead of silently losing it. */
export class AuthorizeError extends Error {
  constructor() {
    super(OBLIGATIONS_INVALID_MESSAGE);
    this.name = "AuthorizeError";
  }
}

/** Derive `needsApproval` from a decision's details: a permitting policy result
 *  annotated `@enforcement_effect("require_approval")`. */
export function deriveNeedsApproval(details: unknown): boolean {
  const results = (
    details as {
      policy_results?: Array<{ applicable?: boolean; enforcement_effect?: string }>;
    }
  )?.policy_results;
  // Only the policy that actually matched this request (`applicable: true`)
  // counts — a non-matching require_approval policy elsewhere in the set must not
  // flag this decision.
  return Array.isArray(results)
    ? results.some((r) => r?.applicable === true && r?.enforcement_effect === "require_approval")
    : false;
}

/** The engine's wire shape for one obligations object (snake_case). */
interface WireObligations {
  redact?: unknown;
  max_items?: unknown;
  log_values?: unknown;
  extra?: unknown;
}

const MAX_ITEMS_UPPER_BOUND = 4294967295;
/** Bound on a `redact` list — beyond it the payload is treated as unreadable. */
export const MAX_REDACT_ENTRIES = 10000;

/** Read one wire obligations object into the SDK shape. A known key that is
 *  present but unreadable — `redact` not a non-empty list of non-blank strings
 *  (or longer than {@link MAX_REDACT_ENTRIES}), `max_items` not an integer in
 *  1..=4294967295, `log_values` not a boolean — throws {@link AuthorizeError}:
 *  a constraint the SDK cannot read must not be silently dropped. `extra`
 *  keeps its string values and ignores the rest (it is uninterpreted by
 *  contract). `undefined` (field absent) reads as no obligations. */
function readObligations(wire: unknown): Obligations | undefined {
  if (wire === undefined) return undefined;
  if (!wire || typeof wire !== "object" || Array.isArray(wire)) throw new AuthorizeError();
  const w = wire as WireObligations;
  const out: Obligations = {};
  if (w.redact !== undefined) {
    if (!Array.isArray(w.redact) || w.redact.length === 0 || w.redact.length > MAX_REDACT_ENTRIES) {
      throw new AuthorizeError();
    }
    const seen = new Set<string>();
    for (const v of w.redact) {
      if (typeof v !== "string" || !v.trim()) throw new AuthorizeError();
      seen.add(v.trim());
    }
    out.redact = [...seen];
  }
  if (w.max_items !== undefined) {
    if (
      typeof w.max_items !== "number" ||
      !Number.isInteger(w.max_items) ||
      w.max_items < 1 ||
      w.max_items > MAX_ITEMS_UPPER_BOUND
    ) {
      throw new AuthorizeError();
    }
    out.maxItems = w.max_items;
  }
  if (w.log_values !== undefined) {
    if (typeof w.log_values !== "boolean") throw new AuthorizeError();
    out.logValues = w.log_values;
  }
  if (w.extra && typeof w.extra === "object" && !Array.isArray(w.extra)) {
    const extra: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(w.extra as Record<string, unknown>)) {
      if (typeof v === "string") extra[k] = [v];
      else if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string")) {
        extra[k] = [...new Set(v as string[])].sort();
      }
    }
    if (Object.keys(extra).length) out.extra = extra;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Merge every carrier's obligations to the strictest reading: `redact` union
 *  (first-seen order), `maxItems` minimum, `logValues` logical AND, `extra`
 *  the sorted distinct values per key. */
function mergeObligations(parts: readonly Obligations[]): Obligations | undefined {
  const out: Obligations = {};
  const redact = new Set<string>();
  const extraValues = new Map<string, Set<string>>();
  for (const p of parts) {
    for (const r of p.redact ?? []) redact.add(r);
    if (p.maxItems !== undefined) {
      out.maxItems = out.maxItems === undefined ? p.maxItems : Math.min(out.maxItems, p.maxItems);
    }
    if (p.logValues !== undefined) {
      out.logValues = out.logValues === undefined ? p.logValues : out.logValues && p.logValues;
    }
    for (const [k, vs] of Object.entries(p.extra ?? {})) {
      if (!extraValues.has(k)) extraValues.set(k, new Set());
      for (const v of vs) extraValues.get(k)!.add(v);
    }
  }
  if (redact.size) out.redact = [...redact];
  if (extraValues.size) {
    const extra: Record<string, string[]> = {};
    for (const k of [...extraValues.keys()].sort()) extra[k] = [...extraValues.get(k)!].sort();
    out.extra = extra;
  }
  return Object.keys(out).length ? out : undefined;
}

/**
 * Derive the obligations attached to an `Allow` from a decision's details.
 *
 * Every carrier is merged to the strictest reading — the engine's own merged
 * `details.obligations` (present on a final Allow) together with the
 * `obligations` of every permit that determined the decision
 * (`policy_results[]` with `applicable: true`, exactly as
 * {@link deriveNeedsApproval} reads `enforcement_effect`). A backend that emits
 * only one of the two sources therefore yields the same result as one that
 * emits both, and a stricter per-policy key is never lost to the engine merge.
 * Returns `undefined` when there is nothing to honour. Throws
 * {@link AuthorizeError} when a known key is present but unreadable. Call it
 * only for a decision that may carry obligations — an Allow.
 */
export function deriveObligations(details: unknown): Obligations | undefined {
  const d = details as
    | { policy_results?: Array<Record<string, unknown>>; obligations?: unknown }
    | null
    | undefined;
  if (!d || typeof d !== "object") return undefined;
  const parts: Obligations[] = [];
  const results = Array.isArray(d.policy_results) ? d.policy_results : [];
  for (const r of results) {
    if (r?.applicable !== true) continue;
    const o = readObligations(r.obligations);
    if (o) parts.push(o);
  }
  const merged = readObligations(d.obligations);
  if (merged) parts.push(merged);
  return mergeObligations(parts);
}

/** A policy the engine refused to compile — a Cedar syntax or validation
 *  error. Thrown by `load()` / `ready()` and by every decision after it.
 *
 *  The engine compiles lazily (its API is asynchronous), so a policy queued by
 *  `allow()` / `load()` / `reload()` is compiled before the first decision.
 *  When one does not compile, the governor does not carry on without it: a
 *  dropped `forbid` would turn its denials into allows. Every later decision
 *  throws this same error until `reload()` replaces the policy set. Call
 *  `await govern.ready()` after loading to surface it at start-up. Carries the
 *  `policy` name and, when it came from a file, the `source` path. */
export class PolicyCompileError extends Error {
  readonly name = "PolicyCompileError";
  /** The name the policy was loaded under. */
  readonly policy: string;
  /** The file it was loaded from, when it came from one. */
  readonly source?: string;
  constructor(policy: string, source: string | undefined, cause: unknown) {
    super(
      `policy "${policy}"${source ? ` from ${source}` : ""} does not compile ` +
        `(${compileDetail(cause)}). Every decision is refused until reload() ` +
        `replaces the policy set.`
    );
    this.policy = policy;
    this.source = source;
  }
}

/** How much of the engine's error text a {@link PolicyCompileError} carries.
 *  The engine's detail can quote the offending source, such as a string
 *  literal, so it is cut short; the kind of error before it is kept. */
const COMPILE_DETAIL_LIMIT = 40;

/** The engine's error as "kind: detail", the detail cut to
 *  {@link COMPILE_DETAIL_LIMIT} characters. Drops the engine's
 *  `add_policy failed:` prefix and a repeated kind. The Python lane does the
 *  same. */
function compileDetail(cause: unknown): string {
  let text = (cause instanceof Error ? cause.message : String(cause)).trim();
  text = text.replace(/^add_policy failed:\s*/, "");
  const cut = (s: string) =>
    s.length <= COMPILE_DETAIL_LIMIT ? s : s.slice(0, COMPILE_DETAIL_LIMIT - 1) + "…";
  const colon = text.indexOf(": ");
  if (colon < 0) return cut(text);
  const kind = text.slice(0, colon);
  let detail = text.slice(colon + 2);
  if (detail.startsWith(kind + ": ")) detail = detail.slice(kind.length + 2);
  return `${cut(kind)}: ${cut(detail)}`;
}

/** A policy queued for the engine. `source` names the file it came from. */
export interface QueuedPolicy {
  name: string;
  code: string;
  source?: string;
}

export interface GovernanceBackend {
  readonly kind: "in-process" | "networked";
  /** A short human label for the dev announce line. */
  readonly label: string;
  /** Register a policy. In-process loads it; networked ignores it (policies are
   *  managed by the control plane) after warning once. */
  addPolicy(policy: QueuedPolicy): void;
  /** Authorize a request. Fail-closed. */
  authorize(req: AuthorizeRequest): Promise<Decision>;
  /** The in-process engine (for local sub-agent attenuation), or null when
   *  networked — attenuation is enforced server-side in Enterprise. */
  engine(): Promise<Engine> | null;
}

/** DE default — the compiled engine in-process. */
export class InProcessBackend implements GovernanceBackend {
  readonly kind = "in-process" as const;
  readonly label = "dev mode, in-process engine";
  private _enginePromise?: Promise<Engine>;
  private _pending: QueuedPolicy[] = [];
  /** Set once a queued policy fails to compile; never cleared. A backend that
   *  holds it refuses every decision — `reload()` builds a fresh backend. */
  private _failure?: PolicyCompileError;
  /** Compiles run one at a time, so two concurrent first decisions cannot
   *  both take the same queued policy, or race past a failure. */
  private _queue: Promise<unknown> = Promise.resolve();

  addPolicy(policy: QueuedPolicy): void {
    this._pending.push(policy);
  }

  private _ready(): Promise<Engine> {
    const run = this._queue.then(() => this._compilePending());
    this._queue = run.catch(() => undefined);
    return run;
  }

  private async _compilePending(): Promise<Engine> {
    if (this._failure) throw this._failure;
    if (!this._enginePromise) this._enginePromise = Engine.create();
    const engine = await this._enginePromise;
    // A policy leaves the queue only once the engine holds it. On the first
    // one that does not compile, the failure is recorded and sticks: the
    // policies after it are never silently skipped into a set that decides.
    while (this._pending.length) {
      const p = this._pending[0];
      try {
        await engine.addPolicy({ name: p.name, code: p.code });
      } catch (e) {
        this._failure = new PolicyCompileError(p.name, p.source, e);
        throw this._failure;
      }
      this._pending.shift();
    }
    return engine;
  }

  async authorize(req: AuthorizeRequest): Promise<Decision> {
    const engine = await this._ready();
    const resp = (await engine.authorize({
      principal: req.principal,
      action: req.action,
      resource: req.resource,
      context: req.context ?? {},
    })) as Record<string, unknown>;
    return {
      decision: (resp.decision as string) ?? "Deny",
      reason: (resp.reason as string) ?? "",
      decisionId: resp.request_id as string | undefined,
      needsApproval: deriveNeedsApproval(resp.details),
      // Only an Allow can carry obligations; an unreadable known key throws
      // AuthorizeError here (fail-closed) rather than being dropped.
      obligations: resp.decision === "Allow" ? deriveObligations(resp.details) : undefined,
    };
  }

  engine(): Promise<Engine> {
    return this._ready();
  }
}

/** Enterprise — POST /authorize to the networked control plane. */
export class NetworkedBackend implements GovernanceBackend {
  readonly kind = "networked" as const;
  readonly label: string;
  private readonly _base: string;
  private readonly _token?: string;
  private readonly _tenantId?: string;
  private _warnedPolicy = false;

  constructor(url: string, token?: string, tenantId?: string) {
    this._base = url.replace(/\/+$/, "");
    this._token = token;
    this._tenantId = tenantId;
    this.label = `control plane: ${this._base}`;
  }

  addPolicy(): void {
    if (!this._warnedPolicy) {
      // eslint-disable-next-line no-console
      console.warn(
        "watchlight: WATCHLIGHT_APDP_URL is set — policies are managed by the " +
          "control plane; local allow()/load() is ignored."
      );
      this._warnedPolicy = true;
    }
  }

  async authorize(req: AuthorizeRequest): Promise<Decision> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this._token) headers["authorization"] = `Bearer ${this._token}`;
    if (this._tenantId) headers["x-wl-tenant-id"] = this._tenantId;
    let data: Record<string, unknown>;
    try {
      const resp = await fetch(`${this._base}/authorize`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          principal: req.principal,
          action: req.action,
          resource: req.resource,
          context: req.context ?? {},
        }),
      });
      if (!resp.ok) return { decision: "Deny", reason: `APDP error: ${resp.status}` };
      data = (await resp.json()) as Record<string, unknown>;
    } catch (e) {
      // Fail-closed: an unreachable control plane denies.
      return { decision: "Deny", reason: `APDP unreachable: ${String(e)}` };
    }
    return {
      decision: (data.decision as string) ?? "Deny",
      reason: (data.reason as string) ?? "",
      decisionId: data.request_id as string | undefined,
      needsApproval: deriveNeedsApproval(data.details),
      // Only an Allow can carry obligations; an unreadable known key throws
      // AuthorizeError (fail-closed) rather than being dropped or mapped to a
      // transport Deny.
      obligations: data.decision === "Allow" ? deriveObligations(data.details) : undefined,
    };
  }

  engine(): null {
    return null;
  }
}

/** Select the backend: networked when a URL is given (option or
 *  WATCHLIGHT_APDP_URL), in-process otherwise. */
export function selectBackend(opts: {
  apdpUrl?: string;
  token?: string;
  tenantId?: string;
}): GovernanceBackend {
  const url = opts.apdpUrl ?? process.env.WATCHLIGHT_APDP_URL;
  if (url && url.trim()) {
    return new NetworkedBackend(
      url.trim(),
      opts.token ?? process.env.WATCHLIGHT_PLUGIN_TOKEN,
      opts.tenantId ?? process.env.WATCHLIGHT_TENANT_ID
    );
  }
  return new InProcessBackend();
}
