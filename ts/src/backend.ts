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
 * - any other `@obligate_<name>("raw")` → `extra[name] = "raw"`, uninterpreted.
 *
 * When several permits carry the Allow the known keys merge deterministically —
 * `redact` is the union, `maxItems` the minimum, `logValues` the logical AND —
 * so the result is always at least as strict as every contributing policy.
 * `extra` values are uninterpreted and are never merged: a key is exposed when
 * every contributing permit agrees on its value, and dropped when they differ.
 * Every field is omitted when unset; the whole object is omitted when empty.
 */
export interface Obligations {
  redact?: string[];
  maxItems?: number;
  logValues?: boolean;
  /** Unknown `@obligate_*` keys, raw and uninterpreted. */
  extra?: Record<string, string>;
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

/** Read one wire obligations object into the SDK shape, keeping only
 *  well-typed values: `redact` a non-empty list of non-blank strings (trimmed,
 *  de-duplicated), `max_items` an integer in 1..=4294967295, `log_values` a
 *  boolean, `extra` a string→string map. Anything else is left out. */
function readObligations(wire: unknown): Obligations | undefined {
  if (!wire || typeof wire !== "object" || Array.isArray(wire)) return undefined;
  const w = wire as WireObligations;
  const out: Obligations = {};
  if (Array.isArray(w.redact)) {
    const seen = new Set<string>();
    for (const v of w.redact) {
      if (typeof v !== "string") continue;
      const t = v.trim();
      if (t) seen.add(t);
    }
    if (seen.size) out.redact = [...seen];
  }
  if (
    typeof w.max_items === "number" &&
    Number.isInteger(w.max_items) &&
    w.max_items >= 1 &&
    w.max_items <= MAX_ITEMS_UPPER_BOUND
  ) {
    out.maxItems = w.max_items;
  }
  if (typeof w.log_values === "boolean") out.logValues = w.log_values;
  if (w.extra && typeof w.extra === "object" && !Array.isArray(w.extra)) {
    const extra: Record<string, string> = {};
    for (const [k, v] of Object.entries(w.extra as Record<string, unknown>)) {
      if (typeof v === "string") extra[k] = v;
    }
    if (Object.keys(extra).length) out.extra = extra;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Merge the obligations of several contributing permits: `redact` union (in
 *  first-seen order), `maxItems` minimum, `logValues` logical AND, `extra`
 *  only where every carrier agrees on the value. */
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
    for (const [k, v] of Object.entries(p.extra ?? {})) {
      if (!extraValues.has(k)) extraValues.set(k, new Set());
      extraValues.get(k)!.add(v);
    }
  }
  if (redact.size) out.redact = [...redact];
  const extra: Record<string, string> = {};
  for (const [k, vs] of extraValues) if (vs.size === 1) extra[k] = [...vs][0];
  if (Object.keys(extra).length) out.extra = extra;
  return Object.keys(out).length ? out : undefined;
}

/**
 * Derive the obligations attached to an `Allow` from a decision's details.
 *
 * Source of truth is the engine's merged `details.obligations` (present only on
 * a final Allow). A backend that predates that field, or that emits only the
 * per-policy `details.policy_results[].obligations`, gets the same merge derived
 * here from the permits that determined the decision (`applicable: true`) —
 * exactly as {@link deriveNeedsApproval} reads `enforcement_effect`. `extra` is
 * never merged by the engine, so it is always read from the per-policy results.
 * Returns `undefined` when there is nothing to honour. The caller decides
 * whether the verdict is one that may carry obligations (only an Allow does).
 */
export function deriveObligations(details: unknown): Obligations | undefined {
  const d = details as
    | { policy_results?: Array<Record<string, unknown>>; obligations?: unknown }
    | null
    | undefined;
  if (!d || typeof d !== "object") return undefined;
  const results = Array.isArray(d.policy_results) ? d.policy_results : [];
  const perPolicy: Obligations[] = [];
  for (const r of results) {
    if (r?.applicable !== true) continue;
    const o = readObligations(r.obligations);
    if (o) perPolicy.push(o);
  }
  const fromPolicies = mergeObligations(perPolicy);
  const merged = readObligations(d.obligations);
  if (!merged) return fromPolicies;
  // The engine's merge is authoritative for the known keys; `extra` comes from
  // the per-policy results because the engine deliberately does not merge it.
  const out: Obligations = { ...merged };
  delete out.extra;
  if (fromPolicies?.extra) out.extra = fromPolicies.extra;
  return Object.keys(out).length ? out : undefined;
}

export interface GovernanceBackend {
  readonly kind: "in-process" | "networked";
  /** A short human label for the dev announce line. */
  readonly label: string;
  /** Register a policy. In-process loads it; networked ignores it (policies are
   *  managed by the control plane) after warning once. */
  addPolicy(policy: { name: string; code: string }): void;
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
  private _pending: { name: string; code: string }[] = [];

  addPolicy(policy: { name: string; code: string }): void {
    this._pending.push(policy);
  }

  private async _ready(): Promise<Engine> {
    if (!this._enginePromise) this._enginePromise = Engine.create();
    const engine = await this._enginePromise;
    if (this._pending.length) {
      const batch = this._pending;
      this._pending = [];
      for (const p of batch) await engine.addPolicy(p);
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
      obligations: deriveObligations(resp.details),
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
      const data = (await resp.json()) as Record<string, unknown>;
      return {
        decision: (data.decision as string) ?? "Deny",
        reason: (data.reason as string) ?? "",
        decisionId: data.request_id as string | undefined,
        needsApproval: deriveNeedsApproval(data.details),
        obligations: deriveObligations(data.details),
      };
    } catch (e) {
      // Fail-closed: an unreachable control plane denies.
      return { decision: "Deny", reason: `APDP unreachable: ${String(e)}` };
    }
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
