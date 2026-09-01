// @watchlight/sdk — the Watchlight Developer-Edition govern glue for Node/TS.
//
// Thin, dependency-light glue over @watchlight/engine (the compiled wl-apdp
// core). It contains ZERO decision logic — every ALLOW/DENY comes from the
// engine. It mirrors the Python `watchlight` package: declare intent, govern a
// tool, get a fail-closed decision, and a value-free `.watchlight/audit.jsonl`
// trail.
//
//   import { govern, Denied } from "@watchlight/sdk";
//   govern.load("watchlight.policy.json");            // or govern.allow("permit(...);")
//   const search = govern.tool(webSearch, { intent: "research" });
//   await search(query);                              // ALLOW → runs; else throws Denied
//
// TypeScript uses a higher-order function (`govern.tool(fn, {intent})`) rather
// than a decorator — decorators are still awkward across TS build setups, and a
// HOF works everywhere with full type inference.

import * as fs from "node:fs";
import * as path from "node:path";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import { Scope, DE_MAX_DEPTH } from "./attenuation";
import { selectBackend, type GovernanceBackend } from "./backend";
import { sanitize as sanitizeText, type SanitizeOptions, type SanitizeResult } from "./sanitize";
import {
  runPolicyTests,
  type PolicyTestCase,
  type PolicyTestReport,
  type PolicyTestResult,
} from "./policytest";

export { Scope, DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling } from "./attenuation";
export { governedHooks } from "./claude-agent";
export type { GovernedHooksOptions, GovernedHooksResult } from "./claude-agent";
export { governTool, governTools } from "./langchain";
export type {
  LangChainToolLike,
  GovernToolOptions,
  GovernToolsOptions,
} from "./langchain";
export { sanitize, SanitizeError, DETECTOR_VERSION } from "./sanitize";
export type {
  PiiType,
  RedactMode,
  SanitizeOptions,
  SanitizeReport,
  SanitizeResult,
} from "./sanitize";
export type { GovernanceBackend, Decision, AuthorizeRequest } from "./backend";
export { InProcessBackend, NetworkedBackend } from "./backend";
export { runPolicyTests, loadTestSuite } from "./policytest";
export type {
  PolicyTestCase,
  PolicyTestReport,
  PolicyTestResult,
  PolicyTestSuite,
} from "./policytest";

// ── caller-facing decision reasons (SECURITY: uniform + non-revealing) ──────
// The reason surfaced to the caller NEVER explains WHY a request was denied — a
// specific reason ("no matching policy" vs "forbidden by X" vs "amount exceeds
// limit") would leak the authorization boundary to an attacker probing it, who
// could then tune an attack. Every denial returns the SAME opaque reason; the
// Denied message still names the caller's own request (intent + tool), which is
// their input, not a leak. Operators reconstruct the true cause from signed
// lineage / the decisionId (Enterprise), never from this string.
export const DENY_REASON = "not authorized";
const APPROVAL_REASON = "approval required";

function reasonForVerdict(verdict: "Allow" | "Deny" | "NeedsApproval"): string {
  if (verdict === "Deny") return DENY_REASON;
  if (verdict === "NeedsApproval") return APPROVAL_REASON;
  return "";
}

/** Raised when the policy engine refuses a governed tool call (fail-closed). */
export class Denied extends Error {
  readonly tool: string;
  readonly intent: string;
  readonly reason: string;
  constructor(tool: string, intent: string, reason: string) {
    super(`watchlight denied intent '${intent}' on tool/${tool}: ${reason}`);
    this.name = "Denied";
    this.tool = tool;
    this.intent = intent;
    this.reason = reason;
  }
}

/** Raised when a governed call is permitted only after a human confirmation
 *  (the matched permit carries the `require_approval` enforcement effect) and no
 *  valid approval was supplied. Fail-closed: the tool body did NOT run. */
export class NeedsApproval extends Error {
  readonly tool: string;
  readonly intent: string;
  readonly decisionId?: string;
  readonly reason: string;
  constructor(tool: string, intent: string, decisionId: string | undefined, reason: string) {
    super(`watchlight requires human approval for intent '${intent}' on tool/${tool}`);
    this.name = "NeedsApproval";
    this.tool = tool;
    this.intent = intent;
    this.decisionId = decisionId;
    this.reason = reason;
  }
}

/** A per-call binding: a fixed value, or a function of the tool's arguments. */
export type Binding<A extends unknown[]> = string | ((...args: A) => string);

/** A record of attributes passed into Cedar `context.*`, or a function of args. */
export type ContextBinding<A extends unknown[]> =
  | Record<string, unknown>
  | ((...args: A) => Record<string, unknown>);

/** Full result of {@link Watchlight.authorize}. */
export interface AuthorizeResult {
  /** `"Allow"` | `"Deny"` | `"NeedsApproval"`. */
  decision: "Allow" | "Deny" | "NeedsApproval";
  allowed: boolean;
  needsApproval: boolean;
  /** True when a valid approval token downgraded a NeedsApproval to Allow. */
  approved: boolean;
  /** Per-decision correlation id (engine `request_id`) — join to your records. */
  decisionId?: string;
  reason: string;
}

// ── approval tokens (DE: local, single-use, HMAC, TTL) ───────────────
// Enterprise mints these KMS-signed and records them in signed lineage.
const APPROVAL_SECRET = randomBytes(32);
const USED_APPROVALS = new Set<string>();

const approvalPayload = (
  principal: string,
  action: string,
  resource: string,
  exp: number,
  nonce: string
): string => `${principal} ${action} ${resource} ${exp} ${nonce}`;

function mintApprovalToken(principal: string, action: string, resource: string, ttlMs: number): string {
  const exp = Date.now() + ttlMs;
  // A per-mint nonce makes every token unique, so two approvals for the same
  // (principal, action, resource) minted in the same millisecond never collide
  // — and "single-use" is genuinely per-mint, not per-(challenge, exp).
  const nonce = randomBytes(8).toString("hex");
  const sig = createHmac("sha256", APPROVAL_SECRET)
    .update(approvalPayload(principal, action, resource, exp, nonce))
    .digest("hex");
  return `${exp}.${nonce}.${sig}`;
}

/** Verify + CONSUME an approval token (single-use). Bound to the exact
 *  (principal, action, resource); rejects expired, tampered, or reused tokens. */
function consumeApprovalToken(
  token: string,
  principal: string,
  action: string,
  resource: string
): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [expStr, nonce, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expected = createHmac("sha256", APPROVAL_SECRET)
    .update(approvalPayload(principal, action, resource, exp, nonce))
    .digest("hex");
  if (sig.length !== expected.length) return false;
  if (!timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) return false;
  if (USED_APPROVALS.has(token)) return false;
  USED_APPROVALS.add(token);
  return true;
}

function resolveBinding<A extends unknown[]>(
  b: Binding<A> | undefined,
  args: A
): string | undefined {
  if (b === undefined) return undefined;
  return typeof b === "function" ? b(...args) : b;
}

/** A function governed by {@link Watchlight.tool} — always async (the engine's
 *  authorize path is async in WebAssembly). */
export type Governed<A extends unknown[], R> = (...args: A) => Promise<Awaited<R>>;

const norm = (x?: readonly string[] | null): string[] => (x ? [...x] : []);

export interface WatchlightOptions {
  /** Stable agent identity for the audit trail. Defaults to
   *  `WATCHLIGHT_AGENT` env or `"my-agent"`. */
  agent?: string;
  /** Directory for the audit trail. `audit.jsonl` is written inside it.
   *  Defaults to `.watchlight`. */
  auditDir?: string;
  /** Graduate to the networked control plane: authorize against this APDP URL
   *  instead of the in-process engine. Defaults to `WATCHLIGHT_APDP_URL`. When
   *  unset, governance runs fully in-process (Developer Edition). */
  apdpUrl?: string;
  /** Bearer token for the networked control plane. Defaults to
   *  `WATCHLIGHT_PLUGIN_TOKEN`. Ignored in-process. */
  token?: string;
  /** Tenant id (`X-Wl-Tenant-Id`) for the networked control plane. Defaults to
   *  `WATCHLIGHT_TENANT_ID`. Ignored in-process. */
  tenantId?: string;
}

export interface ScopeOptions {
  tools?: readonly string[];
  resources?: readonly string[];
  intents?: readonly string[];
  maxDepth?: number;
  timeBudgetSeconds?: number;
}

/**
 * An in-process policy decision point for a single agent. Wraps the
 * `@watchlight/engine` core; policies are loaded from a file or added inline and
 * each governed call is authorized against them. Fail-closed: with no matching
 * policy, every call is denied.
 */
export class Watchlight {
  readonly agent: string;
  private readonly _auditPath: string;
  private readonly _backend: GovernanceBackend;
  private _policyCount = 0;
  private _announced = false;

  constructor(opts: WatchlightOptions = {}) {
    this.agent = opts.agent ?? process.env.WATCHLIGHT_AGENT ?? "my-agent";
    this._auditPath = path.join(opts.auditDir ?? ".watchlight", "audit.jsonl");
    this._backend = selectBackend({
      apdpUrl: opts.apdpUrl,
      token: opts.token,
      tenantId: opts.tenantId,
    });
  }

  /** `"in-process"` (Developer Edition) or `"networked"` (graduated to the
   *  control plane via WATCHLIGHT_APDP_URL). */
  get mode(): "in-process" | "networked" {
    return this._backend.kind;
  }

  // ── policy loading ────────────────────────────────────────────────

  /** Add one Cedar policy inline. Chainable. (In networked mode policies are
   *  managed by the control plane and this is ignored, with a one-time warning.) */
  allow(cedarCode: string, name?: string): this {
    this._backend.addPolicy({ name: name ?? `policy-${this._policyCount}`, code: cedarCode });
    this._policyCount += 1;
    return this;
  }

  /** Load policies from a JSON file — a list of `{name, code}` (or
   *  `{policies:[...]}`). Fail-closed: a missing file loads nothing, so every
   *  governed call is denied until a policy permits it. Chainable. */
  load(file: string): this {
    if (!fs.existsSync(file)) return this;
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const entries: { name?: string; code: string }[] = Array.isArray(data)
      ? data
      : (data.policies ?? []);
    for (const e of entries) this.allow(e.code, e.name);
    return this;
  }

  // ── sub-agent scope attenuation ───────────────────────────────────

  /** Create a root capability scope for this agent, from which sub-agent scopes
   *  are attenuated (strict-subset). Async because the engine initializes
   *  lazily; `attenuate()` on the returned scope is synchronous. The Developer
   *  Edition governs the tree up to depth {@link DE_MAX_DEPTH}. */
  async scope(opts: ScopeOptions = {}): Promise<Scope> {
    const eng = this._backend.engine();
    if (!eng) {
      throw new Error(
        "sub-agent attenuation runs in-process; with WATCHLIGHT_APDP_URL set it is " +
          "enforced by the control plane server-side. Use the Enterprise API for networked attenuation."
      );
    }
    const engine = await eng;
    const root = new Scope({
      engine,
      auditPath: this._auditPath,
      agent: this.agent,
      allowedTools: norm(opts.tools),
      allowedResources: norm(opts.resources),
      allowedIntents: norm(opts.intents),
      maxDepth: Math.min(opts.maxDepth ?? DE_MAX_DEPTH, DE_MAX_DEPTH),
      timeBudgetSeconds: opts.timeBudgetSeconds ?? 3600,
      depth: 0,
    });
    root.emitRoot();
    return root;
  }

  // ── governing tools ───────────────────────────────────────────────

  /**
   * Wrap a function as a governed tool with the given `intent`. On every call
   * the engine authorizes `(agent, intent, tool/<name>)`. On ALLOW the function
   * runs; on anything else a {@link Denied} is thrown and the body never
   * executes. The returned function is async.
   */
  tool<A extends unknown[], R>(
    fn: (...args: A) => R,
    opts: {
      intent: string;
      /** Acting principal, e.g. `User::"u1"` — value or `(args) => value`.
       *  Defaults to the agent. */
      principal?: Binding<A>;
      /** Cedar resource entity — value or `(args) => value`. Defaults to
       *  `tool/<name>`. */
      resource?: Binding<A>;
      /** Attributes for Cedar `context.*` — object or `(args) => object`. */
      context?: ContextBinding<A>;
      /** Human-in-the-loop hook. Called when the decision is `NeedsApproval`;
       *  return `true` to proceed (records an approval), `false`/absent to hold
       *  (throws `NeedsApproval`). */
      onNeedsApproval?: (info: {
        intent: string;
        resource: string;
        principal: string;
        decisionId?: string;
        reason: string;
      }) => boolean | Promise<boolean>;
    }
  ): Governed<A, R> {
    const intent = opts.intent;
    const name = fn.name || "anonymous";
    return async (...args: A): Promise<Awaited<R>> => {
      const principal = resolveBinding(opts.principal, args) ?? this.agent;
      const resource = resolveBinding(opts.resource, args) ?? `tool/${name}`;
      const context =
        typeof opts.context === "function" ? opts.context(...args) : opts.context ?? {};

      const d = await this.authorize({ principal, action: intent, resource, context });
      if (d.allowed) return (await fn(...args)) as Awaited<R>;
      if (d.needsApproval) {
        if (opts.onNeedsApproval) {
          const ok = await opts.onNeedsApproval({
            intent,
            resource,
            principal,
            decisionId: d.decisionId,
            reason: d.reason,
          });
          if (ok) {
            const token = this.mintApproval({ principal, action: intent, resource });
            const d2 = await this.authorize({ principal, action: intent, resource, context, approval: token });
            if (d2.allowed) return (await fn(...args)) as Awaited<R>;
          }
        }
        throw new NeedsApproval(name, intent, d.decisionId, d.reason);
      }
      throw new Denied(name, intent, d.reason || DENY_REASON);
    };
  }

  /**
   * Authorize a raw `(intent, tool)` pair, audit the decision, and return it.
   * Fail-closed. Used by framework adapters (e.g. the Claude Agent SDK hooks)
   * that gate tool calls themselves rather than wrapping the function — the
   * decision is identical to {@link tool}, just without running a body.
   */
  async check(
    intent: string,
    toolName: string
  ): Promise<{ allowed: boolean; decision: string; reason: string; decisionId?: string }> {
    const d = await this.authorize({ action: intent, resource: `tool/${toolName}` });
    return { allowed: d.allowed, decision: d.decision, reason: d.reason, decisionId: d.decisionId };
  }

  /**
   * Authorize an action with full control — per-call `principal`, `resource`,
   * and Cedar `context` — and get a correlation id back. The low-level primitive
   * behind {@link tool}; use it directly for any consequential action.
   *
   * Returns a three-state verdict: `Allow` / `Deny` / `NeedsApproval`. A
   * `NeedsApproval` (matched permit annotated `require_approval`) is downgraded
   * to `Allow` when a valid single-use `approval` token — from
   * {@link mintApproval}, minted after a human confirms — is supplied.
   * Fail-closed and audited (value-free).
   */
  async authorize(req: {
    action: string;
    principal?: string;
    resource?: string;
    context?: Record<string, unknown>;
    /** A token from {@link mintApproval} (after human confirmation). */
    approval?: string;
  }): Promise<AuthorizeResult> {
    const { result, principal, resource, decisionId } = await this._decide(req);
    this._audit(req.action, resource, result.decision, result.reason, {
      principal,
      decisionId,
      approved: result.approved,
    });
    return result;
  }

  /**
   * The pure decision core behind {@link authorize}: run the engine, apply the
   * approval-token downgrade, and compute the three-state verdict — WITHOUT
   * writing to the audit trail. Used by {@link authorize} (which then audits)
   * and by {@link test} (which must not pollute the trail with fixture runs).
   */
  private async _decide(req: {
    action: string;
    principal?: string;
    resource?: string;
    context?: Record<string, unknown>;
    approval?: string;
  }): Promise<{
    result: AuthorizeResult;
    principal: string;
    resource: string;
    decisionId?: string;
  }> {
    const principal = req.principal ?? this.agent;
    const resource = req.resource ?? "resource";
    const raw = await this._backend.authorize({
      principal,
      action: req.action,
      resource,
      context: req.context ?? {},
    });
    let allowed = raw.decision === "Allow";
    let needsApproval = allowed && !!raw.needsApproval;
    let approved = false;
    if (needsApproval) {
      if (req.approval && consumeApprovalToken(req.approval, principal, req.action, resource)) {
        approved = true;
        needsApproval = false; // human-confirmed → proceed
      } else {
        allowed = false; // hold for approval
      }
    }
    const decision: AuthorizeResult["decision"] = allowed
      ? "Allow"
      : needsApproval
        ? "NeedsApproval"
        : "Deny";
    return {
      result: {
        decision,
        allowed,
        needsApproval,
        approved,
        decisionId: raw.decisionId,
        // Non-revealing, uniform reason (never the engine's specific one).
        reason: reasonForVerdict(decision),
      },
      principal,
      resource,
      decisionId: raw.decisionId,
    };
  }

  /**
   * Run a list of policy fixtures against the loaded policies and report which
   * pass — a golden-test harness for CI, so a policy change is verified before
   * it gates real actions. Each case asserts the expected verdict
   * (`Allow` / `Deny` / `NeedsApproval`) for a `(principal, action, resource,
   * context)`; set `approved: true` to mint a valid approval token and assert
   * the human-confirmed downgrade. Does NOT write to the audit trail. A verdict
   * mismatch is a failed result (inspect `report.failed` and assert on it in
   * your test runner); a malformed fixture missing `action`/`expect` throws.
   */
  async test(cases: readonly PolicyTestCase[]): Promise<PolicyTestReport> {
    return runPolicyTests(
      (req) => this._decide(req).then((d) => d.result),
      (challenge) => this.mintApproval(challenge),
      cases
    );
  }

  /**
   * Mint a single-use approval token for a specific `(principal, action,
   * resource)`, to pass to {@link authorize} after a human confirms a
   * `NeedsApproval` decision. Local HMAC, TTL-bounded (default 2 min). In
   * Enterprise these are KMS-signed and recorded in signed lineage.
   */
  mintApproval(
    challenge: { action: string; principal?: string; resource?: string },
    opts: { ttlMs?: number } = {}
  ): string {
    return mintApprovalToken(
      challenge.principal ?? this.agent,
      challenge.action,
      challenge.resource ?? "resource",
      opts.ttlMs ?? 120_000
    );
  }

  /**
   * Strip PII from text before an agent reads it (governed data minimization).
   * Deterministic, fail-closed. Writes a value-free `sanitization` record to the
   * audit trail (counts by PII type + mode — never the values) and returns the
   * redacted text plus the report. Operates on extracted text — extract a
   * document to text first (never hand the agent a "redacted PDF").
   */
  sanitize(
    content: string,
    opts: SanitizeOptions & { intent?: string; resource?: string } = {}
  ): SanitizeResult {
    const { intent = "read", resource = "document", mode, types } = opts;
    const result = sanitizeText(content, { mode, types });
    this._auditSanitize(intent, resource, result);
    return result;
  }

  // ── internals ─────────────────────────────────────────────────────

  private _auditSanitize(intent: string, resource: string, result: SanitizeResult): void {
    this._announce();
    const { report } = result;
    // eslint-disable-next-line no-console
    console.log(
      `watchlight: SANIT ${intent.padEnd(9)} ${resource}     redacted ${report.total} (${report.mode})`
    );
    // Value-free: counts by PII type + mode only — never the PII values.
    const record = {
      ts: new Date().toISOString(),
      agent: this.agent,
      intent,
      event: "sanitization",
      resource,
      mode: report.mode,
      detector: report.detectorVersion,
      counts: report.counts,
      total: report.total,
    };
    try {
      fs.mkdirSync(path.dirname(this._auditPath), { recursive: true });
      fs.appendFileSync(this._auditPath, JSON.stringify(record) + "\n", "utf8");
    } catch {
      // Best-effort in dev mode.
    }
  }

  private _announce(): void {
    if (!this._announced) {
      // eslint-disable-next-line no-console
      console.log(`watchlight: governing '${this.agent}' (${this._backend.label})`);
      this._announced = true;
    }
  }

  private _audit(
    intent: string,
    resource: string,
    decision: string,
    reason: string,
    extra: { principal?: string; decisionId?: string; approved?: boolean } = {}
  ): void {
    this._announce();
    const tag =
      decision === "Allow" ? (extra.approved ? "OK✓" : "ALLOW") : decision === "NeedsApproval" ? "APPRV?" : "DENY";
    const trailer = decision === "Allow" ? "" : `     ${reason || DENY_REASON}`;
    // eslint-disable-next-line no-console
    console.log(`watchlight: ${tag.padEnd(6)} ${intent.padEnd(9)} ${resource}${trailer}`);
    // Value-free audit: argument VALUES never enter the trail — only the
    // governance decision + correlation id. Mirrors the production audit contract.
    const record: Record<string, unknown> = {
      ts: new Date().toISOString(),
      agent: this.agent,
      principal: extra.principal ?? this.agent,
      intent,
      resource,
      decision,
    };
    if (extra.decisionId) record.decision_id = extra.decisionId;
    if (extra.approved) record.approved = true;
    try {
      fs.mkdirSync(path.dirname(this._auditPath), { recursive: true });
      fs.appendFileSync(this._auditPath, JSON.stringify(record) + "\n", "utf8");
    } catch {
      // Audit is best-effort in dev mode; never let it break the app.
    }
  }
}

/** A ready-to-use default governor so `import { govern } from "@watchlight/sdk"`
 *  just works. Starts with NO policies — fail-closed — until you `govern.load()`
 *  a file or `govern.allow()` a policy inline. */
export const govern = new Watchlight();
