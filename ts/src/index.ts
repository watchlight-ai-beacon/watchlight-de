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
import { Scope, DE_MAX_DEPTH } from "./attenuation";
import { selectBackend, type GovernanceBackend } from "./backend";
import { sanitize as sanitizeText, type SanitizeOptions, type SanitizeResult } from "./sanitize";

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
  tool<A extends unknown[], R>(fn: (...args: A) => R, opts: { intent: string }): Governed<A, R> {
    const intent = opts.intent;
    const name = fn.name || "anonymous";
    const resource = `tool/${name}`;
    return async (...args: A): Promise<Awaited<R>> => {
      const [decision, reason] = await this._authorize(intent, resource);
      this._audit(intent, resource, decision, reason);
      if (decision !== "Allow") {
        throw new Denied(name, intent, reason || "no matching policy");
      }
      return (await fn(...args)) as Awaited<R>;
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
  ): Promise<{ allowed: boolean; decision: string; reason: string }> {
    const resource = `tool/${toolName}`;
    const [decision, reason] = await this._authorize(intent, resource);
    this._audit(intent, resource, decision, reason);
    return { allowed: decision === "Allow", decision, reason };
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

  private async _authorize(intent: string, resource: string): Promise<[string, string]> {
    const { decision, reason } = await this._backend.authorize({
      principal: this.agent,
      action: intent,
      resource,
      context: {},
    });
    return [decision, reason];
  }

  private _announce(): void {
    if (!this._announced) {
      // eslint-disable-next-line no-console
      console.log(`watchlight: governing '${this.agent}' (${this._backend.label})`);
      this._announced = true;
    }
  }

  private _audit(intent: string, resource: string, decision: string, reason: string): void {
    this._announce();
    const allowed = decision === "Allow";
    const tag = allowed ? "ALLOW" : "DENY";
    const trailer = allowed ? "" : `     ${reason || "no matching policy"}`;
    // eslint-disable-next-line no-console
    console.log(`watchlight: ${tag.padEnd(5)} ${intent.padEnd(9)} ${resource}${trailer}`);
    // Value-free audit: argument VALUES never enter the trail — only the
    // governance decision. Mirrors the production audit contract.
    const record = {
      ts: new Date().toISOString(),
      agent: this.agent,
      intent,
      resource,
      decision,
    };
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
