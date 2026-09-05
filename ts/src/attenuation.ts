// Sub-agent scope attenuation — the TS mirror of Python `watchlight.attenuation`.
//
// A Scope is a capability set that can spawn strictly-narrower child scopes. Any
// dimension a child requests that the parent does not hold is denied by the real
// engine strict-subset validator (@watchlight/engine), and every attenuation is
// written to the value-free audit trail. The Developer Edition governs the tree
// up to DE_MAX_DEPTH; Enterprise removes the cap and enforces it server-side.

import * as crypto from "node:crypto";
import type { Engine, GrantedScope, RequestedScope } from "@watchlight/engine";
import * as path from "node:path";
import { AuditTrail, type AttenuationRecord, type WritableAuditRecord } from "./audit";
import {
  ScopeTokenError,
  nowSeconds,
  signingSecret,
  signScopeToken,
  type ScopeRootClaim,
  type ScopeStepClaim,
  type ScopeTokenClaims,
} from "./scope-token";

/** Developer-Edition sub-agent tree depth ceiling. */
export const DE_MAX_DEPTH = 5;

const CEILING_NOTICE = (cap: number, depth: number) =>
  `Developer Edition governs sub-agent trees up to depth ${cap}; ` +
  `requested depth ${depth}. Enterprise removes this cap and enforces it server-side.`;

/** Raised at the Developer-Edition depth ceiling. NOT a policy denial — a
 *  product boundary. Every attenuation up to the cap was a real, engine-validated
 *  strict subset. */
export class DevEditionCeiling extends Error {
  readonly depth: number;
  readonly cap: number;
  constructor(depth: number) {
    super(CEILING_NOTICE(DE_MAX_DEPTH, depth));
    this.name = "DevEditionCeiling";
    this.depth = depth;
    this.cap = DE_MAX_DEPTH;
  }
}

/** Raised when a requested child scope is not a strict subset of its parent. */
export class AttenuationDenied extends Error {
  readonly violations: string[];
  readonly reason: string;
  constructor(violations: string[], reason: string) {
    super(`sub-agent scope denied: ${reason}`);
    this.name = "AttenuationDenied";
    this.violations = violations;
    this.reason = reason;
  }
}

const norm = (x?: readonly string[] | null): string[] => (x ? [...x] : []);
/** Fixed message for a spent scope (never carries scope or token details). */
const EXPIRED_SCOPE = "scope has expired";
const nodeId = (): string => crypto.randomBytes(4).toString("hex");

export interface AttenuateOptions {
  tools?: readonly string[];
  resources?: readonly string[];
  intents?: readonly string[];
  timeBudgetSeconds?: number;
  /** The sub-agent this scope is spawned FOR. Appends that name to the child's
   *  {@link Scope.actorChain}, which is what a delegated governor
   *  ({@link Watchlight.delegate}) records and what a policy reads as
   *  `context.actor_chain`. Omit it to narrow authority without naming a new
   *  actor: the child then inherits the parent's chain unchanged. */
  agent?: string;
}

interface ScopeInit {
  engine: Engine;
  /** The governor's audit trail (file + optional sink) — shared by every scope
   *  in the tree, so attenuations report through the same `auditSink`.
   *  Preferred; when omitted a file-only trail is built from `auditPath`. */
  audit?: AuditTrail;
  /** File-only fallback for callers that construct a Scope directly. */
  auditPath?: string;
  agent: string;
  allowedTools: string[];
  allowedResources: string[];
  allowedIntents: string[];
  maxDepth: number;
  timeBudgetSeconds: number;
  depth: number;
  parentId?: string;
  /** The scope this one was attenuated from (undefined for a root). Lets
   *  {@link Scope.toToken} serialise the full chain for engine replay. */
  parent?: Scope;
  /** Signing secrets for {@link Scope.toToken}, newest first; inherited by
   *  children. The first entry signs, every entry verifies. Unset ⇒ minting
   *  fails closed. Never logged or written. */
  signingSecrets?: Uint8Array[];
  /** Epoch seconds this scope came into force (defaults to now). */
  issuedAt?: number;
  /** The ordered actor chain, root first, that a call made through this scope
   *  carries. Defaults to `[agent]` for a root. */
  actorChain?: readonly string[];
}

/** Options for {@link Scope.toToken}. */
export interface ScopeTokenOptions {
  /** Token lifetime in seconds. Defaults to — and is always capped at — the
   *  scope's remaining lifetime ({@link Scope.expiresAt}). */
  ttlSeconds?: number;
}

/** A capability scope that can spawn strictly-narrower child scopes. Create the
 *  root with {@link Watchlight.scope}; call {@link attenuate} to derive a
 *  sub-agent scope. `attenuate` is synchronous (the engine validator is sync). */
export class Scope {
  readonly agent: string;
  readonly allowedTools: string[];
  readonly allowedResources: string[];
  readonly allowedIntents: string[];
  readonly maxDepth: number;
  readonly timeBudgetSeconds: number;
  readonly depth: number;
  readonly nodeId: string;
  readonly parentId?: string;
  /** The ordered delegation chain a call made through this scope acts under,
   *  root first — `["flight-booker", "seat-picker"]` for a seat-picker spawned
   *  by a flight-booker. The last entry is the acting (leaf) agent. A root
   *  scope's chain is just the governor's agent; each {@link attenuate} that
   *  names an `agent` appends one entry, so the chain is at most
   *  `DE_MAX_DEPTH + 1` long. */
  readonly actorChain: readonly string[];
  /** Epoch seconds this scope came into force. */
  readonly issuedAt: number;
  private _expiresAt: number;
  private readonly _parent?: Scope;
  private readonly _signingSecrets?: Uint8Array[];
  private readonly _engine: Engine;
  private readonly _audit: AuditTrail;

  constructor(init: ScopeInit) {
    this._engine = init.engine;
    this._audit =
      init.audit ?? new AuditTrail(init.auditPath ?? path.join(".watchlight", "audit.jsonl"));
    this.agent = init.agent;
    this.allowedTools = norm(init.allowedTools);
    this.allowedResources = norm(init.allowedResources);
    this.allowedIntents = norm(init.allowedIntents);
    this.maxDepth = init.maxDepth;
    this.timeBudgetSeconds = init.timeBudgetSeconds;
    this.depth = init.depth;
    this.nodeId = nodeId();
    this.parentId = init.parentId;
    this.actorChain = Object.freeze([...(init.actorChain ?? [init.agent])]);
    this._parent = init.parent;
    this._signingSecrets = init.signingSecrets;
    this.issuedAt = init.issuedAt ?? nowSeconds();
    // A scope never outlives its parent, whatever its own budget says.
    this._expiresAt = this.issuedAt + this.timeBudgetSeconds;
    if (init.parent) this._expiresAt = Math.min(this._expiresAt, init.parent.expiresAt);
  }

  /** Epoch seconds after which this scope is spent: `issuedAt + timeBudgetSeconds`,
   *  clamped to the parent's expiry (and, for a scope rebuilt from a token, to
   *  the token's `exp`). */
  get expiresAt(): number {
    return this._expiresAt;
  }

  /** @internal Lower this scope's expiry (never raise it). Used when a scope is
   *  rebuilt from a token so it cannot outlive the token. */
  _bindExpiry(exp: number): void {
    this._expiresAt = Math.min(this._expiresAt, exp);
  }

  /** True once this scope is past {@link expiresAt}. */
  get expired(): boolean {
    return nowSeconds() >= this._expiresAt;
  }

  /**
   * Fail closed on a spent scope: throws {@link ScopeTokenError} (`expired`) once
   * the scope is past {@link expiresAt}. Called by {@link attenuate} and
   * {@link toToken}; call it yourself before acting under a scope you hold
   * across time (e.g. a scope rebuilt from a token in a long-running worker).
   */
  assertActive(): void {
    if (this.expired) throw new ScopeTokenError("expired", EXPIRED_SCOPE);
  }

  /** The engine-granted dimensions of this level, as a token claim. */
  private _stepClaim(): ScopeStepClaim {
    return {
      tools: [...this.allowedTools],
      resources: [...this.allowedResources],
      intents: [...this.allowedIntents],
      time_budget_seconds: this.timeBudgetSeconds,
    };
  }

  /**
   * Serialise this scope for another process: an HMAC-signed token carrying the
   * root grant and the engine-granted scope at every level down to this one.
   * The receiving `Watchlight.scopeFromToken()` verifies the signature and time
   * window, then re-runs the engine's strict-subset attenuation level by level
   * — the token is integrity across processes sharing the secret, never
   * authority. Fails closed with {@link ScopeTokenError} when no `signingSecret`
   * was configured or the scope has no remaining lifetime. The token never
   * carries argument values, audit paths, or the secret.
   */
  toToken(opts: ScopeTokenOptions = {}): string {
    // The FIRST configured secret signs; the rest exist so a token signed under
    // a previous one still verifies while it is listed.
    const secret = signingSecret(this._signingSecrets);
    this.assertActive();
    const now = nowSeconds();
    const remaining = this.expiresAt - now;
    const ttl = opts.ttlSeconds === undefined ? remaining : opts.ttlSeconds;
    if (!Number.isSafeInteger(ttl) || ttl <= 0) {
      throw new ScopeTokenError("lifetime", "ttlSeconds must be a positive integer");
    }
    const exp = Math.min(now + ttl, this.expiresAt);

    // Walk to the root, collecting each level's GRANTED dimensions.
    const levels: Scope[] = [];
    for (let s: Scope | undefined = this; s; s = s._parent) levels.unshift(s);
    const rootScope = levels[0];
    const root: ScopeRootClaim = { ...rootScope._stepClaim(), max_depth: rootScope.maxDepth };
    const chain = levels.slice(1).map((s) => s._stepClaim());
    if (chain.length !== this.depth) {
      throw new ScopeTokenError("mismatch", "scope lineage does not match its depth");
    }
    const claims: ScopeTokenClaims = { agent: this.agent, root, chain, depth: this.depth, iat: now, exp };
    return signScopeToken(claims, secret);
  }

  /**
   * Derive a sub-agent scope — a strict subset of this one. Any dimension you
   * omit inherits the parent's (and the engine clamps it regardless). Throws
   * {@link AttenuationDenied} if the request exceeds the parent, and
   * {@link DevEditionCeiling} at the Developer-Edition depth ceiling.
   */
  attenuate(opts: AttenuateOptions = {}): Scope {
    this.assertActive(); // a spent scope grants nothing further (fail-closed)
    const childDepth = this.depth + 1;
    const requestedTools = opts.tools !== undefined ? norm(opts.tools) : this.allowedTools;

    // Developer-Edition ceiling — a product boundary, checked before the engine.
    if (childDepth > DE_MAX_DEPTH) {
      this._record({
        nodeId: nodeId(),
        parentId: this.nodeId,
        tools: requestedTools,
        resource: `sub-agent depth ${childDepth}`,
        decision: "Deny",
        depth: childDepth,
        reason: CEILING_NOTICE(DE_MAX_DEPTH, childDepth),
      });
      throw new DevEditionCeiling(childDepth);
    }

    const parent: GrantedScope = {
      allowed_tools: this.allowedTools,
      allowed_resources: this.allowedResources.map((matcher) => ({ matcher })),
      allowed_intents: this.allowedIntents,
      max_depth: this.maxDepth,
      time_budget_seconds: this.timeBudgetSeconds,
      depth: this.depth,
    };
    const request: RequestedScope = {
      allowed_tools: requestedTools,
      allowed_resources: (opts.resources !== undefined ? norm(opts.resources) : this.allowedResources).map(
        (matcher) => ({ matcher })
      ),
      allowed_intents: opts.intents !== undefined ? norm(opts.intents) : this.allowedIntents,
      max_depth: Math.max(0, this.maxDepth - 1),
      time_budget_seconds:
        opts.timeBudgetSeconds !== undefined ? opts.timeBudgetSeconds : this.timeBudgetSeconds,
    };

    const resp = this._engine.attenuateScope(parent, request);
    if (resp.decision !== "Allow") {
      const violations = "violations" in resp ? resp.violations : [];
      const reason =
        ("reason" in resp && resp.reason) || "requested scope is not a strict subset of the parent";
      this._record({
        nodeId: nodeId(),
        parentId: this.nodeId,
        tools: requestedTools,
        resource: `sub-agent depth ${childDepth}`,
        decision: "Deny",
        depth: childDepth,
        reason,
      });
      throw new AttenuationDenied(violations, reason);
    }

    // The engine returns the CLAMPED grant — never the child's raw request.
    const granted = resp.granted_scope;
    const grantedResources = (granted.allowed_resources ?? request.allowed_resources).map((r) =>
      typeof r === "string" ? r : r.matcher
    );
    const child = new Scope({
      engine: this._engine,
      audit: this._audit,
      agent: this.agent,
      allowedTools: granted.allowed_tools ?? request.allowed_tools,
      allowedResources: grantedResources,
      allowedIntents: granted.allowed_intents ?? request.allowed_intents,
      maxDepth: granted.max_depth ?? request.max_depth,
      timeBudgetSeconds: granted.time_budget_seconds ?? request.time_budget_seconds,
      depth: granted.depth ?? childDepth,
      parentId: this.nodeId,
      parent: this,
      signingSecrets: this._signingSecrets,
      // Naming the sub-agent this scope is spawned for extends the delegation
      // chain; narrowing without a name leaves the acting identity unchanged.
      actorChain: opts.agent ? [...this.actorChain, opts.agent] : this.actorChain,
    });
    this._record({
      nodeId: child.nodeId,
      parentId: this.nodeId,
      tools: child.allowedTools,
      resource: `sub-agent depth ${child.depth}`,
      decision: "Allow",
      depth: child.depth,
    });
    return child;
  }

  /** Record this scope as the root of an attenuation tree (parent-less). */
  emitRoot(): void {
    this._record({
      nodeId: this.nodeId,
      parentId: undefined,
      tools: this.allowedTools,
      resource: "root scope",
      decision: "Allow",
      depth: this.depth,
    });
  }

  private _record(r: {
    nodeId: string;
    parentId?: string;
    tools: readonly string[];
    resource: string;
    decision: AttenuationRecord["decision"];
    depth: number;
    reason?: string;
  }): void {
    // Value-free by construction — a scope's dimensions are capability NAMES,
    // never argument values. Shape matches Python's audit tree records.
    const record: WritableAuditRecord<AttenuationRecord> = {
      ts: new Date().toISOString(),
      agent: this.agent,
      intent: "attenuate",
      event: "attenuation",
      node_id: r.nodeId,
      resource: r.resource,
      decision: r.decision,
      depth: r.depth,
      tools: [...r.tools],
    };
    if (r.parentId) record.parent_id = r.parentId;
    if (r.reason) record.reason = r.reason;
    // One funnel: the governor's file + optional sink (see ./audit.ts).
    this._audit.write(record);
  }
}
