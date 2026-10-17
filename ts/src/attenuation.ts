// Sub-agent scope attenuation — the TS mirror of Python `watchlight.attenuation`.
//
// A Scope is a capability set that can spawn strictly-narrower child scopes. Any
// dimension a child requests that the parent does not hold is denied by the real
// engine strict-subset validator (@watchlight/engine), and every attenuation is
// written to the value-free audit trail. Every tree is bounded by its
// maxDelegationDepth — a governance control (default 8); a hop past it is a deny
// with reason code DELEGATION_DEPTH_EXCEEDED.
//
// A child's timeBudgetSeconds is granted exactly or refused, never shortened. A
// child that names none inherits the whole seconds its parent has left
// (Scope.remainingSeconds()); a named budget larger than that, or than the
// parent's own budget, is refused with a TimeBudget violation.

import * as crypto from "node:crypto";
import type { Engine, GrantedScope, RequestedScope } from "@watchlight/engine";
import * as path from "node:path";
import { AuditTrail, type AttenuationRecord, type WritableAuditRecord } from "./audit";
import { assertActorChain, assertAgentNameRules, assertNameList } from "./principals";
import {
  MAX_CHAIN_LENGTH,
  ScopeTokenError,
  nowSeconds,
  signingSecret,
  signScopeToken,
  type ScopeRootClaim,
  type ScopeStepClaim,
  type ScopeTokenClaims,
} from "./scope-token";

/** Default `maxDelegationDepth`: how many attenuation hops a sub-agent tree may go
 *  below its root (depth 0). A governance control, not an edition limit. */
export const DEFAULT_MAX_DELEGATION_DEPTH = 8;

/** Reason code on a refused attenuation that would exceed `maxDelegationDepth`. */
export const DELEGATION_DEPTH_EXCEEDED = "DELEGATION_DEPTH_EXCEEDED" as const;

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

/** Thrown when an attenuation would take a sub-agent tree deeper than its
 *  `maxDelegationDepth`. A deny like any other refused attenuation — the child is
 *  never created — with a distinct {@link code} so it can be told apart from a
 *  scope that is not a strict subset. `depth` is the depth the refused child
 *  would have had; `limit` is the limit it exceeded. */
export class DelegationDepthExceeded extends AttenuationDenied {
  readonly code: typeof DELEGATION_DEPTH_EXCEEDED = DELEGATION_DEPTH_EXCEEDED;
  readonly depth: number;
  readonly limit: number;
  constructor(depth: number, limit: number) {
    super(["MaxDepth"], `delegation depth ${depth} exceeds max_delegation_depth ${limit}`);
    this.name = "DelegationDepthExceeded";
    this.depth = depth;
    this.limit = limit;
  }
}

const norm = (x?: readonly string[] | null): string[] => (x ? [...x] : []);

/** The largest time budget the engine accepts (an unsigned 32-bit count of seconds). */
export const MAX_TIME_BUDGET_SECONDS = 2 ** 32 - 1;

/** The fixed reason for a named time budget the parent cannot give. It states
 *  only the whole seconds available, never the requested value. */
function budgetRefusal(available: number): string {
  if (available <= 0) return "the parent scope has less than one second left; at most 0 seconds are available";
  return `time_budget_seconds exceeds the parent's remaining time; at most ${available} seconds are available`;
}

/** Whether `value` is a whole number of seconds the engine accepts. */
const isEngineBudget = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= MAX_TIME_BUDGET_SECONDS;

/** A root scope's time budget: a whole number of seconds from 1 to
 *  {@link MAX_TIME_BUDGET_SECONDS}. Value-free `TypeError` or `RangeError`
 *  otherwise, so a root can never start spent, negative or unbounded. */
export function checkRootTimeBudget(timeBudgetSeconds: unknown): number {
  if (typeof timeBudgetSeconds !== "number" || !Number.isInteger(timeBudgetSeconds)) {
    throw new TypeError("timeBudgetSeconds must be an integer");
  }
  if (timeBudgetSeconds < 1 || timeBudgetSeconds > MAX_TIME_BUDGET_SECONDS) {
    throw new RangeError(`timeBudgetSeconds must be from 1 to ${MAX_TIME_BUDGET_SECONDS}`);
  }
  return timeBudgetSeconds;
}

/** The bounds on a child scope's request (see `principals.ts`): each list
 *  bounded in entries and bytes, the sub-agent's name a valid agent name, and
 *  the chain it extends within `MAX_ACTOR_CHAIN_BYTES`. Value-free `TypeError`;
 *  nothing is decided or recorded. */
function checkRequest(opts: AttenuateOptions, chain: readonly string[], where: string): AttenuateOptions {
  // The checked arrays replace the caller's: each iterable is read exactly once.
  const checked: AttenuateOptions = {
    ...opts,
    tools: assertNameList(opts.tools, "tools"),
    resources: assertNameList(opts.resources, "resources"),
    intents: assertNameList(opts.intents, "intents"),
  };
  if (opts.agent !== undefined && opts.agent !== null && opts.agent !== "") {
    assertAgentNameRules(opts.agent, where);
    assertActorChain([...chain, opts.agent], where);
  }
  return checked;
}
/** Fixed message for a spent scope (never carries scope or token details). */
const EXPIRED_SCOPE = "scope has expired";
const nodeId = (): string => crypto.randomBytes(4).toString("hex");

/** An attenuation record's `resource`: the sub-agent the scope is for, when one
 *  is named, else the depth. */
const scopeLabel = (depth: number, agent?: string): string =>
  agent ? `scope for ${agent}` : `sub-agent depth ${depth}`;

/** The dimensions an attenuation is checked against — a {@link Scope}'s or a
 *  {@link ScopePreview}'s. */
interface ScopeDims {
  readonly allowedTools: readonly string[];
  readonly allowedResources: readonly string[];
  readonly allowedIntents: readonly string[];
  readonly maxDepth: number;
  readonly timeBudgetSeconds: number;
  readonly depth: number;
  readonly maxDelegationDepth: number;
}

type AttenuationOutcome =
  | { kind: "depth"; requestedTools: string[]; childDepth: number }
  | { kind: "deny"; requestedTools: string[]; childDepth: number; violations: string[]; reason: string }
  | {
      kind: "allow";
      childDepth: number;
      grant: {
        allowedTools: string[];
        allowedResources: string[];
        allowedIntents: string[];
        maxDepth: number;
        timeBudgetSeconds: number;
        depth: number;
      };
    };

/** Run the engine's strict-subset check for a child of `p`. Creates and records
 *  nothing: the one decision both {@link Scope.attenuate} and the previews act
 *  on, so the two cannot disagree.
 *
 *  `available` is the whole seconds the parent can still give (see
 *  {@link Scope.remainingSeconds}). A budget the child NAMES is granted exactly
 *  or refused, never shortened: one above `available` is refused with a
 *  `TimeBudget` violation. A budget the child omits inherits `available`. A
 *  parent with no whole second left grants nothing. */
function attenuationOutcome(
  engine: Engine,
  p: ScopeDims,
  opts: AttenuateOptions,
  available: number
): AttenuationOutcome {
  const childDepth = p.depth + 1;
  const requestedTools = opts.tools !== undefined ? norm(opts.tools) : [...p.allowedTools];

  // maxDelegationDepth — a governance control, checked before the engine.
  if (childDepth > p.maxDelegationDepth) return { kind: "depth", requestedTools, childDepth };

  // A parent with no whole second left can give no time, named or inherited.
  if (available <= 0) {
    return { kind: "deny", requestedTools, childDepth, violations: ["TimeBudget"], reason: budgetRefusal(0) };
  }

  // A named budget larger than the parent can give — more than it has left, or
  // more than its own budget — is refused before the engine, with a reason that
  // states the seconds available. Anything that is not a whole number of
  // seconds in the engine's range is left to the engine, which refuses it.
  const named = opts.timeBudgetSeconds;
  if (isEngineBudget(named) && named > available) {
    return { kind: "deny", requestedTools, childDepth, violations: ["TimeBudget"], reason: budgetRefusal(available) };
  }

  const parent: GrantedScope = {
    allowed_tools: [...p.allowedTools],
    allowed_resources: p.allowedResources.map((matcher) => ({ matcher })),
    allowed_intents: [...p.allowedIntents],
    max_depth: p.maxDepth,
    time_budget_seconds: p.timeBudgetSeconds,
    depth: p.depth,
  };
  const request: RequestedScope = {
    allowed_tools: requestedTools,
    allowed_resources: (opts.resources !== undefined ? norm(opts.resources) : [...p.allowedResources]).map(
      (matcher) => ({ matcher })
    ),
    allowed_intents: opts.intents !== undefined ? norm(opts.intents) : [...p.allowedIntents],
    max_depth: Math.max(0, p.maxDepth - 1),
    // An absent budget inherits what the parent has left; a named one is passed
    // as given, so the engine checks its type and the widening.
    time_budget_seconds: opts.timeBudgetSeconds !== undefined ? opts.timeBudgetSeconds : available,
  };

  const resp = engine.attenuateScope(parent, request);
  if (resp.decision !== "Allow") {
    const violations = "violations" in resp ? resp.violations : [];
    // The engine's own depth budget is spent — the same deny.
    if (violations.includes("MaxDepth") && p.maxDepth <= 0) return { kind: "depth", requestedTools, childDepth };
    const reason =
      ("reason" in resp && resp.reason) || "requested scope is not a strict subset of the parent";
    return { kind: "deny", requestedTools, childDepth, violations, reason };
  }

  // The engine returns the CLAMPED grant — never the child's raw request.
  const granted = resp.granted_scope;
  const grantedBudget = granted.time_budget_seconds ?? request.time_budget_seconds;
  // The engine compares a budget with the parent's GRANTED budget only. A named
  // budget must also fit in the time the parent has left: it is refused, never
  // shortened, so a child never starts work sized for time it does not have. A
  // named budget's grant must be exactly what was named, and no grant may
  // exceed what the parent has left.
  const namedChanged = opts.timeBudgetSeconds !== undefined && grantedBudget !== opts.timeBudgetSeconds;
  if (namedChanged || grantedBudget > available) {
    return { kind: "deny", requestedTools, childDepth, violations: ["TimeBudget"], reason: budgetRefusal(available) };
  }
  return {
    kind: "allow",
    childDepth,
    grant: {
      allowedTools: granted.allowed_tools ?? request.allowed_tools,
      allowedResources: (granted.allowed_resources ?? request.allowed_resources).map((r) =>
        typeof r === "string" ? r : r.matcher
      ),
      allowedIntents: granted.allowed_intents ?? request.allowed_intents,
      maxDepth: granted.max_depth ?? request.max_depth,
      timeBudgetSeconds: grantedBudget,
      depth: granted.depth ?? childDepth,
    },
  };
}

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
  /** The deepest any scope in this tree may be (the root is depth 0). Set on the
   *  root from the governor's `maxDelegationDepth`; children inherit it.
   *  Defaults to `depth + maxDepth`. */
  maxDelegationDepth?: number;
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
   *  `maxDelegationDepth + 1` long. */
  readonly actorChain: readonly string[];
  /** The deepest any scope in this tree may be (the root is depth 0) — the
   *  governor's `maxDelegationDepth`, or lower when the root scope set one. */
  readonly maxDelegationDepth: number;
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
    // Never past the structural bound, however the scope was constructed.
    this.maxDelegationDepth = Math.min(init.maxDelegationDepth ?? init.depth + init.maxDepth, MAX_CHAIN_LENGTH);
    this.nodeId = nodeId();
    this.parentId = init.parentId;
    this.actorChain = Object.freeze([...(init.actorChain ?? [init.agent])]);
    this._parent = init.parent;
    this._signingSecrets = init.signingSecrets;
    this.issuedAt = init.issuedAt ?? nowSeconds();
    this._expiresAt = this.issuedAt + this.timeBudgetSeconds;
    // An invariant, not a clamp: attenuate() grants a child no more than the
    // whole seconds its parent has left, so a child's expiry is never past its
    // parent's. Kept so a scope can never outlive its parent however it was
    // constructed.
    if (init.parent) this._expiresAt = Math.min(this._expiresAt, init.parent.expiresAt);
  }

  /** Epoch seconds after which this scope is spent: `issuedAt + timeBudgetSeconds`,
   *  never past the parent's expiry (and, for a scope rebuilt from a token,
   *  never past the token's `exp`). */
  get expiresAt(): number {
    return this._expiresAt;
  }

  /** The whole seconds this scope can still give a child: the time left before
   *  {@link expiresAt} on the wall clock, rounded down, and never more than
   *  {@link timeBudgetSeconds}. `0` once less than one second is left. With 2.9
   *  seconds left, 2 are available.
   *
   *  This is what a child that names no `timeBudgetSeconds` inherits, and the
   *  most a child may name: a larger named budget is refused, never shortened. */
  remainingSeconds(): number {
    return this._availableAt(Date.now() / 1000);
  }

  private _availableAt(now: number): number {
    const left = Math.floor(this._expiresAt - now);
    return Math.max(0, Math.min(this.timeBudgetSeconds, left));
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
   * {@link AttenuationDenied} if the request exceeds the parent — or
   * {@link DelegationDepthExceeded}, a subclass, when the child would be deeper
   * than {@link maxDelegationDepth}.
   *
   * `timeBudgetSeconds` is granted exactly or refused, never shortened. Omit it
   * to inherit this scope's {@link remainingSeconds}. A named budget larger
   * than {@link remainingSeconds} (or than this scope's own budget) throws
   * {@link AttenuationDenied} with a `TimeBudget` violation whose reason states
   * the seconds available. A spent scope throws {@link ScopeTokenError}
   * (`expired`), and one with less than a second left grants nothing either.
   */
  attenuate(opts: AttenuateOptions = {}): Scope {
    return this._attenuateAt(opts, undefined);
  }

  /** @internal {@link attenuate} at the wall-clock instant `now` (epoch
   *  seconds; `undefined`: the current time). Only a token replay pins it, so
   *  every level of the chain is checked at the one instant the replayed root
   *  was issued. */
  _attenuateAt(opts: AttenuateOptions, now: number | undefined): Scope {
    this.assertActive(); // a spent scope grants nothing further (fail-closed)
    const at = now ?? Date.now() / 1000;
    // Bounded before the engine and before any record: the requested tools, the
    // sub-agent's name and the chain it extends are all written down.
    opts = checkRequest(opts, this.actorChain, "attenuate()");
    // A named sub-agent's records carry the chain it would act under.
    const named = opts.agent ? [...this.actorChain, opts.agent] : undefined;
    const out = attenuationOutcome(this._engine, this, opts, this._availableAt(at));
    // A hop past maxDelegationDepth is a deny: the child is never created.
    if (out.kind === "depth") return this._denyDepth(out.requestedTools, out.childDepth, opts.agent);
    if (out.kind === "deny") {
      this._record({
        nodeId: nodeId(),
        parentId: this.nodeId,
        tools: out.requestedTools,
        resource: scopeLabel(out.childDepth, opts.agent),
        decision: "Deny",
        depth: out.childDepth,
        reason: out.reason,
        actorChain: named,
      });
      throw new AttenuationDenied(out.violations, out.reason);
    }

    const g = out.grant;
    const child = new Scope({
      engine: this._engine,
      audit: this._audit,
      agent: this.agent,
      allowedTools: g.allowedTools,
      allowedResources: g.allowedResources,
      allowedIntents: g.allowedIntents,
      maxDepth: g.maxDepth,
      timeBudgetSeconds: g.timeBudgetSeconds,
      depth: g.depth,
      maxDelegationDepth: this.maxDelegationDepth,
      parentId: this.nodeId,
      parent: this,
      signingSecrets: this._signingSecrets,
      // Issued at the instant its budget was checked against the parent.
      issuedAt: Math.floor(at),
      // Naming the sub-agent this scope is spawned for extends the delegation
      // chain; narrowing without a name leaves the acting identity unchanged.
      actorChain: named ?? this.actorChain,
    });
    this._record({
      nodeId: child.nodeId,
      parentId: this.nodeId,
      tools: child.allowedTools,
      resource: scopeLabel(child.depth, opts.agent),
      decision: "Allow",
      depth: child.depth,
      actorChain: named,
    });
    return child;
  }

  /**
   * What {@link attenuate} would grant, without granting it or recording
   * anything — for showing a sub-agent's effective authority. Runs the same
   * engine check and returns a {@link ScopePreview}: the clamped grant, or the
   * violations and reason it would be refused with. A preview is data, never a
   * scope: it cannot authorize, delegate, or mint a token.
   */
  previewAttenuate(opts: AttenuateOptions = {}): ScopePreview {
    this.assertActive();
    opts = checkRequest(opts, this.actorChain, "previewAttenuate()");
    return previewChild(this._engine, this, this.actorChain, opts, this.remainingSeconds());
  }

  /** Refuse a hop past {@link maxDelegationDepth}: record the deny — the observed
   *  depth and the limit — then throw. The child is never created. */
  private _denyDepth(requestedTools: readonly string[], childDepth: number, agent?: string): never {
    const err = new DelegationDepthExceeded(childDepth, this.maxDelegationDepth);
    this._record({
      nodeId: nodeId(),
      parentId: this.nodeId,
      tools: requestedTools,
      resource: scopeLabel(childDepth, agent),
      decision: "Deny",
      depth: childDepth,
      reason: err.reason,
      reasonCode: DELEGATION_DEPTH_EXCEEDED,
      maxDelegationDepth: this.maxDelegationDepth,
      actorChain: agent ? [...this.actorChain, agent] : undefined,
    });
    throw err;
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
    reasonCode?: typeof DELEGATION_DEPTH_EXCEEDED;
    maxDelegationDepth?: number;
    actorChain?: readonly string[];
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
    if (r.reasonCode) record.reason_code = r.reasonCode;
    if (r.maxDelegationDepth !== undefined) record.max_delegation_depth = r.maxDelegationDepth;
    // The named sub-agent the scope is for, and the chain it acts under.
    if (r.actorChain && r.actorChain.length) record.actor_chain = [...r.actorChain];
    // One funnel: the governor's file + optional sink (see ./audit.ts).
    this._audit.write(record);
  }
}

interface ScopePreviewInit {
  engine: Engine;
  allowed: boolean;
  allowedTools: readonly string[];
  allowedResources: readonly string[];
  allowedIntents: readonly string[];
  maxDepth: number;
  timeBudgetSeconds: number;
  depth: number;
  maxDelegationDepth: number;
  actorChain: readonly string[];
  violations?: readonly string[];
  reason?: string;
  reasonCode?: typeof DELEGATION_DEPTH_EXCEEDED;
}

/**
 * What a scope would be granted — the engine's answer, as data, with nothing
 * recorded.
 *
 * Returned by {@link Watchlight.previewScope} and {@link Scope.previewAttenuate},
 * for showing an agent's effective authority without writing to the audit
 * trail. It runs the same engine strict-subset check as {@link Scope.attenuate},
 * but it is not a grant: it has no `attenuate`, cannot authorize, delegate or
 * mint a token, and nothing is recorded. {@link previewAttenuate} previews the
 * next level down.
 *
 * `allowed` says whether the scope would be granted. When it would not,
 * `violations` and `reason` say why (`reasonCode` is `DELEGATION_DEPTH_EXCEEDED`
 * for a hop past the depth limit) and `allowedTools` is the requested set.
 */
export class ScopePreview {
  readonly allowed: boolean;
  readonly allowedTools: readonly string[];
  readonly allowedResources: readonly string[];
  readonly allowedIntents: readonly string[];
  readonly maxDepth: number;
  readonly timeBudgetSeconds: number;
  readonly depth: number;
  readonly maxDelegationDepth: number;
  readonly actorChain: readonly string[];
  readonly violations: readonly string[];
  readonly reason: string;
  readonly reasonCode?: typeof DELEGATION_DEPTH_EXCEEDED;
  private readonly _engine: Engine;

  /** @internal Built by {@link Watchlight.previewScope} and the previews. */
  constructor(init: ScopePreviewInit) {
    this._engine = init.engine;
    this.allowed = init.allowed;
    this.allowedTools = Object.freeze(norm(init.allowedTools));
    this.allowedResources = Object.freeze(norm(init.allowedResources));
    this.allowedIntents = Object.freeze(norm(init.allowedIntents));
    this.maxDepth = init.maxDepth;
    this.timeBudgetSeconds = init.timeBudgetSeconds;
    this.depth = init.depth;
    this.maxDelegationDepth = Math.min(init.maxDelegationDepth, MAX_CHAIN_LENGTH);
    this.actorChain = Object.freeze([...init.actorChain]);
    this.violations = Object.freeze([...(init.violations ?? [])]);
    this.reason = init.reason ?? "";
    this.reasonCode = init.reasonCode;
  }

  /** Preview the next level down, exactly as {@link Scope.attenuate} would
   *  decide it. Below a preview that would be refused, nothing would be granted
   *  either. */
  previewAttenuate(opts: AttenuateOptions = {}): ScopePreview {
    opts = checkRequest(opts, this.actorChain, "previewAttenuate()");
    if (!this.allowed) {
      return new ScopePreview({
        engine: this._engine,
        allowed: false,
        allowedTools: opts.tools !== undefined ? norm(opts.tools) : this.allowedTools,
        allowedResources: [],
        allowedIntents: [],
        maxDepth: 0,
        timeBudgetSeconds: 0,
        depth: this.depth + 1,
        maxDelegationDepth: this.maxDelegationDepth,
        actorChain: opts.agent ? [...this.actorChain, opts.agent] : this.actorChain,
        violations: this.violations,
        reason: "its parent scope would not be granted",
        reasonCode: this.reasonCode,
      });
    }
    // A preview was never issued, so no time has passed for it: it can give its
    // whole budget.
    return previewChild(this._engine, this, this.actorChain, opts, this.timeBudgetSeconds);
  }

  /** The preview as plain data — what `JSON.stringify` writes. */
  toJSON(): Record<string, unknown> {
    const out: Record<string, unknown> = {
      allowed: this.allowed,
      tools: [...this.allowedTools],
      resources: [...this.allowedResources],
      intents: [...this.allowedIntents],
      depth: this.depth,
      max_depth: this.maxDepth,
      time_budget_seconds: this.timeBudgetSeconds,
      actor_chain: [...this.actorChain],
    };
    if (!this.allowed) {
      out.violations = [...this.violations];
      out.reason = this.reason;
      if (this.reasonCode) out.reason_code = this.reasonCode;
    }
    return out;
  }
}

/** The {@link ScopePreview} of a child of `p` — nothing recorded. */
function previewChild(
  engine: Engine,
  p: ScopeDims,
  chain: readonly string[],
  opts: AttenuateOptions,
  available: number
): ScopePreview {
  const out = attenuationOutcome(engine, p, opts, available);
  const actorChain = opts.agent ? [...chain, opts.agent] : chain;
  if (out.kind === "allow") {
    const g = out.grant;
    return new ScopePreview({
      engine,
      allowed: true,
      allowedTools: g.allowedTools,
      allowedResources: g.allowedResources,
      allowedIntents: g.allowedIntents,
      maxDepth: g.maxDepth,
      timeBudgetSeconds: g.timeBudgetSeconds,
      depth: g.depth,
      maxDelegationDepth: p.maxDelegationDepth,
      actorChain,
    });
  }
  const depthErr = out.kind === "depth" ? new DelegationDepthExceeded(out.childDepth, p.maxDelegationDepth) : undefined;
  return new ScopePreview({
    engine,
    allowed: false,
    allowedTools: out.requestedTools,
    allowedResources: [],
    allowedIntents: [],
    maxDepth: 0,
    timeBudgetSeconds: 0,
    depth: out.childDepth,
    maxDelegationDepth: p.maxDelegationDepth,
    actorChain,
    violations: depthErr ? depthErr.violations : out.kind === "deny" ? out.violations : [],
    reason: depthErr ? depthErr.reason : out.kind === "deny" ? out.reason : "",
    reasonCode: depthErr ? DELEGATION_DEPTH_EXCEEDED : undefined,
  });
}
