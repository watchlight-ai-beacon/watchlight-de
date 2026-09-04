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
import { AuditTrail } from "./audit";

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
const nodeId = (): string => crypto.randomBytes(4).toString("hex");

export interface AttenuateOptions {
  tools?: readonly string[];
  resources?: readonly string[];
  intents?: readonly string[];
  timeBudgetSeconds?: number;
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
  }

  /**
   * Derive a sub-agent scope — a strict subset of this one. Any dimension you
   * omit inherits the parent's (and the engine clamps it regardless). Throws
   * {@link AttenuationDenied} if the request exceeds the parent, and
   * {@link DevEditionCeiling} at the Developer-Edition depth ceiling.
   */
  attenuate(opts: AttenuateOptions = {}): Scope {
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
    decision: string;
    depth: number;
    reason?: string;
  }): void {
    // Value-free by construction — a scope's dimensions are capability NAMES,
    // never argument values. Shape matches Python's audit tree records.
    const record: Record<string, unknown> = {
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
