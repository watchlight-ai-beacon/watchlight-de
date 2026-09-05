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
import { Scope, DE_MAX_DEPTH, type AttenuateOptions } from "./attenuation";
import { AuditTrail, type AuditSink } from "./audit";
import { ApprovalTokens, resolveApprovalKey, type ApprovalStore } from "./approval";
import {
  ScopeTokenError,
  normalizeSecret,
  requireSecret,
  sameSet,
  verifyScopeToken,
} from "./scope-token";
import {
  countAuditRecords,
  countFromSource,
  countFromSourceAsync,
  type Counters,
  type CountersOptions,
  type CounterSource,
} from "./counters";
import { AuthorizeError, selectBackend, type GovernanceBackend, type Obligations } from "./backend";
import { sanitize as sanitizeText, type SanitizeOptions, type SanitizeResult } from "./sanitize";
import { screen as screenText, type ScreenOptions, type ScreenResult } from "./screen";
import { principals } from "./principals";
import {
  runPolicyTests,
  type PolicyTestCase,
  type PolicyTestReport,
  type PolicyTestResult,
} from "./policytest";

export { Scope, DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling } from "./attenuation";
export type { AuditRecord, AuditSink } from "./audit";
export { ApprovalError, APPROVAL_KEY_LABEL, APPROVAL_PAYLOAD_VERSION, APPROVAL_MIN_SECRET_BYTES, DEFAULT_APPROVAL_STORE_TIMEOUT_MS } from "./approval";
export type { ApprovalStore, ApprovalErrorCode } from "./approval";
export type { ScopeTokenOptions, AttenuateOptions } from "./attenuation";
export { ScopeTokenError, SCOPE_TOKEN_PREFIX, MAX_TOKEN_LENGTH } from "./scope-token";
export type { ScopeTokenClaims, ScopeTokenErrorCode } from "./scope-token";
export {
  countAuditRecords,
  parseWindowSeconds,
  AuditTrailUnreadable,
  DEFAULT_COUNTERS_MAX_BYTES,
  MAX_COUNTERS_WINDOW_SECONDS,
  MAX_COUNTERS_LINE_BYTES,
  MAX_COUNTERS_NESTING,
} from "./counters";
export { CounterSourceError } from "./counters";
export type { Counters, CountersOptions, CounterOutcome, CounterWindow } from "./counters";
export type { CounterQuery, CounterSource, CounterSourceKind } from "./counters";
export { governedHooks, DEFAULT_ON_RESULT_TIMEOUT_MS } from "./claude-agent";
export type { GovernedHooksOptions, GovernedHooksResult } from "./claude-agent";
export { governTool, governTools } from "./langchain";
export type {
  LangChainToolLike,
  GovernToolOptions,
  GovernToolsOptions,
} from "./langchain";
export { sanitize, SanitizeError, DETECTOR_VERSION, DECISION_ID_MAX_LENGTH, DEFAULT_PII_TYPES, HEURISTIC_PII_TYPES } from "./sanitize";
export type {
  PiiType,
  RedactMode,
  SanitizeOptions,
  SanitizeReport,
  SanitizeResult,
} from "./sanitize";
export { principals, entityRef, policyEntityRef, escapeCedarString } from "./principals";
export { screen, ScreenError, SCREEN_DETECTOR_VERSION, SCREEN_FAMILIES } from "./screen";
export type { ScreenFamily, ScreenMode, ScreenOptions, ScreenReport, ScreenResult } from "./screen";
export type { GovernanceBackend, Decision, AuthorizeRequest } from "./backend";
export { InProcessBackend, NetworkedBackend } from "./backend";
export { runPolicyTests, loadTestSuite } from "./policytest";
export type { Obligations } from "./backend";
export { AuthorizeError };
export { OBLIGATIONS_INVALID_MESSAGE, MAX_REDACT_ENTRIES } from "./backend";
export type {
  ExpectedObligations,
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

/** What a result hook learns about the call whose result it is inspecting.
 *  `decisionId` is the SAME id written on that call's decision record, so the
 *  decision line and the `egress` line in the audit trail join on one key. */
export interface EgressInfo {
  intent: string;
  resource: string;
  principal: string;
  decisionId?: string;
  /** The obligations the decision that let the body run carries (see
   *  {@link Obligations}) — honour them here. Absent when it carries none.
   *  Populated by `tool`, `governTool` / `governTools` and the `governedHooks`
   *  `PostToolUse` hook alike. */
  obligations?: Obligations;
}

/** A hook run over a governed tool's RESULT — after the body returns, before the
 *  caller (or the model) sees it. This is where you run `sanitize`, `screen`, or
 *  a second `authorize` against the result's classification. Return a value to
 *  REPLACE the payload (e.g. a redacted copy); return `undefined` or `null`
 *  (Python: `None`) to pass it through unchanged. Throw to WITHHOLD it: the
 *  error propagates and the raw result is never handed back (fail-closed). */
export type OnResult<R> = (
  result: R,
  info: EgressInfo
) => R | void | null | Promise<R | void | null>;

/** Thrown (internally) when an egress hook outruns its deadline; the payload is
 *  withheld. Carries no payload-derived data. */
class EgressTimeout extends Error {
  constructor() {
    super("egress hook deadline exceeded");
    this.name = "EgressTimeout";
  }
}

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
  /** Constraints the permitting policies attach to this `Allow` via
   *  `@obligate_*` annotations — `redact`, `maxItems`, `logValues`, and raw
   *  `extra` keys (see {@link Obligations}). Present only on an `Allow` (an
   *  approved one included) that carries at least one obligation; never on
   *  `Deny` or `NeedsApproval`. Honour it in your code or in `onResult`. An
   *  Allow whose known obligations cannot be read rejects with
   *  {@link AuthorizeError} instead of returning. */
  obligations?: Obligations;
}

// ── approval tokens (DE: local, single-use, HMAC, TTL) ───────────────
// Minting, verification, the signing key and the seen-token store all live in
// `./approval` — including the per-process defaults and what they do NOT cover
// (a second process, a second replica). Enterprise mints these KMS-signed and
// records them in signed lineage.

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
   *  Defaults to `.watchlight`. Every governor pointed at the same directory —
   *  concurrent instances in one process included — appends to the same file,
   *  so those records interleave and are told apart only by their fields. */
  auditDir?: string;
  /** Write the local `audit.jsonl` at all. Defaults to `true`. Set `false` to
   *  make {@link WatchlightOptions.auditSink} the SOLE destination: no
   *  `.watchlight` directory and no file are created, and {@link
   *  Watchlight.counters} — which reads the local file — throws. With the file
   *  off and no sink, records have nowhere to go and the SDK says so once. */
  auditFile?: boolean;
  /** Additive destination for every audit record — decisions, sanitizations
   *  and attenuations (including those of scopes derived via {@link
   *  Watchlight.scope}). Receives a frozen copy with exactly the fields the
   *  `audit.jsonl` line carries; the local file stays on. Fire-and-forget: a
   *  returned promise is not awaited, and a throw or rejection is reported once
   *  and never blocks or changes a decision. */
  auditSink?: AuditSink;
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
  /** Shared secret (≥ 16 bytes) for {@link Scope.toToken} /
   *  {@link Watchlight.scopeFromToken} — lets an attenuated scope cross a process
   *  boundary with integrity. Defaults to `WATCHLIGHT_TOKEN_SECRET`. When unset,
   *  minting and verifying scope tokens fail closed; there is no built-in
   *  default. Never logged or written. */
  tokenSecret?: string | Uint8Array;
  /** How a call that names no `principal` is recorded. Defaults to `true`: the
   *  agent is the subject and is recorded as a TYPED entity reference,
   *  `Agent::"<name>"` (build one with {@link principals}). Set `false` to
   *  restore the previous behaviour, where the BARE agent name — untyped, and
   *  indistinguishable on sight from a user id — stood in for the missing
   *  subject; that is transitional, warns once per process, and is removed in a
   *  later version. See "Breaking in 0.8.0" in the identity model:
   *  https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md */
  strictPrincipal?: boolean;
  /** Shared secret (>= 16 bytes) that approval tokens are signed under, so a
   *  token minted in one process verifies in another and survives a redeploy
   *  inside its TTL. Defaults to `WATCHLIGHT_APPROVAL_SECRET`, then to
   *  `tokenSecret` — one secret configures both, because the approval key is
   *  `HMAC-SHA256(secret, "watchlight-de:approval-token:v1")` and never the
   *  secret itself. With nothing configured a RANDOM PER-PROCESS key is used:
   *  tokens then never cross a process boundary, and a restart invalidates
   *  every outstanding approval. A token presented to a governor holding a
   *  different key is refused exactly like an expired one — the decision stays
   *  `NeedsApproval` with the uniform `approval required` reason. Never logged
   *  or written. Shared with every view made by {@link Watchlight.as}. */
  approvalSecret?: string | Uint8Array;
  /** Where consumed approval-token ids are reserved, which is what makes an
   *  approval single-use. Defaults to an IN-PROCESS map shared by every
   *  governor in this process and by nothing else — atomic within the process
   *  (of N concurrent consumes of one token, exactly one is approved) but
   *  behind two replicas the same token can be consumed once on each. Supply a
   *  shared store ({@link ApprovalStore}) and single-use holds across every
   *  replica. Its `add(id, expiresAt)` MUST be an atomic check-and-set
   *  returning `true` when the reservation was new and `false` when the id was
   *  already present — a read followed by an unconditional write cannot enforce
   *  single use. Fail-closed: `false`, a throw, a timeout, or a non-boolean
   *  return all refuse the approval; none of them admits one. Shared with every
   *  view made by {@link Watchlight.as}. */
  approvalStore?: ApprovalStore;
  /** Read side of {@link auditSink}: where {@link Watchlight.counters} gets its
   *  number. Defaults to folding the local `audit.jsonl`. Configure it and
   *  `counters` folds your durable store instead — the same store the sink
   *  writes to — so a quota spans every replica and survives a redeploy. A
   *  source that throws, or returns anything but a non-negative integer, fails
   *  the read closed ({@link CounterSourceError}); it never falls back to the
   *  local file. An async source is read with {@link Watchlight.countersAsync}.
   *  Shared with every view made by {@link Watchlight.as}. */
  counterSource?: CounterSource;
}

/**
 * The Cedar `context` key the SDK reserves for the ACTOR — the runtime that
 * made the call, as distinct from the subject it acted for. The pair follows
 * RFC 8693 (OAuth 2.0 Token Exchange), which separates the subject (`sub`, here
 * `principal`) from the actor (`act`, here `context.actor`):
 *
 *     // this agent may book, whoever it is acting for
 *     permit(principal, action == Action::"book", resource)
 *     when { context.actor == "flight-booker" };
 *
 * Every governed call carries it, so an agent acting alone
 * (`principal = Agent::"flight-booker"`) and the same agent acting for a person
 * (`principal = User::"alice"`) are one policy vocabulary and two distinct
 * lines in the trail.
 *
 * It is a context key rather than an entity attribute because `context.*` with
 * `==`, `is`, `like` and set `contains` is the operator surface the engine
 * resolves; an entity attribute would silently deny.
 */
export const ACTOR_CONTEXT_KEY = "actor";

/**
 * The Cedar `context` key the SDK reserves for the ordered ACTOR CHAIN, root
 * first — RFC 8693's nested `act`, flattened into the shape the engine
 * resolves. A set-valued entry supports `contains`, so a policy can ask whether
 * an agent was anywhere in the delegation:
 *
 *     // this booking agent's delegation may pick seats, at any depth
 *     permit(principal is User, action == Action::"pick_seat", resource)
 *     when { context.actor_chain.contains("flight-booker") };
 *
 * `context.actor` answers a different question — *which* agent made this call —
 * and remains the leaf, so policies written against it are unaffected. Both
 * keys are set on every authorization; the chain of a call made outside any
 * delegation is the single-element `[agent]`.
 */
export const ACTOR_CHAIN_CONTEXT_KEY = "actor_chain";

/** The longest an actor chain can be: the root agent plus one entry per
 *  attenuation level, bounded by the Developer-Edition depth ceiling. */
export const MAX_ACTOR_CHAIN = DE_MAX_DEPTH + 1;

/** Fixed, value-free message of {@link AuthorizeRequestError}. */
export const REQUEST_INVALID_MESSAGE =
  "the authorization request is not valid for the engine (check the principal " +
  "and resource entity types)";

/** Thrown when the engine cannot evaluate the request at all — most often an
 *  entity type it does not recognise, e.g. `Service::"x"` as a principal. The
 *  call is refused (fail-closed, the tool body never runs) and the refusal is
 *  audited as a `Deny` like any other. The engine's own message is never
 *  echoed: it is not a caller-facing reason. */
export class AuthorizeRequestError extends Error {
  constructor() {
    super(REQUEST_INVALID_MESSAGE);
    this.name = "AuthorizeRequestError";
  }
}

/** Fixed, value-free message of {@link ReservedContextError}. */
export const RESERVED_CONTEXT_MESSAGE =
  "context keys 'actor' and 'actor_chain' are reserved for the acting agent and are set by the SDK";

/** Thrown when a caller's `context` sets a reserved actor key to a value that
 *  differs from the governor's own — the acting agent, or the delegation chain
 *  of the scope the call was made through. Refused rather than overwritten, so
 *  a policy reading either key can trust it. An identical value is fine. */
export class ReservedContextError extends Error {
  constructor() {
    super(RESERVED_CONTEXT_MESSAGE);
    this.name = "ReservedContextError";
  }
}

const sameChain = (a: unknown, b: readonly string[]): boolean =>
  Array.isArray(a) && a.length === b.length && a.every((v, i) => v === b[i]);

const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Reject an agent name that cannot be recorded or referenced unambiguously —
 *  in the constructor, in {@link Watchlight.as} and in
 *  {@link Watchlight.delegate} alike, so it fails at the name rather than
 *  later, inside the engine. */
function assertAgentName(agent: unknown, where: string): asserts agent is string {
  if (typeof agent !== "string" || !agent.trim()) {
    throw new TypeError(`${where}: agent must be a non-empty string`);
  }
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(agent)) {
    throw new TypeError(`${where}: agent must not contain control characters`);
  }
}

/** The caller's context with the reserved actor keys stamped on it. */
function withActorContext(
  context: Record<string, unknown> | undefined,
  actor: string,
  chain: readonly string[]
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...(context ?? {}) };
  // The SDK's values always win — and a caller who disagreed is told, never
  // silently overruled. The chain is derived from the scope the call was made
  // through, so a caller can neither supply nor extend one.
  // `hasOwn`, not `in`: an inherited property is not a caller-supplied key.
  if (hasOwn(out, ACTOR_CONTEXT_KEY) && out[ACTOR_CONTEXT_KEY] !== actor) {
    throw new ReservedContextError();
  }
  if (hasOwn(out, ACTOR_CHAIN_CONTEXT_KEY) && !sameChain(out[ACTOR_CHAIN_CONTEXT_KEY], chain)) {
    throw new ReservedContextError();
  }
  out[ACTOR_CONTEXT_KEY] = actor;
  out[ACTOR_CHAIN_CONTEXT_KEY] = [...chain];
  return out;
}

/** Everything a governor owns that is NOT its name: the engine and its compiled
 *  policies, the audit trail (file + sink), the scope-token secret, and the
 *  counters. A view made by {@link Watchlight.as} shares this object by
 *  reference, so it is provably the same engine, the same policies and the same
 *  trail — only the name stamped on records and decisions differs.
 *  @internal */
interface GovernorState {
  trail: AuditTrail;
  backend: GovernanceBackend;
  tokenSecret?: Uint8Array;
  /** The approval signing key + seen-token store. On the SHARED state, so an
   *  approval minted through one view is consumed — and, once consumed, refused
   *  — through every other view of the same governor. A view that had its own
   *  store would let one token be spent once per name. */
  approval: ApprovalTokens;
  /** The read side of the trail, shared for the same reason: `counters()` must
   *  answer the same number whichever name asks. */
  counterSource?: CounterSource;
  policyCount: number;
  announced: boolean;
  /** Resolved sources already loaded — the key of {@link Watchlight.load}'s
   *  idempotence. */
  sources: Set<string>;
  strictPrincipal: boolean;
  /** The audit options in force, so {@link Watchlight._configure} can apply one
   *  of them without dropping the others. */
  auditOptions: { dir?: string; file?: boolean; sink?: AuditSink };
  /** Set on the exported default governor, for the "no sink configured"
   *  notice. */
  isDefault: boolean;
  wroteRecord: boolean;
  warnedDefaultSink: boolean;
}

/** The memo key of a policy source: its real path, so two names for one file
 *  (a symlink included) are one source. Falls back to the resolved path when
 *  the file cannot be realpath'd — a missing file is not remembered anyway. */
function resolveSource(file: string): string {
  try {
    return fs.realpathSync(file);
  } catch {
    return path.resolve(file);
  }
}

function newState(opts: WatchlightOptions): GovernorState {
  // Resolved once: the approval key falls back to the scope-token secret, so
  // both are derived from the same configured value.
  const tokenSecret = normalizeSecret(opts.tokenSecret ?? process.env.WATCHLIGHT_TOKEN_SECRET);
  return {
    trail: new AuditTrail(
      opts.auditFile === false ? null : path.join(opts.auditDir ?? ".watchlight", "audit.jsonl"),
      opts.auditSink
    ),
    backend: selectBackend({
      apdpUrl: opts.apdpUrl,
      token: opts.token,
      tenantId: opts.tenantId,
    }),
    tokenSecret: tokenSecret,
    approval: new ApprovalTokens(
      resolveApprovalKey(opts.approvalSecret, tokenSecret),
      opts.approvalStore
    ),
    counterSource: opts.counterSource,
    policyCount: 0,
    announced: false,
    sources: new Set<string>(),
    strictPrincipal: opts.strictPrincipal !== false,
    auditOptions: { dir: opts.auditDir, file: opts.auditFile, sink: opts.auditSink },
    isDefault: false,
    wroteRecord: false,
    warnedDefaultSink: false,
  };
}

/** One process-wide notice that the agent name is standing in for a missing
 *  subject — the transitional `strictPrincipal: false` behaviour. */
let warnedLenientPrincipal = false;
function warnLenientPrincipal(): void {
  if (warnedLenientPrincipal) return;
  warnedLenientPrincipal = true;
  // eslint-disable-next-line no-console
  console.warn(
    "watchlight: strictPrincipal is off, so the BARE agent name is recorded as the acting " +
      "principal of calls that name none, instead of the typed Agent::\"<name>\". The bare " +
      "name binds to an unpredictable one of the entity types your policies name it with, " +
      "and the same policy set can decide differently in different processes. This is " +
      "transitional and is removed in a later version: name the subject at the call site " +
      "with `principal` (see `principals.user`), and write agent-scoped policies against " +
      "Agent::\"<name>\" or the reserved `context.actor` key."
  );
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
  /** The delegation chain this governor acts under, root first; the last entry
   *  is {@link agent}. A governor that was not delegated to acts alone, so its
   *  chain is just its own name. Set by {@link delegate} from the scope the
   *  sub-agent was spawned under — never by a caller. */
  readonly actorChain: readonly string[];
  /** The scope a delegated governor acts under — the one {@link delegate}
   *  derived. Pass this governor (or this scope) to {@link delegate} again to
   *  go one level deeper. Undefined on a governor that is not a delegate. */
  readonly delegatedScope?: Scope;
  /** Shared with every view made by {@link as} — see {@link GovernorState}. */
  private readonly _shared: GovernorState;

  // The state below is reached through accessors so that a view and the
  // governor it came from read and write ONE copy of it.
  private get _trail(): AuditTrail {
    return this._shared.trail;
  }
  private get _backend(): GovernanceBackend {
    return this._shared.backend;
  }
  private get _tokenSecret(): Uint8Array | undefined {
    return this._shared.tokenSecret;
  }
  private get _approval(): ApprovalTokens {
    return this._shared.approval;
  }
  private get _counterSource(): CounterSource | undefined {
    return this._shared.counterSource;
  }
  private get _announced(): boolean {
    return this._shared.announced;
  }
  private set _announced(v: boolean) {
    this._shared.announced = v;
  }

  constructor(opts: WatchlightOptions = {}) {
    const agent = opts.agent ?? process.env.WATCHLIGHT_AGENT ?? "my-agent";
    assertAgentName(agent, "new Watchlight({ agent })");
    this.agent = agent;
    this.actorChain = Object.freeze([this.agent]);
    this._shared = newState(opts);
  }

  /**
   * A view of THIS governor acting under a different agent name. The view
   * shares the engine, the compiled policies, the audit trail, the sink, the
   * scope-token secret and the policy count by reference — nothing is
   * reloaded, no second engine is constructed, and a policy added through
   * either one is immediately visible to both. Only the name stamped on audit
   * records and passed to the engine differs. Any number of names therefore
   * costs one engine and one policy load.
   *
   *     const billing = govern.as("billing-agent");
   *     const research = govern.as("research-agent");   // same engine
   */
  as(agent: string): Watchlight {
    assertAgentName(agent, "as(agent)");
    // A delegate's name is what the delegation granted. Renaming it — directly,
    // or through a per-call `agent` override, which lands here — would drop the
    // actor chain from the context and the record, so it is refused rather than
    // silently losing the delegation.
    if (this.actorChain.length > 1) {
      throw new TypeError(
        "as(agent): a delegated governor cannot be renamed — its name is part of the " +
          "actor chain. Use delegate(from, agent) to spawn a sub-agent under it."
      );
    }
    const view = Object.create(Watchlight.prototype) as Watchlight;
    // Shared BY REFERENCE — the whole point of the view. A rename is not a
    // delegation: the view acts alone under its own name.
    Object.assign(view, {
      agent,
      actorChain: Object.freeze([agent]),
      _shared: this._shared,
    });
    return view;
  }

  /**
   * Spawn a governor for a SUB-AGENT under `scope`, and record the delegation.
   *
   * The sub-agent's authority is `scope` narrowed by `opts` — the engine's
   * strict-subset attenuation, so it can never hold what its parent lacks — and
   * its identity is the parent's {@link actorChain} with `agent` appended.
   * Every decision and every record it produces then carries the ordered chain
   * (root first) alongside the leaf actor, and a policy can ask either
   * question: `context.actor == "seat-picker"` (who made this call) or
   * `context.actor_chain.contains("flight-booker")` (whose delegation is this).
   *
   *     const root = await govern.scope({ tools: ["search", "book"] });
   *     const picker = govern.delegate(root, "seat-picker", { tools: ["search"] });
   *     await picker.authorize({ action: "pick_seat", principal: principals.user("alice") });
   *     govern.delegate(picker, "row-checker");          // one level deeper
   *
   * The engine, the compiled policies, the audit trail and the sink are shared
   * with this governor, exactly as for {@link as}. Throws
   * {@link AttenuationDenied} if `opts` widens the scope and
   * {@link DevEditionCeiling} past the depth ceiling — which also bounds the
   * chain at {@link MAX_ACTOR_CHAIN} entries.
   */
  delegate(from: Scope | Watchlight, agent: string, opts: AttenuateOptions = {}): Watchlight {
    assertAgentName(agent, "delegate(from, agent)");
    const parent = from instanceof Watchlight ? from.delegatedScope : from;
    if (!parent) {
      throw new TypeError(
        "delegate(from, agent): `from` must be a scope, or a governor that was itself delegated"
      );
    }
    const child = parent.attenuate({ ...opts, agent });
    const view = Object.create(Watchlight.prototype) as Watchlight;
    Object.assign(view, {
      agent,
      actorChain: child.actorChain,
      delegatedScope: child,
      _shared: this._shared,
    });
    return view;
  }

  /** `"in-process"` (Developer Edition) or `"networked"` (graduated to the
   *  control plane via WATCHLIGHT_APDP_URL). */
  get mode(): "in-process" | "networked" {
    return this._backend.kind;
  }

  // ── policy loading ────────────────────────────────────────────────

  /** How many policies this governor holds — the count shared with every view
   *  from {@link as}. Counts what was added, not what the engine merged. */
  get policyCount(): number {
    return this._shared.policyCount;
  }

  /** Whether any policy is loaded. `false` means every call is denied
   *  (fail-closed), which is a configuration mistake worth asserting on at
   *  start-up. */
  get hasPolicies(): boolean {
    return this._shared.policyCount > 0;
  }

  /** Add one Cedar policy inline. Chainable. Always additive: calling it twice
   *  with the same code adds it twice (use {@link load} for a set you may load
   *  more than once). (In networked mode policies are managed by the control
   *  plane and this is ignored, with a one-time warning.) */
  allow(cedarCode: string, name?: string): this {
    this._backend.addPolicy({
      name: name ?? `policy-${this._shared.policyCount}`,
      code: cedarCode,
    });
    this._shared.policyCount += 1;
    return this;
  }

  /** Load policies from a JSON file — a list of `{name, code}` (or
   *  `{policies:[...]}`). Fail-closed: a missing file loads nothing, so every
   *  governed call is denied until a policy permits it. Chainable.
   *
 *  IDEMPOTENT PER SOURCE: the source is remembered under its real path
   *  (symlinks resolved), or under `sourceId` when you give one, and loading the
   *  same source again is a no-op — priming an engine in a factory and loading
   *  the same file again from an initialiser cannot double the set. A file that
   *  does not exist is not remembered, so it loads once it appears. Two
   *  different paths to the same file are one source; two files with the same
   *  content are two, unless you give them a shared `sourceId`. The memo is
   *  shared with every view from {@link as}.
   *
   *  The memo is keyed on identity, not content: EDITING a file already loaded
   *  and calling `load` again is a no-op, and the new policies do not apply.
   *  Pass `{ force: true }` to load it again — policies are only ever added, so
   *  the previous copy stays and `policyCount` grows; construct a fresh
   *  governor when you need the old set gone. */
  load(file: string, opts: { sourceId?: string; force?: boolean } = {}): this {
    const key = opts.sourceId ?? resolveSource(file);
    if (!opts.force && this._shared.sources.has(key)) return this;
    if (!fs.existsSync(file)) return this;
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    const entries: { name?: string; code: string }[] = Array.isArray(data)
      ? data
      : (data.policies ?? []);
    for (const e of entries) this.allow(e.code, e.name);
    this._shared.sources.add(key);
    return this;
  }

  /** The subject of a call that named none: a TYPED reference to this agent,
   *  `Agent::"<name>"` — when no human is on whose behalf the call runs, the
   *  agent is the subject, and typing it says so on sight and in a policy.
   *  Transitionally, `strictPrincipal: false` restores the bare, untyped agent
   *  name (warned once per process). Framework adapters use this so their
   *  `egress` records carry the same subject as the decision they join.
   *  @internal */
  _principal(explicit?: string): string {
    if (explicit !== undefined && explicit !== null && explicit !== "") return explicit;
    if (this._shared.strictPrincipal) return principals.agent(this.agent);
    warnLenientPrincipal();
    return this.agent;
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
      audit: this._trail,
      agent: this.agent,
      allowedTools: norm(opts.tools),
      allowedResources: norm(opts.resources),
      allowedIntents: norm(opts.intents),
      maxDepth: Math.min(opts.maxDepth ?? DE_MAX_DEPTH, DE_MAX_DEPTH),
      timeBudgetSeconds: opts.timeBudgetSeconds ?? 3600,
      depth: 0,
      tokenSecret: this._tokenSecret,
    });
    root.emitRoot();
    return root;
  }

  /**
   * Re-establish a scope minted by {@link Scope.toToken} in another process.
   * Verifies the token's format, HMAC (constant-time), agent binding, `iat`/`exp`
   * window and lifetime bound, then rebuilds the root grant and replays every
   * level of the chain through the engine's strict-subset attenuation — exactly
   * as if `attenuate()` had been called here. The engine, not the token, decides
   * whether each level is a subset: a widened chain throws
   * {@link AttenuationDenied} even with a valid signature, and a chain whose
   * engine-granted result differs from the token's claim is rejected. Throws
   * {@link ScopeTokenError} when `tokenSecret` is unset (fail-closed) or the
   * token is malformed, tampered, expired, or bound to a different agent. The
   * returned scope cannot outlive the token's `exp`.
   */
  async scopeFromToken(token: string): Promise<Scope> {
    const secret = requireSecret(this._tokenSecret);
    const claims = verifyScopeToken(token, secret, { agent: this.agent });
    const root = await this.scope({
      tools: claims.root.tools,
      resources: claims.root.resources,
      intents: claims.root.intents,
      maxDepth: claims.root.max_depth,
      timeBudgetSeconds: claims.root.time_budget_seconds,
    });
    let scope = root;
    for (const step of claims.chain) {
      scope = scope.attenuate({
        tools: step.tools,
        resources: step.resources,
        intents: step.intents,
        timeBudgetSeconds: step.time_budget_seconds,
      });
    }
    // The engine's grant must be exactly what the token claimed for this level.
    const claimed = claims.chain.length ? claims.chain[claims.chain.length - 1] : claims.root;
    if (
      scope.depth !== claims.depth ||
      !sameSet(scope.allowedTools, claimed.tools) ||
      !sameSet(scope.allowedResources, claimed.resources) ||
      !sameSet(scope.allowedIntents, claimed.intents) ||
      scope.timeBudgetSeconds !== claimed.time_budget_seconds ||
      (claims.chain.length === 0 && scope.maxDepth !== claims.root.max_depth)
    ) {
      throw new ScopeTokenError("mismatch", "engine grant does not match the token's claim");
    }
    scope._bindExpiry(claims.exp);
    return scope;
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
      /** Acting principal — value or `(args) => value`; build it with
       *  {@link principals} (`principals.user(sub)`). With none, the agent is
       *  the subject and is recorded as `Agent::"<name>"`. */
      principal?: Binding<A>;
      /** Agent name for this tool, overriding the governor's — the same view
       *  {@link as} returns, applied to one tool. */
      agent?: string;
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
      /** Egress hook. Awaited AFTER the body returns and BEFORE the result is
       *  handed back, with `{ intent, resource, principal, decisionId,
       *  obligations? }` — the `decisionId` and obligations of the decision
       *  that let the body run. Return a value to
       *  replace the payload; `void` passes it through; a throw propagates and
       *  the raw result is withheld (fail-closed). Writes a value-free `egress`
       *  audit record joined to the decision by `decision_id`. */
      onResult?: OnResult<Awaited<R>>;
    }
  ): Governed<A, R> {
    const intent = opts.intent;
    const name = fn.name || "anonymous";
    // A per-tool `agent` is exactly a view of this governor (same engine, same
    // policies, same trail) with a different name on it.
    const gov = opts.agent ? this.as(opts.agent) : this;
    return async (...args: A): Promise<Awaited<R>> => {
      const principal = gov._principal(resolveBinding(opts.principal, args));
      const resource = resolveBinding(opts.resource, args) ?? `tool/${name}`;
      const context =
        typeof opts.context === "function" ? opts.context(...args) : opts.context ?? {};
      // Run the body, then the egress hook (if any) over its result. `decisionId`
      // is the id of the decision that authorized THIS run.
      const run = async (d: AuthorizeResult): Promise<Awaited<R>> => {
        const out = (await fn(...args)) as Awaited<R>;
        if (!opts.onResult) return out;
        const info: EgressInfo = { intent, resource, principal, decisionId: d.decisionId };
        if (d.obligations) info.obligations = d.obligations;
        const { value } = await gov._applyOnResult(out, opts.onResult, info);
        return value;
      };

      const d = await gov.authorize({ principal, action: intent, resource, context });
      if (d.allowed) return run(d);
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
            const token = gov.mintApproval({ principal, action: intent, resource });
            const d2 = await gov.authorize({ principal, action: intent, resource, context, approval: token });
            if (d2.allowed) return run(d2);
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
  ): Promise<{ allowed: boolean; decision: string; reason: string; principal: string; decisionId?: string; obligations?: Obligations }> {
    const d = await this.authorize({ action: intent, resource: `tool/${toolName}` });
    const out: { allowed: boolean; decision: string; reason: string; principal: string; decisionId?: string; obligations?: Obligations } = {
      allowed: d.allowed, decision: d.decision, reason: d.reason,
      // The subject the decision was recorded against — no acting subject was
      // named, so adapters report exactly what the decision record carries.
      principal: this._principal(),
      decisionId: d.decisionId,
    };
    if (d.obligations) out.obligations = d.obligations;
    return out;
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
    /** Agent name for this one call, overriding the governor's — the same view
     *  {@link as} returns, applied to a single decision. It is what the record
     *  carries and what the policy reads as `context.actor`. */
    agent?: string;
  }): Promise<AuthorizeResult> {
    if (req.agent && req.agent !== this.agent) {
      const { agent, ...rest } = req;
      return this.as(agent).authorize(rest);
    }
    let decided;
    try {
      decided = await this._decide(req);
    } catch (e) {
      // A request the engine cannot evaluate is a refusal like any other: it is
      // recorded, then raised typed. (A `ReservedContextError` is the caller's
      // own context and is raised before anything reaches the engine.)
      if (e instanceof ReservedContextError || e instanceof AuthorizeError) throw e;
      this._audit(req.action, req.resource ?? "resource", "Deny", DENY_REASON, {
        principal: req.principal,
      });
      throw new AuthorizeRequestError();
    }
    const { result, principal, resource, decisionId } = decided;
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
    const principal = this._principal(req.principal);
    const resource = req.resource ?? "resource";
    const raw = await this._backend.authorize({
      principal,
      action: req.action,
      resource,
      // The acting agent is the ACTOR, and its delegation chain the ACTOR
      // CHAIN — reserved context keys the SDK owns, so a policy can name the
      // runtime (`context.actor == "…"`) or its delegation
      // (`context.actor_chain.contains("…")`) independently of the subject it
      // acts for. A caller value that disagrees with either is refused.
      context: withActorContext(req.context, this.agent, this.actorChain),
    });
    let allowed = raw.decision === "Allow";
    let needsApproval = allowed && !!raw.needsApproval;
    let approved = false;
    if (needsApproval) {
      if (req.approval && (await this._approval.consume(req.approval, principal, req.action, resource))) {
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
    const result: AuthorizeResult = {
      decision,
      allowed,
      needsApproval,
      approved,
      decisionId: raw.decisionId,
      // Non-revealing, uniform reason (never the engine's specific one).
      reason: reasonForVerdict(decision),
    };
    // Obligations ride only on a final Allow: a NeedsApproval hold or a Deny
    // has nothing to honour, whatever the matched permits declared.
    if (decision === "Allow" && raw.obligations) result.obligations = raw.obligations;
    return { result, principal, resource, decisionId: raw.decisionId };
  }

  /**
   * Run a list of policy fixtures against the loaded policies and report which
   * pass — a golden-test harness for CI, so a policy change is verified before
   * it gates real actions. Each case asserts the expected verdict
   * (`Allow` / `Deny` / `NeedsApproval`) for a `(principal, action, resource,
   * context)`; set `approved: true` to mint a valid approval token and assert
   * the human-confirmed downgrade; set `obligations: { redact, maxItems,
   * logValues, extra }` to also assert the obligations an `Allow` must carry.
   * Does NOT write to the audit trail. A verdict mismatch is a failed result
   * (inspect `report.failed` and assert on it in your test runner); a malformed
   * fixture — missing `action`/`expect`, or an ill-typed `obligations` — throws.
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
   *
   * SCOPE OF THE DEFAULTS — both are per-process, and neither is upgraded
   * silently:
   *
   * * **The signing key.** With no `approvalSecret` (or `tokenSecret`) the key
   *   is random and per-process: a token minted here is refused by any other
   *   process, and a redeploy invalidates every outstanding approval —
   *   indistinguishably from a genuine hold, since the reason is uniform.
   *   Configure `approvalSecret` to mint in one process and consume in another.
   * * **Single use.** "Used once" is recorded in the `approvalStore`, which
   *   defaults to a map in THIS process. Behind two replicas the same token can
   *   therefore be consumed once on EACH — single-use is per-replica, not per
   *   token, and that degrades silently under a routine scaling change.
   *   Configure `approvalStore` with a store every replica shares and
   *   single-use holds across all of them.
   *
   * Both live on the state a view made by {@link as} shares, so a token minted
   * through one name and consumed through another is the SAME token: the second
   * use is refused as a replay, not admitted a second time.
   */
  mintApproval(
    challenge: { action: string; principal?: string; resource?: string },
    opts: { ttlMs?: number } = {}
  ): string {
    return this._approval.mint(
      this._principal(challenge.principal),
      challenge.action,
      challenge.resource ?? "resource",
      opts.ttlMs ?? 120_000
    );
  }

  /**
   * Strip PII from text before an agent reads it (governed data minimization).
   * Deterministic, fail-closed. Writes a value-free `sanitization` record to the
   * audit trail (counts by PII type + mode — never the values, including any
   * `known` dictionary values) and returns the redacted text plus the report.
   * Operates on extracted text — extract a document to text first (never hand
   * the agent a "redacted PDF").
   *
   * `principal` names WHO the text was sanitized for and is written to the
   * record under the same key the decision line uses, so "what was redacted,
   * for whom" is answerable from that record alone — including when the
   * sanitization runs BEFORE any decision exists to join to. Omit it and the
   * agent is the subject, recorded as `Agent::"<name>"` exactly as a decision
   * with no named principal is. It is an identifier the caller supplies; never
   * anything derived from the content.
   */
  sanitize(content: string, opts: SanitizeOptions & { agent?: string } = {}): SanitizeResult {
    if (opts.agent && opts.agent !== this.agent) {
      const { agent, ...rest } = opts;
      return this.as(agent).sanitize(content, rest);
    }
    const { intent = "read", resource = "document", mode, types, decisionId, known } = opts;
    // The subject the redaction was performed FOR. A call that names none has
    // this agent as its subject — recorded as the TYPED `Agent::"<name>"`, the
    // same reference the decision line carries, never a bare name.
    const principal = this._principal(opts.principal);
    // `decisionId` and `principal` are validated (bounded, no control chars)
    // inside sanitizeText before they are echoed onto the report and written to
    // the audit line; `known` values are redacted in-process and never reach the
    // report or the audit line.
    const result = sanitizeText(content, { mode, types, decisionId, principal, known });
    this._auditSanitize(intent, resource, result);
    return result;
  }

  /**
   * Screen text for prompt-injection / output-leak shapes before it (re-)enters
   * the model — a retrieved page, a tool result, a document — or before model
   * output leaves. Rule-based, deterministic, fail-closed. Writes a value-free
   * `screening` record to the audit trail (counts per family + `flagged` — never
   * the text) and returns the text (untouched in `report` mode, family markers
   * in `redact` mode) plus the report. Pass the `decisionId` of the decision
   * that governed the read to join the two records on `decision_id`, and
   * `principal` to name whom it was screened for (the agent, typed, when the
   * call names no subject — as on {@link sanitize}).
   */
  screen(
    content: string,
    opts: ScreenOptions & { intent?: string; resource?: string; agent?: string } = {}
  ): ScreenResult {
    if (opts.agent && opts.agent !== this.agent) {
      const { agent, ...rest } = opts;
      return this.as(agent).screen(content, rest);
    }
    const { intent = "read", resource = "content", mode, families, decisionId } = opts;
    // As in `sanitize`: the subject the screening was performed for, typed when
    // the call names none.
    const principal = this._principal(opts.principal);
    // `decisionId` and `principal` are validated (bounded, no control chars)
    // inside screenText before they are echoed onto the report and written to
    // the audit line.
    const result = screenText(content, { mode, families, decisionId, principal });
    this._auditScreen(intent, resource, result);
    return result;
  }

  /**
   * Fold this governor's local audit trail into a count the caller places in
   * Cedar `context` — the input to a quota policy such as
   * `permit(...) when { context.reads_this_hour < 100 }`. Counts DECISION
   * records (never `sanitization` / `egress` / `attenuation`) for exactly this
   * `principal` — and, when given, this `intent` and `resource` — whose `ts`
   * falls in `(now - window, now]`. `outcome` selects `allowed` (default),
   * `denied` (Deny + NeedsApproval holds) or `all`. Reads only the local file
   * (an `auditSink` mirrors records elsewhere but is never read back), streams
   * it, and scans at most `maxBytes` from its end — `truncated` flags a lower
   * bound. Malformed lines are skipped and counted in `skipped`, never echoed.
   * A missing file is zero counts; an unreadable one throws
   * {@link AuditTrailUnreadable}. Synchronous, so it can run inside a `context`
   * binding right before the decision it feeds.
   *
   * With a `counterSource` configured this folds THAT store instead of the local
   * file — same query, same filters, same window — and `source` says which. A
   * source that throws or returns a non-count throws {@link CounterSourceError};
   * an asynchronous source throws too, naming {@link countersAsync}, rather than
   * quietly handing back a local number. The source is on the shared state, so
   * every view made by {@link as} counts from the same place.
   */
  counters(opts: CountersOptions): Counters {
    if (this._counterSource) return countFromSource(this._counterSource, opts);
    return countAuditRecords(this._localTrailPath(), opts);
  }

  /**
   * {@link counters} for an asynchronous `counterSource` — the only way to read
   * one that returns a promise. Identical in every other respect, and identical
   * to `counters` when no source is configured (the local file is read
   * synchronously either way), so a caller can use it unconditionally. Await it
   * BEFORE the call whose `context` it feeds; a `context` binding itself is
   * synchronous.
   */
  async countersAsync(opts: CountersOptions): Promise<Counters> {
    if (this._counterSource) return countFromSourceAsync(this._counterSource, opts);
    return countAuditRecords(this._localTrailPath(), opts);
  }

  /** The local file counters fold when no `counterSource` is configured.
   *  Counters are folded from the LOCAL file; with `auditFile: false` there is
   *  nothing to fold, and a quota that cannot be counted must not read as zero
   *  (that would silently widen it). Fail closed instead — unless a
   *  `counterSource` answers, which is exactly the pairing `auditFile: false`
   *  calls for: the sink holds the records and the source counts them. */
  private _localTrailPath(): string {
    const trailPath = this._trail.path;
    if (trailPath === null) {
      throw new Error(
        "counters() reads the local audit file, which is disabled by `auditFile: false`; " +
          "configure a `counterSource` to count your own sink's records instead"
      );
    }
    return trailPath;
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
    const record: Record<string, unknown> = {
      ts: new Date().toISOString(),
      agent: this.agent,
      ...this._chainField(),
      intent,
      event: "sanitization",
      resource,
      mode: report.mode,
      detector: report.detectorVersion,
      counts: report.counts,
      total: report.total,
    };
    // Same key as the `authorize` line, so the two records join on `decision_id`.
    if (report.decisionId) record.decision_id = report.decisionId;
    // Same key, and the same typed vocabulary, as the `authorize` line: the
    // record names its subject even with no decision to join to.
    if (report.principal) record.principal = report.principal;
    this._writeAudit(record);
  }

  /**
   * Run an egress hook over a governed tool's result and audit the outcome.
   * Shared by {@link tool} and the framework adapters (`governTool`, the Claude
   * `PostToolUse` hook) so all three behave identically. An `undefined` or
   * `null` return passes the payload through; any other value replaces it. If
   * the hook throws — or outruns `timeoutMs`, when given — the error propagates
   * and NO value is returned — the raw result is withheld (fail-closed) — after
   * an `egress` record marks the payload as withheld. A hook that settles after
   * the deadline is ignored (never audited twice, never released). The record
   * is value-free: never the result, nor anything derived from it.
   * @internal
   */
  async _applyOnResult<R>(
    result: R,
    hook: OnResult<R>,
    info: EgressInfo,
    opts: { timeoutMs?: number } = {}
  ): Promise<{ value: R; replaced: boolean }> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = Promise.resolve().then(() => hook(result, info));
    // A late rejection after the deadline must not surface as an unhandled one.
    attempt.catch(() => {});
    const deadline = new Promise<never>((_, reject) => {
      if (opts.timeoutMs === undefined) return;
      timer = setTimeout(() => reject(new EgressTimeout()), opts.timeoutMs);
    });
    let replacement: R | void | null;
    try {
      replacement = await Promise.race([attempt, deadline]);
    } catch (e) {
      this._auditEgress(info, { replaced: false, withheld: true });
      throw e;
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
    const replaced = replacement !== undefined && replacement !== null;
    this._auditEgress(info, { replaced });
    return { value: replaced ? (replacement as R) : result, replaced };
  }

  private _auditEgress(info: EgressInfo, outcome: { replaced: boolean; withheld?: boolean }): void {
    this._announce();
    const disposition = outcome.withheld ? "withheld" : outcome.replaced ? "replaced" : "passthrough";
    // eslint-disable-next-line no-console
    console.log(`watchlight: EGRESS ${info.intent.padEnd(9)} ${info.resource}     ${disposition}`);
    // Value-free: the disposition of the payload only — never the payload, its
    // size, or anything derived from it. `decision_id` joins this line to the
    // call's decision record.
    const record: Record<string, unknown> = {
      ts: new Date().toISOString(),
      agent: this.agent,
      ...this._chainField(),
      principal: info.principal,
      intent: info.intent,
      event: "egress",
      resource: info.resource,
      replaced: outcome.replaced,
    };
    if (info.decisionId) record.decision_id = info.decisionId;
    if (outcome.withheld) record.withheld = true;
    this._writeAudit(record);
  }

  private _auditScreen(intent: string, resource: string, result: ScreenResult): void {
    this._announce();
    const { report } = result;
    // eslint-disable-next-line no-console
    console.log(
      `watchlight: SCREEN ${intent.padEnd(9)} ${resource}     flagged ${report.total} (${report.mode})`
    );
    // Value-free: counts per rule family + mode + flagged — never the text.
    const record: Record<string, unknown> = {
      ts: new Date().toISOString(),
      agent: this.agent,
      ...this._chainField(),
      intent,
      event: "screening",
      resource,
      mode: report.mode,
      detector: report.detectorVersion,
      counts: report.counts,
      total: report.total,
      flagged: report.flagged,
    };
    // Same key as the `authorize` line, so the two records join on `decision_id`.
    if (report.decisionId) record.decision_id = report.decisionId;
    // Same key, and the same typed vocabulary, as the `authorize` line: the
    // record names its subject even with no decision to join to.
    if (report.principal) record.principal = report.principal;
    this._writeAudit(record);
  }

  /** `actor_chain` for a record, and nothing at all when this governor is not
   *  a delegate — a call outside any delegation keeps the record shape it has
   *  always had, and its chain is the single-element `[agent]` anyway. */
  private _chainField(): { actor_chain?: string[] } {
    return this.actorChain.length > 1 ? { actor_chain: [...this.actorChain] } : {};
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
      ...this._chainField(),
      // Never the agent standing in for an unnamed subject: `_principal` has
      // already resolved it (to the typed Agent::"<name>" by default).
      principal: this._principal(extra.principal),
      intent,
      resource,
      decision,
    };
    if (extra.decisionId) record.decision_id = extra.decisionId;
    if (extra.approved) record.approved = true;
    this._writeAudit(record);
  }

  /** The single funnel for every audit record this governor produces: the local
   *  `audit.jsonl` append, then the optional `auditSink` (fire-and-forget). */
  private _writeAudit(record: Record<string, unknown>): void {
    if (!this._shared.wroteRecord) {
      this._shared.wroteRecord = true;
      // The exported default governor is pre-constructed, so nothing has had a
      // chance to give it a durable destination. Say it once, the first time it
      // writes — a trail that exists only in the working directory is a
      // configuration choice, not an accident.
      if (this._shared.isDefault && !this._trail.hasSink && !this._shared.warnedDefaultSink) {
        this._shared.warnedDefaultSink = true;
        // eslint-disable-next-line no-console
        console.warn(
          "watchlight: the default governor writes only to the local audit file — " +
            "no auditSink is configured. Call configureDefault({ auditSink }) before the " +
            "first governed call to send records to a durable destination."
        );
      }
    }
    this._trail.write(record);
  }

  /** Apply options to a governor that has not written an audit record yet.
   *  Behind {@link configureDefault}; not part of the public surface.
   *  @internal */
  _configure(opts: WatchlightOptions): void {
    if (this._shared.wroteRecord) {
      throw new Error(
        "configureDefault must run before the default governor writes its first audit " +
          "record — the records already written would not reach the new destination"
      );
    }
    const shared = this._shared;
    if (opts.agent !== undefined) {
      assertAgentName(opts.agent, "configureDefault({ agent })");
      Object.assign(this, { agent: opts.agent, actorChain: Object.freeze([opts.agent]) });
    }
    if (opts.auditDir !== undefined || opts.auditFile !== undefined || opts.auditSink !== undefined) {
      // MERGE: a later call that names only one audit option must not drop the
      // sink (or the directory) an earlier one configured.
      const audit = shared.auditOptions;
      if (opts.auditDir !== undefined) audit.dir = opts.auditDir;
      if (opts.auditFile !== undefined) audit.file = opts.auditFile;
      if (opts.auditSink !== undefined) audit.sink = opts.auditSink;
      shared.trail = new AuditTrail(
        audit.file === false ? null : path.join(audit.dir ?? ".watchlight", "audit.jsonl"),
        audit.sink
      );
    }
    if (opts.tokenSecret !== undefined) shared.tokenSecret = normalizeSecret(opts.tokenSecret);
    if (opts.strictPrincipal !== undefined) shared.strictPrincipal = opts.strictPrincipal !== false;
    if (opts.apdpUrl !== undefined || opts.token !== undefined || opts.tenantId !== undefined) {
      // A different backend is a different policy holder: the policies added to
      // the old one do not move with it.
      shared.backend = selectBackend({
        apdpUrl: opts.apdpUrl,
        token: opts.token,
        tenantId: opts.tenantId,
      });
      shared.policyCount = 0;
      shared.sources.clear();
    }
  }
}

/** A ready-to-use default governor so `import { govern } from "@watchlight/sdk"`
 *  just works. Starts with NO policies — fail-closed — until you `govern.load()`
 *  a file or `govern.allow()` a policy inline, and with no audit sink until
 *  {@link configureDefault} gives it one. */
export const govern = new Watchlight();
// Marked so the first record it writes can point out that it has no sink.
(govern as unknown as { _shared: GovernorState })._shared.isDefault = true;

/**
 * Configure the exported {@link govern} — the one governor an application never
 * constructs, and therefore the one that could not otherwise be given an
 * `auditSink`, an `auditDir`, a `tokenSecret` or a name.
 *
 *     import { govern, configureDefault } from "@watchlight/sdk";
 *     configureDefault({ agent: "billing-agent", auditSink: (r) => ship(r) });
 *
 * Call it once, before the first governed call. It throws if the default
 * governor has already written an audit record: records written before the sink
 * existed cannot be sent to it, and a trail split across two destinations reads
 * like a data bug. Only the options you pass are applied, and they MERGE with
 * any earlier call's — configuring `auditDir` after an `auditSink` keeps the
 * sink. Policies already added survive — except when `apdpUrl` / `token` /
 * `tenantId` switch the backend, which replaces the policy holder and resets
 * the count.
 */
export function configureDefault(opts: WatchlightOptions): Watchlight {
  govern._configure(opts);
  return govern;
}
