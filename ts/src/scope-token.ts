// Serialisable attenuated scopes — the wire format behind `scope.toToken()` and
// `Watchlight.scopeFromToken()`.
//
// A scope token lets a scope derived in one process be re-established in
// another (a queue worker, a scheduler) WITHOUT trusting the job payload: the
// token is an HMAC over the canonical scope claims, and the receiving side
// re-runs the engine's strict-subset attenuation for every level of the chain
// before the scope is usable. The token is integrity, not authority — the
// engine, not the token, decides whether the requested chain is a subset.
//
// This module is pure (no engine, no I/O): canonicalisation, signing and
// verification. It is mirrored byte-for-byte by Python `watchlight.scope_token`.
//
// ── Token format ────────────────────────────────────────────────────────────
//
//   wls1.<base64url(canonical JSON claims)>.<base64url(HMAC-SHA256)>
//
//   * `wls1` is the format version; unknown versions are rejected.
//   * The HMAC key is the raw bytes of the token secret. The HMAC input is the
//     ASCII bytes of `"wls1." + base64url(payload)` — so the version is signed.
//   * base64url is RFC 4648 §5 with NO padding; non-canonical encodings and
//     padding are rejected.
//   * The whole token is bounded to MAX_TOKEN_LENGTH characters.
//
// ── Claims ──────────────────────────────────────────────────────────────────
//
//   {
//     "agent": "<governor identity>",
//     "chain": [ { "intents": [...], "resources": [...], "time_budget_seconds": N, "tools": [...] }, ... ],
//     "depth": <chain.length>,
//     "exp":   <epoch seconds>,
//     "iat":   <epoch seconds>,
//     "root":  { "intents": [...], "max_depth": N, "resources": [...], "time_budget_seconds": N, "tools": [...] }
//   }
//
//   `root` is the root scope's grant; `chain[i]` is the ENGINE-GRANTED scope at
//   depth i+1 (never a raw request), which the verifier replays as the request
//   for that level. Exactly these keys, no others.
//
// ── Canonical JSON (both lanes MUST agree byte-for-byte) ────────────────────
//
//   * Object keys sorted by Unicode code point; all keys are ASCII.
//   * No whitespace anywhere.
//   * `tools`, `resources`, `intents` are sets: sorted by Unicode code point
//     (NOT by UTF-16 code unit), duplicates preserved.
//   * Integers only for numbers (plain decimal, no exponent, no fraction);
//     every number is a non-negative safe integer.
//   * Strings escaped per RFC 8259 with the minimal escape set: `"` `\` and
//     control characters U+0000–U+001F (`\b \f \n \r \t`, else `\u00XX`);
//     everything else — including non-ASCII — is emitted literally (UTF-8).
//     Strings must be valid Unicode scalar values (no lone surrogates).

import { createHmac, timingSafeEqual } from "node:crypto";

/** Token format version prefix. */
export const SCOPE_TOKEN_PREFIX = "wls1";
/** Upper bound on a token's length (characters); longer input is rejected unparsed. */
export const MAX_TOKEN_LENGTH = 16_384;
/** Tolerated clock skew for a token whose `iat` is in the future (seconds). */
export const MAX_IAT_SKEW_SECONDS = 60;
/** Minimum token-secret length (bytes). */
export const MIN_SECRET_BYTES = 16;
/** Maximum chain length a token may carry (mirrors the DE depth ceiling). */
export const MAX_CHAIN_LENGTH = 5;

const HMAC_BYTES = 32;
const B64URL = /^[A-Za-z0-9_-]+$/;

/** The granted dimensions of one level of the chain. */
export interface ScopeStepClaim {
  tools: string[];
  resources: string[];
  intents: string[];
  time_budget_seconds: number;
}

/** The root scope's grant. */
export interface ScopeRootClaim extends ScopeStepClaim {
  max_depth: number;
}

/** Everything a scope token carries. */
export interface ScopeTokenClaims {
  agent: string;
  root: ScopeRootClaim;
  chain: ScopeStepClaim[];
  depth: number;
  iat: number;
  exp: number;
}

export type ScopeTokenErrorCode =
  | "no_secret"
  | "weak_secret"
  | "too_large"
  | "malformed"
  | "version"
  | "signature"
  | "identity"
  | "future_iat"
  | "expired"
  | "lifetime"
  | "mismatch";

/** Raised when a scope token cannot be minted or is rejected. The message never
 *  contains the token, its claims, or the secret. */
export class ScopeTokenError extends Error {
  readonly code: ScopeTokenErrorCode;
  constructor(code: ScopeTokenErrorCode, message: string) {
    super(`scope token rejected (${code}): ${message}`);
    this.name = "ScopeTokenError";
    this.code = code;
  }
}

// ── canonical JSON ──────────────────────────────────────────────────────────

/** Compare two strings by Unicode code point (Python `sorted()` order). */
export function codePointCompare(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const na = ia.next();
    const nb = ib.next();
    if (na.done && nb.done) return 0;
    if (na.done) return -1;
    if (nb.done) return 1;
    const ca = na.value.codePointAt(0) as number;
    const cb = nb.value.codePointAt(0) as number;
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
}

const isSafeNonNegInt = (n: unknown): n is number =>
  typeof n === "number" && Number.isSafeInteger(n) && n >= 0;

// A lone (unpaired) UTF-16 surrogate — not a Unicode scalar value.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function canonicalString(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new ScopeTokenError("malformed", "string is not valid Unicode");
  // JSON.stringify emits exactly the minimal escape set for well-formed strings.
  return JSON.stringify(s);
}

/** Serialise a claims value to canonical JSON. Arrays are emitted in the order
 *  given — callers sort set-valued arrays first (see {@link normalizeClaims}). */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new ScopeTokenError("malformed", "numbers must be safe integers");
    return String(value);
  }
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(codePointCompare);
    return `{${keys.map((k) => `${canonicalString(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
  }
  throw new ScopeTokenError("malformed", "unsupported value in claims");
}

const sortedSet = (xs: readonly string[]): string[] => [...xs].sort(codePointCompare);

function normalizeStep(s: ScopeStepClaim): ScopeStepClaim {
  return {
    tools: sortedSet(s.tools),
    resources: sortedSet(s.resources),
    intents: sortedSet(s.intents),
    time_budget_seconds: s.time_budget_seconds,
  };
}

/** Return a copy of `claims` with every set-valued array sorted — the exact
 *  object whose canonical JSON is signed. */
export function normalizeClaims(claims: ScopeTokenClaims): ScopeTokenClaims {
  return {
    agent: claims.agent,
    root: { ...normalizeStep(claims.root), max_depth: claims.root.max_depth },
    chain: claims.chain.map(normalizeStep),
    depth: claims.depth,
    iat: claims.iat,
    exp: claims.exp,
  };
}

// ── secret handling ─────────────────────────────────────────────────────────

/** Coerce a configured secret to bytes and enforce the minimum length. Never
 *  echoes the secret. */
export function normalizeSecret(secret: string | Uint8Array | undefined): Uint8Array | undefined {
  // An empty / whitespace-only value (an unfilled `.env` placeholder) is "unset":
  // constructing a governor must not fail for users who never mint a token —
  // the token operations themselves fail closed with `no_secret`.
  if (secret === undefined || (typeof secret === "string" && secret.trim().length === 0)) return undefined;
  if (typeof secret !== "string" && secret.length === 0) return undefined;
  // Copy caller-provided bytes so a later mutation of their array cannot change the key.
  const bytes = typeof secret === "string" ? Buffer.from(secret, "utf8") : Buffer.from(secret);
  if (bytes.length < MIN_SECRET_BYTES) {
    throw new ScopeTokenError("weak_secret", `token secret must be at least ${MIN_SECRET_BYTES} bytes`);
  }
  return bytes;
}

export function requireSecret(secret: Uint8Array | undefined): Uint8Array {
  if (!secret) {
    throw new ScopeTokenError(
      "no_secret",
      "scope tokens require a token secret — construct Watchlight with { tokenSecret } " +
        "(or set WATCHLIGHT_TOKEN_SECRET); there is no default"
    );
  }
  return secret;
}

// ── sign / verify ───────────────────────────────────────────────────────────

const b64url = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");

/** Strict base64url decode: alphabet-only, no padding, canonical encoding. */
function b64urlDecode(s: string): Uint8Array {
  if (s.length === 0 || !B64URL.test(s) || s.length % 4 === 1) {
    throw new ScopeTokenError("malformed", "token segment is not base64url");
  }
  const bytes = Buffer.from(s, "base64url");
  if (bytes.toString("base64url") !== s) {
    throw new ScopeTokenError("malformed", "token segment is not canonical base64url");
  }
  return bytes;
}

function hmac(secret: Uint8Array, signedPart: string): Buffer {
  return createHmac("sha256", secret).update(signedPart, "utf8").digest();
}

/** Mint a token over `claims` (normalised + canonicalised here). */
export function signScopeToken(claims: ScopeTokenClaims, secret: Uint8Array): string {
  const payload = Buffer.from(canonicalJson(normalizeClaims(claims)), "utf8");
  const signedPart = `${SCOPE_TOKEN_PREFIX}.${b64url(payload)}`;
  const token = `${signedPart}.${b64url(hmac(secret, signedPart))}`;
  if (token.length > MAX_TOKEN_LENGTH) {
    throw new ScopeTokenError("too_large", `token exceeds ${MAX_TOKEN_LENGTH} characters`);
  }
  return token;
}

function expectStringArray(v: unknown, what: string): string[] {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) {
    throw new ScopeTokenError("malformed", `${what} must be a list of strings`);
  }
  return v as string[];
}

function expectInt(v: unknown, what: string): number {
  if (!isSafeNonNegInt(v)) throw new ScopeTokenError("malformed", `${what} must be a non-negative integer`);
  return v;
}

function expectExactKeys(obj: unknown, keys: readonly string[], what: string): Record<string, unknown> {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new ScopeTokenError("malformed", `${what} must be an object`);
  }
  const rec = obj as Record<string, unknown>;
  const have = Object.keys(rec).sort(codePointCompare);
  const want = [...keys].sort(codePointCompare);
  if (have.length !== want.length || have.some((k, i) => k !== want[i])) {
    throw new ScopeTokenError("malformed", `${what} has unexpected or missing fields`);
  }
  return rec;
}

const STEP_KEYS = ["intents", "resources", "time_budget_seconds", "tools"] as const;
const ROOT_KEYS = [...STEP_KEYS, "max_depth"] as const;
const CLAIM_KEYS = ["agent", "chain", "depth", "exp", "iat", "root"] as const;

function parseStep(v: unknown, what: string): ScopeStepClaim {
  const o = expectExactKeys(v, STEP_KEYS, what);
  return {
    tools: expectStringArray(o.tools, `${what}.tools`),
    resources: expectStringArray(o.resources, `${what}.resources`),
    intents: expectStringArray(o.intents, `${what}.intents`),
    time_budget_seconds: expectInt(o.time_budget_seconds, `${what}.time_budget_seconds`),
  };
}

/** Validate an already-authenticated payload against the exact claims schema. */
export function parseClaims(raw: unknown): ScopeTokenClaims {
  const o = expectExactKeys(raw, CLAIM_KEYS, "claims");
  if (typeof o.agent !== "string" || o.agent.length === 0) {
    throw new ScopeTokenError("malformed", "claims.agent must be a non-empty string");
  }
  const rootRec = expectExactKeys(o.root, ROOT_KEYS, "claims.root");
  const root: ScopeRootClaim = {
    ...parseStep(
      { tools: rootRec.tools, resources: rootRec.resources, intents: rootRec.intents, time_budget_seconds: rootRec.time_budget_seconds },
      "claims.root"
    ),
    max_depth: expectInt(rootRec.max_depth, "claims.root.max_depth"),
  };
  if (root.max_depth > MAX_CHAIN_LENGTH) {
    throw new ScopeTokenError("malformed", `claims.root.max_depth must not exceed ${MAX_CHAIN_LENGTH}`);
  }
  if (!Array.isArray(o.chain) || o.chain.length > MAX_CHAIN_LENGTH) {
    throw new ScopeTokenError("malformed", `claims.chain must be a list of at most ${MAX_CHAIN_LENGTH} steps`);
  }
  const chain = o.chain.map((s, i) => parseStep(s, `claims.chain[${i}]`));
  const depth = expectInt(o.depth, "claims.depth");
  if (depth !== chain.length) throw new ScopeTokenError("malformed", "claims.depth must equal the chain length");
  const iat = expectInt(o.iat, "claims.iat");
  const exp = expectInt(o.exp, "claims.exp");
  return { agent: o.agent, root, chain, depth, iat, exp };
}

/** Whole-second epoch clock. */
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/**
 * Verify a token's shape, signature (constant-time), identity binding and time
 * window, and return its claims. Does NOT touch the engine — the caller must
 * still replay the chain through `attenuate()` before trusting the scope.
 */
export function verifyScopeToken(
  token: unknown,
  secret: Uint8Array,
  opts: { agent: string; now?: number }
): ScopeTokenClaims {
  if (typeof token !== "string") throw new ScopeTokenError("malformed", "token must be a string");
  if (token.length > MAX_TOKEN_LENGTH) {
    throw new ScopeTokenError("too_large", `token exceeds ${MAX_TOKEN_LENGTH} characters`);
  }
  const parts = token.split(".");
  if (parts.length !== 3) throw new ScopeTokenError("malformed", "token must have three segments");
  const [version, payloadB64, sigB64] = parts;
  if (version !== SCOPE_TOKEN_PREFIX) throw new ScopeTokenError("version", "unsupported token version");

  // Shape checks only (strict base64url; decoding is not parsing), then
  // authenticate BEFORE anything inside the payload is interpreted.
  const payload = b64urlDecode(payloadB64);
  const provided = b64urlDecode(sigB64);
  const expected = hmac(secret, `${version}.${payloadB64}`);
  if (provided.length !== HMAC_BYTES || !timingSafeEqual(provided, expected)) {
    throw new ScopeTokenError("signature", "signature does not verify");
  }

  let raw: unknown;
  try {
    raw = JSON.parse(Buffer.from(payload).toString("utf8"));
  } catch {
    throw new ScopeTokenError("malformed", "payload is not JSON");
  }
  const claims = parseClaims(raw);
  // The payload must be in canonical form — a re-encoding of the parsed claims
  // that differs from what was signed is rejected (no alternate encodings).
  if (canonicalJson(claims) !== Buffer.from(payload).toString("utf8")) {
    throw new ScopeTokenError("malformed", "payload is not canonical");
  }

  if (claims.agent !== opts.agent) throw new ScopeTokenError("identity", "token is bound to a different agent");

  const now = opts.now ?? nowSeconds();
  if (claims.iat > now + MAX_IAT_SKEW_SECONDS) throw new ScopeTokenError("future_iat", "token issued in the future");
  if (claims.exp <= now) throw new ScopeTokenError("expired", "token has expired");
  if (claims.exp <= claims.iat) throw new ScopeTokenError("lifetime", "token expires before it was issued");
  // A token may never outlive the scope it names: its lifetime is bounded by
  // the (engine-clamped) time budget of the deepest level it carries.
  const budget = claims.chain.length ? claims.chain[claims.chain.length - 1].time_budget_seconds : claims.root.time_budget_seconds;
  if (claims.exp - claims.iat > budget) {
    throw new ScopeTokenError("lifetime", "token lifetime exceeds the scope's time budget");
  }
  return claims;
}

/** Set-equality on string lists (order-insensitive, multiplicity-sensitive). */
export function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = sortedSet(a);
  const sb = sortedSet(b);
  return sa.every((x, i) => x === sb[i]);
}
