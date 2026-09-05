// Approval tokens — the single-use, TTL-bounded confirmation that downgrades a
// `NeedsApproval` decision to `Allow`.
//
// A token is `<exp>.<nonce>.<hmac>`, bound to the exact (principal, action,
// resource) it was minted for. Two things decide whether it is honoured:
//
//   1. the KEY it is signed with — by default a random per-process key, so a
//      token never leaves the process that minted it and a restart invalidates
//      every outstanding approval. Configure `approvalSecret` (or `tokenSecret`,
//      from which the approval key is derived) and a token minted in one process
//      verifies in another, and survives a redeploy inside its TTL.
//   2. the SEEN-TOKEN STORE that makes it single-use — by default an in-process
//      map, so "used once" holds only within one process: behind two replicas
//      the same token can be consumed once on each. Configure `approvalStore`
//      with a shared store and single-use holds across every replica.
//
// Both defaults are safe for a single-process agent and are the wrong choice for
// a replicated deployment; neither is silently upgraded. Every refusal here is
// fail-closed: the caller sees the SAME `NeedsApproval` hold whichever of these
// checks refused (expired, tampered, signed with another key, already consumed,
// or a store that could not answer), so a probing caller learns nothing about
// which one it was. Enterprise mints these KMS-signed and records them in
// signed lineage.

import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";

/** Minimum length of a configured approval secret, in bytes. Matches the
 *  scope-token secret bound. */
export const APPROVAL_MIN_SECRET_BYTES = 16;

/**
 * Domain separator for the approval key.
 *
 * The approval key is never the configured secret itself: it is
 * `HMAC-SHA256(secret, APPROVAL_KEY_LABEL)`. So one secret can configure both
 * halves of the SDK — `tokenSecret` signs scope tokens with the raw secret and
 * approval tokens with this derived key — and the two keys stay independent: a
 * scope token can never be replayed as an approval, nor the reverse, and
 * disclosure of one derived key does not yield the other.
 */
export const APPROVAL_KEY_LABEL = "watchlight-de:approval-token:v1";

/** Reasons an approval secret is refused at configuration time. */
export type ApprovalErrorCode = "weak_secret" | "invalid_secret";

/** Raised when the approval configuration itself is unusable — fail-closed at
 *  construction rather than at the first approval. Never echoes the secret. */
export class ApprovalError extends Error {
  readonly code: ApprovalErrorCode;
  constructor(code: ApprovalErrorCode, message: string) {
    super(`approval configuration rejected (${code}): ${message}`);
    this.name = "ApprovalError";
    this.code = code;
  }
}

/**
 * An application-supplied store of approval-token ids that have already been
 * consumed — the same shape as an `auditSink`: your object, your storage, called
 * by the SDK. Configured via `WatchlightOptions.approvalStore`.
 *
 * `has(id)` answers whether the id was already consumed; `add(id, expiresAt)`
 * records it. `expiresAt` is epoch milliseconds — the moment the token expires
 * on its own, so a row may be dropped after it (a TTL / expiry index). Both may
 * be synchronous or return a promise; both are awaited before the approval is
 * honoured.
 *
 * The id is `<exp>.<nonce>` — unique per mint, and deliberately NOT the token:
 * the signature never leaves the process, so a store whose rows leak yields no
 * usable approval.
 *
 * Fail-closed: if either call throws or rejects, the approval is REFUSED (the
 * decision stays `NeedsApproval`) — a store that cannot answer never admits.
 * `has` + `add` is check-then-act, so under concurrency two replicas can both
 * see `has === false`; a store that must be strictly single-use should make
 * `add` conditional (an insert that fails on a duplicate key, `SET … NX`) and
 * either throw or return `false` when the id is already present — a `false`
 * return refuses the approval.
 */
export interface ApprovalStore {
  /** True when this id was already consumed. */
  has(id: string): boolean | Promise<boolean>;
  /** Record this id as consumed. Return `false` if it was already present. */
  add(id: string, expiresAt: number): void | boolean | Promise<void | boolean>;
}

/**
 * The default seen-token store: an in-process map of id → expiry.
 *
 * PER-PROCESS ONLY. It is shared by every governor in one process, and by
 * nothing else: behind two replicas the same approval token can be consumed once
 * on each, and a restart forgets every consumed id (harmless, since the same
 * restart also invalidates the random per-process key — unless an
 * `approvalSecret` is configured, which is exactly when a shared store is
 * needed too). Ids are dropped once they expire, so the map stays bounded by the
 * number of approvals live inside one TTL.
 */
class MemoryApprovalStore implements ApprovalStore {
  private readonly _seen = new Map<string, number>();

  has(id: string): boolean {
    const exp = this._seen.get(id);
    if (exp === undefined) return false;
    if (Date.now() > exp) {
      this._seen.delete(id);
      return false; // expired ids are refused by the TTL check, not by this store
    }
    return true;
  }

  add(id: string, expiresAt: number): void {
    const now = Date.now();
    if (this._seen.size > 0) {
      for (const [k, exp] of this._seen) if (now > exp) this._seen.delete(k);
    }
    this._seen.set(id, expiresAt);
  }
}

/** Process-wide default store, so the in-memory single-use registry behaves
 *  exactly as it did before it was pluggable: shared by every governor in the
 *  process, and by nothing outside it. */
const DEFAULT_STORE: ApprovalStore = new MemoryApprovalStore();

/** Random per-process approval key — the default when no secret is configured.
 *  Minted once at import, so every governor in the process agrees, and no
 *  other process (or restart) ever does. */
const PROCESS_KEY = randomBytes(32);

/** Coerce a configured approval secret to bytes and enforce the minimum length.
 *  An empty / whitespace-only value (an unfilled `.env` placeholder) is "unset".
 *  Never echoes the secret. */
export function normalizeApprovalSecret(
  secret: string | Uint8Array | undefined
): Uint8Array | undefined {
  if (secret === undefined || secret === null) return undefined;
  if (typeof secret === "string") {
    if (secret.trim().length === 0) return undefined;
    return Buffer.from(secret, "utf8");
  }
  if (typeof (secret as Uint8Array).length !== "number") {
    throw new ApprovalError("invalid_secret", "approval secret must be a string or byte array");
  }
  if (secret.length === 0) return undefined;
  return Buffer.from(secret); // copy: a later mutation must not change the key
}

/** Derive the approval key from a configured secret. See {@link APPROVAL_KEY_LABEL}. */
export function deriveApprovalKey(secret: Uint8Array): Uint8Array {
  if (secret.length < APPROVAL_MIN_SECRET_BYTES) {
    throw new ApprovalError(
      "weak_secret",
      `approval secret must be at least ${APPROVAL_MIN_SECRET_BYTES} bytes`
    );
  }
  return createHmac("sha256", Buffer.from(secret)).update(APPROVAL_KEY_LABEL).digest();
}

/**
 * Resolve the key approval tokens are signed with, in order of precedence:
 * an explicit `approvalSecret`, `WATCHLIGHT_APPROVAL_SECRET`, the already
 * normalized `tokenSecret` (which also covers `WATCHLIGHT_TOKEN_SECRET`), and
 * finally the random per-process key. A configured secret is never used raw —
 * see {@link deriveApprovalKey}.
 */
export function resolveApprovalKey(
  approvalSecret: string | Uint8Array | undefined,
  tokenSecret: Uint8Array | undefined
): Uint8Array {
  const configured =
    normalizeApprovalSecret(approvalSecret) ??
    normalizeApprovalSecret(process.env.WATCHLIGHT_APPROVAL_SECRET) ??
    tokenSecret;
  return configured === undefined ? PROCESS_KEY : deriveApprovalKey(configured);
}

/**
 * Domain separator AND format version of the signed payload. It is the first
 * field of every payload, so a token minted under a different payload format
 * simply does not verify — the change is a refusal, never a silent
 * reinterpretation — and the format can evolve by bumping this string.
 */
export const APPROVAL_PAYLOAD_VERSION = "watchlight-de:approval:v1";

/**
 * The exact bytes an approval token signs — the ONE function both minting and
 * verification go through, so there is no second implementation to drift.
 *
 * Every field is length-prefixed: `<utf8 byte length>:<field>`, concatenated in
 * a fixed order. Nothing is escaped because nothing needs to be — the length
 * says where each field ends, so no combination of field values can produce the
 * bytes of a different combination. A delimiter-joined payload could: with
 * `principal action resource`, the triple (`U`, `a`, `r1 r2`) and the triple
 * (`U`, `a r1`, `r2`) join to the same string, and one approval would then be
 * valid for the other — reachable in practice, since a principal carries an
 * identifier from a token claim and a resource routinely carries a path.
 * Lengths are UTF-8 BYTES so both language packages sign identical bytes.
 */
function payloadFor(
  principal: string,
  action: string,
  resource: string,
  exp: number,
  nonce: string
): string {
  const fields = [APPROVAL_PAYLOAD_VERSION, principal, action, resource, String(exp), nonce];
  return fields.map((f) => `${Buffer.byteLength(f, "utf8")}:${f}`).join("");
}

/** Mints and consumes approval tokens for one governor. */
export class ApprovalTokens {
  private readonly _key: Uint8Array;
  private readonly _store: ApprovalStore;
  private _warned = false;

  constructor(key: Uint8Array, store?: ApprovalStore) {
    this._key = key;
    this._store = store ?? DEFAULT_STORE;
  }

  /** Mint a token bound to `(principal, action, resource)`, valid for `ttlMs`. */
  mint(principal: string, action: string, resource: string, ttlMs: number): string {
    const exp = Date.now() + ttlMs;
    // A per-mint nonce makes every token unique, so two approvals for the same
    // (principal, action, resource) minted in the same millisecond never collide
    // — and "single-use" is genuinely per-mint, not per-(challenge, exp).
    const nonce = randomBytes(8).toString("hex");
    const sig = createHmac("sha256", Buffer.from(this._key))
      .update(payloadFor(principal, action, resource, exp, nonce))
      .digest("hex");
    return `${exp}.${nonce}.${sig}`;
  }

  /**
   * Verify + CONSUME a token (single-use). Bound to the exact (principal,
   * action, resource); refuses a token that is malformed, expired, tampered,
   * signed with a different key, or already consumed — and refuses when the
   * seen-token store cannot answer. Returns `false` for every refusal; the
   * caller turns that into the same `NeedsApproval` hold in every case.
   */
  async consume(
    token: string,
    principal: string,
    action: string,
    resource: string
  ): Promise<boolean> {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [expStr, nonce, sig] = parts;
    const exp = Number(expStr);
    if (!Number.isFinite(exp) || Date.now() > exp) return false;
    const expected = createHmac("sha256", Buffer.from(this._key))
      .update(payloadFor(principal, action, resource, exp, nonce))
      .digest("hex");
    if (sig.length !== expected.length) return false;
    let sigBytes: Buffer;
    try {
      sigBytes = Buffer.from(sig, "hex");
    } catch {
      return false;
    }
    const expectedBytes = Buffer.from(expected, "hex");
    if (sigBytes.length !== expectedBytes.length) return false;
    if (!timingSafeEqual(sigBytes, expectedBytes)) return false;
    // Only an authentic token reaches the store, so an unauthenticated caller
    // can never burn an id or drive load into it.
    const id = `${exp}.${nonce}`;
    try {
      if (await this._store.has(id)) return false;
      const added = await this._store.add(id, exp);
      if (added === false) return false; // the store already held it (atomic add)
    } catch {
      // Fail-closed: a store that cannot answer refuses the approval. The
      // failure is reported once, without the error or the id.
      this._warnOnce();
      return false;
    }
    return true;
  }

  private _warnOnce(): void {
    if (this._warned) return;
    this._warned = true;
    // eslint-disable-next-line no-console
    console.warn(
      "watchlight: approval store failed; the approval was refused (fail-closed) — " +
        "further approval-store failures are suppressed"
    );
  }
}
