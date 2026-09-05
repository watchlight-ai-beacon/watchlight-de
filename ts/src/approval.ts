// Approval tokens — the single-use, TTL-bounded confirmation that downgrades a
// `NeedsApproval` decision to `Allow`.
//
// A token is `<exp>.<nonce>.<hmac>`, bound to the exact (principal, action,
// resource) it was minted for. Two things decide whether it is honoured:
//
//   1. the KEY it is signed with — by default a random per-process key, so a
//      token never leaves the process that minted it and a restart invalidates
//      every outstanding approval. Configure `approvalSecret` (or `signingSecret`,
//      which also covers approvals) and a token minted in one process
//      verifies in another, and survives a redeploy inside its TTL.
//   2. the SEEN-TOKEN STORE that makes it single-use — by default an in-process
//      map, so "used once" holds only within one process: behind two replicas
//      the same token can be consumed once on each. Configure `approvalStore`
//      with a shared store and single-use holds across every replica.
//
// Single use is ONE atomic check-and-set: `add(id, expiresAt)` reserves the id
// and answers whether the reservation was new. There is deliberately no
// "check, then insert" — `consume` is async, so anything between the two would
// be an interleaving window in which N concurrent consumes of one token all
// observe "not yet used". A single agent fanning out parallel tool calls after
// one human confirmation is exactly that race.
//
// The reservations belong to the store: nothing here ever deletes one.
// `expiresAt` is the epoch-millisecond deadline after which an id is safe to
// drop, and a store that implements the optional `prune(before)` is asked to do
// that dropping on the same code path as the reservation — opportunistically,
// bounded, and with its outcome discarded, so cleanup can never move a verdict.
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

/** One configured secret, or an ordered list of them — the first signs, every
 *  one verifies. */
export type SecretInput = string | Uint8Array | readonly (string | Uint8Array)[];

/**
 * Domain separator for the approval key.
 *
 * The approval key is never the configured secret itself: it is
 * `HMAC-SHA256(secret, APPROVAL_KEY_LABEL)`. So one secret can configure both
 * halves of the SDK — `signingSecret` signs scope tokens with the raw secret and
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
 * `add(id, expiresAt)` is the whole contract, and it MUST BE AN ATOMIC
 * CHECK-AND-SET: reserve `id` only if it is not already present, and return
 * `true` when the reservation was new, `false` when the id was already there.
 * `expiresAt` is epoch milliseconds — the moment the token expires on its own,
 * so a row may be dropped after it (a TTL / expiry index). It may be
 * synchronous or return a promise; it is awaited before the approval is
 * honoured.
 *
 * In SQL that is an insert that fails (or affects no row) on a duplicate key;
 * in Redis it is `SET key value NX PXAT <expiresAt>`, whose `null` reply means
 * "already present". **A store that cannot do this in one atomic step cannot
 * enforce single use** — a separate "does it exist?" read followed by a write
 * leaves a window in which N concurrent consumes of the same token all see it
 * unused, and every one of them is approved. Do not implement `add` as a read
 * plus an unconditional write.
 *
 * ```ts
 * add: (id, expiresAt) =>
 *   redis.set(`wl:appr:${id}`, "1", { NX: true, PXAT: expiresAt }).then((r) => r !== null),
 * ```
 *
 * The id is `<exp>.<nonce>` — unique per mint, and deliberately NOT the token:
 * the signature never leaves the process, so a store whose rows leak yields no
 * usable approval.
 *
 * ## Who owns expiry
 *
 * **The reservations are yours, and the SDK never deletes one.** `add` is the
 * only write it makes; there is no background task inside this package that
 * sweeps your rows. `expiresAt` is the EPOCH-MILLISECOND deadline after which
 * that id is safe to drop: the token expires on its own at exactly that
 * instant, and an expired token is refused before the store is ever consulted,
 * so a row past its deadline can never admit anything. A store that keeps every
 * row forever is therefore correct and unbounded — give the row a TTL (Redis
 * `PXAT`), or an indexed `expires_at` column you delete from.
 *
 * Implement the optional {@link ApprovalStore.prune} and the SDK will ask for
 * that deletion on the same code path as the reservation, so the cleanup lives
 * with the write instead of in a separate cron. It stays YOUR deletion — the
 * SDK only says when and up to which deadline.
 *
 * Fail-closed, in every direction: `false` refuses; a throw or a rejection
 * refuses; outrunning {@link DEFAULT_APPROVAL_STORE_TIMEOUT_MS} refuses; and a
 * return that is not a boolean refuses too, because a store that will not say
 * whether the reservation was new cannot be relied on for single use. A store
 * that cannot answer never admits. `prune` is the one exception, and it is the
 * exception in the other direction — see its own note.
 */
export interface ApprovalStore {
  /** Atomically reserve `id`. `true` = newly reserved (the approval may
   *  proceed); `false` = already present (the approval is refused). */
  add(id: string, expiresAt: number): boolean | Promise<boolean>;
  /**
   * OPTIONAL cleanup: delete every reservation whose `expiresAt` is at or
   * before `before` (epoch milliseconds). Omit it and the store behaves exactly
   * as it always has — nothing extra is called, and expiry is entirely yours.
   *
   * ```ts
   * prune: (before) => db.query("DELETE FROM approvals WHERE expires_at <= $1", [before]),
   * ```
   *
   * **When it is called.** Opportunistically, from `authorize`: after an
   * approval has been reserved, at most once every
   * {@link APPROVAL_PRUNE_INTERVAL_MS} per governor, and never more than one at
   * a time — so an authorize does at most ONE extra store call and cleanup can
   * never pile up behind the decision path. It is not called when `add` itself
   * failed: a store that is already struggling is not handed more work.
   *
   * **`before` lags now.** It is `Date.now() - `{@link APPROVAL_PRUNE_GRACE_MS},
   * not the current instant, so a row outlives its own deadline by that margin.
   * Deleting a reservation LATE is harmless — the token it belongs to is
   * already refused on expiry, before the store is consulted. Deleting one
   * EARLY is not: with replica clocks a little apart, a row dropped ahead of
   * the deadline another replica is still measuring against would let a live
   * token be consumed a second time. The margin buys the safe side of that.
   *
   * **Failure changes nothing.** The verdict is decided before `prune` is
   * called, and its outcome is discarded: a throw, a rejection, a timeout, or
   * any return value leaves that verdict exactly as it was. A cleanup failure
   * must never deny a valid approval — the only cost of a prune that never
   * succeeds is rows that stay, and a row that stays can only refuse a replay,
   * never admit one. The failure is reported once on stderr so the unbounded
   * table is visible.
   */
  prune?(before: number): unknown;
  /** Optional, and NEVER consulted when consuming a token — single use is
   *  decided by `add` alone, in one step. Present only so a store can also
   *  expose a read for your own inspection. */
  has?(id: string): boolean | Promise<boolean>;
}

/** How long the seen-token store gets to answer before the approval is refused.
 *  A store that never settles would otherwise hang the governed call it gates;
 *  the deadline turns that into a refusal (fail-closed), never an admission.
 *  Mirrors the egress hook's `DEFAULT_ON_RESULT_TIMEOUT_MS`, but shorter — this
 *  one sits on the decision path. */
export const DEFAULT_APPROVAL_STORE_TIMEOUT_MS = 2000;

/** How often a governor asks a store that implements `prune` to delete its
 *  expired reservations. Cleanup is opportunistic, not a schedule: it rides an
 *  approval that was already going to talk to the store, and this interval is
 *  what keeps "every approval" from becoming "a DELETE per approval". A
 *  governor that never consumes an approval never prunes — there is nothing to
 *  clean up. */
export const APPROVAL_PRUNE_INTERVAL_MS = 60_000;

/** How far behind `Date.now()` the prune cutoff sits. A reservation therefore
 *  outlives its own deadline by this margin before the SDK offers it for
 *  deletion. Late is harmless — an expired token is refused before the store is
 *  consulted — while early, under replica clocks a little apart, would drop a
 *  row another replica still needs to refuse a replay. */
export const APPROVAL_PRUNE_GRACE_MS = 60_000;

/**
 * The default seen-token store: an in-process map of id → expiry.
 *
 * Atomic WITHIN this process — of N concurrent `authorize` calls carrying one
 * token, exactly one is approved — and PER-PROCESS ONLY. It is shared by every
 * governor in one process, and by nothing else: behind two replicas the same
 * approval token can be consumed once on each, and a restart forgets every
 * consumed id (harmless, since the same
 * restart also invalidates the random per-process key — unless an
 * `approvalSecret` is configured, which is exactly when a shared store is
 * needed too). Ids are dropped once they expire, so the map stays bounded by the
 * number of approvals live inside one TTL.
 *
 * It deliberately implements no `prune`: the sweep is already inside `add`, on
 * every reservation, so there is nothing for the SDK to ask for — and the
 * default path stays exactly the one call it has always been.
 */
class MemoryApprovalStore implements ApprovalStore {
  private readonly _seen = new Map<string, number>();

  /** Test-and-set in ONE synchronous step. Because it never awaits, Node's
   *  single thread cannot interleave another consume between the lookup and the
   *  write: of N concurrent consumes of the same token, exactly one sees
   *  `true`. */
  add(id: string, expiresAt: number): boolean {
    const now = Date.now();
    const seenAt = this._seen.get(id);
    if (seenAt !== undefined && now <= seenAt) return false; // already reserved
    if (this._seen.size > 0) {
      for (const [k, exp] of this._seen) if (now > exp) this._seen.delete(k);
    }
    this._seen.set(id, expiresAt);
    return true;
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

/** Derive one approval key per configured secret, in order — the first signs,
 *  every one verifies, so a rotation is two ordinary deploys. */
export function deriveApprovalKeys(secrets: Uint8Array[]): Uint8Array[] {
  return secrets.map(deriveApprovalKey);
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
 * resolved signing secrets, and finally the random per-process key. A configured secret is never used raw —
 * see {@link deriveApprovalKey}.
 */
export function resolveApprovalKeys(
  approvalSecret: SecretInput | undefined,
  signingSecrets: Uint8Array[] | undefined
): Uint8Array[] {
  const configured =
    normalizeApprovalSecrets(approvalSecret) ??
    normalizeApprovalSecrets(splitEnvSecrets(process.env.WATCHLIGHT_APPROVAL_SECRET)) ??
    signingSecrets;
  return configured === undefined ? [PROCESS_KEY] : deriveApprovalKeys(configured);
}

/**
 * An environment variable carries one secret, or several separated by commas —
 * newest first, as in the option. A SECRET MUST NOT CONTAIN A COMMA: the
 * generated values this SDK documents (base64 or hex) never do, and one that did
 * would be split into pieces and sign with only its first part.
 *
 * An unset or empty variable is "unset" and falls through to the next source. A
 * variable that is SET to something that yields no usable entry — a lone comma,
 * a space — returns the empty list, which the caller then refuses: it was
 * configured, so resolving it to "unset" would quietly fall back to a weaker
 * default.
 */
export function splitEnvSecrets(value: string | undefined): string[] | undefined {
  if (value === undefined || value.length === 0) return undefined;
  return value.split(",").map((v) => v.trim()).filter((v) => v.length > 0);
}

/** {@link normalizeApprovalSecret} over one value or an ordered list. */
export function normalizeApprovalSecrets(
  secret: SecretInput | undefined
): Uint8Array[] | undefined {
  if (secret === undefined || secret === null) return undefined;
  if (Array.isArray(secret)) {
    const entries = (secret as readonly (string | Uint8Array)[])
      .map((entry) => normalizeApprovalSecret(entry))
      .filter((entry): entry is Uint8Array => entry !== undefined);
    if (entries.length === 0) {
      throw new ApprovalError(
        "invalid_secret",
        "an approval-secret list must hold at least one usable secret"
      );
    }
    return entries;
  }
  const one = normalizeApprovalSecret(secret as string | Uint8Array);
  return one === undefined ? undefined : [one];
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
  /** Newest first. `_keys[0]` signs; every entry verifies, so a token minted
   *  under the previous secret is honoured while that secret is still listed. */
  private readonly _keys: Uint8Array[];
  private readonly _store: ApprovalStore;
  private _warned = false;
  /** Separate from `_warned`, so a broken `prune` never suppresses the report
   *  of a broken `add` — one of those refuses approvals, the other does not. */
  private _warnedPrune = false;
  /** When the last opportunistic prune STARTED, and whether one is still
   *  running. Both are claimed synchronously, before any await, so of N
   *  concurrent consumes exactly one begins a prune. */
  private _lastPruneAt = 0;
  private _pruning = false;

  constructor(keys: Uint8Array[], store?: ApprovalStore) {
    this._keys = keys;
    this._store = store ?? DEFAULT_STORE;
  }

  /** Mint a token bound to `(principal, action, resource)`, valid for `ttlMs`. */
  mint(principal: string, action: string, resource: string, ttlMs: number): string {
    const exp = Date.now() + ttlMs;
    // A per-mint nonce makes every token unique, so two approvals for the same
    // (principal, action, resource) minted in the same millisecond never collide
    // — and "single-use" is genuinely per-mint, not per-(challenge, exp).
    const nonce = randomBytes(8).toString("hex");
    const sig = createHmac("sha256", Buffer.from(this._keys[0]))
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
    const payload = payloadFor(principal, action, resource, exp, nonce);
    let sigBytes: Buffer;
    try {
      sigBytes = Buffer.from(sig, "hex");
    } catch {
      return false;
    }
    // Every configured key, in order, so a token signed under the previous
    // secret verifies while that secret is still listed. Which one matched is
    // never reported: the caller sees the same hold either way.
    let authentic = false;
    for (const key of this._keys) {
      const expected = createHmac("sha256", Buffer.from(key)).update(payload).digest("hex");
      if (sig.length !== expected.length) continue;
      const expectedBytes = Buffer.from(expected, "hex");
      if (sigBytes.length !== expectedBytes.length) continue;
      if (timingSafeEqual(sigBytes, expectedBytes)) authentic = true;
    }
    if (!authentic) return false;
    // Only an authentic token reaches the store, so an unauthenticated caller
    // can never burn an id or drive load into it.
    const id = `${exp}.${nonce}`;
    // ONE atomic reservation. Nothing is read before it: an `await` between a
    // check and a write is an interleaving window, and N concurrent consumes of
    // one token would all pass through it.
    let reserved: unknown;
    try {
      reserved = await this._withDeadline(
        Promise.resolve().then(() => this._store.add(id, exp))
      );
    } catch {
      // Fail-closed: a store that cannot answer — a throw, a rejection, or one
      // that never settles — refuses the approval. Reported once, without the
      // error or the id.
      this._warnOnce("approval store failed or timed out");
      return false;
    }
    let verdict: boolean;
    if (reserved === true) verdict = true;
    else if (reserved === false) verdict = false; // the store already held the id
    else {
      // A store that will not say whether the reservation was new cannot be
      // relied on for single use, so it does not get to admit one.
      this._warnOnce("approval store did not report whether the id was newly reserved");
      verdict = false;
    }
    // The verdict above is FINAL. Cleanup runs after it and its outcome is
    // discarded, so expiry sits on the same code path as the reservation
    // without any decision ever depending on it. Reached only because the store
    // answered `add` — a store that just failed is not handed more work.
    await this._maybePrune();
    return verdict;
  }

  /**
   * Ask a store that implements `prune` to delete its expired reservations —
   * at most once per {@link APPROVAL_PRUNE_INTERVAL_MS}, never concurrently
   * with itself, and never in a way that can change or fail a decision.
   *
   * A store WITHOUT `prune` is not touched: no call, no timer, no extra work.
   */
  private async _maybePrune(): Promise<void> {
    const prune = this._store.prune;
    if (typeof prune !== "function") return; // a store without prune is untouched
    const now = Date.now();
    // Claimed synchronously, before the first await: two concurrent consumes
    // cannot both get past this, so at most one prune is ever in flight and an
    // authorize does at most one extra store call.
    if (this._pruning || now - this._lastPruneAt < APPROVAL_PRUNE_INTERVAL_MS) return;
    this._pruning = true;
    this._lastPruneAt = now;
    try {
      // The cutoff LAGS now by the grace margin — see APPROVAL_PRUNE_GRACE_MS.
      // Bounded by the same deadline as `add`, so a prune that never settles
      // cannot hold the decision it rides on open indefinitely.
      await this._withDeadline(
        Promise.resolve().then(() => prune.call(this._store, now - APPROVAL_PRUNE_GRACE_MS))
      );
    } catch {
      // Deliberately NOT fail-closed: the verdict is already decided, and a
      // cleanup failure must never turn into a refused approval. Rows simply
      // stay, and a row that stays can only refuse a replay, never admit one.
      this._warnPruneOnce();
    } finally {
      this._pruning = false;
    }
  }

  /** Race the store against {@link DEFAULT_APPROVAL_STORE_TIMEOUT_MS}, for both
   *  the reservation and the opportunistic prune. A store that settles late is
   *  ignored: for `add` the approval was already refused and the id it may yet
   *  reserve is simply burned, which is the safe direction; for `prune` the
   *  verdict was already decided, and a deletion that lands late deletes rows
   *  that were expired anyway. */
  private _withDeadline(attempt: Promise<unknown>): Promise<unknown> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    // A late rejection must not surface as an unhandled one.
    attempt.catch(() => {});
    const deadline = new Promise<never>((_, reject) => {
      // NOT unref'd: while this is pending an `authorize` call is waiting on
      // it, and a process whose only outstanding work is that call must stay
      // alive to see the refusal — not exit silently as if nothing had been
      // asked. The timer is cleared as soon as the race settles, so it holds
      // the loop for at most the deadline.
      timer = setTimeout(
        () => reject(new Error("approval store deadline exceeded")),
        DEFAULT_APPROVAL_STORE_TIMEOUT_MS
      );
    });
    return Promise.race([attempt, deadline]).finally(() => {
      if (timer !== undefined) clearTimeout(timer);
    });
  }

  private _warnOnce(what: string): void {
    if (this._warned) return;
    this._warned = true;
    // eslint-disable-next-line no-console
    console.warn(
      `watchlight: ${what}; the approval was refused (fail-closed) — ` +
        "further approval-store failures are suppressed"
    );
  }

  /** A failed prune is reported once, and says plainly that no decision moved —
   *  the operator's problem is a table that grows, not a refused approval. */
  private _warnPruneOnce(): void {
    if (this._warnedPrune) return;
    this._warnedPrune = true;
    // eslint-disable-next-line no-console
    console.warn(
      "watchlight: approval store prune failed or timed out; no approval was " +
        "affected, but expired reservations are accumulating — further prune " +
        "failures are suppressed"
    );
  }
}
