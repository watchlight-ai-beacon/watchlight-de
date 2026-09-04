// Shared by agent.mjs and approve.mjs: the pending request, the approval grant,
// audit-trail lookups, and SDK resolution. Same file formats and the same HMAC
// payload as hitl.py, so a request held by one lane can be approved by the other.
//
// Two small JSON documents cross the process boundary between the agent and the
// approver. Neither carries a secret or a tool payload — only the identity of
// the request:
//
//   .watchlight/hitl/pending.json   {decision_id, principal, action, resource, requested_at}
//   .watchlight/hitl/grant.json     {pending_decision_id, principal, action, resource, exp, nonce, sig}
//
// `sig` is HMAC-SHA256 over the grant's other fields under the approver's
// secret. The secret is read from $APPROVER_SECRET by both processes and is
// never written anywhere. The agent verifies the signature, the binding
// (principal, action, resource) and the expiry, records the grant's nonce in
// consumed.json so the same grant cannot be presented twice, and requires the
// grant to name the request it currently has outstanding in pending.json (a file
// the agent itself wrote), so a grant for an earlier request cannot be planted
// for a later one.
//
// Why a grant and not the SDK's own approval token: the DE mints approval tokens
// under a random secret generated when the process starts, and remembers used
// tokens in memory. A token minted by approve.mjs therefore cannot be verified
// by agent.mjs. The grant is what the approver signs; the token is minted by the
// SDK inside the agent process once the grant verifies (onNeedsApproval → true).
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import * as fs from "node:fs";

const require = createRequire(import.meta.url);

/** Resolve the SDK from an installed package first, then from the in-repo build. */
export function loadSdk() {
  const candidates = ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", import.meta.url))];
  for (const spec of candidates) {
    try { return require(spec); } catch (e) { if (e?.code !== "MODULE_NOT_FOUND") throw e; }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}

export const HERE = dirname(fileURLToPath(import.meta.url));
export const AUDIT_DIR = join(HERE, ".watchlight");
export const AUDIT_PATH = join(AUDIT_DIR, "audit.jsonl");
export const STATE_DIR = join(AUDIT_DIR, "hitl");
export const PENDING = join(STATE_DIR, "pending.json");
export const GRANT = join(STATE_DIR, "grant.json");
export const CONSUMED = join(STATE_DIR, "consumed.json");

export const SECRET_ENV = "APPROVER_SECRET";
export const GRANT_TTL_MS = 5 * 60 * 1000;
const GRANT_FIELDS = ["pending_decision_id", "principal", "action", "resource", "exp", "nonce"];

export const rel = (p) => p.slice(HERE.length + 1);
export const nowMs = () => Date.now();

/** The shared secret, from the environment only. Fails closed when unset. */
export function approverSecret() {
  const value = process.env[SECRET_ENV] ?? "";
  if (value.length < 16) {
    console.error(
      `${SECRET_ENV} is not set (or is shorter than 16 characters). approve.mjs and\n` +
      `'agent.mjs resume' share it through the environment only — generate one per session:\n` +
      `  export ${SECRET_ENV}="$(openssl rand -hex 32)"`);
    process.exit(2);
  }
  return Buffer.from(value, "utf8");
}

// ── files ────────────────────────────────────────────────────────────────────

function write(path, doc) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
}

function read(path) {
  if (!fs.existsSync(path)) return null;
  try {
    const doc = JSON.parse(fs.readFileSync(path, "utf8"));
    return doc && typeof doc === "object" && !Array.isArray(doc) ? doc : null;
  } catch {
    return null;
  }
}

/** Start a new approval loop: drop any pending request or unused grant. */
export function reset() {
  for (const p of [PENDING, GRANT]) fs.rmSync(p, { force: true });
}

// ── pending request ──────────────────────────────────────────────────────────

export function writePending(decisionId, principal, action, resource) {
  const doc = { decision_id: decisionId, principal, action, resource, requested_at: nowMs() };
  write(PENDING, doc);
  return doc;
}

export const readPending = () => read(PENDING);

// ── approval grant ───────────────────────────────────────────────────────────

function sign(grant, secret) {
  const payload = GRANT_FIELDS.map((k) => String(grant[k])).join("\n");
  return createHmac("sha256", secret).update(payload).digest("hex");
}

/** Approve a pending request: sign a grant bound to exactly that request and
 *  write it next to the (still outstanding) pending file. */
export function writeGrant(pending, secret) {
  const grant = {
    pending_decision_id: pending.decision_id,
    principal: pending.principal,
    action: pending.action,
    resource: pending.resource,
    exp: nowMs() + GRANT_TTL_MS,
    nonce: randomBytes(16).toString("hex"),
  };
  grant.sig = sign(grant, secret);
  write(GRANT, grant);
  // pending.json stays: the agent compares the grant against it on resume and
  // removes both once the grant is consumed.
  return grant;
}

/** Read the grant without consuming it (for display and for the join). */
export const peekGrant = () => read(GRANT);

/** Write a grant document as-is — used by the replay check to re-present a
 *  grant that was already consumed. */
export const plantGrant = (grant) => write(GRANT, grant);

/** Verify and consume the grant on disk for exactly (principal, action, resource).
 *
 *  Returns `{ grant, why: "ok" }` or `{ grant: null, why }`. The file is removed
 *  as soon as it is read, before any verification, so a crash mid-way never
 *  leaves a reusable grant. A verified grant's nonce is recorded so the same
 *  document cannot be presented again, and the grant must name the request this
 *  agent currently has outstanding (pending.json, which the agent itself wrote)
 *  — so a grant approved for an earlier request cannot be planted for a later
 *  one. On success the pending file is removed too. */
export function takeGrant(principal, action, resource, secret) {
  const grant = read(GRANT);
  fs.rmSync(GRANT, { force: true });
  if (grant === null) return { grant: null, why: "no grant" };
  if ([...GRANT_FIELDS, "sig"].some((k) => !(k in grant))) return { grant: null, why: "malformed grant" };
  const expected = sign(grant, secret);
  const given = String(grant.sig);
  if (given.length !== expected.length || !timingSafeEqual(Buffer.from(given), Buffer.from(expected))) {
    return { grant: null, why: "signature does not verify" };
  }
  if (grant.principal !== principal || grant.action !== action || grant.resource !== resource) {
    return { grant: null, why: "grant is bound to a different request" };
  }
  if (!Number.isInteger(grant.exp) || nowMs() > grant.exp) return { grant: null, why: "grant expired" };
  const used = read(CONSUMED)?.nonces ?? [];
  if (used.includes(grant.nonce)) return { grant: null, why: "grant already used (replay)" };
  write(CONSUMED, { nonces: [...used, grant.nonce] });
  const pending = readPending();
  if (pending === null || pending.decision_id !== grant.pending_decision_id
      || pending.principal !== principal || pending.action !== action || pending.resource !== resource) {
    return { grant: null, why: "grant does not match the outstanding pending request" };
  }
  fs.rmSync(PENDING, { force: true });
  return { grant, why: "ok" };
}

// ── audit trail ──────────────────────────────────────────────────────────────

export function auditLines() {
  if (!fs.existsSync(AUDIT_PATH)) return [];
  return fs.readFileSync(AUDIT_PATH, "utf8").split("\n").filter((l) => l.trim());
}

/** The raw audit line carrying `decisionId` (the last one, if several). */
export function auditLine(decisionId) {
  for (const line of auditLines().reverse()) {
    try { if (JSON.parse(line).decision_id === decisionId) return line; } catch { /* skip */ }
  }
  return null;
}
