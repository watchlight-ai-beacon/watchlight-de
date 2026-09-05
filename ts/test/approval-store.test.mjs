// @watchlight/sdk approval secret + seen-token store test.
//
// Two defaults are per-process and neither may be upgraded silently:
//   * the signing key — random per process, so a token never crosses a process
//     boundary and a redeploy invalidates outstanding approvals;
//   * the seen-token store — a map in this process, so "single use" is
//     per-replica unless a shared store is configured.
// This exercises both: a configured secret makes a token portable, a wrong
// secret refuses it, a shared store makes single-use hold across governors, and
// EVERY store failure refuses rather than admits. Runs the real engine.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, ApprovalError, APPROVAL_KEY_LABEL, APPROVAL_PAYLOAD_VERSION } = require("../dist/index.js");
const { deriveApprovalKey, normalizeApprovalSecret } = require("../dist/approval.js");
const { createHmac } = require("node:crypto");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);';
const SECRET_A = "a-shared-approval-secret-32-bytes";
const SECRET_B = "a-different-approval-secret-abcd";

/** A governor with its own audit dir — one per "process" in these tests. */
const gov = (opts = {}) => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-appr-"));
  const g = new Watchlight({ agent: "appr-agent", auditDir, ...opts });
  g.allow(WIRE, "wire");
  return g;
};

/** A governor whose every action needs approval — so only the TOKEN decides the
 *  verdict, and a payload collision would show up as an Allow. */
const ANY = '@enforcement_effect("require_approval")\npermit(principal, action, resource);';
const govAny = () => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-appr-"));
  const g = new Watchlight({
    agent: "appr-agent", auditDir, approvalSecret: SECRET_A, approvalStore: sharedStore(),
  });
  g.allow(ANY, "any");
  return g;
};

const challenge = { action: "wire", resource: "acct/1" };
const held = async (g, approval) =>
  g.authorize({ action: "wire", resource: "acct/1", ...(approval ? { approval } : {}) });

/** An explicit shared seen-token store — the shape an integrator supplies, whose
 *  `add` is the atomic check-and-set the contract requires. */
const sharedStore = () => {
  const seen = new Map();
  return {
    calls: [],
    add(id, expiresAt) {
      this.calls.push(["add", id, expiresAt]);
      if (seen.has(id)) return false;
      seen.set(id, expiresAt);
      return true;
    },
  };
};

const withWarnSpy = async (fn) => {
  const orig = console.warn;
  const warns = [];
  console.warn = (...a) => warns.push(a.map(String).join(" "));
  try { return await fn(warns); } finally { console.warn = orig; }
};

async function main() {
  console.log("approval secret");
  {
    // Two governors with the SAME configured secret stand in for two processes.
    const minter = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const store = sharedStore();
    const consumer = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const token = minter.mintApproval(challenge);
    const d = await held(consumer, token);
    ok("a token minted under a configured secret verifies in another governor",
      d.decision === "Allow" && d.approved === true);

    // …and the same token is refused by a governor holding a different key.
    const other = gov({ approvalSecret: SECRET_B, approvalStore: sharedStore() });
    const token2 = minter.mintApproval(challenge);
    const d2 = await held(other, token2);
    ok("a token verified against a different secret is refused, fail-closed",
      d2.decision === "NeedsApproval" && d2.allowed === false && d2.approved === false);
    ok("the refusal is the uniform reason — it never says which check refused",
      d2.reason === "approval required");
  }
  {
    // One secret configures both halves: the approval key is derived from
    // `tokenSecret` with a domain separator when no `approvalSecret` is given.
    const minter = gov({ tokenSecret: SECRET_A, approvalStore: sharedStore() });
    const consumer = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const d = await held(consumer, minter.mintApproval(challenge));
    ok("tokenSecret alone configures approvals (same derived key as approvalSecret)",
      d.decision === "Allow" && d.approved === true);
    ok("the derivation label is exported and versioned",
      APPROVAL_KEY_LABEL === "watchlight-de:approval-token:v1");
  }
  {
    let err;
    try { gov({ approvalSecret: "too-short" }); } catch (e) { err = e; }
    ok("a weak approval secret fails closed at construction",
      err instanceof ApprovalError && err.code === "weak_secret");
    ok("the error never echoes the secret", err && !String(err.message).includes("too-short"));
  }
  {
    // Nothing configured: the random per-process key still works within the
    // process, which is exactly the scope documented on `mintApproval`.
    const g = gov();
    const d = await held(g, g.mintApproval(challenge));
    ok("the per-process default still approves inside one process",
      d.decision === "Allow" && d.approved === true);
    const foreign = gov({ approvalSecret: SECRET_A });
    const d2 = await held(foreign, g.mintApproval(challenge));
    ok("a per-process token is refused by a governor with a configured secret",
      d2.decision === "NeedsApproval");
  }

  console.log("seen-token store: single use across replicas");
  {
    const store = sharedStore();
    // Two governors, one shared store — two replicas behind a load balancer.
    const a = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const b = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const token = a.mintApproval(challenge);
    const first = await held(a, token);
    const second = await held(b, token);
    ok("the first consumption is approved", first.decision === "Allow" && first.approved === true);
    ok("replaying the same token on another replica is REFUSED",
      second.decision === "NeedsApproval" && second.approved === false);

    // Without the shared store the same replay is admitted twice — the gap the
    // store closes, asserted so it cannot regress into a silent default.
    const c = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const d = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const t2 = c.mintApproval(challenge);
    const r1 = await held(c, t2);
    const r2 = await held(d, t2);
    ok("with SEPARATE stores the same token is consumed once on each replica",
      r1.decision === "Allow" && r2.decision === "Allow");
  }
  {
    const store = sharedStore();
    const g = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const token = g.mintApproval(challenge);
    await held(g, token);
    ok("the reservation is a SINGLE call — never a read then a write",
      store.calls.length === 1 && store.calls[0][0] === "add");
    const [, id] = store.calls.find(([op]) => op === "add");
    const [exp, nonce, sig] = token.split(".");
    ok("the store id is `<exp>.<nonce>` — never the signature", id === `${exp}.${nonce}`);
    ok("the signature never reaches the store", !JSON.stringify(store.calls).includes(sig));
    const [, , expiresAt] = store.calls.find(([op]) => op === "add");
    ok("`add` gets the token's own expiry in epoch milliseconds",
      expiresAt === Number(exp) && expiresAt > Date.now());
  }
  {
    // A store may be asynchronous, exactly like an auditSink — as long as its
    // `add` is still one atomic check-and-set.
    const seen = new Set();
    const asyncStore = {
      async add(id) {
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      },
    };
    const g = gov({ approvalSecret: SECRET_A, approvalStore: asyncStore });
    const token = g.mintApproval(challenge);
    const first = await held(g, token);
    const second = await held(g, token);
    ok("an async store is awaited: approved once, then refused",
      first.decision === "Allow" && second.decision === "NeedsApproval");
  }
  {
    // A conditional `add` (INSERT … ON CONFLICT / SET NX) reports the race by
    // returning false, and that refuses too.
    const g = gov({ approvalSecret: SECRET_A, approvalStore: { add: () => false } });
    const d = await held(g, g.mintApproval(challenge));
    ok("`add` returning false (already present) refuses the approval",
      d.decision === "NeedsApproval");
  }
  for (const [name, value] of [["undefined", undefined], ["null", null], ["a number", 1], ["a string", "ok"]]) {
    // A store that will not say whether the reservation was NEW cannot enforce
    // single use, so it never gets to admit one.
    const warns = await withWarnSpy(async (w) => {
      const g = gov({ approvalSecret: SECRET_A, approvalStore: { add: () => value } });
      const d = await held(g, g.mintApproval(challenge));
      ok(`an \`add\` returning ${name} refuses the approval`, d.decision === "NeedsApproval");
      return w;
    });
    ok(`…and says the store did not report the reservation (${name})`,
      warns.length === 1 && warns[0].includes("newly reserved"));
  }

  console.log("seen-token store: fail closed");
  {
    const boom = () => { throw new Error("store down"); };
    for (const [name, store] of [
      ["add", { add: boom }],
      ["async add", { add: async () => { throw new Error("store down"); } }],
    ]) {
      const warns = await withWarnSpy(async (w) => {
        const g = gov({ approvalSecret: SECRET_A, approvalStore: store });
        const d = await held(g, g.mintApproval(challenge));
        ok(`a throwing ${name} REFUSES the approval (never admits)`, d.decision === "NeedsApproval");
        return w;
      });
      ok(`a throwing ${name} is reported without the error or the id`,
        warns.length === 1 && warns[0].includes("approval store failed") && !warns[0].includes("store down"));
    }
  }
  {
    const warns = await withWarnSpy(async (w) => {
      const g = gov({ approvalSecret: SECRET_A, approvalStore: { add: () => { throw new Error("x"); } } });
      for (let i = 0; i < 3; i++) await held(g, g.mintApproval(challenge));
      return w;
    });
    ok("a broken store is reported once, not once per approval", warns.length === 1);
  }
  {
    // The store is only consulted for an AUTHENTIC token, so a forged one can
    // neither burn an id nor drive load into a remote store.
    const store = sharedStore();
    const g = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const token = g.mintApproval(challenge);
    const [exp, nonce] = token.split(".");
    const forged = `${exp}.${nonce}.${"0".repeat(64)}`;
    const d = await held(g, forged);
    ok("a forged signature is refused", d.decision === "NeedsApproval");
    ok("a forged token never reaches the store", store.calls.length === 0);
    const bound = await held(g, token);
    ok("the genuine token still works afterwards — its id was not burned",
      bound.decision === "Allow");
  }
  {
    // Binding and TTL are unchanged by the store.
    const g = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const wrong = g.mintApproval({ action: "wire", resource: "acct/OTHER" });
    ok("a token bound to another resource is refused",
      (await held(g, wrong)).decision === "NeedsApproval");
    const expired = g.mintApproval(challenge, { ttlMs: -1 });
    ok("an expired token is refused", (await held(g, expired)).decision === "NeedsApproval");
  }

  console.log("concurrency: one token, one Allow");
  {
    // The P0 this guards: `consume` is async, so a "check, then insert" store
    // would put an await between the two and let every concurrent consume of one
    // token through. The reservation is ONE atomic check-and-set instead.
    const g = gov();                       // the DEFAULT in-process store
    const token = g.mintApproval(challenge);
    const results = await Promise.all(Array.from({ length: 8 }, () => held(g, token)));
    const allows = results.filter((d) => d.decision === "Allow").length;
    ok("8 parallel consumes of one token with the default store yield exactly one Allow",
      allows === 1, `got ${allows}`);
    ok("…and the other 7 are held", results.filter((d) => d.decision === "NeedsApproval").length === 7);
  }
  {
    // Same guarantee across governors sharing one atomic store — two replicas,
    // both handling the fan-out at once.
    const store = sharedStore();
    const a = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const b = gov({ approvalSecret: SECRET_A, approvalStore: store });
    const token = a.mintApproval(challenge);
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) => held(i % 2 ? a : b, token))
    );
    ok("8 parallel consumes across two governors on one store yield exactly one Allow",
      results.filter((d) => d.decision === "Allow").length === 1);
  }
  {
    // With latency between the caller and the store — the case a check-then-act
    // implementation loses — an atomic `add` still admits exactly one.
    const seen = new Set();
    const slowAtomic = {
      async add(id) {
        await new Promise((r) => setTimeout(r, 10));   // network latency
        if (seen.has(id)) return false;                // …then one atomic step
        seen.add(id);
        return true;
      },
    };
    const g = gov({ approvalSecret: SECRET_A, approvalStore: slowAtomic });
    const token = g.mintApproval(challenge);
    const results = await Promise.all(Array.from({ length: 8 }, () => held(g, token)));
    ok("8 parallel consumes against a latency-injected async store yield exactly one Allow",
      results.filter((d) => d.decision === "Allow").length === 1);
  }

  console.log("a store that never answers");
  {
    // Fail-STUCK is not acceptable either: a store that never settles would hang
    // the governed call it gates, so it is raced against a deadline and refused.
    const { DEFAULT_APPROVAL_STORE_TIMEOUT_MS } = require("../dist/index.js");
    ok("the deadline is exported and shorter than the egress hook's",
      DEFAULT_APPROVAL_STORE_TIMEOUT_MS === 2000);
    const warns = await withWarnSpy(async (w) => {
      const g = gov({ approvalSecret: SECRET_A, approvalStore: { add: () => new Promise(() => {}) } });
      const started = Date.now();
      const d = await held(g, g.mintApproval(challenge));
      ok("a store that never settles refuses rather than hanging authorize",
        d.decision === "NeedsApproval");
      ok("…within the deadline, not indefinitely",
        Date.now() - started >= DEFAULT_APPROVAL_STORE_TIMEOUT_MS &&
        Date.now() - started < DEFAULT_APPROVAL_STORE_TIMEOUT_MS + 1500);
      return w;
    });
    ok("the timeout is reported once, without the id", warns.length === 1 && warns[0].includes("timed out"));
  }

  console.log("signed payload is unambiguous");
  {
    // Field values are length-prefixed, so no two different triples can sign the
    // same bytes. With a delimiter-joined payload these two collide:
    //   ('U', 'a',    'r1 r2')  vs  ('U', 'a r1', 'r2')
    const g = govAny();
    const token = g.mintApproval({ principal: "U", action: "a", resource: "r1 r2" });
    const shifted = await g.authorize({ principal: "U", action: "a r1", resource: "r2", approval: token });
    ok("a token for (U, a, 'r1 r2') does not verify for (U, 'a r1', r2)",
      shifted.decision === "NeedsApproval" && shifted.approved === false);
    // The same token still verifies for the triple it was actually minted for,
    // so the refusal above is the field boundary and nothing else.
    const exact = await g.authorize({ principal: "U", action: "a", resource: "r1 r2", approval: token });
    ok("…and still verifies for the triple it was minted for", exact.decision === "Allow");

    // The principal/action boundary cannot be shifted either.
    const g2 = govAny();
    const t2 = g2.mintApproval({ principal: "U u2", action: "a", resource: "r" });
    const d2 = await g2.authorize({ principal: "U", action: "u2 a", resource: "r", approval: t2 });
    ok("the principal/action boundary cannot be shifted either",
      d2.decision === "NeedsApproval");
  }
  {
    // Fields with a space, a quote, a backslash, a colon, a digit-colon prefix
    // and non-ASCII text round-trip exactly.
    const g = govAny();
    const awkward = {
      principal: 'User::"a b\\c" 12:34',
      action: "wire funds",
      resource: 'acct/"x y"\\z — ünïcode',
    };
    const d = await g.authorize({ ...awkward, approval: g.mintApproval(awkward) });
    ok("a principal/action/resource with spaces, quotes and backslashes round-trips",
      d.decision === "Allow" && d.approved === true);
  }
  {
    // A token minted under the previous (delimiter-joined, unversioned) payload
    // format is refused: the version marker makes the change explicit, never a
    // silent reinterpretation.
    const g = gov({ approvalSecret: SECRET_A, approvalStore: sharedStore() });
    const key = deriveApprovalKey(normalizeApprovalSecret(SECRET_A));
    const exp = Date.now() + 120_000;
    const nonce = "0011223344556677";
    const legacy = createHmac("sha256", Buffer.from(key))
      .update(`appr-agent wire acct/1 ${exp} ${nonce}`)
      .digest("hex");
    const d = await held(g, `${exp}.${nonce}.${legacy}`);
    ok("a token minted under the previous payload format does not verify",
      d.decision === "NeedsApproval");
    ok("the payload format carries a domain separator and a version",
      APPROVAL_PAYLOAD_VERSION === "watchlight-de:approval:v1");
  }
  {
    // A field that itself looks like a length prefix is still unambiguous.
    const g = govAny();
    const ch = { principal: "3:abc", action: "5:defgh", resource: "0:" };
    const d = await g.authorize({ ...ch, approval: g.mintApproval(ch) });
    ok("a field shaped like a length prefix round-trips", d.decision === "Allow");
    const near = await g.authorize({
      principal: "3:abc5", action: ":defgh", resource: "0:", approval: g.mintApproval(ch),
    });
    ok("…and shifting that boundary is refused", near.decision === "NeedsApproval");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
