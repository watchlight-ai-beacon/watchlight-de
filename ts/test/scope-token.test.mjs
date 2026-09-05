// @watchlight/sdk — serialisable attenuated scopes (scope.toToken /
// Watchlight.scopeFromToken). Runs the real @watchlight/engine core: the
// receiving side must REPLAY the chain through the engine's strict-subset
// validator, so a widened chain is refused even with a valid signature.
// Cross-lane: tests/fixtures/scope-token.json is shared with the Python suite —
// both lanes must reproduce the canonical JSON and the token byte-for-byte.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, AttenuationDenied, ScopeTokenError, SCOPE_TOKEN_PREFIX, MAX_TOKEN_LENGTH } = require("../dist/index.js");
const { canonicalJson, normalizeClaims, signScopeToken, verifyScopeToken } = require("../dist/scope-token.js");

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(join(here, "..", "..", "tests", "fixtures", "scope-token.json"), "utf8"));

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const rejects = async (name, fn, code, extra = () => true) => {
  let err = null;
  try { await fn(); } catch (e) { err = e; }
  const isTokenErr = err instanceof ScopeTokenError && err.code === code;
  ok(name, isTokenErr && extra(err), err ? `${err.name}/${err.code ?? ""}: ${err.message}` : "did not throw");
};

const SECRET = "unit-test-secret-0123456789abcdef";
const tmp = () => fs.mkdtempSync(join(os.tmpdir(), "wl-sdk-tok-"));
const gov = (opts = {}) => new Watchlight({ agent: "test-agent", auditDir: tmp(), tokenSecret: SECRET, ...opts });
const now = () => Math.floor(Date.now() / 1000);
const sorted = (xs) => [...xs].sort();
const same = (a, b) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

async function main() {
  delete process.env.WATCHLIGHT_TOKEN_SECRET;

  // ── round trip within one process ──
  const g = gov();
  const root = await g.scope({ tools: ["read", "search", "write"], resources: ["docs/*"], intents: ["research"], timeBudgetSeconds: 600 });
  const child = root.attenuate({ tools: ["read", "search"] });
  const grandchild = child.attenuate({ tools: ["read"], timeBudgetSeconds: 300 });
  const token = grandchild.toToken();
  ok("token is versioned + three segments", token.startsWith(`${SCOPE_TOKEN_PREFIX}.`) && token.split(".").length === 3);
  ok("token is base64url only", /^wls1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token));

  const back = await g.scopeFromToken(token);
  ok("rebuilt scope has the same depth", back.depth === 2, String(back.depth));
  ok("rebuilt scope has the engine-granted tools", same(back.allowedTools, ["read"]), JSON.stringify(back.allowedTools));
  ok("rebuilt scope keeps resources/intents", same(back.allowedResources, ["docs/*"]) && same(back.allowedIntents, ["research"]));
  ok("rebuilt scope keeps the clamped time budget", back.timeBudgetSeconds === 300);
  ok("rebuilt scope cannot outlive the token", back.expiresAt <= grandchild.expiresAt && back.expiresAt <= now() + 300);
  ok("rebuilt scope can attenuate further via the engine", back.attenuate({ tools: ["read"] }).depth === 3);
  let widen = null;
  try { back.attenuate({ tools: ["read", "write"] }); } catch (e) { widen = e; }
  ok("rebuilt scope still cannot widen", widen instanceof AttenuationDenied);

  // ── payload hygiene: only the documented claims, nothing else ──
  const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  ok("payload carries exactly the documented keys", JSON.stringify(Object.keys(payload).sort()) === JSON.stringify(["agent", "chain", "depth", "exp", "iat", "root"]));
  ok("payload has no audit path and no secret", !token.includes("audit") && !token.includes(SECRET) && !JSON.stringify(payload).includes("wl-sdk-tok-"));
  ok("payload chain carries GRANTED dims per level", payload.chain.length === 2 && same(payload.chain[0].tools, ["read", "search"]) && same(payload.chain[1].tools, ["read"]));

  // ── another process with the same secret accepts it (a fresh governor + audit dir) ──
  const worker = gov();
  const inWorker = await worker.scopeFromToken(token);
  ok("second process with the same secret accepts the token", inWorker.depth === 2 && same(inWorker.allowedTools, ["read"]));

  // ── acceptance: tampered payload ──
  const [v, p, s] = token.split(".");
  const flipped = p[10] === "A" ? "B" : "A";
  await rejects("tampered payload is rejected (signature)", () => g.scopeFromToken(`${v}.${p.slice(0, 10)}${flipped}${p.slice(11)}.${s}`), "signature");
  // Flip a middle character: the last char of unpadded base64url carries zero bits, so a
  // flip there can yield a non-canonical string rejected as malformed before the HMAC check.
  await rejects("tampered signature is rejected", () => g.scopeFromToken(`${v}.${p}.${s.slice(0, 5)}${s[5] === "A" ? "B" : "A"}${s.slice(6)}`), "signature");
  await rejects("wrong secret is rejected (signature)", () => gov({ tokenSecret: "another-secret-0123456789abcdef" }).scopeFromToken(token), "signature");

  // ── acceptance: widened scope with a VALID signature → the engine refuses ──
  const widened = signScopeToken({
    agent: "test-agent",
    root: { tools: ["read"], resources: [], intents: ["research"], max_depth: 5, time_budget_seconds: 600 },
    chain: [{ tools: ["read", "delete"], resources: [], intents: ["research"], time_budget_seconds: 600 }],
    depth: 1, iat: now(), exp: now() + 300,
  }, Buffer.from(SECRET));
  let engineSaidNo = null;
  try { await g.scopeFromToken(widened); } catch (e) { engineSaidNo = e; }
  ok("widened chain with a valid signature is refused BY THE ENGINE", engineSaidNo instanceof AttenuationDenied, String(engineSaidNo));
  ok("engine names the overreaching dimension", engineSaidNo && engineSaidNo.violations.includes("AllowedTools"), JSON.stringify(engineSaidNo?.violations));

  // ── acceptance: expired ──
  const expired = signScopeToken({
    agent: "test-agent",
    root: { tools: ["read"], resources: [], intents: [], max_depth: 5, time_budget_seconds: 600 },
    chain: [], depth: 0, iat: now() - 700, exp: now() - 100,
  }, Buffer.from(SECRET));
  await rejects("expired token is rejected", () => g.scopeFromToken(expired), "expired");

  // ── fail-closed: no secret ──
  const bare = new Watchlight({ agent: "test-agent", auditDir: tmp() });
  const bareRoot = await bare.scope({ tools: ["read"] });
  await rejects("toToken without a secret fails closed", () => bareRoot.toToken(), "no_secret", (e) => e.message.includes("signingSecret"));
  await rejects("scopeFromToken without a secret fails closed", () => bare.scopeFromToken(token), "no_secret");
  let weak = null;
  try { new Watchlight({ agent: "x", auditDir: tmp(), tokenSecret: "short" }); } catch (e) { weak = e; }
  ok("a short secret is refused at construction", weak instanceof ScopeTokenError && weak.code === "weak_secret" && !weak.message.includes("short"));

  // ── identity binding ──
  await rejects("token bound to another agent is rejected", () => new Watchlight({ agent: "other-agent", auditDir: tmp(), tokenSecret: SECRET }).scopeFromToken(token), "identity");

  // ── format hardening ──
  await rejects("unknown version is rejected", () => g.scopeFromToken(`wls2.${p}.${s}`), "version");
  await rejects("two segments is malformed", () => g.scopeFromToken(`${v}.${p}`), "malformed");
  await rejects("padded base64 is malformed", () => g.scopeFromToken(`${v}.${p}==.${s}`), "malformed");
  await rejects("non-base64url chars are malformed", () => g.scopeFromToken(`${v}.${p}+/.${s}`), "malformed");
  await rejects("oversized token is rejected before parsing", () => g.scopeFromToken(`${v}.${"A".repeat(MAX_TOKEN_LENGTH)}.${s}`), "too_large");
  await rejects("non-string token is malformed", () => g.scopeFromToken(12345), "malformed");
  const base = { agent: "test-agent", root: { tools: ["read"], resources: [], intents: [], max_depth: 5, time_budget_seconds: 600 }, chain: [], depth: 0 };
  await rejects("future iat is rejected", () => g.scopeFromToken(signScopeToken({ ...base, iat: now() + 3600, exp: now() + 3900 }, Buffer.from(SECRET))), "future_iat");
  await rejects("lifetime beyond the scope's budget is rejected", () => g.scopeFromToken(signScopeToken({ ...base, iat: now(), exp: now() + 601 }, Buffer.from(SECRET))), "lifetime");
  await rejects("root max_depth above the ceiling is rejected", () => g.scopeFromToken(signScopeToken({ ...base, root: { ...base.root, max_depth: 9 }, iat: now(), exp: now() + 60 }, Buffer.from(SECRET))), "malformed");
  await rejects("depth/chain mismatch is rejected", () => g.scopeFromToken(signScopeToken({ ...base, depth: 1, iat: now(), exp: now() + 60 }, Buffer.from(SECRET))), "malformed");
  // A validly signed payload with an extra field: sign the raw string by hand.
  {
    const { createHmac } = await import("node:crypto");
    const raw = canonicalJson({ ...normalizeClaims({ ...base, iat: now(), exp: now() + 60 }), extra: "x" });
    const body = `${SCOPE_TOKEN_PREFIX}.${Buffer.from(raw).toString("base64url")}`;
    const sig = createHmac("sha256", Buffer.from(SECRET)).update(body).digest().toString("base64url");
    await rejects("unknown claim fields are rejected", () => g.scopeFromToken(`${body}.${sig}`), "malformed");
    const nonCanon = `${SCOPE_TOKEN_PREFIX}.${Buffer.from(JSON.stringify({ ...base, iat: now(), exp: now() + 60 }, null, 1)).toString("base64url")}`;
    const sig2 = createHmac("sha256", Buffer.from(SECRET)).update(nonCanon).digest().toString("base64url");
    await rejects("non-canonical payload encoding is rejected", () => g.scopeFromToken(`${nonCanon}.${sig2}`), "malformed");
  }

  // ── ttl is capped at the scope's remaining lifetime ──
  const shortRoot = await g.scope({ tools: ["read"], timeBudgetSeconds: 120 });
  const capped = verifyScopeToken(shortRoot.toToken({ ttlSeconds: 999999 }), Buffer.from(SECRET), { agent: "test-agent" });
  ok("ttl is capped at the scope's expiry", capped.exp <= shortRoot.expiresAt && capped.exp - capped.iat <= 120, JSON.stringify({ exp: capped.exp, iat: capped.iat }));
  await rejects("non-positive ttl is rejected", () => shortRoot.toToken({ ttlSeconds: 0 }), "lifetime");

  // ── cross-lane fixture (shared with the Python suite) ──
  ok("fixture: canonical JSON reproduced byte-for-byte", canonicalJson(normalizeClaims(fixture.claims)) === fixture.canonical);
  ok("fixture: token reproduced byte-for-byte", signScopeToken(fixture.claims, Buffer.from(fixture.secret, "utf8")) === fixture.token);
  const fx = verifyScopeToken(fixture.token, Buffer.from(fixture.secret, "utf8"), { agent: fixture.agent, now: fixture.now });
  ok("fixture: verifies and yields the normalised claims", canonicalJson(fx) === fixture.canonical);
  const fg = new Watchlight({ agent: fixture.agent, auditDir: tmp(), tokenSecret: fixture.secret });
  const fs2 = await fg.scopeFromToken(fixture.token);
  ok("fixture: engine replays the chain to depth 2 / tools [read_file]", fs2.depth === 2 && same(fs2.allowedTools, ["read_file"]), JSON.stringify(fs2.allowedTools));
  await rejects("fixture: rejected under the wrong agent", () => gov({ tokenSecret: fixture.secret }).scopeFromToken(fixture.token), "identity");

  // ── fixture edge cases (astral chars, empty arrays, duplicates) ──
  for (const c of fixture.cases) {
    ok(`fixture[${c.name}]: canonical reproduced`, canonicalJson(normalizeClaims(c.claims)) === c.canonical);
    ok(`fixture[${c.name}]: token reproduced`, signScopeToken(c.claims, Buffer.from(fixture.secret, "utf8")) === c.token);
    ok(`fixture[${c.name}]: verifies`, canonicalJson(verifyScopeToken(c.token, Buffer.from(fixture.secret, "utf8"), { agent: fixture.agent, now: fixture.now })) === c.canonical);
  }

  // ── a rebuilt scope past the token's exp is spent: attenuate/toToken refuse ──
  const live = await g.scopeFromToken((await g.scope({ tools: ["read", "search"], timeBudgetSeconds: 600 })).attenuate({ tools: ["read"] }).toToken());
  live._bindExpiry(now() - 1); // simulate the token's exp having passed
  ok("spent scope reports expired", live.expired === true);
  await rejects("spent rebuilt scope refuses attenuate", () => live.attenuate({ tools: ["read"] }), "expired", (e) => e.message.endsWith("scope has expired"));
  await rejects("spent rebuilt scope refuses toToken", () => live.toToken(), "expired");
  await rejects("assertActive fails closed on a spent scope", () => live.assertActive(), "expired");

  // ── an EMPTY env secret is "unset" (the unfilled .env placeholder), while one
  //    SET to nothing usable is a misconfiguration and is refused ──
  process.env.WATCHLIGHT_SIGNING_SECRET = "";
  let emptyOk = null;
  try { emptyOk = new Watchlight({ agent: "test-agent", auditDir: tmp() }); } catch (e) { emptyOk = e; }
  ok("empty WATCHLIGHT_SIGNING_SECRET does not break construction", emptyOk instanceof Watchlight, String(emptyOk));
  await rejects("...but token operations still fail closed", async () => (await emptyOk.scope({ tools: ["read"] })).toToken(), "no_secret");
  process.env.WATCHLIGHT_SIGNING_SECRET = "   ";
  let blank = null;
  try { blank = new Watchlight({ agent: "test-agent", auditDir: tmp() }); } catch (e) { blank = e; }
  ok("an env secret set to nothing usable is refused, not treated as unset",
    blank instanceof ScopeTokenError && blank.code === "no_secret", String(blank));
  delete process.env.WATCHLIGHT_SIGNING_SECRET;
  let emptyOpt = null;
  try { emptyOpt = new Watchlight({ agent: "test-agent", auditDir: tmp(), signingSecret: "" }); } catch (e) { emptyOpt = e; }
  ok("empty signingSecret option is treated as unset", emptyOpt instanceof Watchlight);

  // ── a Uint8Array secret is copied: mutating the caller's array cannot change the key ──
  const keyBytes = new Uint8Array(Buffer.from(SECRET, "utf8"));
  const gb = new Watchlight({ agent: "test-agent", auditDir: tmp(), tokenSecret: keyBytes });
  keyBytes.fill(0);
  const tokB = (await gb.scope({ tools: ["read"] })).toToken();
  ok("Uint8Array secret is copied at construction", (await gov().scopeFromToken(tokB)).depth === 0);

  // ── a token-rebuilt scope reports through the governor's audit funnel (file + auditSink) ──
  const sunk = [];
  const sinkDir = tmp();
  const gs = new Watchlight({ agent: "test-agent", auditDir: sinkDir, tokenSecret: SECRET, auditSink: (r) => sunk.push(r) });
  const rebuilt = await gs.scopeFromToken((await gov().scope({ tools: ["read", "search"], timeBudgetSeconds: 600 })).attenuate({ tools: ["read"] }).toToken());
  rebuilt.attenuate({ tools: ["read"] });
  const sunkAtt = sunk.filter((r) => r.event === "attenuation");
  ok("auditSink receives the rebuilt root + replayed level + further attenuation", sunkAtt.map((r) => r.depth).join(",") === "0,1,2", JSON.stringify(sunkAtt.map((r) => r.depth)));
  const fileAtt = fs.readFileSync(join(sinkDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse).filter((r) => r.event === "attenuation");
  ok("audit.jsonl carries the same attenuation records as the sink", fileAtt.length === sunkAtt.length && fileAtt.every((r, i) => r.node_id === sunkAtt[i].node_id));
  ok("sink records are value-free (no token, no secret)", !JSON.stringify(sunk).includes("wls1.") && !JSON.stringify(sunk).includes(SECRET));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
