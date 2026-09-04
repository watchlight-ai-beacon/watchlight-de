// @watchlight/sdk — obligations on verdicts. A permit annotated
// `@obligate_redact("ssn")` / `@obligate_max_items("8")` / `@obligate_log_values("false")`
// / `@obligate_<name>("raw")` surfaces as `result.obligations` on an Allow.
//
// The derivation is exercised from STUBBED decision payloads (the shared
// tests/fixtures/obligations.json, consumed byte-for-byte by the Python suite
// too) so it does not depend on the installed engine version: the end-to-end
// path runs the networked backend against a local HTTP stub that returns those
// payloads. A final live-engine probe asserts the real thing when the installed
// @watchlight/engine emits the field, and reports a skip when it predates it.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createServer } from "node:http";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, runPolicyTests, AuthorizeError, OBLIGATIONS_INVALID_MESSAGE, MAX_REDACT_ENTRIES } = require("../dist/index.js");
const { deriveObligations, InProcessBackend } = require("../dist/backend.js");
const { normalizeExpectedObligations } = require("../dist/policytest.js");

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli.js");
const fixture = JSON.parse(fs.readFileSync(join(here, "..", "..", "tests", "fixtures", "obligations.json"), "utf8"));

let pass = 0, fail = 0, skipped = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const skip = (name, why) => { console.log(`  - ${name} (skipped: ${why})`); skipped++; };
const throws = async (name, fn, re) => {
  let err = null;
  try { await fn(); } catch (e) { err = e; }
  ok(name, err && (!re || re.test(err.message)), err ? `unexpected: ${err.message}` : "did not throw");
};

// SDK (camelCase) → wire (snake_case) with sorted keys, so both lanes compare
// against the same fixture string.
function toWire(o) {
  if (!o) return null;
  const w = {};
  if (o.redact) w.redact = [...o.redact].sort();
  if (o.maxItems !== undefined) w.max_items = o.maxItems;
  if (o.logValues !== undefined) w.log_values = o.logValues;
  if (o.extra) w.extra = o.extra;
  return w;
}
const canon = (v) => JSON.stringify(sortKeys(v));
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}

const tmp = () => fs.mkdtempSync(join(os.tmpdir(), "wl-oblig-"));

/** A stub control plane: answers every POST /authorize with the payload
 *  selected by the request's `action`. */
function stubServer(byAction) {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const { action } = JSON.parse(body);
      const payload = byAction[action];
      res.writeHead(payload ? 200 : 500, { "content-type": "application/json" });
      res.end(JSON.stringify(payload ?? { error: "no stub" }));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => server.close(r)),
  })));
}

async function main() {
  delete process.env.WATCHLIGHT_APDP_URL;

  // ── 1. shared fixture: derivation is byte-identical to the expected wire form ──
  console.log("shared fixture (tests/fixtures/obligations.json)");
  ok("fixed error message matches the fixture", OBLIGATIONS_INVALID_MESSAGE === fixture.error_message && MAX_REDACT_ENTRIES === fixture.max_redact_entries);
  for (const c of fixture.cases) {
    if (c.error) {
      let err = null;
      try { deriveObligations(c.details); } catch (e) { err = e; }
      ok(c.name, err instanceof AuthorizeError && err.message === fixture.error_message, err ? `unexpected: ${err.name}: ${err.message}` : "did not throw");
      continue;
    }
    const got = canon(toWire(deriveObligations(c.details)));
    const want = canon(c.expected);
    ok(c.name, got === want, `\n      want ${want}\n      got  ${got}`);
  }
  {
    const big = { policy_results: [{ applicable: true, obligations: { redact: Array.from({ length: MAX_REDACT_ENTRIES + 1 }, (_, i) => `f${i}`) } }] };
    let err = null;
    try { deriveObligations(big); } catch (e) { err = e; }
    ok("a redact list beyond the bound fails closed", err instanceof AuthorizeError);
    const atBound = { policy_results: [{ applicable: true, obligations: { redact: Array.from({ length: MAX_REDACT_ENTRIES }, (_, i) => `f${i}`) } }] };
    ok("a redact list at the bound is read", deriveObligations(atBound).redact.length === MAX_REDACT_ENTRIES);
  }

  // ── 2. verdict gate, end to end through the networked backend ──
  console.log("verdict gate (stubbed decisions)");
  const stubs = fixture.stub_decisions;
  const srv = await stubServer({
    allow: stubs.allow_with_obligations,
    deny: stubs.deny_with_stray_obligations,
    denybad: stubs.deny_with_unreadable_obligations,
    allowbad: stubs.allow_with_unreadable_obligations,
    hold: stubs.needs_approval_with_obligations,
  });
  try {
    const g = new Watchlight({ agent: "oblig-agent", auditDir: tmp(), apdpUrl: srv.url });
    const a = await g.authorize({ action: "allow", resource: "doc/1" });
    ok("Allow carries the obligations", a.decision === "Allow" &&
      canon(toWire(a.obligations)) === canon({ redact: ["ssn"], extra: { ttl: ["30"] } }), JSON.stringify(a));
    ok("extra keys pass through untouched", a.obligations.extra.ttl[0] === "30");
    const d = await g.authorize({ action: "deny", resource: "doc/1" });
    ok("Deny never carries obligations, even if the payload has some", d.decision === "Deny" && d.obligations === undefined, JSON.stringify(d));
    const db = await g.authorize({ action: "denybad", resource: "doc/1" });
    ok("a Deny with unreadable obligations is still a plain Deny (nothing to honour)", db.decision === "Deny" && db.obligations === undefined);
    await throws("an Allow with an unreadable known obligation rejects with AuthorizeError (fail-closed)",
      () => g.authorize({ action: "allowbad", resource: "doc/1" }), new RegExp(`^${fixture.error_message}$`));
    {
      let err = null;
      try { await g.authorize({ action: "allowbad", resource: "doc/1" }); } catch (e) { err = e; }
      ok("the error is an AuthorizeError with the fixed message", err instanceof AuthorizeError && err.message === OBLIGATIONS_INVALID_MESSAGE);
      const body = g.tool(async () => "ran", { intent: "allowbad", resource: () => "doc/1" });
      let toolErr = null, ran = null;
      try { ran = await body(); } catch (e) { toolErr = e; }
      ok("a governed tool never runs its body on that decision", ran === null && toolErr !== null, String(toolErr));
    }
    const h = await g.authorize({ action: "hold", resource: "doc/1" });
    ok("NeedsApproval never carries obligations", h.decision === "NeedsApproval" && h.obligations === undefined, JSON.stringify(h));
    const token = g.mintApproval({ action: "hold", resource: "doc/1" });
    const ap = await g.authorize({ action: "hold", resource: "doc/1", approval: token });
    ok("an approved Allow carries them", ap.decision === "Allow" && ap.approved === true &&
      canon(toWire(ap.obligations)) === canon({ redact: ["ssn"], max_items: 4 }), JSON.stringify(ap));
    // Governed tool: the hook receives the same result the caller would.
    const readDoc = g.tool(async (id) => `SSN 123-45-6789 for ${id}`, {
      intent: "allow", resource: (id) => `doc/${id}`,
      onResult: async (text, info) => {
        // A real app looks up `result.obligations` from the authorize decision;
        // here we prove the decision that let the body run carried them.
        const again = await g.authorize({ action: "allow", resource: info.resource });
        return again.obligations?.redact?.includes("ssn") ? g.sanitize(text, { resource: info.resource, types: ["SSN"] }).text : text;
      },
    });
    const out = await readDoc("7");
    ok("onResult can honour a redact obligation via sanitize", /<SSN_1>/.test(out) && !/123-45-6789/.test(out), out);

    // Policy tests through the stub (verdict + obligations expectation).
    const report = await g.test([
      { name: "redact ssn", action: "allow", resource: "doc/1", expect: "Allow", obligations: { redact: ["ssn"], extra: { ttl: "30" } } },
      { name: "redact ssn (extra as a list)", action: "allow", resource: "doc/1", expect: "Allow", obligations: { redact: ["ssn"], extra: { ttl: ["30"] } } },
      { name: "deny carries none", action: "deny", resource: "doc/1", expect: "Deny" },
      { name: "hold carries none", action: "hold", resource: "doc/1", expect: "NeedsApproval", obligations: {} },
      { name: "approved carries them (wire spelling)", action: "hold", resource: "doc/1", approved: true, expect: "Allow", obligations: { redact: ["ssn"], max_items: 4 } },
    ]);
    ok("govern.test asserts obligations end to end", report.failed === 0,
      JSON.stringify(report.results.filter((r) => !r.ok)));
    const rep = report.results[0];
    ok("result exposes actual + expected obligations", rep.obligations?.redact?.[0] === "ssn" && rep.expectedObligations?.redact?.[0] === "ssn");
  } finally {
    await srv.close();
  }

  // ── 3. runPolicyTests with a pure stub decide ──
  console.log("policy test expectations");
  const decideWith = (obligations) => async () => ({ decision: "Allow", reason: "", ...(obligations ? { obligations } : {}) });
  const mint = () => "tok";
  const allowSsn = decideWith({ redact: ["ssn", "dob"], maxItems: 8, logValues: false, extra: { ttl: ["30", "60"] } });
  let r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow",
    obligations: { redact: ["dob", "ssn"], maxItems: 8, logValues: false, extra: { ttl: ["60", "30", "60"] } } }]);
  ok("exact match passes (redact and extra order-insensitive, de-duplicated)", r.failed === 0, JSON.stringify(r));
  r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow",
    obligations: { redact: ["dob", "ssn"], max_items: 8, log_values: false, extra: { ttl: ["30", "60"] } } }]);
  ok("snake_case spellings are accepted", r.failed === 0, JSON.stringify(r));
  r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow", obligations: { redact: ["ssn"] } }]);
  ok("a subset expectation fails (exact match, not containment)", r.failed === 1 && r.results[0].actual === "Allow");
  r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow", obligations: { redact: ["dob", "ssn"], maxItems: 8, logValues: false, extra: { ttl: "60" } } }]);
  ok("a partial extra value set fails (a string is a one-element set)", r.failed === 1);
  r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow" }]);
  ok("no expectation → obligations are not compared", r.failed === 0 && r.results[0].obligations?.maxItems === 8);
  r = await runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow", obligations: {} }]);
  ok("`{}` asserts no obligations and fails when some are carried", r.failed === 1);
  r = await runPolicyTests(decideWith(undefined), mint, [{ action: "x", expect: "Allow", obligations: {} }]);
  ok("`{}` passes when none are carried", r.failed === 0);
  r = await runPolicyTests(decideWith(undefined), mint, [{ action: "x", expect: "Allow", obligations: { redact: ["ssn"] } }]);
  ok("expected but absent fails", r.failed === 1);
  r = await runPolicyTests(async () => ({ decision: "Deny", reason: "not authorized" }), mint, [{ action: "x", expect: "Deny", obligations: {} }]);
  ok("`{}` is accepted on a Deny expectation", r.failed === 0);

  const malformed = [
    ["a string", "ssn", /must be an object/],
    ["an unknown key", { redakt: ["ssn"] }, /unknown obligations key 'redakt'/],
    ["an empty redact", { redact: [] }, /redact/],
    ["a blank redact entry", { redact: ["ssn", " "] }, /redact/],
    ["a non-string redact entry", { redact: [1] }, /redact/],
    ["a zero maxItems", { maxItems: 0 }, /maxItems/],
    ["a string maxItems", { max_items: "8" }, /maxItems/],
    ["a string logValues", { logValues: "false" }, /logValues/],
    ["contradictory spellings", { maxItems: 8, max_items: 3 }, /disagree/],
    ["a non-string extra value", { extra: { ttl: 30 } }, /extra/],
    ["an array extra", { extra: ["ttl"] }, /extra/],
    ["an empty extra value list", { extra: { ttl: [] } }, /extra/],
    ["a non-string entry in an extra value list", { extra: { ttl: ["30", 60] } }, /extra/],
    ["a null maxItems", { maxItems: null }, /maxItems/],
    ["a null redact", { redact: null }, /redact/],
    ["a null extra", { extra: null }, /extra/],
    ["mixed spellings where one is null", { maxItems: 8, max_items: null }, /disagree/],
  ];
  for (const [label, obligations, re] of malformed) {
    await throws(`malformed expectation throws: ${label}`, () => runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Allow", obligations }]), re);
  }
  await throws("non-empty obligations on a Deny expectation throws",
    () => runPolicyTests(allowSsn, mint, [{ action: "x", expect: "Deny", obligations: { redact: ["ssn"] } }]), /only be expected on an Allow/);
  await throws("non-empty obligations on a NeedsApproval expectation throws",
    () => runPolicyTests(allowSsn, mint, [{ action: "x", expect: "NeedsApproval", obligations: { maxItems: 1 } }]), /only be expected on an Allow/);
  ok("normalizeExpectedObligations canonicalizes to camelCase",
    canon(normalizeExpectedObligations({ redact: [" ssn ", "ssn"], max_items: 2, log_values: true, extra: {} }, "f")) ===
      canon({ redact: ["ssn"], maxItems: 2, logValues: true }));
  ok("normalizeExpectedObligations lifts a string extra to a sorted set",
    canon(normalizeExpectedObligations({ extra: { a: "x", b: ["z", "y", "z"] } }, "f")) === canon({ extra: { a: ["x"], b: ["y", "z"] } }));

  // ── 4. CLI: a malformed obligations expectation is a malformed suite (exit 2) ──
  console.log("CLI");
  const suiteDir = tmp();
  const mal = join(suiteDir, "mal.json");
  fs.writeFileSync(mal, JSON.stringify({
    policies: [{ name: "p", code: 'permit(principal, action == Action::"read", resource);' }],
    tests: [{ action: "read", expect: "Allow", obligations: "ssn" }],
  }));
  const r4 = spawnSync(process.execPath, [CLI, "policy", "test", mal], { encoding: "utf8" });
  ok("CLI malformed obligations expectation exits 2", r4.status === 2, `- status ${r4.status}\n${r4.stderr}`);
  const mismatch = join(suiteDir, "mismatch.json");
  fs.writeFileSync(mismatch, JSON.stringify({
    policies: [{ name: "p", code: 'permit(principal, action == Action::"read", resource);' }],
    tests: [{ name: "plain permit carries none", action: "read", expect: "Allow", obligations: { redact: ["ssn"] } }],
  }));
  const r5 = spawnSync(process.execPath, [CLI, "policy", "test", mismatch], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  ok("CLI reports an obligations mismatch as a failure (exit 1)", r5.status === 1 && /expected obligations .*"redact"/.test(r5.stdout), `- status ${r5.status}\n${r5.stdout}`);

  // ── 5. live engine: real annotation → real obligations. The skip is decided on
  //      the RAW engine payload (does the engine emit `obligations` at all?), never
  //      on the SDK result — so an SDK regression cannot hide behind a skip. ──
  console.log("live engine");
  const ANNOTATED = '@obligate_redact("ssn, dob")\n@obligate_max_items("8")\n@obligate_log_values("false")\n@obligate_retention("30d")\npermit(principal, action == Action::"read", resource);';
  const probe = new InProcessBackend();
  probe.addPolicy({ name: "annotated", code: ANNOTATED });
  const rawEngine = await probe.engine();
  const raw = await rawEngine.authorize({ principal: "p", action: "read", resource: "doc/1", context: {} });
  const rawDetails = raw?.details ?? {};
  const engineEmits = "obligations" in rawDetails ||
    (Array.isArray(rawDetails.policy_results) && rawDetails.policy_results.some((r) => r && "obligations" in r));
  if (!engineEmits) {
    skip("live engine surfaces @obligate_* annotations", "the installed @watchlight/engine emits no obligations field in its raw payload");
  } else {
    ok("live engine: raw payload carries the merged details.obligations", rawDetails.obligations && Array.isArray(rawDetails.obligations.redact), JSON.stringify(rawDetails.obligations));
    const live = new Watchlight({ agent: "oblig-live", auditDir: tmp() });
    live.allow(ANNOTATED, "annotated");
    const lr = await live.authorize({ action: "read", resource: "doc/1" });
    ok("live engine: Allow", lr.decision === "Allow", JSON.stringify(lr));
    ok("live engine: SDK result carries obligations", lr.obligations !== undefined, JSON.stringify(lr));
    ok("live engine: redact union", canon([...(lr.obligations?.redact ?? [])].sort()) === canon(["dob", "ssn"]), JSON.stringify(lr.obligations));
    ok("live engine: maxItems", lr.obligations?.maxItems === 8);
    ok("live engine: logValues", lr.obligations?.logValues === false);
    ok("live engine: extra passes through as a value list", canon(lr.obligations?.extra?.retention) === canon(["30d"]), JSON.stringify(lr.obligations?.extra));
    const liveReport = await live.test([{ action: "read", expect: "Allow",
      obligations: { redact: ["ssn", "dob"], maxItems: 8, logValues: false, extra: { retention: "30d" } } }]);
    ok("live engine: govern.test asserts them", liveReport.failed === 0, JSON.stringify(liveReport.results));
    // Two carrying permits: the SDK's merge agrees with the engine's.
    const two = new Watchlight({ agent: "oblig-two", auditDir: tmp() });
    two.allow('@obligate_redact("ssn")\n@obligate_max_items("8")\npermit(principal, action == Action::"read", resource);', "a");
    two.allow('@obligate_redact("dob")\n@obligate_max_items("3")\n@obligate_log_values("true")\npermit(principal, action == Action::"read", resource);', "b");
    const tr = await two.authorize({ action: "read", resource: "doc/2" });
    ok("live engine: two carriers merge to the strictest reading",
      tr.decision === "Allow" && canon([...(tr.obligations?.redact ?? [])].sort()) === canon(["dob", "ssn"]) && tr.obligations?.maxItems === 3 && tr.obligations?.logValues === true,
      JSON.stringify(tr.obligations));
    const denied = await live.authorize({ action: "write", resource: "doc/1" });
    ok("live engine: a Deny carries none", denied.decision === "Deny" && denied.obligations === undefined);
  }
  const plain = new Watchlight({ agent: "oblig-plain", auditDir: tmp() });
  plain.allow('permit(principal, action == Action::"read", resource);', "plain");
  const pr = await plain.authorize({ action: "read" });
  ok("live engine: an unannotated permit carries no obligations", pr.decision === "Allow" && pr.obligations === undefined);

  console.log(`\nobligations: ${pass} passed, ${fail} failed${skipped ? `, ${skipped} skipped` : ""}`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
