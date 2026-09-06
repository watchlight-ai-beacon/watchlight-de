// @watchlight/sdk policy test harness — golden fixtures asserting
// Allow/Deny/NeedsApproval against the real @watchlight/engine, the audit-free
// guarantee, and the `watchlight policy test` CLI. No mocks.
import { createRequire } from "node:module";
import { join, dirname } from "node:path";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight } = require("../dist/index.js");
const CLI = join(dirname(new URL(import.meta.url).pathname), "..", "dist", "cli.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

// A representative money-movement policy set: a funded-balance check.
const POLICIES = [
  { name: "funded-book",
    code: 'permit(principal, action == Action::"book", resource) when { context.amount <= context.limit && context.refundable };' },
  { name: "big-wire-approval",
    code: '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource) when { context.amount > 1000 };' },
  { name: "alice-pays",
    code: 'permit(principal == User::"alice", action == Action::"pay", resource);' },
];

const CASES = [
  { name: "book under limit + refundable allows", action: "book",
    context: { amount: 200, limit: 500, refundable: true }, expect: "Allow" },
  { name: "book over limit denies", action: "book",
    context: { amount: 800, limit: 500, refundable: true }, expect: "Deny" },
  { name: "book non-refundable denies", action: "book",
    context: { amount: 200, limit: 500, refundable: false }, expect: "Deny" },
  { name: "big wire needs approval", action: "wire",
    context: { amount: 2000 }, expect: "NeedsApproval" },
  { name: "big wire with human approval allows", action: "wire",
    context: { amount: 2000 }, approved: true, expect: "Allow" },
  { name: "small wire denies (no matching permit)", action: "wire",
    context: { amount: 500 }, expect: "Deny" },
  { name: "alice may pay", action: "pay", principal: 'User::"alice"', expect: "Allow" },
  { name: "bob may not pay", action: "pay", principal: 'User::"bob"', expect: "Deny" },
];

function loadGovernor(auditDir) {
  const g = new Watchlight({ agent: "policy-test", auditDir });
  for (const p of POLICIES) g.allow(p.code, p.name);
  return g;
}

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-ptest-"));

  // Actor fixtures must exercise the same real engine as an explicit handle.
  const actorGovAuditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-actor-"));
  const actorGov = new Watchlight({ agent: "policy-test", auditDir: actorGovAuditDir });
  actorGov.allow('permit(principal, action == Action::"document_review", resource == Resource::"tool/read_document") when { context.actor == "document-reader" };');
  const request = { action: "document_review", resource: "tool/read_document" };
  ok("real engine actor handle allows", (await actorGov.as("document-reader").authorize(request)).decision === "Allow");
  const actorAudit = join(actorGovAuditDir, "audit.jsonl");
  const beforeActorAudit = fs.readFileSync(actorAudit, "utf8");
  const actorReport = await actorGov.test([
    { ...request, actor: "document-reader", expect: "Allow" },
    { ...request, actor: "other-reader", expect: "Deny" },
    { ...request, expect: "Deny" },
    { ...request, actor: "document-reader", principal: 'User::"alice"', expect: "Allow" },
  ]);
  ok("fixture actor allows", actorReport.failed === 0, JSON.stringify(actorReport));
  let unknownRejected = false;
  try { await actorGov.test([{ action: "missing", expect: "Deny", actro: "document-reader" }]); }
  catch (e) { unknownRejected = /unknown fixture key/.test(e.message); }
  ok("unknown fixture key throws", unknownRejected);
  ok("actor fixtures leave governor identity unchanged", actorGov.agent === "policy-test" && JSON.stringify(actorGov.actorChain) === '["policy-test"]');
  ok("actor fixtures do not write audit", fs.readFileSync(actorAudit, "utf8") === beforeActorAudit);
  actorGov.allow('@enforcement_effect("require_approval")\npermit(principal == Agent::"document-reader", action == Action::"review", resource) when { context.actor == "document-reader" && context.actor_chain == ["document-reader"] };');
  const actorApproval = await actorGov.test([
    { action: "review", actor: "document-reader", expect: "NeedsApproval" },
    { action: "review", actor: "document-reader", approved: true, expect: "Allow" },
    { action: "review", actor: "document-reader", approved: true, expect: "Allow" },
    { action: "review", actor: "document-reader", principal: 'User::"alice"', approved: true, expect: "Deny" },
  ]);
  ok("actor approval tokens use the actor principal and chain", actorApproval.failed === 0, JSON.stringify(actorApproval));
  ok("actor approvals do not write audit", fs.readFileSync(actorAudit, "utf8") === beforeActorAudit);
  for (const actor of [null, 17, "", " ", "reader\nother"]) {
    let rejected = false;
    try { await actorGov.test([{ action: "review", actor, expect: "Deny" }]); }
    catch { rejected = true; }
    ok(`invalid actor rejected: ${JSON.stringify(actor)}`, rejected);
  }
  let reservedRejected = false;
  try { await actorGov.test([{ action: "review", actor: "reader", context: { actor: "other" }, expect: "Deny" }]); }
  catch (e) { reservedRejected = e.name === "ReservedContextError"; }
  ok("actor fixture cannot override reserved context", reservedRejected);

  // ── 1. programmatic: every fixture passes against the real engine ──
  const g = loadGovernor(auditDir);
  const report = await g.test(CASES);
  ok("all fixtures pass", report.failed === 0,
    `- ${report.failed} failed: ${report.results.filter(r => !r.ok).map(r => `${r.name}[${r.expected}!=${r.actual}]`).join(", ")}`);
  ok("report totals are consistent",
    report.total === CASES.length && report.passed + report.failed === report.total);

  // ── 2. a wrong expectation is reported as a failure (harness has teeth) ──
  const bad = await g.test([{ name: "deny expected but allows", action: "book",
    context: { amount: 10, limit: 500, refundable: true }, expect: "Deny" }]);
  ok("wrong expectation fails", bad.failed === 1 && bad.results[0].ok === false);
  ok("failure carries the actual verdict", bad.results[0].actual === "Allow");

  // ── 3. audit-free: running fixtures writes NOTHING to the trail ──
  const auditFile = join(auditDir, "audit.jsonl");
  ok("test() does not write the audit trail", !fs.existsSync(auditFile));
  // sanity: a real authorize() DOES write, proving the dir/path are wired
  await g.authorize({ action: "pay", principal: 'User::"alice"' });
  ok("authorize() still writes the audit trail", fs.existsSync(auditFile));

  // ── 4. CLI: a passing suite exits 0 ──
  const suiteDir = fs.mkdtempSync(join(os.tmpdir(), "wl-suite-"));
  const passSuite = join(suiteDir, "pass.json");
  fs.writeFileSync(passSuite, JSON.stringify({ policies: POLICIES, tests: CASES }));
  const r0 = spawnSync(process.execPath, [CLI, "policy", "test", passSuite], { encoding: "utf8" });
  ok("CLI passing suite exits 0", r0.status === 0, `- status ${r0.status}\n${r0.stdout}${r0.stderr}`);
  ok("CLI prints a summary", /8 passed, 0 failed/.test(r0.stdout), `- got:\n${r0.stdout}`);

  // ── 5. CLI: a failing suite exits 1 ──
  const failSuite = join(suiteDir, "fail.json");
  fs.writeFileSync(failSuite, JSON.stringify({ policies: POLICIES,
    tests: [{ name: "wrong", action: "book", context: { amount: 10, limit: 500, refundable: true }, expect: "Deny" }] }));
  const r1 = spawnSync(process.execPath, [CLI, "policy", "test", failSuite], { encoding: "utf8" });
  ok("CLI failing suite exits 1", r1.status === 1, `- status ${r1.status}`);

  // ── 6. CLI: policyFile resolves relative to the suite ──
  const polFile = join(suiteDir, "watchlight.policy.json");
  fs.writeFileSync(polFile, JSON.stringify(POLICIES));
  const refSuite = join(suiteDir, "ref.json");
  fs.writeFileSync(refSuite, JSON.stringify({ policyFile: "watchlight.policy.json",
    tests: [{ name: "alice pays", action: "pay", principal: 'User::"alice"', expect: "Allow" }] }));
  const r2 = spawnSync(process.execPath, [CLI, "policy", "test", refSuite], { encoding: "utf8" });
  ok("CLI resolves policyFile relative to suite", r2.status === 0, `- status ${r2.status}\n${r2.stdout}${r2.stderr}`);

  // ── 7. CLI: missing arg is a usage error (exit 2), not a false pass ──
  const r3 = spawnSync(process.execPath, [CLI, "policy", "test"], { encoding: "utf8" });
  ok("CLI missing suite arg exits 2", r3.status === 2, `- status ${r3.status}`);

  // ── 8. nonce: two identical approved fixtures both downgrade (no token collision) ──
  const dup = await g.test([
    { name: "wire approved A", action: "wire", context: { amount: 3000 }, approved: true, expect: "Allow" },
    { name: "wire approved B", action: "wire", context: { amount: 3000 }, approved: true, expect: "Allow" },
  ]);
  ok("duplicate approved fixtures both pass (nonce)", dup.failed === 0,
    `- ${JSON.stringify(dup.results.map(r => [r.name, r.actual]))}`);

  // ── 9. malformed fixture (missing expect/action) throws, never a false pass ──
  let threwExpect = false, threwAction = false;
  try { await g.test([{ action: "book", context: { amount: 1, limit: 5, refundable: true } }]); }
  catch { threwExpect = true; }
  try { await g.test([{ expect: "Deny" }]); } catch { threwAction = true; }
  ok("missing expect throws", threwExpect);
  ok("missing action throws", threwAction);

  const malSuite = join(suiteDir, "mal.json");
  fs.writeFileSync(malSuite, JSON.stringify({ policies: POLICIES, tests: [{ action: "book" }] }));
  const r4 = spawnSync(process.execPath, [CLI, "policy", "test", malSuite], { encoding: "utf8" });
  ok("CLI malformed fixture exits 2", r4.status === 2, `- status ${r4.status}`);

  const actorSuite = join(suiteDir, "actor.json");
  const actorPolicies = [{ code: 'permit(principal, action == Action::"document_review", resource == Resource::"tool/read_document") when { context.actor == "document-reader" };' }];
  fs.writeFileSync(actorSuite, JSON.stringify({ policies: actorPolicies, tests: [{ ...request, actor: "document-reader", expect: "Allow" }] }));
  const actorCli = spawnSync(process.execPath, [CLI, "policy", "test", actorSuite], { encoding: "utf8" });
  ok("CLI actor fixture allows", actorCli.status === 0, actorCli.stdout + actorCli.stderr);
  fs.writeFileSync(actorSuite, JSON.stringify({ policies: actorPolicies, tests: [{ ...request, actro: "document-reader", expect: "Deny" }] }));
  const unknownCli = spawnSync(process.execPath, [CLI, "policy", "test", actorSuite], { encoding: "utf8" });
  ok("CLI unknown fixture key exits 2", unknownCli.status === 2 && /unknown fixture key 'actro'/.test(unknownCli.stderr), unknownCli.stderr);

  console.log(`\npolicytest: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
