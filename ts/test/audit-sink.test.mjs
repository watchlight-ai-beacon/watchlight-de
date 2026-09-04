// @watchlight/sdk auditSink test — every record kind (decision, approved
// decision, sanitization, attenuation Allow/Deny) reaches the sink with EXACTLY
// the fields the audit.jsonl line carries; the sink gets a frozen copy and can't
// alter the file; a throwing or rejecting sink never changes a decision and is
// reported once; a never-settling async sink never delays `authorize`
// (fire-and-forget). Runs the real @watchlight/engine core.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, Scope, InProcessBackend, AttenuationDenied, DevEditionCeiling, DE_MAX_DEPTH } = require("../dist/index.js");
const { AuditTrail } = require("../dist/audit.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const RESEARCH = 'permit(principal, action == Action::"research", resource);';
const WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);';
const SAMPLE = "mail a@b.com card 4111 1111 1111 1111";

const gov = (auditSink) => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-sink-"));
  const g = new Watchlight({ agent: "sink-agent", auditDir, auditSink });
  g.allow(RESEARCH, "research").allow(WIRE, "wire");
  return { g, auditDir };
};
const lines = (auditDir) =>
  fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
// Everything about a record except the per-run ids/timestamps.
const shape = (r) => [r.event ?? "decision", r.intent, r.resource, r.decision, r.approved ?? false, r.depth ?? null];

/** Drive every audit-producing path once. */
async function exercise(g) {
  const allow = await g.authorize({ action: "research", resource: "tool/webSearch" });
  const deny = await g.authorize({ action: "transfer", resource: "tool/transfer", context: { amount: 1000 } });
  const held = await g.authorize({ action: "wire", resource: "acct/1" });
  const token = g.mintApproval({ action: "wire", resource: "acct/1" });
  const approved = await g.authorize({ action: "wire", resource: "acct/1", approval: token });
  const research = g.tool(async (q) => `r:${q}`, { intent: "research" });
  await research("cedar policies");
  g.sanitize(SAMPLE, { resource: "doc.txt" });
  const root = await g.scope({ tools: ["read", "write"] });
  const child = root.attenuate({ tools: ["read"] });
  try { root.attenuate({ tools: ["read", "delete"] }); } catch (e) { if (!(e instanceof AttenuationDenied)) throw e; }
  let s = child;
  for (let d = child.depth; d < DE_MAX_DEPTH; d++) s = s.attenuate({ tools: ["read"] });
  try { s.attenuate({ tools: ["read"] }); } catch (e) { if (!(e instanceof DevEditionCeiling)) throw e; }
  return [allow.decision, deny.decision, held.decision, approved.decision, approved.approved];
}

const withWarnSpy = async (fn) => {
  const orig = console.warn;
  const warns = [];
  console.warn = (...a) => warns.push(a.map(String).join(" "));
  try { return await fn(warns); } finally { console.warn = orig; }
};
const tick = () => new Promise((r) => setImmediate(r));

async function main() {
  // ── control: the same run with no sink ──
  const control = gov(undefined);
  const controlResults = await exercise(control.g);
  const controlShapes = lines(control.auditDir).map(shape);

  // ── 1. every record kind reaches the sink with identical fields ──
  {
    const seen = [];
    const { g, auditDir } = gov((rec) => { seen.push(rec); });
    await exercise(g);
    const file = lines(auditDir);
    ok("sink saw every file line, same order, same fields", JSON.stringify(seen) === JSON.stringify(file),
      `${seen.length} vs ${file.length}`);
    ok("covers decisions", seen.some((r) => r.event === undefined && r.decision === "Allow") && seen.some((r) => r.event === undefined && r.decision === "Deny"));
    ok("covers NeedsApproval + approved decision", seen.some((r) => r.decision === "NeedsApproval") && seen.some((r) => r.approved === true && r.decision === "Allow"));
    ok("covers sanitization", seen.some((r) => r.event === "sanitization" && r.counts && r.counts.EMAIL === 1));
    ok("covers attenuation Allow and Deny (escalation + ceiling)",
      seen.some((r) => r.event === "attenuation" && r.decision === "Allow" && r.resource === "root scope") &&
      seen.filter((r) => r.event === "attenuation" && r.decision === "Deny" && r.reason).length === 2);
    ok("sink records are value-free", !JSON.stringify(seen).includes("a@b.com") && !JSON.stringify(seen).includes("4111") && !JSON.stringify(seen).includes("cedar policies"));
    ok("local file still written with the sink on (additive)", file.length === controlShapes.length);
  }

  // ── 2. the sink gets a frozen copy and cannot alter the file ──
  {
    let frozen = true;
    const { g, auditDir } = gov((rec) => {
      frozen = frozen && Object.isFrozen(rec) && (rec.counts === undefined || Object.isFrozen(rec.counts)) && (rec.tools === undefined || Object.isFrozen(rec.tools));
      try { rec.decision = "Allow"; rec.injected = true; } catch { /* strict-mode throw on frozen */ }
    });
    await exercise(g);
    const file = lines(auditDir);
    ok("sink record is deeply frozen", frozen);
    ok("sink mutation never reaches the file", file.some((r) => r.decision === "Deny") && !file.some((r) => "injected" in r));
  }

  // ── 3. a throwing sink changes nothing, warns once ──
  await withWarnSpy(async (warns) => {
    let calls = 0;
    const { g, auditDir } = gov(() => { calls++; throw new Error("sink down: tool/webSearch"); });
    const results = await exercise(g);
    ok("throwing sink: authorize results identical to control", JSON.stringify(results) === JSON.stringify(controlResults));
    ok("throwing sink: file records identical to control", JSON.stringify(lines(auditDir).map(shape)) === JSON.stringify(controlShapes));
    ok("throwing sink: still invoked for every record", calls === controlShapes.length, String(calls));
    ok("throwing sink: warned exactly once", warns.length === 1, JSON.stringify(warns));
    ok("throwing sink: warning names the error type only, no record content",
      warns[0].includes("Error") && !warns[0].includes("webSearch") && !warns[0].includes("sink down"));
  });

  // ── 4. a rejecting async sink changes nothing, warns once, no unhandled rejection ──
  await withWarnSpy(async (warns) => {
    let unhandled = 0;
    const onUnhandled = () => { unhandled++; };
    process.on("unhandledRejection", onUnhandled);
    const seen = [];
    const { g, auditDir } = gov(async (rec) => { seen.push(rec); throw new TypeError("nope"); });
    const results = await exercise(g);
    await tick(); await tick();
    process.off("unhandledRejection", onUnhandled);
    ok("rejecting sink: authorize results identical to control", JSON.stringify(results) === JSON.stringify(controlResults));
    ok("rejecting sink: every record still delivered before the failure", JSON.stringify(seen) === JSON.stringify(lines(auditDir)));
    ok("rejecting sink: warned exactly once (TypeError)", warns.length === 1 && warns[0].includes("TypeError"), JSON.stringify(warns));
    ok("rejecting sink: no unhandled rejection", unhandled === 0);
  });

  // ── 5. fire-and-forget: a never-settling sink never delays a decision ──
  {
    const { g } = gov(() => new Promise(() => {}));
    const t0 = Date.now();
    const r = await Promise.race([
      g.authorize({ action: "research", resource: "tool/webSearch" }),
      new Promise((res) => setTimeout(() => res("timeout"), 2000)),
    ]);
    ok("never-settling sink: authorize still resolves promptly", r !== "timeout" && r.decision === "Allow" && Date.now() - t0 < 2000);
  }

  // ── 6. a spoofed error name never reaches the warning (sink-controlled text) ──
  await withWarnSpy(async (warns) => {
    const { g } = gov((rec) => { throw Object.assign(new Error("x"), { name: "LEAK:" + JSON.stringify(rec) }); });
    await g.authorize({ action: "research", resource: "tool/webSearch" });
    ok("spoofed error name is replaced by the literal Error", warns.length === 1 && warns[0].includes("(Error)"));
    ok("warning carries no record content", !warns[0].includes("LEAK") && !warns[0].includes("webSearch") && !warns[0].includes("research"));
  });

  // ── 7. one warning per error KIND, not per governor ──
  await withWarnSpy(async (warns) => {
    const kinds = [TypeError, TypeError, RangeError];
    const { g } = gov(() => { throw new (kinds.shift())("k"); });
    for (let i = 0; i < 3; i++) await g.authorize({ action: "research", resource: "tool/webSearch" });
    ok("warned once per kind (TypeError, RangeError)", warns.length === 2 && warns[0].includes("TypeError") && warns[1].includes("RangeError"), JSON.stringify(warns));
  });

  // ── 8. the funnel never throws, even for an unserializable record ──
  {
    const seen = [];
    const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-sink-"));
    const trail = new AuditTrail(join(dir, "audit.jsonl"), (r) => seen.push(r));
    let threw = false;
    try { trail.write({ ts: "x", loop: 1n }); } catch { threw = true; }  // BigInt is not JSON-serializable
    ok("unserializable record: funnel does not throw, nothing written or sent", !threw && !fs.existsSync(join(dir, "audit.jsonl")) && seen.length === 0);
  }

  // ── 9. ScopeInit still accepts the legacy `auditPath` (additive) ──
  {
    const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-sink-"));
    const engine = await new InProcessBackend().engine();
    const root = new Scope({ engine, auditPath: join(dir, "audit.jsonl"), agent: "legacy", allowedTools: ["read"], allowedResources: [], allowedIntents: [], maxDepth: DE_MAX_DEPTH, timeBudgetSeconds: 60, depth: 0 });
    root.emitRoot();
    root.attenuate({ tools: ["read"] });
    ok("legacy auditPath Scope still writes the file", lines(dir).filter((r) => r.event === "attenuation").length === 2);
  }

  // ── 10. egress records (onResult) and sanitize decision_id flow through the sink unchanged ──
  {
    const seen = [];
    const { g, auditDir } = gov((rec) => { seen.push(rec); });
    const fetchDoc = g.tool(async (id) => `doc ${id}`, { intent: "research", onResult: (out) => out.toUpperCase() });
    await fetchDoc("42");
    const withheld = g.tool(async () => "secret", { intent: "research", onResult: () => { throw new Error("egress blocked"); } });
    try { await withheld(); } catch { /* fail-closed: withheld */ }
    const d = await g.authorize({ action: "research", resource: "doc.txt" });
    g.sanitize(SAMPLE, { resource: "doc.txt", decisionId: d.decisionId });
    const file = lines(auditDir);
    ok("egress + sanitize: sink saw every file line with identical fields", JSON.stringify(seen) === JSON.stringify(file));
    const egress = seen.filter((r) => r.event === "egress");
    ok("egress records reach the sink (replaced + withheld), joined by decision_id",
      egress.length === 2 && egress[0].replaced === true && egress[1].withheld === true && egress.every((r) => typeof r.decision_id === "string"));
    ok("egress record is value-free", !JSON.stringify(egress).includes("DOC 42") && !JSON.stringify(egress).includes("secret"));
    const san = seen.find((r) => r.event === "sanitization");
    ok("sanitization decision_id flows through unchanged", san && san.decision_id === d.decisionId && typeof d.decisionId === "string");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
