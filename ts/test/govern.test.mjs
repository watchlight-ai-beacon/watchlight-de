// @watchlight/sdk end-to-end test — govern.tool ALLOW/DENY, value-free audit,
// and sub-agent scope attenuation (subset / escalation / DE ceiling). Runs the
// real @watchlight/engine core. No test framework — plain Node asserts.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, Denied, AttenuationDenied, DevEditionCeiling } = require("../dist/index.js");

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-sdk-"));
  const g = new Watchlight({ agent: "test-agent", auditDir });
  g.allow('permit(principal, action == Action::"research", resource);', "allow-research");

  // ── govern.tool: ALLOW runs the body, DENY throws and never runs it ──
  let sideEffect = 0;
  const research = g.tool(async (q) => { sideEffect++; return `results for ${q}`; }, { intent: "research" });
  const transfer = g.tool(async (amt) => { sideEffect++; return `sent ${amt}`; }, { intent: "transfer" });

  const out = await research("cedar policies");
  ok("permitted tool runs and returns", out === "results for cedar policies");
  ok("permitted tool body executed", sideEffect === 1);

  let denied = null;
  try { await transfer(1000); } catch (e) { denied = e; }
  ok("ungoverned intent throws Denied", denied instanceof Denied, String(denied));
  ok("denied tool body NEVER executed (fail-closed)", sideEffect === 1);

  // ── value-free audit trail ──
  const lines = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const toolRecs = lines.filter((r) => r.event !== "attenuation");
  ok("two tool decisions audited", toolRecs.length === 2, JSON.stringify(toolRecs));
  ok("research audited ALLOW", toolRecs.some((r) => r.intent === "research" && r.decision === "Allow"));
  ok("transfer audited Deny", toolRecs.some((r) => r.intent === "transfer" && r.decision === "Deny"));
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("audit is value-free (no arg values leaked)", !raw.includes("cedar policies") && !raw.includes("1000"));

  // ── sub-agent scope attenuation ──
  const root = await g.scope({ tools: ["read", "search"], timeBudgetSeconds: 600 });
  const child = root.attenuate({ tools: ["read"], timeBudgetSeconds: 300 });
  ok("subset attenuation Allowed", Array.isArray(child.allowedTools) && child.allowedTools.includes("read") && !child.allowedTools.includes("search"));

  let esc = null;
  try { root.attenuate({ tools: ["read", "write"] }); } catch (e) { esc = e; }
  ok("tool escalation throws AttenuationDenied", esc instanceof AttenuationDenied, String(esc));

  // Depth ceiling: attenuate DE_MAX_DEPTH (5) levels, the 6th must throw.
  let s = await g.scope({ tools: ["a"] });
  let ceiling = null;
  try { for (let i = 0; i < 7; i++) s = s.attenuate({ tools: ["a"] }); }
  catch (e) { ceiling = e; }
  ok("DE depth ceiling enforced", ceiling instanceof DevEditionCeiling, String(ceiling));

  // ── attenuation records present + value-free ──
  const attRecs = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse).filter((r) => r.event === "attenuation");
  ok("attenuation events audited", attRecs.length >= 4);
  ok("attenuation records carry tree shape", attRecs.every((r) => "node_id" in r && "depth" in r && Array.isArray(r.tools)));

  // ── onResult: govern what a tool RETURNS (egress) ──
  const egDir = fs.mkdtempSync(join(os.tmpdir(), "wl-egress-"));
  const eg = new Watchlight({ agent: "egress-agent", auditDir: egDir });
  eg.allow('permit(principal, action == Action::"read", resource);', "allow-read");
  eg.allow('@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);', "wire-hitl");
  const seen = [];
  async function readDoc(id) { return `SECRET-${id}`; }
  const govRead = eg.tool(readDoc, {
    intent: "read",
    resource: (id) => `doc/${id}`,
    onResult: (result, info) => { seen.push(info); return result.replace("SECRET", "<REDACTED>"); },
  });
  const redacted = await govRead("7");
  ok("onResult replacement reaches the caller", redacted === "<REDACTED>-7", redacted);
  ok("onResult info carries intent/resource/principal/decisionId",
    seen[0]?.intent === "read" && seen[0]?.resource === "doc/7" && seen[0]?.principal === "egress-agent" && typeof seen[0]?.decisionId === "string",
    JSON.stringify(seen[0]));

  async function plain() { return "plain"; }
  const govPlain = eg.tool(plain, { intent: "read", onResult: () => {} });
  ok("void onResult leaves the payload unchanged", (await govPlain()) === "plain");

  async function nullHook() { return "kept"; }
  const govNull = eg.tool(nullHook, { intent: "read", onResult: () => null });
  ok("null onResult passes through like undefined (parity with Python None)", (await govNull()) === "kept");

  async function noHook() { return "nohook"; }
  ok("tool without onResult unchanged", (await eg.tool(noHook, { intent: "read" })()) === "nohook");

  async function leaky() { return "RAW-PAYLOAD"; }
  const govLeaky = eg.tool(leaky, { intent: "read", onResult: () => { throw new Error("classifier unavailable"); } });
  let egErr = null, egOut;
  try { egOut = await govLeaky(); } catch (e) { egErr = e; }
  ok("throwing onResult fails closed (error propagates, raw result never returned)",
    egErr?.message === "classifier unavailable" && egOut === undefined, String(egErr));

  // Approval path: the egress line joins the decision that actually let the body run.
  async function wire() { return "wired"; }
  const wireSeen = [];
  const govWire = eg.tool(wire, { intent: "wire", resource: "acct/1", onNeedsApproval: () => true, onResult: (_r, info) => { wireSeen.push(info); } });
  ok("approved call still runs onResult", (await govWire()) === "wired");

  const egRecs = fs.readFileSync(join(egDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const decRec = egRecs.find((r) => r.resource === "doc/7" && r.decision === "Allow");
  const egRec = egRecs.find((r) => r.event === "egress" && r.resource === "doc/7");
  ok("egress record joined to its decision record by decision_id",
    egRec && decRec && egRec.decision_id === decRec.decision_id && egRec.decision_id === seen[0].decisionId, JSON.stringify([egRec, decRec]));
  ok("egress record marks replacement", egRec?.replaced === true && egRec?.principal === "egress-agent" && egRec?.intent === "read");
  ok("passthrough egress record replaced:false",
    egRecs.some((r) => r.event === "egress" && r.resource === "tool/plain" && r.replaced === false && !r.withheld));
  ok("withheld egress record on hook failure",
    egRecs.some((r) => r.event === "egress" && r.resource === "tool/leaky" && r.replaced === false && r.withheld === true));
  ok("no egress record without onResult", !egRecs.some((r) => r.event === "egress" && r.resource === "tool/noHook"));
  ok("null passthrough audited replaced:false", egRecs.some((r) => r.event === "egress" && r.resource === "tool/nullHook" && r.replaced === false && !r.withheld));
  const approvedRec = egRecs.find((r) => r.resource === "acct/1" && r.approved === true);
  ok("approval path: egress joins the APPROVED decision",
    approvedRec && wireSeen[0]?.decisionId === approvedRec.decision_id
      && egRecs.some((r) => r.event === "egress" && r.resource === "acct/1" && r.decision_id === approvedRec.decision_id));
  const egRaw = fs.readFileSync(join(egDir, "audit.jsonl"), "utf8");
  ok("egress audit is value-free (neither raw nor replaced payload)",
    !egRaw.includes("SECRET") && !egRaw.includes("REDACTED") && !egRaw.includes("RAW-PAYLOAD") && !egRaw.includes("classifier"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
