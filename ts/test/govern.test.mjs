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

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
