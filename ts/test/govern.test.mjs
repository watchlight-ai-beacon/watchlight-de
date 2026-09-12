// @watchlight/sdk end-to-end test — govern.tool ALLOW/DENY, value-free audit,
// and sub-agent scope attenuation (subset / escalation / max_delegation_depth). Runs the
// real @watchlight/engine core. No test framework — plain Node asserts.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const {
  Watchlight, Denied, AttenuationDenied, DelegationDepthExceeded,
  DEFAULT_MAX_DELEGATION_DEPTH, DELEGATION_DEPTH_EXCEEDED,
} = require("../dist/index.js");

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

  // ── max_delegation_depth: a governance control (default 8), not an edition cap ──
  ok("default maxDelegationDepth is 8", DEFAULT_MAX_DELEGATION_DEPTH === 8 && g.maxDelegationDepth === 8);
  // Eight hops — past the old depth-5 cap — each a strict subset of its parent.
  let s = await g.scope({ tools: ["a", "b", "c"], intents: ["research", "summarize"] });
  const wanted = [["a", "b"], ["a", "b"], ["a"], ["a"], ["a"], ["a"], ["a"], ["a"]];
  let subsetOk = true;
  for (let i = 0; i < wanted.length; i++) {
    const parentTools = new Set(s.allowedTools);
    s = s.attenuate({ tools: wanted[i], intents: ["research"] });
    subsetOk &&=
      s.depth === i + 1 &&
      s.allowedTools.length === wanted[i].length &&
      s.allowedTools.every((t) => parentTools.has(t) && wanted[i].includes(t)) &&
      s.allowedIntents.join() === "research";
  }
  ok("an 8-hop chain within the limit is permitted, attenuated at every hop", subsetOk && s.depth === 8);
  let depthErr = null;
  try { s.attenuate({ tools: ["a"] }); } catch (e) { depthErr = e; }
  ok("a hop past the default limit throws DelegationDepthExceeded", depthErr instanceof DelegationDepthExceeded, String(depthErr));
  ok("...which is an AttenuationDenied (a deny)", depthErr instanceof AttenuationDenied);
  ok("...with the distinct reason code",
    depthErr && depthErr.code === DELEGATION_DEPTH_EXCEEDED && DELEGATION_DEPTH_EXCEEDED === "DELEGATION_DEPTH_EXCEEDED");
  ok("...carrying the observed depth and the limit", depthErr && depthErr.depth === 9 && depthErr.limit === 8);
  let widenErr = null;
  try { s.attenuate({ tools: ["a", "b"] }); } catch (e) { widenErr = e; }
  ok("strict subset still applies at depth 8", widenErr instanceof AttenuationDenied);

  // A custom lower limit denies sooner, and the deny is audited with depth + limit.
  const lowDir = fs.mkdtempSync(join(os.tmpdir(), "wl-sdk-depth-"));
  const low = new Watchlight({ agent: "depth-agent", auditDir: lowDir, maxDelegationDepth: 3 });
  let l = await low.scope({ tools: ["a"] });
  for (let i = 0; i < 3; i++) l = l.attenuate({ tools: ["a"] });
  let lowErr = null;
  try { l.attenuate({ tools: ["a"] }); } catch (e) { lowErr = e; }
  ok("a custom lower limit denies sooner",
    lowErr instanceof DelegationDepthExceeded && lowErr.depth === 4 && lowErr.limit === 3, String(lowErr));
  const lowRecs = fs.readFileSync(join(lowDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const last = lowRecs[lowRecs.length - 1];
  ok("the depth deny is recorded with reason_code, depth and limit",
    last.event === "attenuation" && last.decision === "Deny" && last.reason_code === "DELEGATION_DEPTH_EXCEEDED" &&
      last.depth === 4 && last.max_delegation_depth === 3 && last.parent_id === l.nodeId,
    JSON.stringify(last));
  const lowered = await low.scope({ tools: ["a"], maxDepth: 1 });
  const raisedAttempt = await low.scope({ tools: ["a"], maxDepth: 50 });
  ok("scope() lowers the limit but never raises it",
    lowered.maxDelegationDepth === 1 && raisedAttempt.maxDelegationDepth === 3);
  let badErr = null;
  try { new Watchlight({ agent: "bad", auditDir: lowDir, maxDelegationDepth: 65 }); } catch (e) { badErr = e; }
  ok("an out-of-range limit is rejected", badErr instanceof RangeError, String(badErr));
  const zero = new Watchlight({ agent: "zero", auditDir: lowDir, maxDelegationDepth: 0 });
  let zeroErr = null;
  try { (await zero.scope({ tools: ["a"] })).attenuate({ tools: ["a"] }); } catch (e) { zeroErr = e; }
  ok("0 allows no sub-agents", zeroErr instanceof DelegationDepthExceeded && zeroErr.depth === 1 && zeroErr.limit === 0);

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
    seen[0]?.intent === "read" && seen[0]?.resource === "doc/7" && seen[0]?.principal === 'Agent::"egress-agent"' && typeof seen[0]?.decisionId === "string",
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
  ok("egress record marks replacement", egRec?.replaced === true && egRec?.principal === 'Agent::"egress-agent"' && egRec?.intent === "read");
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
