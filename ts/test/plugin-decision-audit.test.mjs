// Every decision a framework adapter makes is in the audit trail — the
// TypeScript half of tests/integrations/test_plugin_decision_audit.py.
//
// The TypeScript adapters (`governTool` for LangChain / LangGraph.js and
// `governedHooks` for the Claude Agent SDK) decide through the governor's own
// `authorize`, so each decision writes the direct path's record. This file pins
// that, per adapter: an Allow and a Deny each write EXACTLY ONE decision record,
// with `event: "decision"` and the direct path's fields only; no value the call
// carried ever reaches the trail; the audit sink sees the same records; and
// `counters()` counts them.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, governTool, governedHooks } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

// Values a call carries. None of them may appear anywhere in the trail.
const CANARIES = ["CANARY-input-7f3a9", "CANARY-ctx-c41d", "CANARY-nested-0b2e"];
// The fields a decision record may carry — the DecisionRecord type, written out.
const ALLOWED_FIELDS = new Set([
  "ts", "agent", "actor_chain", "event", "principal", "intent", "resource",
  "decision", "decision_id", "approved", "execution_id",
]);
const REQUIRED_FIELDS = ["ts", "agent", "event", "principal", "intent", "resource", "decision"];

const lines = (dir) =>
  fs.readFileSync(join(dir, "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const decisions = (recs) => recs.filter((r) => (r.event ?? "decision") === "decision");

function governor(agent) {
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-plugin-audit-"));
  const sunk = [];
  const gov = new Watchlight({ agent, auditDir: dir, auditSink: (r) => { sunk.push(r); } });
  gov.allow('permit(principal, action == Action::"research", resource);', "allow-research");
  return { gov, dir, sunk };
}

function checkRecords(label, dir, sunk, agent) {
  const raw = fs.readFileSync(join(dir, "audit.jsonl"), "utf8");
  ok(`${label}: no call value reaches the trail`, CANARIES.every((c) => !raw.includes(c)));
  const recs = decisions(lines(dir));
  ok(`${label}: one record per decision (Allow, then Deny)`,
    recs.length === 2 && recs[0].decision === "Allow" && recs[1].decision === "Deny",
    JSON.stringify(recs.map((r) => r.decision)));
  for (const r of recs) {
    ok(`${label}: ${r.decision} record carries event "decision"`, r.event === "decision");
    ok(`${label}: ${r.decision} record has the required fields`, REQUIRED_FIELDS.every((k) => k in r));
    ok(`${label}: ${r.decision} record has no other fields`,
      Object.keys(r).every((k) => ALLOWED_FIELDS.has(k)), JSON.stringify(Object.keys(r)));
    ok(`${label}: ${r.decision} record names the agent and subject`,
      r.agent === agent && r.principal === `Agent::"${agent}"`);
  }
  ok(`${label}: the sink saw exactly the file's records`, JSON.stringify(decisions(sunk)) === JSON.stringify(recs));
  ok(`${label}: no call value reaches the sink`, CANARIES.every((c) => !JSON.stringify(sunk).includes(c)));
}

async function main() {
  // ── LangChain / LangGraph.js: governTool ──
  {
    const agent = "lc-audit-agent";
    const { gov, dir, sunk } = governor(agent);
    const tool = (name) => ({ name, invoke: async (input) => `${name}:${JSON.stringify(input)}` });
    const ctx = () => ({ query: CANARIES[1], nested: { v: CANARIES[2] } });
    const search = governTool(tool("web_search"), { governor: gov, intent: "research", context: ctx });
    const wire = governTool(tool("wire_transfer"), { governor: gov, intent: "transfer", context: ctx });
    await search.invoke({ q: CANARIES[0] });
    let denied = false;
    try { await wire.invoke({ to: CANARIES[0] }); } catch { denied = true; }
    ok("governTool: the denied call is refused", denied);
    checkRecords("governTool", dir, sunk, agent);
    const c = gov.counters({ principal: `Agent::"${agent}"`, intent: "research", window: "1h" });
    ok("governTool: counters() counts the adapter's decision", c.count === 1, JSON.stringify(c));
  }

  // ── Claude Agent SDK: governedHooks ──
  {
    const agent = "claude-audit-agent";
    const { gov, dir, sunk } = governor(agent);
    const intents = { WebSearch: "research", TransferFunds: "transfer" };
    const { hooks } = governedHooks({
      governor: gov,
      intentFor: (t) => intents[t] ?? t,
      context: () => ({ query: CANARIES[1], nested: { v: CANARIES[2] } }),
    });
    const pre = hooks.PreToolUse[0].hooks[0];
    const allow = await pre({ hook_event_name: "PreToolUse", tool_name: "WebSearch", tool_input: { q: CANARIES[0] } });
    const deny = await pre({ hook_event_name: "PreToolUse", tool_name: "TransferFunds", tool_input: { to: CANARIES[0] } });
    ok("governedHooks: allow then deny",
      allow.hookSpecificOutput?.permissionDecision === "allow" && deny.hookSpecificOutput?.permissionDecision === "deny");
    checkRecords("governedHooks", dir, sunk, agent);
    const c = gov.counters({ principal: `Agent::"${agent}"`, intent: "transfer", window: "1h", outcome: "denied" });
    ok("governedHooks: counters() counts the adapter's deny", c.count === 1, JSON.stringify(c));
  }

  // ── a Python framework plugin's lifecycle lines in a shared trail ──
  // They name their kind in `event_type` and carry neither `event` nor
  // `decision`: well-formed, not decisions, and not counted as skipped.
  {
    const agent = "shared-trail-agent";
    const { gov, dir } = governor(agent);
    await governTool({ name: "web_search", invoke: async () => "ok" }, { governor: gov, intent: "research" }).invoke({});
    fs.appendFileSync(join(dir, "audit.jsonl"),
      JSON.stringify({ event_id: "evt_1", event_type: "execution_started", timestamp: new Date().toISOString(), execution_id: "exec_1" }) + "\n" +
      JSON.stringify({ event_id: "evt_2", event_type: "execution_completed", timestamp: new Date().toISOString(), execution_id: "exec_1" }) + "\n");
    const c = gov.counters({ principal: `Agent::"${agent}"`, window: "1h", outcome: "all" });
    ok("counters(): lifecycle lines are not skipped", c.skipped === 0, JSON.stringify(c));
    ok("counters(): lifecycle lines are not decisions", c.count === 1, JSON.stringify(c));
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
