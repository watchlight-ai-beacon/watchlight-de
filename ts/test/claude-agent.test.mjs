// @watchlight/sdk Claude Agent SDK hooks adapter test — the PreToolUse gate
// authorizes via the in-process engine, allows permitted tools, denies the rest
// fail-closed, and never throws back to the SDK.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, governedHooks } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

// Invoke the registered PreToolUse hook the way the Claude Agent SDK would.
const callPreToolUse = async (hooks, toolName, toolInput = {}) => {
  const cb = hooks.PreToolUse[0].hooks[0];
  return cb({ hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput });
};

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-claude-"));
  const governor = new Watchlight({ agent: "claude-agent", auditDir });
  governor.allow('permit(principal, action == Action::"research", resource);', "allow-research");

  // Map Claude tool names → governance intents.
  const TOOL_INTENTS = { WebSearch: "research", TransferFunds: "transfer" };
  const { hooks } = governedHooks({ governor, intentFor: (t) => TOOL_INTENTS[t] ?? t });

  ok("hooks expose a PreToolUse matcher entry", Array.isArray(hooks.PreToolUse) && typeof hooks.PreToolUse[0].hooks[0] === "function");

  // Permitted tool → allow
  const allow = await callPreToolUse(hooks, "WebSearch", { query: "cedar" });
  ok("permitted tool → permissionDecision allow",
    allow.hookSpecificOutput?.permissionDecision === "allow", JSON.stringify(allow));

  // Ungoverned intent → deny (fail-closed), with a reason
  const deny = await callPreToolUse(hooks, "TransferFunds", { amount: 1000 });
  ok("ungoverned tool → permissionDecision deny",
    deny.hookSpecificOutput?.permissionDecision === "deny", JSON.stringify(deny));
  ok("deny carries a reason", typeof deny.hookSpecificOutput?.permissionDecisionReason === "string");
  ok("hookEventName echoed", deny.hookSpecificOutput?.hookEventName === "PreToolUse");

  // Fail-closed: a governance error (thrown by intentFor) must still deny, not throw.
  const { hooks: brokenHooks } = governedHooks({
    governor,
    intentFor: () => { throw new Error("boom"); },
  });
  let threw = false;
  let broken;
  try { broken = await callPreToolUse(brokenHooks, "WebSearch"); } catch { threw = true; }
  ok("hook never throws back to the SDK", !threw);
  ok("governance error is fail-closed (deny)",
    broken?.hookSpecificOutput?.permissionDecision === "deny", JSON.stringify(broken));
  ok("governance error reason is opaque (no internal detail leaked)",
    broken?.hookSpecificOutput?.permissionDecisionReason === "not authorized",
    broken?.hookSpecificOutput?.permissionDecisionReason);

  // Audit: value-free, both decisions recorded, no arg values leaked.
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  const recs = raw.trim().split("\n").map(JSON.parse);
  ok("decisions audited", recs.some((r) => r.intent === "research" && r.decision === "Allow")
    && recs.some((r) => r.intent === "transfer" && r.decision === "Deny"));
  ok("audit value-free (no tool args)", !raw.includes("cedar") && !raw.includes("1000"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
