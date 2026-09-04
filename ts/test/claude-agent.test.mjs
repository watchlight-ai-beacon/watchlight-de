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

  // ── onResult → PostToolUse (egress): govern what the tool RETURNS ──
  ok("no PostToolUse hook installed without onResult", hooks.PostToolUse === undefined);

  const callPre = (h, toolName, toolUseId) =>
    h.PreToolUse[0].hooks[0]({ hook_event_name: "PreToolUse", tool_name: toolName, tool_input: {}, tool_use_id: toolUseId }, toolUseId);
  const callPost = (h, toolName, toolResponse, toolUseId) =>
    h.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: toolName, tool_input: {}, tool_response: toolResponse, tool_use_id: toolUseId }, toolUseId);

  const infos = [];
  const { hooks: eh } = governedHooks({
    governor, intentFor: (t) => TOOL_INTENTS[t] ?? t,
    onResult: (result, info) => { infos.push(info); return typeof result === "string" && result.includes("SECRET") ? "<redacted>" : undefined; },
  });
  ok("PostToolUse hook installed with onResult", typeof eh.PostToolUse?.[0]?.hooks?.[0] === "function");
  ok("PreToolUse still installed", typeof eh.PreToolUse?.[0]?.hooks?.[0] === "function");

  const pre1 = await callPre(eh, "WebSearch", "tu-1");
  ok("pre gate allows", pre1.hookSpecificOutput?.permissionDecision === "allow");
  const post1 = await callPost(eh, "WebSearch", "SECRET result", "tu-1");
  ok("replaced output reaches the model via updatedToolOutput",
    post1.hookSpecificOutput?.hookEventName === "PostToolUse" && post1.hookSpecificOutput?.updatedToolOutput === "<redacted>", JSON.stringify(post1));
  ok("onResult info joined to the PreToolUse decision",
    infos[0]?.intent === "research" && infos[0]?.resource === "tool/WebSearch" && infos[0]?.principal === "claude-agent" && typeof infos[0]?.decisionId === "string",
    JSON.stringify(infos[0]));

  ok("an unannotated permit puts no obligations key on the hook info", infos.length >= 1 && !("obligations" in infos[0]));

  // The PostToolUse hook receives the SAME obligations the PreToolUse decision carried.
  const og = new Watchlight({ agent: "claude-oblig-agent", auditDir: fs.mkdtempSync(join(os.tmpdir(), "wl-oblig-")) });
  og.allow('@obligate_redact("ssn, email")\n@obligate_max_items("3")\npermit(principal, action == Action::"read", resource);', "read-redacted");
  const oInfos = [];
  const { hooks: oh } = governedHooks({ governor: og, intentFor: () => "read", onResult: (r, info) => { oInfos.push(info); return undefined; } });
  await callPre(oh, "ReadDoc", "tu-o1");
  await callPost(oh, "ReadDoc", "doc body", "tu-o1");
  const oDecision = await og.authorize({ action: "read", resource: "tool/ReadDoc" });
  ok("PostToolUse onResult info carries the decision's obligations",
    oInfos.length === 1 && oInfos[0].obligations !== undefined && JSON.stringify(oInfos[0].obligations) === JSON.stringify(oDecision.obligations)
      && oInfos[0].obligations.redact.length === 2 && oInfos[0].obligations.maxItems === 3, JSON.stringify([oInfos[0], oDecision.obligations]));

  await callPre(eh, "WebSearch", "tu-2");
  const post2 = await callPost(eh, "WebSearch", "plain result", "tu-2");
  ok("void onResult passes through (no updatedToolOutput)", !("updatedToolOutput" in (post2.hookSpecificOutput ?? {})), JSON.stringify(post2));

  const { hooks: th } = governedHooks({ governor, intentFor: (t) => TOOL_INTENTS[t] ?? t, onResult: () => { throw new Error("screen down"); } });
  await callPre(th, "WebSearch", "tu-3");
  let postThrew = false, post3;
  try { post3 = await callPost(th, "WebSearch", "RAW-SECRET", "tu-3"); } catch { postThrew = true; }
  ok("throwing onResult never throws back to the SDK", !postThrew);
  ok("throwing onResult withholds the raw output (opaque replacement)",
    post3?.hookSpecificOutput?.updatedToolOutput === "not authorized", JSON.stringify(post3));

  // null → passthrough (parity with Python None): no updatedToolOutput.
  const { hooks: nh } = governedHooks({ governor, intentFor: (t) => TOOL_INTENTS[t] ?? t, onResult: () => null });
  await callPre(nh, "WebSearch", "tu-null");
  const postNull = await callPost(nh, "WebSearch", "kept", "tu-null");
  ok("null onResult passes through (no updatedToolOutput)", !("updatedToolOutput" in (postNull.hookSpecificOutput ?? {})), JSON.stringify(postNull));

  // Deadline: a hook that outruns onResultTimeoutMs withholds the output.
  ok("default SDK matcher timeout is 10s (deadline 8s = 80%)", eh.PostToolUse[0].timeout === 10, String(eh.PostToolUse[0].timeout));
  const { hooks: slow } = governedHooks({
    governor, intentFor: (t) => TOOL_INTENTS[t] ?? t,
    onResult: () => new Promise(() => {}),   // never settles (remote classifier hang)
    onResultTimeoutMs: 50,
  });
  ok("explicit deadline sets the SDK matcher timeout above it", slow.PostToolUse[0].timeout === 1, String(slow.PostToolUse[0].timeout));
  const preSlow = await callPre(slow, "WebSearch", "tu-slow");
  ok("slow: pre gate allows", preSlow.hookSpecificOutput?.permissionDecision === "allow");
  const t0 = Date.now();
  const postSlow = await callPost(slow, "WebSearch", "RAW-SLOW-SECRET", "tu-slow");
  ok("slow onResult is withheld at the deadline (opaque replacement, no throw)",
    postSlow?.hookSpecificOutput?.updatedToolOutput === "not authorized" && Date.now() - t0 < 2000, JSON.stringify(postSlow));
  let rangeErr = null;
  try { governedHooks({ governor, onResult: () => undefined, onResultTimeoutMs: 0 }); } catch (e) { rangeErr = e; }
  ok("non-positive onResultTimeoutMs is rejected", rangeErr instanceof RangeError);

  // No tool_use_id → no join: the hook still runs, the egress record carries no decision_id.
  const preNoId = await callPre(eh, "WebSearch", undefined);
  ok("no-id: pre gate allows", preNoId.hookSpecificOutput?.permissionDecision === "allow");
  const postNoId = await callPost(eh, "WebSearch", "SECRET-noid", undefined);
  ok("no-id: hook still governs the output", postNoId.hookSpecificOutput?.updatedToolOutput === "<redacted>");
  ok("no-id: info carries no decisionId (no fallback join)", infos.at(-1)?.decisionId === undefined && infos.at(-1)?.resource === "tool/WebSearch");

  const recs2 = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  ok("slow: withheld egress record joined to its decision",
    recs2.some((r) => r.event === "egress" && r.withheld === true && r.decision_id && recs2.some((d) => !d.event && d.decision_id === r.decision_id && d.decision === "Allow")));
  ok("no-id: egress record present without decision_id", recs2.some((r) => r.event === "egress" && r.replaced === true && !("decision_id" in r)));
  const dec1 = recs2.find((r) => r.decision_id === infos[0].decisionId && !r.event);
  const egr1 = recs2.find((r) => r.event === "egress" && r.decision_id === infos[0].decisionId);
  ok("egress record joined to the decision record by decision_id",
    dec1?.decision === "Allow" && dec1?.resource === "tool/WebSearch" && egr1?.replaced === true, JSON.stringify([dec1, egr1]));
  ok("passthrough egress record replaced:false", recs2.some((r) => r.event === "egress" && r.decision_id === infos[1]?.decisionId && r.replaced === false && !r.withheld));
  ok("withheld egress record on hook failure", recs2.some((r) => r.event === "egress" && r.withheld === true));
  const raw2 = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("egress audit value-free (no raw or replaced payload)", !raw2.includes("SECRET") && !raw2.includes("redacted") && !raw2.includes("screen down") && !raw2.includes("SLOW") && !raw2.includes("kept"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
