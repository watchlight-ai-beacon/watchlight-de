// @watchlight/sdk adapter parity test — an adapter reaches the SAME decision as
// `govern.tool()` for the same inputs, and an adapter called with none of the
// per-call terms behaves exactly as it always has.
//
// PART A is the backward-compatibility half: every assertion in it holds on the
// adapters as they were BEFORE per-call terms existed (same intent, same
// resource, same principal, same audit records, same `Denied`). Run it against
// an older build and it still passes.
//
// PART B is the regression probe for the bug this file was written for: a
// policy whose verdict depends on Cedar `context` denied through an adapter and
// allowed through `tool()` with identical inputs, because an adapter had no way
// to carry context or name a subject.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, governTool, governTools, governedHooks, Denied, NeedsApproval, principals } =
  require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const tmpDir = (tag) => fs.mkdtempSync(join(os.tmpdir(), `wl-parity-${tag}-`));
const records = (dir) =>
  fs.readFileSync(join(dir, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));

// A LangChain `StructuredTool` look-alike: name + invoke + a passthrough member.
function mockTool(name) {
  let ran = 0;
  return {
    name,
    description: `mock ${name}`,
    invoke: async (input) => { ran++; return `${name}:${JSON.stringify(input)}`; },
    ranCount: () => ran,
  };
}

// Drive the SDK's PreToolUse hook the way the Claude Agent SDK would.
const callPre = async (hooks, toolName, toolInput = {}, id) => {
  const cb = hooks.PreToolUse[0].hooks[0];
  return cb(
    { hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput, tool_use_id: id },
    id
  );
};

// A tenancy rule: the verdict depends ENTIRELY on Cedar context.
const TENANCY =
  'permit(principal, action == Action::"read_ticket", resource) when { ' +
  "context has owner && context has caller && context.caller == context.owner };";

async function partA() {
  console.log("PART A — defaults unchanged (holds before and after)");

  // ── governTool with nothing but an intent ──────────────────────────
  const dir = tmpDir("a1");
  const gov = new Watchlight({ agent: "lc-agent", auditDir: dir });
  gov.allow('permit(principal, action == Action::"research", resource);', "allow-research");

  const search = mockTool("web_search");
  const wire = mockTool("wire_transfer");
  const govSearch = governTool(search, { governor: gov, intent: "research" });
  const govWire = governTool(wire, { governor: gov, intent: "transfer" });

  ok("A: governed tool keeps its name", govSearch.name === "web_search");
  ok("A: governed tool keeps its other members", govSearch.description === "mock web_search");
  ok("A: original tool not mutated", search !== govSearch && typeof search.invoke === "function");

  const out = await govSearch.invoke({ query: "cedar" });
  ok("A: permitted invoke returns the tool's own result", out === 'web_search:{"query":"cedar"}');
  ok("A: underlying tool ran once", search.ranCount() === 1);

  let denied = null;
  try { await govWire.invoke({ to: "acct-9", amount: 1000 }); } catch (e) { denied = e; }
  ok("A: unpermitted invoke throws Denied", denied instanceof Denied, String(denied));
  ok("A: Denied names the tool and the intent",
    denied?.tool === "wire_transfer" && denied?.intent === "transfer");
  ok("A: Denied carries the opaque reason", denied?.reason === "not authorized");
  ok("A: denied body NEVER ran (fail-closed)", wire.ranCount() === 0);

  const recA = records(dir);
  ok("A: default resource is tool/<name>",
    recA[0].resource === "tool/web_search" && recA[1].resource === "tool/wire_transfer");
  ok("A: default intent is the one given, verbatim",
    recA[0].intent === "research" && recA[1].intent === "transfer");
  ok('A: default subject is the agent, typed Agent::"<name>"',
    recA.every((r) => r.principal === 'Agent::"lc-agent"'), JSON.stringify(recA.map((r) => r.principal)));
  ok("A: decisions recorded Allow then Deny",
    recA[0].decision === "Allow" && recA[1].decision === "Deny");
  ok("A: audit stays value-free",
    !JSON.stringify(recA).includes("acct-9") && !JSON.stringify(recA).includes("cedar"));

  // ── governTools with nothing but intentFor ─────────────────────────
  const dir2 = tmpDir("a2");
  const gov2 = new Watchlight({ agent: "lc-agent", auditDir: dir2 });
  gov2.allow('permit(principal, action == Action::"research", resource);', "allow-research");
  const [gs, gw] = governTools([mockTool("web_search"), mockTool("wire_transfer")], {
    governor: gov2,
    intentFor: (n) => ({ web_search: "research", wire_transfer: "transfer" }[n] ?? n),
  });
  ok("A: governTools allows the mapped-permitted tool",
    (await gs.invoke({ q: "x" })).startsWith("web_search:"));
  let arrDenied = false;
  try { await gw.invoke({ a: 1 }); } catch { arrDenied = true; }
  ok("A: governTools denies the mapped-unpermitted tool", arrDenied);
  const recA2 = records(dir2);
  ok("A: governTools keeps one resource per tool",
    recA2[0].resource === "tool/web_search" && recA2[1].resource === "tool/wire_transfer");

  // ── governedHooks with nothing but intentFor ───────────────────────
  const dir3 = tmpDir("a3");
  const gov3 = new Watchlight({ agent: "hook-agent", auditDir: dir3 });
  gov3.allow('permit(principal, action == Action::"research", resource);', "allow-research");
  const { hooks } = governedHooks({
    governor: gov3,
    intentFor: (t) => ({ WebSearch: "research" }[t] ?? t),
  });
  const allowOut = await callPre(hooks, "WebSearch", { q: "x" }, "u1");
  const denyOut = await callPre(hooks, "Bash", { cmd: "rm -rf /" }, "u2");
  ok("A: hooks allow a permitted tool",
    allowOut.hookSpecificOutput.permissionDecision === "allow");
  ok("A: hooks deny an unpermitted tool",
    denyOut.hookSpecificOutput.permissionDecision === "deny");
  ok("A: hooks return the opaque reason on a deny",
    denyOut.hookSpecificOutput.permissionDecisionReason === "not authorized");
  ok("A: an allow carries no reason", !("permissionDecisionReason" in allowOut.hookSpecificOutput));
  const recA3 = records(dir3);
  ok("A: hooks default resource is tool/<name>",
    recA3[0].resource === "tool/WebSearch" && recA3[1].resource === "tool/Bash");
  ok('A: hooks default subject is Agent::"<name>"',
    recA3.every((r) => r.principal === 'Agent::"hook-agent"'));
  ok("A: hooks audit value-free", !JSON.stringify(recA3).includes("rm -rf"));

  // ── the egress hook still learns the same call ─────────────────────
  const dir4 = tmpDir("a4");
  const gov4 = new Watchlight({ agent: "eg-agent", auditDir: dir4 });
  gov4.allow('permit(principal, action == Action::"research", resource);', "allow-research");
  const infos = [];
  const govFetch = governTool(mockTool("fetch_doc"), {
    governor: gov4,
    intent: "research",
    onResult: (result, info) => { infos.push(info); return "[redacted]"; },
  });
  const replaced = await govFetch.invoke({ id: 7 });
  ok("A: onResult replaces the payload", replaced === "[redacted]");
  ok("A: onResult info is the same call",
    infos[0].intent === "research" &&
    infos[0].resource === "tool/fetch_doc" &&
    infos[0].principal === 'Agent::"eg-agent"' &&
    typeof infos[0].decisionId === "string",
    JSON.stringify(infos[0]));
  ok("A: egress record joins the decision by decision_id",
    records(dir4).some((r) => r.event === "egress" && r.decision_id === infos[0].decisionId));
}

async function partB() {
  console.log("\nPART B — parity with tool()");

  // ── the reproduction: a context-dependent policy ───────────────────
  const dir = tmpDir("b1");
  const gov = new Watchlight({ agent: "tenancy-agent", auditDir: dir });
  gov.allow(TENANCY, "same-tenant");

  // Baseline: through tool(), the rule is satisfiable.
  const direct = gov.tool(async ({ ticket }) => `ticket:${ticket}`, {
    intent: "read_ticket",
    resource: "tool/read_ticket",
    principal: ({ caller }) => principals.user(caller),
    context: ({ caller, owner }) => ({ caller, owner }),
  });
  ok("B: tool() allows a matching tenancy", (await direct({ ticket: 1, caller: "u1", owner: "u1" })) === "ticket:1");

  // governTool takes the same terms and reaches the same verdict.
  const lcTool = mockTool("read_ticket");
  const governed = governTool(lcTool, {
    governor: gov,
    intent: "read_ticket",
    principal: ({ caller }) => principals.user(caller),
    context: ({ caller, owner }) => ({ caller, owner }),
  });
  const same = await governed.invoke({ ticket: 1, caller: "u1", owner: "u1" });
  ok("B: governTool allows the same tenancy tool() allows", same.startsWith("read_ticket:"));
  let crossDenied = null;
  try { await governed.invoke({ ticket: 2, caller: "u2", owner: "u1" }); } catch (e) { crossDenied = e; }
  ok("B: governTool denies a cross-tenant call", crossDenied instanceof Denied);
  ok("B: cross-tenant body never ran", lcTool.ranCount() === 1);

  // The hooks gate takes them too.
  const { hooks } = governedHooks({
    governor: gov,
    principal: ({ toolInput }) => principals.user(toolInput.caller),
    context: ({ toolInput }) => ({ caller: toolInput.caller, owner: toolInput.owner }),
  });
  const hookAllow = await callPre(hooks, "read_ticket", { caller: "u1", owner: "u1" }, "h1");
  const hookDeny = await callPre(hooks, "read_ticket", { caller: "u2", owner: "u1" }, "h2");
  ok("B: hooks allow the same tenancy tool() allows",
    hookAllow.hookSpecificOutput.permissionDecision === "allow");
  ok("B: hooks deny a cross-tenant call",
    hookDeny.hookSpecificOutput.permissionDecision === "deny");

  // The named subject reaches the decision AND the record, on every path.
  const recB = records(dir);
  ok("B: the subject is on every record, not the agent",
    recB.length === 5 &&
    recB.filter((r) => r.principal === 'User::"u1"').length === 3 &&
    recB.filter((r) => r.principal === 'User::"u2"').length === 2 &&
    !recB.some((r) => r.principal.startsWith("Agent::")),
    JSON.stringify(recB.map((r) => r.principal)));
  ok("B: the tenancy attributes never enter the trail as values",
    !JSON.stringify(recB).includes("ticket:"));

  // ── governTools: a per-tool resource mapping ───────────────────────
  const dir2 = tmpDir("b2");
  const gov2 = new Watchlight({ agent: "res-agent", auditDir: dir2 });
  gov2.allow('permit(principal, action == Action::"read", resource == Resource::"db/tickets");', "tickets");
  const [tickets, invoices] = governTools([mockTool("read_tickets"), mockTool("read_invoices")], {
    governor: gov2,
    intentFor: () => "read",
    resourceFor: (n) => ({ read_tickets: "db/tickets", read_invoices: "db/invoices" }[n]),
  });
  ok("B: governTools resourceFor anchors the permitted resource",
    (await tickets.invoke({})).startsWith("read_tickets:"));
  let invDenied = false;
  try { await invoices.invoke({}); } catch { invDenied = true; }
  ok("B: governTools resourceFor anchors the unpermitted one too", invDenied);
  const recB2 = records(dir2);
  ok("B: mapped resources land on the records",
    recB2[0].resource === "db/tickets" && recB2[1].resource === "db/invoices");
  ok("B: an unmapped tool keeps tool/<name>",
    governTools([mockTool("x")], { governor: gov2, resourceFor: () => undefined }).length === 1);

  // ── hooks: a per-call resource mapping ─────────────────────────────
  const dir3 = tmpDir("b3");
  const gov3 = new Watchlight({ agent: "hres-agent", auditDir: dir3 });
  gov3.allow('permit(principal, action == Action::"read", resource == Resource::"db/tickets");', "tickets");
  const { hooks: rhooks } = governedHooks({
    governor: gov3,
    intentFor: () => "read",
    resourceFor: ({ toolName, toolInput }) => (toolName === "Query" ? `db/${toolInput.table}` : undefined),
  });
  const qAllow = await callPre(rhooks, "Query", { table: "tickets" }, "r1");
  const qDeny = await callPre(rhooks, "Query", { table: "invoices" }, "r2");
  ok("B: hooks resourceFor reads the call's own arguments",
    qAllow.hookSpecificOutput.permissionDecision === "allow" &&
    qDeny.hookSpecificOutput.permissionDecision === "deny");
  ok("B: mapped resource on the record", records(dir3)[0].resource === "db/tickets");

  // ── a per-adapter agent rename ─────────────────────────────────────
  const dir4 = tmpDir("b4");
  const gov4 = new Watchlight({ agent: "root-agent", auditDir: dir4 });
  gov4.allow('permit(principal, action == Action::"read", resource) when { context.actor == "renamed-agent" };', "only-renamed");
  const renamed = governTool(mockTool("read_thing"), { governor: gov4, intent: "read", agent: "renamed-agent" });
  ok("B: governTool agent override reaches context.actor",
    (await renamed.invoke({})).startsWith("read_thing:"));
  const { hooks: ahooks } = governedHooks({ governor: gov4, intentFor: () => "read", agent: "renamed-agent" });
  ok("B: hooks agent override reaches context.actor",
    (await callPre(ahooks, "read_thing", {}, "a1")).hookSpecificOutput.permissionDecision === "allow");
  ok("B: the record carries the renamed agent as its subject",
    records(dir4).every((r) => r.principal === 'Agent::"renamed-agent"'));

  // ── human-in-the-loop, on both adapters ────────────────────────────
  const dir5 = tmpDir("b5");
  const gov5 = new Watchlight({ agent: "hitl-agent", auditDir: dir5 });
  gov5.allow('@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);', "wire-hitl");

  const heldTool = mockTool("wire_transfer");
  const held = governTool(heldTool, { governor: gov5, intent: "wire" });
  let hold = null;
  try { await held.invoke({ amount: 10 }); } catch (e) { hold = e; }
  ok("B: governTool surfaces NeedsApproval, with the decision id", hold instanceof NeedsApproval && typeof hold.decisionId === "string", String(hold));
  ok("B: the held body never ran", heldTool.ranCount() === 0);

  const seen = [];
  const confirmed = governTool(mockTool("wire_transfer"), {
    governor: gov5,
    intent: "wire",
    onNeedsApproval: (info) => { seen.push(info); return true; },
  });
  ok("B: governTool proceeds once a human confirms",
    (await confirmed.invoke({ amount: 10 })).startsWith("wire_transfer:"));
  ok("B: the hook was told which call it was confirming",
    seen[0].intent === "wire" && seen[0].resource === "tool/wire_transfer" &&
    seen[0].reason === "approval required");

  const { hooks: hheld } = governedHooks({ governor: gov5, intentFor: () => "wire" });
  ok("B: hooks still deny an unconfirmed NeedsApproval",
    (await callPre(hheld, "wire_transfer", {}, "w1")).hookSpecificOutput.permissionDecision === "deny");
  const { hooks: hok } = governedHooks({
    governor: gov5, intentFor: () => "wire", onNeedsApproval: () => true,
  });
  ok("B: hooks allow it once a human confirms",
    (await callPre(hok, "wire_transfer", {}, "w2")).hookSpecificOutput.permissionDecision === "allow");
  const { hooks: hno } = governedHooks({
    governor: gov5, intentFor: () => "wire", onNeedsApproval: () => false,
  });
  ok("B: a hook that declines still denies",
    (await callPre(hno, "wire_transfer", {}, "w3")).hookSpecificOutput.permissionDecision === "deny");
  const { hooks: hthrow } = governedHooks({
    governor: gov5, intentFor: () => "wire", onNeedsApproval: () => { throw new Error("boom"); },
  });
  ok("B: a throwing approval hook denies (fail-closed)",
    (await callPre(hthrow, "wire_transfer", {}, "w4")).hookSpecificOutput.permissionDecision === "deny");

  // ── a fixed (non-binding) subject is accepted too ──────────────────
  const dir6 = tmpDir("b6");
  const gov6 = new Watchlight({ agent: "fixed-agent", auditDir: dir6 });
  gov6.allow('permit(principal == User::"alice", action == Action::"read", resource);', "alice-only");
  const asAlice = governTool(mockTool("read_thing"), {
    governor: gov6, intent: "read", principal: principals.user("alice"),
  });
  ok("B: a fixed principal reaches the decision",
    (await asAlice.invoke({})).startsWith("read_thing:"));
  ok("B: and the record names it", records(dir6)[0].principal === 'User::"alice"');

  // ── the egress record follows the mapped resource and subject ──────
  const dir7 = tmpDir("b7");
  const gov7 = new Watchlight({ agent: "eg2-agent", auditDir: dir7 });
  gov7.allow('permit(principal, action == Action::"read", resource);', "allow-read");
  const egInfos = [];
  const egTool = governTool(mockTool("read_row"), {
    governor: gov7,
    intent: "read",
    principal: principals.user("alice"),
    resource: ({ table }) => `db/${table}`,
    onResult: (_r, info) => { egInfos.push(info); },
  });
  await egTool.invoke({ table: "tickets" });
  ok("B: onResult sees the resolved subject and resource",
    egInfos[0].principal === 'User::"alice"' && egInfos[0].resource === "db/tickets",
    JSON.stringify(egInfos[0]));
}

async function main() {
  await partA();
  await partB();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
