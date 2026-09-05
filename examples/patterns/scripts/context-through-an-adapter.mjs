// Pattern check: a context-dependent policy holds through a framework adapter.
//
// The rule under test reads Cedar `context` and nothing else — it permits a
// read only when the caller owns the record. It must reach the SAME verdict
// three ways: through `govern.tool()`, through the LangChain / LangGraph.js
// adapter, and through the Claude Agent SDK hooks gate. If an adapter cannot
// carry the context the rule reads, the rule denies on the adapter path while
// allowing on the hand-written one — the same policy, two answers.
import { loadSdk, checks } from "./_sdk.mjs";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const { Watchlight, governTool, governedHooks, Denied, principals } = loadSdk();
const t = checks("context through an adapter");

const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-adapter-context-"));
const govern = new Watchlight({ agent: "support-agent", auditDir });
govern.allow(
  'permit(principal, action == Action::"read_ticket", resource) when { ' +
    "context has owner && context has caller && context.caller == context.owner };",
  "same-tenant-only"
);

// The per-call terms, written once and passed to every path.
const principal = ({ caller }) => principals.user(caller);
const context = ({ caller, owner }) => ({ caller, owner });

// ── 1. the hand-written governed tool ────────────────────────────────
const readTicket = govern.tool(async ({ id }) => `ticket-${id}`, {
  intent: "read_ticket",
  resource: "tool/read_ticket",
  principal,
  context,
});

t.ok("tool(): the owner may read", (await readTicket({ id: 7, caller: "u1", owner: "u1" })) === "ticket-7");
let direct = null;
try { await readTicket({ id: 7, caller: "u2", owner: "u1" }); } catch (e) { direct = e; }
t.ok("tool(): someone else may not", direct instanceof Denied);

// ── 2. the LangChain / LangGraph.js adapter ──────────────────────────
// A `StructuredTool` stand-in: the adapter is typed against `name` + `invoke`.
let ran = 0;
const ticketTool = { name: "read_ticket", invoke: async ({ id }) => { ran++; return `ticket-${id}`; } };

const governed = governTool(ticketTool, { intent: "read_ticket", governor: govern, principal, context });

t.ok("governTool: the owner may read", (await governed.invoke({ id: 7, caller: "u1", owner: "u1" })) === "ticket-7");
let viaAdapter = null;
try { await governed.invoke({ id: 7, caller: "u2", owner: "u1" }); } catch (e) { viaAdapter = e; }
t.ok("governTool: someone else may not", viaAdapter instanceof Denied);
t.ok("governTool: the denied body never ran", ran === 1);

// ── 3. the Claude Agent SDK hooks gate ───────────────────────────────
const { hooks } = governedHooks({
  governor: govern,
  principal: ({ toolInput }) => principals.user(toolInput.caller),
  context: ({ toolInput }) => ({ caller: toolInput.caller, owner: toolInput.owner }),
});
const gate = async (toolInput, id) =>
  (
    await hooks.PreToolUse[0].hooks[0](
      { hook_event_name: "PreToolUse", tool_name: "read_ticket", tool_input: toolInput, tool_use_id: id },
      id
    )
  ).hookSpecificOutput.permissionDecision;

t.ok("hooks: the owner may read", (await gate({ caller: "u1", owner: "u1" }, "h1")) === "allow");
t.ok("hooks: someone else may not", (await gate({ caller: "u2", owner: "u1" }, "h2")) === "deny");

// ── the record answers "for whom", on every path ─────────────────────
const trail = fs
  .readFileSync(join(auditDir, "audit.jsonl"), "utf8")
  .trim()
  .split("\n")
  .map((line) => JSON.parse(line));

t.ok(
  "every decision names the acting user, not the agent",
  trail.length === 6 && trail.every((r) => r.principal === 'User::"u1"' || r.principal === 'User::"u2"'),
  trail.map((r) => r.principal).join(", ")
);
t.ok(
  "the three paths agree: three Allows, three Denies",
  trail.filter((r) => r.decision === "Allow").length === 3 &&
    trail.filter((r) => r.decision === "Deny").length === 3
);
t.ok("the trail stays value-free", !JSON.stringify(trail).includes("ticket-7"));

fs.rmSync(auditDir, { recursive: true, force: true });
t.done();
