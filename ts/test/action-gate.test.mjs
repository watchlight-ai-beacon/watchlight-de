// @watchlight/sdk governed action gate — runtime context, per-call principal,
// correlation id, and the three-state Allow/Deny/NeedsApproval verdict + HITL
// token exchange. Runs the real @watchlight/engine.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, Denied, NeedsApproval } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-gate-"));
  const g = new Watchlight({ agent: "booking-agent", auditDir });
  g.allow('permit(principal, action == Action::"book", resource) when { context.amount <= context.limit };', "funded");
  g.allow('permit(principal == User::"alice", action == Action::"pay", resource);', "alice-pays");
  g.allow('@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource) when { context.amount > 1000 };', "big-wire");

  // ── 1. runtime context binding (the crux) ──
  let ran = 0;
  const book = g.tool((order) => { ran++; return `booked ${order.id}`; }, {
    intent: "book",
    context: (order) => ({ amount: order.amount, limit: 100 }),
  });
  ok("context: within budget runs", (await book({ id: "t1", amount: 50 })) === "booked t1" && ran === 1);
  let denied = false;
  try { await book({ id: "t2", amount: 200 }); } catch (e) { denied = e instanceof Denied; }
  ok("context: over budget denied", denied && ran === 1);

  // ── 2. per-call principal binding ──
  const pay = g.tool((req) => `paid ${req.amount}`, {
    intent: "pay",
    principal: (req) => `User::"${req.user}"`,
  });
  ok("principal: alice permitted", (await pay({ user: "alice", amount: 10 })) === "paid 10");
  let bobDenied = false;
  try { await pay({ user: "bob", amount: 10 }); } catch (e) { bobDenied = e instanceof Denied; }
  ok("principal: bob denied", bobDenied);

  // ── 3. correlation id ──
  const d = await g.authorize({ action: "book", resource: 'trip/t9', context: { amount: 1, limit: 100 } });
  ok("authorize returns a decisionId", typeof d.decisionId === "string" && d.decisionId.length > 0);
  ok("decision is Allow", d.decision === "Allow" && d.allowed);

  // ── 4. three-state verdict: NeedsApproval ──
  const w = await g.authorize({ action: "wire", resource: 'acct/1', context: { amount: 5000 } });
  ok("big wire → NeedsApproval", w.decision === "NeedsApproval" && !w.allowed && w.needsApproval);

  // ── 4b. HITL token exchange ──
  const token = g.mintApproval({ action: "wire", resource: 'acct/1' });
  const approved = await g.authorize({ action: "wire", resource: 'acct/1', context: { amount: 5000 }, approval: token });
  ok("approved wire → Allow", approved.decision === "Allow" && approved.allowed && approved.approved);
  const reuse = await g.authorize({ action: "wire", resource: 'acct/1', context: { amount: 5000 }, approval: token });
  ok("approval token is single-use", reuse.decision === "NeedsApproval");
  const wrongTok = g.mintApproval({ action: "wire", resource: 'acct/other' });
  const bound = await g.authorize({ action: "wire", resource: 'acct/1', context: { amount: 5000 }, approval: wrongTok });
  ok("token bound to resource (wrong resource rejected)", bound.decision === "NeedsApproval");

  // ── 4c. govern.tool onNeedsApproval hook ──
  let wired = 0;
  const wire = g.tool((r) => { wired++; return `wired ${r.amount}`; }, {
    intent: "wire",
    resource: (r) => `acct/${r.to}`,
    context: (r) => ({ amount: r.amount }),
    onNeedsApproval: async () => true, // human said yes
  });
  ok("tool: approved via hook runs", (await wire({ to: "z", amount: 5000 })) === "wired 5000" && wired === 1);
  const wireNo = g.tool((r) => { wired++; return "x"; }, {
    intent: "wire", resource: (r) => `acct/${r.to}`, context: (r) => ({ amount: r.amount }),
    onNeedsApproval: async () => false, // human declined
  });
  let held = false;
  try { await wireNo({ to: "y", amount: 5000 }); } catch (e) { held = e instanceof NeedsApproval; }
  ok("tool: declined hook throws NeedsApproval, body not run", held && wired === 1);

  // ── 5. audit: correlation id + principal, value-free (no context values) ──
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("audit carries decision_id", raw.includes('"decision_id"'));
  ok("audit carries per-call principal", raw.includes('"principal":"User::\\"alice\\""'));
  ok("audit records an approval", raw.includes('"approved":true'));
  ok("audit value-free (no context amounts)", !raw.includes('5000') && !raw.includes('"amount"'));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
