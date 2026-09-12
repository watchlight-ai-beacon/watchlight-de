// subagent-confinement — the strict-subset rule, run through the real engine.
//
// Attenuation is a capability check (Scope.attenuate), not a policy decision, so
// it cannot be expressed as a `watchlight policy test` suite. This script asserts:
// a child scope narrower than its parent is granted (and holds exactly the
// clamped subset); a wider one is refused with AttenuationDenied; what a parent
// never held, or already dropped, cannot be re-acquired further down the tree;
// a hop past max_delegation_depth is a deny (DelegationDepthExceeded) with its own
// reason code; the
// audit trail records every grant and refusal with tool NAMES only; and a scope
// token minted in one process is rebuilt in another with the same grants, while
// a tampered or expired token is refused (ScopeTokenError) and the rebuilt scope
// still cannot widen (AttenuationDenied).
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";
import { loadSdk, checks } from "./_sdk.mjs";

const { Watchlight, AttenuationDenied, DelegationDepthExceeded, ScopeTokenError } = loadSdk();
const t = checks("subagent-confinement (attenuation)");

const denied = (fn) => {
  try { fn(); return null; } catch (e) { return e; }
};

const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-pattern-scope-"));
try {
  const govern = new Watchlight({ agent: "orchestrator", auditDir });
  const root = await govern.scope({
    tools: ["read_file", "web_search", "send_email", "transfer_funds"],
    timeBudgetSeconds: 600,
  });

  // Narrower → granted, and the child holds the clamped subset, nothing more.
  const summarizer = root.attenuate({ tools: ["read_file"] });
  t.ok("a strict-subset child is granted", summarizer.depth === 1 && summarizer.parentId === root.nodeId);
  t.ok("the child holds exactly the requested subset", JSON.stringify(summarizer.allowedTools) === JSON.stringify(["read_file"]));
  t.ok("a child cannot outlive its parent's time budget",
    root.attenuate({ tools: ["read_file"], timeBudgetSeconds: 60 }).timeBudgetSeconds === 60 &&
      denied(() => root.attenuate({ tools: ["read_file"], timeBudgetSeconds: 6000 })) instanceof AttenuationDenied);

  // Wider → refused.
  const widen = denied(() => summarizer.attenuate({ tools: ["send_email"] }));
  t.ok("a child asking for a tool its parent lacks is refused with AttenuationDenied",
    widen instanceof AttenuationDenied, String(widen));
  t.ok("the refusal names the violated dimension, never a value",
    widen && Array.isArray(widen.violations) && widen.reason.length > 0);

  // The parent's own denials still hold below it.
  t.ok("what the root never held cannot be granted to any child",
    denied(() => root.attenuate({ tools: ["read_file", "delete_repo"] })) instanceof AttenuationDenied);
  t.ok("a tool the parent dropped cannot be re-acquired by a grandchild",
    denied(() => summarizer.attenuate({ tools: ["web_search"] })) instanceof AttenuationDenied);
  t.ok("a grandchild may still narrow further", summarizer.attenuate({ tools: [] }).allowedTools.length === 0);

  // Depth limit: max_delegation_depth is a governance control; a hop past it is a
  // deny with its own reason code.
  let leaf = root;
  for (let d = 1; d <= root.maxDelegationDepth; d++) leaf = leaf.attenuate({ tools: ["read_file"] });
  const tooDeep = denied(() => leaf.attenuate({ tools: ["read_file"] }));
  t.ok(`depth ${root.maxDelegationDepth + 1} raises DelegationDepthExceeded — a deny with code DELEGATION_DEPTH_EXCEEDED`,
    tooDeep instanceof DelegationDepthExceeded && tooDeep instanceof AttenuationDenied &&
      tooDeep.code === "DELEGATION_DEPTH_EXCEEDED");

  // Audit: every grant and refusal is recorded, value-free.
  const records = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse)
    .filter((r) => r.event === "attenuation");
  const denies = records.filter((r) => r.decision === "Deny");
  const depthDenies = denies.filter((r) => r.reason_code === "DELEGATION_DEPTH_EXCEEDED");
  t.ok("every strict-subset refusal is an attenuation Deny record (4 refusals above)",
    denies.length - depthDenies.length === 4, `got ${denies.length - depthDenies.length}`);
  t.ok("the depth refusal is recorded once, with the observed depth and the limit",
    depthDenies.length === 1 && depthDenies[0].depth === root.maxDelegationDepth + 1 &&
      depthDenies[0].max_delegation_depth === root.maxDelegationDepth,
    JSON.stringify(depthDenies));
  t.ok("records carry tool names and depth only — no arguments, no prompt text",
    records.every((r) => Array.isArray(r.tools) && typeof r.depth === "number" &&
      Object.keys(r).every((k) => ["ts", "agent", "intent", "event", "node_id", "parent_id", "resource", "decision", "depth", "tools", "reason", "reason_code", "max_delegation_depth"].includes(k))));

  // Crossing a process boundary: a scope token carries the chain, the receiving
  // engine re-proves it. Illustrative secret — a real one comes from a secret store.
  // The extra governors below stand in for SEPARATE PROCESSES, which is the one
  // reason to construct more than one over the same policy set — an application
  // names several agents from a single governor with `as()`
  // (see docs/using-the-governor.md).
  // Generated, not written down. Both governors below share this one value;
  // in a real deployment it comes from your secret manager.
  const secret = randomBytes(32).toString("hex");
  const orchestrator = new Watchlight({ agent: "orchestrator", auditDir, signingSecret: secret });
  const worker = new Watchlight({ agent: "orchestrator", auditDir, signingSecret: secret });
  const minted = (await orchestrator.scope({ tools: ["read_file", "web_search", "send_email"], timeBudgetSeconds: 600 }))
    .attenuate({ tools: ["read_file"] });
  const token = minted.toToken();
  const rebuilt = await worker.scopeFromToken(token);
  t.ok("a token rebuilt in another instance with the same secret yields the same grants",
    JSON.stringify(rebuilt.allowedTools) === JSON.stringify(minted.allowedTools) && rebuilt.depth === minted.depth);
  t.ok("the rebuilt scope still cannot widen",
    denied(() => rebuilt.attenuate({ tools: ["send_email"] })) instanceof AttenuationDenied);
  const [v, p, sig] = token.split(".");
  const tampered = `${v}.${p.slice(0, 10)}${p[10] === "A" ? "B" : "A"}${p.slice(11)}.${sig}`;
  const forged = await worker.scopeFromToken(tampered).then(() => null, (e) => e);
  t.ok("a tampered payload is refused with ScopeTokenError", forged instanceof ScopeTokenError && forged.code === "signature", String(forged));
  const wrongSecret = new Watchlight({ agent: "orchestrator", auditDir, signingSecret: randomBytes(32).toString("hex") });
  t.ok("a token verified with a different secret is refused",
    (await wrongSecret.scopeFromToken(token).then(() => null, (e) => e)) instanceof ScopeTokenError);
  // Expiry is checked in whole seconds against the wall clock and the public API
  // takes no injected clock, so mint a 1-second token and poll until the second
  // boundary passes — the shortest wait the check needs, capped at 1.5 s.
  const shortLived = minted.toToken({ ttlSeconds: 1 });
  let late = null;
  for (const deadline = Date.now() + 1500; late === null && Date.now() < deadline; ) {
    const r = await worker.scopeFromToken(shortLived).then(() => null, (e) => e);
    if (r instanceof ScopeTokenError && r.code === "expired") late = r;
    else await new Promise((res) => setTimeout(res, 50));
  }
  t.ok("an expired token is refused with ScopeTokenError", late instanceof ScopeTokenError && late.code === "expired", String(late));
} finally {
  fs.rmSync(auditDir, { recursive: true, force: true });
}
// ── the policy half ────────────────────────────────────────────────────────
// A scope is checked at delegate, never at authorize, so the policy is what
// stops a confined child asking for something else. These are the four verdicts
// the pattern prints.
{
  const g = new Watchlight({ agent: "orchestrator", auditFile: false, auditSink: () => {} });
  g.allow("permit(principal, action, resource);", "baseline");
  g.allow(
    'forbid(principal, action == Action::"transfer", resource)\n' +
      'when { context.actor_chain.contains("research") };',
    "no-money-below-research",
  );
  const root = await g.scope({ tools: ["search", "transfer"] });
  const child = g.delegate(root, "research", { tools: ["search"] });
  const verdict = async (gov, action) => (await gov.authorize({ action, resource: "r" })).decision;

  t.ok("the orchestrator may search", (await verdict(g, "search")) === "Allow");
  t.ok("the orchestrator may transfer", (await verdict(g, "transfer")) === "Allow");
  t.ok("the delegated child may search", (await verdict(child, "search")) === "Allow");
  t.ok("the delegated child may not transfer", (await verdict(child, "transfer")) === "Deny");
  t.ok("delegate appended to the chain", child.actorChain.join(",") === "orchestrator,research");
}

t.done();
