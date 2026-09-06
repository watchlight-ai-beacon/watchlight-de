#!/usr/bin/env node
/**
 * Adversarial harness for the Watchlight Developer Edition.
 *
 * Contributed, and adopted here. It tries to BREAK the SDK and the engine behind
 * it rather than demonstrate them: malformed identities, hostile sink / store /
 * counter implementations, reserved-key collisions, annotation typos, forged
 * tokens, and boundary values on every option that takes one.
 *
 * It complements the unit suites rather than repeating them. Those assert what
 * the SDK is meant to do; this asserts what it must never do, under inputs no
 * well-behaved caller would send.
 *
 * Every case prints one line:
 *
 *   PASS  the safe outcome was asserted, and it held
 *   GAP   the outcome is unsafe or surprising — a defect, unless it is listed in
 *         KNOWN_GAPS below along with the reason it is expected today
 *   INFO  behaviour worth pinning, with no judgement attached: a deliberate
 *         design choice, or a documented hazard, recorded so a change is noticed
 *
 * Every case asserts the SAFE outcome explicitly rather than merely printing what
 * happened, so a regression surfaces as a GAP and not as different output nobody
 * reads.
 *
 * Run it:
 *
 *   scripts/adversarial-harness.mjs        # or: node scripts/adversarial-harness.mjs
 *
 * It exits non-zero on any GAP that is not in KNOWN_GAPS, and on any KNOWN_GAPS
 * entry that no longer reproduces — a fix has to take its baseline entry with it,
 * so the list can never quietly outlive the problems it excuses.
 *
 * The SDK and engine versions are printed in the header: a finding without a
 * version is not reproducible.
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require_ = createRequire(import.meta.url);

// Resolve the SDK from an installed package first, then from this clone's build —
// the same order the examples use, so the harness runs in a fresh clone that has
// only done `cd ts && npm install && npm run build`.
function loadSdk() {
  const repoEntry = fileURLToPath(new URL("../ts/dist/index.js", import.meta.url));
  const repoPkg = fileURLToPath(new URL("../ts/package.json", import.meta.url));
  for (const [entry, pkg] of [
    ["@watchlight/sdk", "@watchlight/sdk/package.json"],
    [repoEntry, repoPkg],
  ]) {
    let mod;
    try {
      mod = require_(entry);
    } catch (e) {
      if (e?.code !== "MODULE_NOT_FOUND") throw e;
      continue;
    }
    // The engine is resolved from wherever the SDK itself resolves it.
    const near = createRequire(require_.resolve(entry));
    let engineVersion = "unknown";
    try { engineVersion = near("@watchlight/engine/package.json").version; } catch { /* reported as unknown */ }
    return { mod, sdkVersion: require_(pkg).version, engineVersion };
  }
  console.error("error: @watchlight/sdk not found. Install it —");
  console.error("         npm i -g @watchlight/sdk");
  console.error("       or build it in this clone —");
  console.error("         cd ts && npm install && npm run build");
  process.exit(2);
}

const { mod: sdk, sdkVersion: SDK, engineVersion: ENGINE } = loadSdk();
const { Watchlight, principals, entityRef, governTool, canConfigureDefault, EgressTimeout } = sdk;

// GAPs that are expected as things stand. The key is the case name exactly as it
// is printed; the value says why it is expected. A GAP that is not listed here
// fails the run, and a listed one that no longer reproduces fails it too — so the
// change that fixes a gap is the change that deletes its entry.
const KNOWN_GAPS = {
  // Empty, and that is the state to keep it in. An entry here is an excuse with
  // an expiry date: it says "this GAP is expected today", and the run fails once
  // the GAP stops reproducing, so the change that fixes one is the change that
  // deletes its entry. Nothing is exempt at the moment.
};

let pass = 0, gap = 0, info = 0;
const GAPS = [];
const P = (name, status, detail = "") => {
  if (status === "PASS") pass++;
  else if (status === "GAP") { gap++; GAPS.push({ name, detail }); }
  else info++;
  console.log("  " + status.padEnd(4) + " " + name.padEnd(44) + " " + detail);
};
const attempt = async (fn) => {
  try { return { ok: await fn() }; }
  catch (e) { return { err: (e && e.constructor && e.constructor.name) || "Error", msg: String(e && e.message).slice(0, 60) }; }
};
const mk = (o = {}) => new Watchlight({ agent: "probe", auditFile: false, ...o });
const SECRET = "0123456789abcdef0123456789abcdef";
const NUL = String.fromCharCode(0);
const BELL = String.fromCharCode(7);

console.log("\nWatchlight adversarial harness -- sdk " + SDK + ", engine " + ENGINE + ", node " + process.versions.node);

console.log("\nA. Identity: can a malformed id become a valid entity?");
for (const [label, id, mustReject] of [
  ["unicode name", "Jose-Muller", false],
  ["1000 chars", "x".repeat(1000), false],
  ["newline", "a\nb", true],
  ["tab", "a\tb", true],
  ["NUL byte", "a" + NUL + "b", true],
  ["bell char", "a" + BELL + "b", true],
  ["embedded quote", 'a"b', false],
  ["empty", "", true],
]) {
  const r = await attempt(() => principals.user(id));
  const rejected = Boolean(r.err);
  if (mustReject) P("principals.user(" + label + ")", rejected ? "PASS" : "GAP", rejected ? r.err : "accepted");
  else P("principals.user(" + label + ")", "INFO", rejected ? "rejected (" + r.err + ")" : "accepted");
}
{
  const r = await attempt(() => entityRef("", "x"));
  P("entityRef with empty TYPE", r.err ? "PASS" : "GAP", r.err || "accepted");
  const r2 = await attempt(() => entityRef('Bad"Type', "x"));
  P("entityRef with quote in TYPE", r2.err ? "PASS" : "INFO", r2.err || "accepted");
}
{
  const g = mk();
  g.allow('permit(principal == User::"admin", action == Action::"x", resource);', "only-admin");
  const crafted = principals.user('nobody" || principal == User::"admin');
  const v = await g.authorize({ action: "x", principal: crafted, resource: "r" });
  P("crafted id cannot forge a clause", v.decision === "Deny" ? "PASS" : "GAP", "decision=" + v.decision);
}

console.log("\nB. as(): can a rename produce an unusable or forged identity?");
for (const [label, name, mustReject] of [
  ["empty", "", true],
  ["spaces", "   ", true],
  ["quote", 'a"b', false],
  ["newline", "a\nb", true],
  ["1000 chars", "x".repeat(1000), false],
]) {
  const r = await attempt(() => mk().as(name).agent);
  const rejected = Boolean(r.err);
  if (mustReject) P("as(" + label + ")", rejected ? "PASS" : "GAP", rejected ? r.err : "accepted");
  else P("as(" + label + ")", "INFO", rejected ? "rejected (" + r.err + ")" : "accepted");
}
{
  const two = mk().as("a").as("b");
  P("as().as() does not build a chain", two.actorChain.length === 1 ? "PASS" : "INFO",
    "agent=" + two.agent + " chain=" + JSON.stringify(two.actorChain));
}

console.log("\nC. Hostile auditSink must never change a decision");
for (const [label, sink] of [
  ["throws synchronously", () => { throw new Error("sink down"); }],
  ["rejects async", async () => { throw new Error("sink down"); }],
  ["returns a non-promise", () => 42],
  ["blocks ~50ms", async () => { await new Promise((r) => setTimeout(r, 50)); }],
]) {
  const g = new Watchlight({ agent: "probe", auditFile: false, auditSink: sink });
  g.allow('permit(principal, action == Action::"s", resource);', "s");
  const r = await attempt(() => g.authorize({ action: "s", principal: principals.user("u"), resource: "r" }).then((x) => x.decision));
  P("sink " + label, r.ok === "Allow" ? "PASS" : "GAP", r.err ? r.err + ": " + r.msg : r.ok);
}

console.log("\nD. Hostile counterSource must fail closed, never guess");
for (const [label, src] of [
  ["throws", () => { throw new Error("db down"); }],
  ["rejects", async () => { throw new Error("db down"); }],
  ["returns -1", () => -1],
  ["returns NaN", () => NaN],
  ["returns 1.5", () => 1.5],
  ["returns Infinity", () => Infinity],
  ['returns "5"', () => "5"],
  ["returns null", () => null],
]) {
  const g = mk({ counterSource: src });
  const r = await attempt(() => g.countersAsync({ principal: principals.user("u"), window: "1h" }).then((x) => x.count));
  P("counterSource " + label, r.err ? "PASS" : "GAP", r.err || ("ACCEPTED count=" + r.ok));
}
for (const [label, w] of [["0", 0], ["-1", -1], ["367d", "367d"], ["abc", "abc"], ["1e9 s", 1e9]]) {
  const r = await attempt(() => mk().countersAsync({ principal: principals.user("u"), window: w }).then((x) => x.count));
  P("counters window=" + label, r.err ? "PASS" : "INFO", r.err || ("accepted count=" + r.ok));
}

console.log("\nE. approvalStore: single use must hold, a broken store must not open");
const approvalGov = (store) => {
  const g = new Watchlight({ agent: "probe", auditFile: false, signingSecret: SECRET, approvalStore: store });
  g.allow('@enforcement_effect("require_approval")\npermit(principal, action == Action::"f", resource);', "f");
  return g;
};
for (const [label, add, safeIsHold] of [
  ["throws", () => { throw new Error("store down"); }, true],
  ["rejects async", async () => { throw new Error("store down"); }, true],
  ["returns false", () => false, true],
  ["returns true", () => true, false],
  ['returns "yes"', () => "yes", true],
  ["returns 1", () => 1, true],
  ["returns null", () => null, true],
  ["returns undefined", () => undefined, true],
]) {
  const g = approvalGov({ add });
  const tok = g.mintApproval({ action: "f", principal: principals.user("u"), resource: "r" });
  const r = await attempt(() => g.authorize({ action: "f", principal: principals.user("u"), resource: "r", approval: tok }).then((x) => x.decision));
  const allowed = r.ok === "Allow";
  P("approvalStore.add() " + label, allowed === !safeIsHold ? "PASS" : "GAP", r.err || r.ok);
}
{
  const seen = new Set();
  const g = approvalGov({ add: (id) => (seen.has(id) ? false : (seen.add(id), true)) });
  const tok = g.mintApproval({ action: "f", principal: principals.user("u"), resource: "r" });
  const a = (await g.authorize({ action: "f", principal: principals.user("u"), resource: "r", approval: tok })).decision;
  const b = (await g.authorize({ action: "f", principal: principals.user("u"), resource: "r", approval: tok })).decision;
  P("replay of a consumed token", a === "Allow" && b !== "Allow" ? "PASS" : "GAP", "first=" + a + " replay=" + b);
}
{
  const g = approvalGov({ add: () => true });
  const tok = g.mintApproval({ action: "f", principal: principals.user("victim"), resource: "r" });
  const v = await attempt(() => g.authorize({ action: "f", principal: principals.user("attacker"), resource: "r", approval: tok }).then((x) => x.decision));
  P("token bound to its principal", v.ok !== "Allow" ? "PASS" : "GAP", v.err || v.ok);
  const v2 = await attempt(() => g.authorize({ action: "f", principal: principals.user("victim"), resource: "other", approval: tok }).then((x) => x.decision));
  P("token bound to its resource", v2.ok !== "Allow" ? "PASS" : "GAP", v2.err || v2.ok);
  const v3 = await attempt(() => g.authorize({ action: "f", principal: principals.user("victim"), resource: "r", approval: "garbage.token.value" }).then((x) => x.decision));
  P("forged token rejected", v3.ok !== "Allow" ? "PASS" : "GAP", v3.err || v3.ok);
}

console.log("\nF. Reserved actor keys: can a caller forge the actor a policy reads?");
{
  const g = mk();
  g.allow('permit(principal, action == Action::"x", resource) when { context.actor == "trusted" };', "actor-gate");
  const forged = await attempt(() => g.authorize({ action: "x", principal: principals.user("u"), resource: "r", context: { actor: "trusted" } }).then((x) => x.decision));
  P("forge context.actor to match a policy", forged.err ? "PASS" : "GAP", forged.err || ("ACCEPTED -> " + forged.ok));
  const chain = await attempt(() => g.authorize({ action: "x", principal: principals.user("u"), resource: "r", context: { actor_chain: ["trusted"] } }).then((x) => x.decision));
  P("forge context.actor_chain", chain.err ? "PASS" : "GAP", chain.err || ("ACCEPTED -> " + chain.ok));
  const same = await attempt(() => g.authorize({ action: "x", principal: principals.user("u"), resource: "r", context: { actor: "probe" } }).then((x) => x.decision));
  P("supply the SAME actor the SDK derives", "INFO", same.err || ("accepted -> " + same.ok));
}

console.log("\nG. Annotations: does a typo silently weaken a policy?");
for (const [label, annot] of [
  ["require_approval (correct)", '@enforcement_effect("require_approval")\n'],
  ["needs_approval (typo value)", '@enforcement_effect("needs_approval")\n'],
  ["garbage value", '@enforcement_effect("not_a_real_value")\n'],
]) {
  const g = mk();
  const loaded = await attempt(() => { g.allow(annot + 'permit(principal, action == Action::"z", resource);', "z"); return g.policyCount; });
  if (loaded.err) { P("annotation " + label, "PASS", "rejected at load: " + loaded.err); continue; }
  const v = await attempt(() => g.authorize({ action: "z", principal: principals.user("u"), resource: "r" }).then((x) => x.decision));
  P("annotation " + label, v.ok === "NeedsApproval" ? "PASS" : "GAP", "loaded silently, decision=" + v.ok);
}
{
  // A misspelled annotation NAME is deliberately only a warning: an unknown
  // annotation is legal Cedar and may legitimately belong to the application.
  // The contract we hold them to is that it is not SILENT.
  const g = mk();
  const warns = [];
  const orig = console.warn;
  console.warn = (...a) => warns.push(a.join(" "));
  g.allow('@enforcment_effect("require_approval")\npermit(principal, action == Action::"n", resource);', "n");
  console.warn = orig;
  P("misspelled annotation name warns", warns.length > 0 ? "PASS" : "GAP",
    warns.length ? "warned" : "SILENT -- a typo'd guard would not be noticed");
}
{
  const g = mk();
  g.allow('@obligate_max_item("2")\npermit(principal, action == Action::"o", resource);', "o");
  const v = await g.authorize({ action: "o", principal: principals.user("u"), resource: "r" });
  const visible = JSON.stringify(v.obligations || {}).includes("max_item");
  P("typo'd obligation stays visible", visible ? "PASS" : "GAP", JSON.stringify(v.obligations || null));
}

console.log("\nH. Scope tokens: can attenuation be widened or re-bound?");
{
  const g = new Watchlight({ agent: "probe", auditFile: false, signingSecret: SECRET });
  const root = await g.scope({ tools: ["search", "book"] });
  const tok = root.toToken();
  const rebound = await attempt(() => g.as("other-name").scopeFromToken(tok));
  P("scope token re-bound to another agent", rebound.err ? "PASS" : "GAP", rebound.err || "ACCEPTED");
  const tampered = await attempt(() => g.scopeFromToken(tok.slice(0, -4) + "0000"));
  P("tampered scope token", tampered.err ? "PASS" : "GAP", tampered.err || "ACCEPTED");
  const widened = await attempt(() => root.attenuate({ tools: ["search", "book", "refund"] }));
  P("attenuate cannot widen", widened.err ? "PASS" : "GAP", widened.err || "ACCEPTED a wider scope");
  const noSecret = new Watchlight({ agent: "probe", auditFile: false });
  const mintless = await attempt(async () => (await noSecret.scope({ tools: ["x"] })).toToken());
  P("toToken without a signing secret", mintless.err ? "PASS" : "GAP", mintless.err || "MINTED unsigned");
}

console.log("\nI. Malformed inputs to sanitize / screen");
{
  const g = mk();
  for (const [label, fn, mustReject] of [
    ["decisionId 129 chars", () => g.sanitize("a@b.com", { decisionId: "x".repeat(129) }), true],
    ["decisionId control char", () => g.sanitize("a@b.com", { decisionId: "a" + NUL + "b" }), true],
    ["screen unknown family", () => g.screen("hi", { families: ["NOPE"] }), true],
    ["sanitize empty input", () => g.sanitize("", { intent: "i" }), false],
    ["sanitize known ['']", () => g.sanitize("hello", { known: [""] }), false],
    ["sanitize overlapping known", () => g.sanitize("aaa", { known: ["a", "aa"] }), false],
    ["principal not an entity ref", () => g.sanitize("a@b.com", { principal: "not-an-entity" }), false],
  ]) {
    const r = await attempt(fn);
    if (mustReject) P(label, r.err ? "PASS" : "GAP", r.err || "ACCEPTED");
    else P(label, "INFO", r.err ? "rejected (" + r.err + ")" : "accepted");
  }
  const big = await attempt(() => g.sanitize("a@b.com ".repeat(200000)).report.total);
  P("sanitize 1.6MB input", big.err ? "INFO" : "PASS", big.err || ("handled, matches=" + big.ok));
}

console.log("\nJ. Fail-closed defaults");
{
  const empty = new Watchlight({ agent: "probe", auditFile: false });
  const v = await empty.authorize({ action: "anything", principal: principals.user("u"), resource: "r" });
  P("no policies loaded denies", v.decision === "Deny" ? "PASS" : "GAP", v.decision);

  const g = mk();
  g.allow('permit(principal, action == Action::"w", resource) when { context.missing == 1 };', "w");
  const v2 = await g.authorize({ action: "w", principal: principals.user("u"), resource: "r" });
  P("missing context attribute denies", v2.decision === "Deny" ? "PASS" : "GAP", v2.decision);

  const v3 = await attempt(() => g.authorize({ action: "w", principal: principals.user("u"), resource: "r", context: Promise.resolve({ missing: 1 }) }));
  P("promise as context throws", v3.err === "UnresolvedContextError" ? "PASS" : "GAP", v3.err || "accepted");

  const noName = await attempt(() => new Watchlight({ auditFile: false }).agent);
  P("unnamed governor must not invent an identity",
    noName.err ? "PASS" : (noName.ok === "my-agent" ? "GAP" : "INFO"),
    noName.err ? "refused at construction (" + noName.err + ")" : "agent=" + JSON.stringify(noName.ok));
}

console.log("\nK. Principal forms and the documented bare-identifier hazard");
{
  const recs = [];
  const g = new Watchlight({ agent: "probe", auditFile: false, auditSink: (r) => recs.push(r) });
  g.allow('permit(principal, action == Action::"p", resource);', "p");

  // An EMPTY principal must raise rather than be attributed to the runtime.
  const empty = await attempt(() => g.authorize({ action: "p", principal: "", resource: "r" }).then((x) => x.decision));
  P("empty principal is refused", empty.err ? "PASS" : "GAP", empty.err || ("ACCEPTED -> " + empty.ok));

  // A BARE identifier is accepted deliberately and is meaningful — recorded, not
  // rewritten. Not a defect; tracked so a change in policy is noticed.
  for (const [label, raw] of [
    ["bare identifier", "u-1"],
    ["unquoted entity-ish", "User::unquoted"],
    ["entity + trailing junk", 'User::"a" || x'],
  ]) {
    const r = await attempt(() => g.authorize({ action: "p", principal: raw, resource: "r" }).then((x) => x.decision));
    P("principal " + label, "INFO", r.err ? "rejected (" + r.err + ")" : "accepted by design -> " + r.ok);
  }
  const written = recs.filter((r) => r.event === undefined).map((r) => r.principal);
  P("no principal is rewritten as the agent",
    written.some((x) => String(x).startsWith('Agent::')) ? "GAP" : "PASS",
    "recorded: " + JSON.stringify(written));

  // sanitize/screen still take any string. Lesser instance of the same thing.
  const recs2 = [];
  const g2 = new Watchlight({ agent: "probe", auditFile: false, auditSink: (r) => recs2.push(r) });
  g2.sanitize("a@b.com", { intent: "i", resource: "r", principal: "not-an-entity" });
  g2.screen("hi", { intent: "i", resource: "r", principal: "also-not-an-entity" });
  const bad = recs2.filter((r) => r.principal && !/^[A-Za-z_]+::".*"$/.test(String(r.principal)));
  P("sanitize/screen principal shape", bad.length === 0 ? "PASS" : "INFO",
    bad.length ? "records any string: " + JSON.stringify(bad.map((r) => r.principal)) : "validated");
}

{
  // DOCUMENTED HAZARD, asserted so a change is noticed: a bare identifier matches
  // User/Agent/Group/Role, and among those an ALLOW beats a FORBID -- the inverse
  // of Cedar's usual rule. A forbid naming an agent is therefore defeated by a
  // permit naming a user with the same id, whenever an untyped principal is passed.
  // The protection is to always pass a typed principal, via principals.user().
  const h = mk();
  h.allow('forbid(principal == Agent::"dual", action == Action::"t", resource);', "deny-agent");
  h.allow('permit(principal == User::"dual", action == Action::"t", resource);', "allow-user");
  const bare = await attempt(() => h.authorize({ action: "t", principal: "dual", resource: "r" }).then((x) => x.decision));
  const typed = await attempt(() => h.authorize({ action: "t", principal: principals.agent("dual"), resource: "r" }).then((x) => x.decision));
  P("bare id: allow beats forbid (documented)", bare.ok === "Allow" ? "INFO" : "PASS",
    "bare -> " + (bare.err || bare.ok) + "  (typed Agent -> " + (typed.err || typed.ok) + ")");
  P("typed principal still honours the forbid", typed.ok === "Deny" ? "PASS" : "GAP", typed.err || typed.ok);
}

{
  const g = mk();
  g.allow('permit(principal == Agent::"trusted", action == Action::"y", resource);', "agent-gate");
  g.allow('permit(principal, action == Action::"z", resource) when { context.actor == "trusted" };', "actor-gate");
  const evil = g.as('nobody" || principal == Agent::"trusted');
  const a = await attempt(() => evil.authorize({ action: "y", resource: "r" }).then((x) => x.decision));
  P("crafted agent name cannot forge Agent::", a.ok === "Deny" ? "PASS" : "GAP", a.err || a.ok);
  const b = await attempt(() => evil.authorize({ action: "z", resource: "r" }).then((x) => x.decision));
  P("crafted agent name cannot forge actor", b.ok === "Deny" ? "PASS" : "GAP", b.err || b.ok);
}

{
  // The unnamed-governor placeholder must not be reachable from policy.
  const unnamed = new Watchlight({ auditFile: false });
  const viaActor = mk();
  viaActor.allow('permit(principal, action == Action::"u", resource) when { context.actor == "<unconfigured>" };', "u");
  const r1 = await attempt(() => new Watchlight({ auditFile: false, auditSink: () => {} })
    .allow('permit(principal, action == Action::"u", resource) when { context.actor == "<unconfigured>" };', "u")
    .authorize({ action: "u", resource: "r" }).then((x) => x.decision));
  P("placeholder unreachable via context.actor", r1.ok === "Deny" ? "PASS" : "GAP", r1.err || r1.ok);
  const r2 = await attempt(() => new Watchlight({ auditFile: false, auditSink: () => {} })
    .allow('permit(principal == Agent::"<unconfigured>", action == Action::"u", resource);', "u")
    .authorize({ action: "u", resource: "r" }).then((x) => x.decision));
  // INFO rather than GAP, deliberately, and it will stay that way. An
  // unconfigured governor's placeholder is still the recorded SUBJECT of a call
  // that names no principal: the engine requires a principal, and a Cedar entity
  // id is an arbitrary string, so there is no id that could be made unnameable by
  // a policy. A policy may therefore name the placeholder, and the answer to that
  // is to name your governor — which is exactly what the placeholder is telling
  // you to do. Pinned here so a change in the behaviour is noticed.
  P("placeholder is nameable via Agent:: principal", "INFO",
    (r2.err || r2.ok) + " -- agent=" + JSON.stringify(unnamed.agent) + "; name your governor");
}

console.log("\nL. Delegation, obligations and the egress hook");
{
  const g = mk({ signingSecret: SECRET });
  g.allow('permit(principal, action == Action::"d", resource);', "d");
  const root = await g.scope({ tools: ["a", "b"] });
  const lvl1 = g.delegate(root, "lvl1");
  P("delegate extends the actor chain", lvl1.actorChain.length === 2 ? "PASS" : "GAP", JSON.stringify(lvl1.actorChain));
  const widen = await attempt(() => g.delegate(root, "wide", { tools: ["a", "b", "c"] }));
  P("delegate cannot widen a scope", widen.err ? "PASS" : "GAP", widen.err || "ACCEPTED a wider scope");
  let depth = 1, scope = lvl1.delegatedScope, stop = null;
  while (depth < 12) {
    const r = await attempt(() => g.delegate(scope, "lvl" + (depth + 1)));
    if (r.err) { stop = r.err; break; }
    scope = r.ok.delegatedScope; depth++;
  }
  P("delegation depth is bounded", stop ? "PASS" : "GAP", "reached depth " + depth + ", stopped by " + stop);
}
{
  // Obligations are advisory BY DESIGN -- the engine reports, the caller honours.
  // Recorded so the contract is explicit: an app that ignores them violates policy
  // silently. An application that acts on obligations must honour every one it
  // is handed -- maxItems and redact included.
  const g = mk();
  g.allow('@obligate_max_items("2")\npermit(principal, action == Action::"m", resource);', "m");
  const v = await g.authorize({ action: "m", principal: principals.user("u"), resource: "r" });
  const tool = governTool({ name: "m", async invoke() { return [1, 2, 3, 4, 5]; } },
    { governor: g, intent: "m", principal: principals.user("u") });
  const out = await attempt(() => tool.invoke({}));
  P("obligations are advisory, not enforced", "INFO",
    "maxItems=" + v.obligations?.maxItems + ", tool returned " + (Array.isArray(out.ok) ? out.ok.length : "?") + " items");
}
{
  // The egress hook is the last gate before a payload reaches the model.
  const g = mk();
  g.allow('permit(principal, action == Action::"e", resource);', "e");
  const mkTool = (onResult, extra = {}) => governTool({ name: "e", async invoke() { return "SECRET"; } },
    { governor: g, intent: "e", principal: principals.user("u"), onResult, ...extra });
  const thrown = await attempt(() => mkTool(() => { throw new Error("nope"); }).invoke({}));
  P("egress hook throw withholds the payload", thrown.err ? "PASS" : "GAP", thrown.err || ("RELEASED " + thrown.ok));
  const replaced = await attempt(() => mkTool(() => "REDACTED").invoke({}));
  P("egress hook can replace the payload", replaced.ok === "REDACTED" ? "PASS" : "GAP", String(replaced.ok));
  // The deadline. This case used to prove the gap -- an onResult hook that hung
  // held the call open for as long as it liked -- so it now proves the fix, which
  // is the same assertion read the other way up. Deliberately driven by a small
  // explicit onResultTimeoutMs rather than the 8 s default: the property is that
  // the deadline fires, not how long the default is, and a harness nobody waits
  // for is a harness nobody runs.
  const HOOK_MS = 1000, DEADLINE_MS = 50;
  const started = Date.now();
  const slow = await attempt(() => mkTool(
    async () => { await new Promise((r) => setTimeout(r, HOOK_MS)); },
    { onResultTimeoutMs: DEADLINE_MS },
  ).invoke({}));
  const took = Date.now() - started;
  P("egress hook deadline withholds the payload", slow.err === "EgressTimeout" ? "PASS" : "GAP",
    slow.err ? slow.err : ("RELEASED " + slow.ok + " after " + took + "ms of hook time"));
  P("the deadline fires, rather than awaiting the hook", took < HOOK_MS ? "PASS" : "GAP",
    "returned after " + took + "ms, hook wanted " + HOOK_MS + "ms");

  // A withheld payload must be withheld in the record too, or the trail says a
  // payload was released that never was.
  {
    const recs = [];
    const gr = new Watchlight({ agent: "probe", auditFile: false, auditSink: (r) => recs.push(r) });
    gr.allow('permit(principal, action == Action::"e", resource);', "e");
    const t = governTool({ name: "e", async invoke() { return "SECRET"; } }, {
      governor: gr, intent: "e", principal: principals.user("u"),
      onResult: async () => { await new Promise((r) => setTimeout(r, HOOK_MS)); },
      onResultTimeoutMs: DEADLINE_MS,
    });
    await attempt(() => t.invoke({}));
    const eg = recs.filter((r) => r.event === "egress").pop();
    P("timed-out egress record says withheld", eg && eg.withheld === true ? "PASS" : "GAP",
      JSON.stringify(eg || null));
    const leaked = JSON.stringify(recs).includes("SECRET");
    P("no withheld payload reaches the trail", leaked ? "GAP" : "PASS", leaked ? "SECRET is in a record" : "value-free");
  }

  // The error is safe to log: a fixed message, a stable name, nothing derived
  // from the payload it was inspecting.
  {
    const e = new EgressTimeout();
    const carries = String(e.message).includes("SECRET");
    P("EgressTimeout is exported and payload-free", !carries && e.name === "EgressTimeout" ? "PASS" : "GAP",
      e.name + ": " + e.message);
  }

  // There is no "off" value, and the refusal happens where the tool is WRAPPED --
  // a misconfigured deadline that only surfaced on the first payload it failed to
  // bound would be the original gap wearing a number.
  for (const [label, ms] of [["0", 0], ["negative", -1], ["NaN", NaN], ["Infinity", Infinity]]) {
    const r = await attempt(() => mkTool(() => "REDACTED", { onResultTimeoutMs: ms }));
    P("onResultTimeoutMs " + label + " refused at wrap time", r.err ? "PASS" : "GAP", r.err || "ACCEPTED");
  }
}
{
  const fresh = canConfigureDefault();
  P("canConfigureDefault reports honestly", typeof fresh === "boolean" ? "PASS" : "GAP", "-> " + fresh);
}

console.log("\n" + "=".repeat(78));
console.log("sdk " + SDK + " / engine " + ENGINE + "    PASS " + pass + "   GAP " + gap + "   INFO " + info);

const reported = new Set(GAPS.map((g) => g.name));
const expected = GAPS.filter((g) => Object.hasOwn(KNOWN_GAPS, g.name));
const unexpected = GAPS.filter((g) => !Object.hasOwn(KNOWN_GAPS, g.name));
const stale = Object.keys(KNOWN_GAPS).filter((name) => !reported.has(name));

if (expected.length) {
  console.log("\nKNOWN GAPS -- expected as things stand, still reported every run:");
  for (const g of expected) {
    console.log("  - " + g.name + " -- " + g.detail);
    console.log("      " + KNOWN_GAPS[g.name]);
  }
}
if (unexpected.length) {
  console.log("\nGAPS:");
  for (const g of unexpected) console.log("  - " + g.name + " -- " + g.detail);
}
if (stale.length) {
  console.log("\nSTALE BASELINE -- these no longer reproduce. Delete them from KNOWN_GAPS:");
  for (const name of stale) console.log("  - " + name);
}
if (!unexpected.length && !stale.length) console.log("\nNo unexpected gaps.");

process.exit(unexpected.length || stale.length ? 1 : 0);
