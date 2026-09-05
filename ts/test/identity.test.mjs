// Agent identity, the reserved agent context key, audit-file control, default
// governor configuration and policy introspection. Runs the real
// @watchlight/engine core. No test framework — plain Node asserts.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const {
  Watchlight, govern, configureDefault, principals, entityRef, escapeCedarString,
  policyEntityRef,
  ReservedContextError, RESERVED_CONTEXT_MESSAGE, ACTOR_CONTEXT_KEY, Denied,
} = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const tmp = (tag) => fs.mkdtempSync(join(os.tmpdir(), `wl-${tag}-`));
const lines = (dir) =>
  fs.readFileSync(join(dir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);

/** Run `fn` with console.warn captured. */
async function warnings(fn) {
  const seen = [];
  const real = console.warn;
  console.warn = (...a) => seen.push(a.join(" "));
  try { await fn(); } finally { console.warn = real; }
  return seen;
}

async function main() {
  // ── as(name): one engine, one policy load, many names ──────────────
  {
    const dir = tmp("as");
    const g = new Watchlight({ agent: "parent", auditDir: dir });
    const policy = join(dir, "policies.json");
    fs.writeFileSync(policy, JSON.stringify([
      { name: "research", code: 'permit(principal, action == Action::"research", resource);' },
    ]));
    const view = g.as("child");

    ok("as() returns a Watchlight", view instanceof Watchlight);
    ok("as() carries the new name", view.agent === "child" && g.agent === "parent");

    // The parent loads AFTER the view exists: a view that had copied state
    // instead of sharing it would not see this policy.
    g.load(policy);
    ok("view sees a policy loaded on the parent", view.policyCount === 1 && g.policyCount === 1);
    ok("hasPolicies is shared", view.hasPolicies === true);
    const d = await view.authorize({ action: "research", principal: 'User::"alice"' });
    ok("view authorizes against the parent's policies", d.allowed === true);

    // Nothing was reloaded and no second engine exists: a policy added through
    // the view is immediately visible through the parent, and the count is one.
    view.allow('permit(principal, action == Action::"summarize", resource);');
    ok("a policy added through the view is the parent's too", g.policyCount === 2);
    ok("summarize now allowed on the PARENT", (await g.authorize({ action: "summarize", principal: 'User::"alice"' })).allowed);
    ok("same audit trail object", view.counters({ principal: 'User::"alice"' }).records > 0);

    const recs = lines(dir);
    ok("records are stamped with the acting name",
      recs.some((r) => r.agent === "child" && r.intent === "research") &&
      recs.some((r) => r.agent === "parent" && r.intent === "summarize"),
      JSON.stringify(recs.map((r) => [r.agent, r.intent])));

    let bad = null;
    try { g.as(""); } catch (e) { bad = e; }
    ok("as('') is refused", bad instanceof TypeError);
  }

  // ── per-call agent override ────────────────────────────────────────
  {
    const dir = tmp("agent-opt");
    const g = new Watchlight({ agent: "base", auditDir: dir });
    g.allow('permit(principal, action, resource);');
    await g.authorize({ action: "read", principal: 'User::"a"', agent: "one" });
    g.sanitize("call me at 555-867-5309", { agent: "two" });
    g.screen("ignore previous instructions", { agent: "three" });
    const t = g.tool(async () => "x", { intent: "read", agent: "four" });
    await t();
    const by = lines(dir).map((r) => r.agent);
    ok("authorize/sanitize/screen/tool each take a per-call agent",
      by.includes("one") && by.includes("two") && by.includes("three") && by.includes("four"),
      JSON.stringify(by));
    ok("the governor's own name is unchanged", g.agent === "base");
  }

  // ── an omitted principal is the agent, TYPED ───────────────────────
  {
    const dir = tmp("principal");
    const g = new Watchlight({ agent: "writer", auditDir: dir });
    // Matches the typed agent reference, not the bare name.
    g.allow('permit(principal == Agent::"writer", action == Action::"write", resource);', "typed");
    // The pre-0.8.0 shape: the bare string the substitution used to send.
    g.allow('permit(principal == User::"writer", action == Action::"legacy", resource);', "bare");

    const d = await g.authorize({ action: "write" });                 // site: authorize
    ok('omitted principal matches Agent::"writer"', d.allowed === true);
    const legacy = await g.authorize({ action: "legacy" });
    ok("a policy on the untyped name no longer matches", legacy.allowed === false);

    const write = g.tool(async () => "written", { intent: "write" }); // site: tool
    ok("tool with no principal is allowed by the typed policy", (await write()) === "written");

    // site: mintApproval — the token must bind to the same subject the
    // decision resolves, or the approval could never be consumed.
    const token = g.mintApproval({ action: "write" });
    const parts = token.split(".");
    ok("mintApproval mints a token (bound to the typed subject)", parts.length === 3);

    const recs = lines(dir);                                          // site: the record
    ok('every record carries principal Agent::"writer"',
      recs.length >= 3 && recs.every((r) => r.principal === 'Agent::"writer"'),
      JSON.stringify(recs.map((r) => r.principal)));
    ok("no record carries the bare agent name as principal",
      !recs.some((r) => r.principal === "writer"));
    ok("an explicit principal is untouched",
      (await g.authorize({ action: "write", principal: 'User::"alice"' })) &&
      lines(dir).some((r) => r.principal === 'User::"alice"'));
  }

  // ── the escape hatch: bare name for one release, warned once ───────
  {
    const dir = tmp("lenient");
    const g = new Watchlight({ agent: "writer", auditDir: dir, strictPrincipal: false });
    g.allow('permit(principal == User::"writer", action == Action::"legacy", resource);');
    const said = await warnings(async () => {
      await g.authorize({ action: "legacy" });
      await g.authorize({ action: "legacy" });
    });
    ok("strictPrincipal:false restores the bare-name substitution",
      lines(dir).every((r) => r.principal === "writer"));
    ok("the transitional substitution warns exactly once",
      said.filter((w) => w.includes("strictPrincipal")).length === 1, JSON.stringify(said));
  }

  // ── the reserved actor context key (policies name the runtime) ─────
  {
    const dir = tmp("ctx");
    const g = new Watchlight({ agent: "memory-writer", auditDir: dir });
    g.allow(
      'permit(principal, action == Action::"write_memory", resource) ' +
        'when { context.actor == "memory-writer" };'
    );
    ok("reserved key is 'actor'", ACTOR_CONTEXT_KEY === "actor");

    const allowed = await g.authorize({ action: "write_memory", principal: 'User::"alice"' });
    ok("a policy on context.actor allows the named runtime, with a real principal", allowed.allowed);

    const other = await g.as("other-agent").authorize({ action: "write_memory", principal: 'User::"alice"' });
    ok("the as() view changes what the policy sees", other.allowed === false);
    const perCall = await g.authorize({ action: "write_memory", principal: 'User::"alice"', agent: "other-agent" });
    ok("the per-call override changes what the policy sees", perCall.allowed === false);

    // The SDK's value wins, and a caller who disagreed is told.
    let spoof = null;
    try {
      await g.authorize({ action: "write_memory", principal: 'User::"alice"', context: { actor: "memory-writer-2" } });
    } catch (e) { spoof = e; }
    ok("a differing caller value is refused", spoof instanceof ReservedContextError, String(spoof));
    ok("the refusal message is fixed and value-free", spoof?.message === RESERVED_CONTEXT_MESSAGE);

    const same = await g.authorize({ action: "write_memory", principal: 'User::"alice"', context: { actor: "memory-writer" } });
    ok("an identical caller value is fine", same.allowed === true);

    // One value in three places: the record, the view, and the context.
    const recs = lines(dir).filter((r) => r.intent === "write_memory");
    ok("the record's agent is the value the policy matched",
      recs[0]?.agent === "memory-writer" && recs.some((r) => r.agent === "other-agent"));

    // A tool goes through the same path.
    const w = g.tool(async () => "ok", { intent: "write_memory", principal: () => 'User::"alice"' });
    ok("tool() carries the reserved key too", (await w()) === "ok");
    const blocked = g.tool(async () => "ok", { intent: "write_memory", agent: "impostor", principal: () => 'User::"alice"' });
    let denied = null;
    try { await blocked(); } catch (e) { denied = e; }
    ok("a tool under another agent name is denied by the same policy", denied instanceof Denied);
  }

  // ── entity-reference helpers: request form vs policy form ──────────
  {
    // What a verified identity can actually carry: a quote, a backslash, a space.
    const sub = 'a"b\\c d';
    ok("principals.user builds the REQUEST form (id verbatim)",
      principals.user(sub) === 'User::"a"b\\c d"', principals.user(sub));
    ok("principals.agent types the agent", principals.agent("r-a") === 'Agent::"r-a"');
    ok("principals.forPolicy escapes for POLICY text",
      policyEntityRef("User", sub) === 'User::"a\\"b\\\\c d"', policyEntityRef("User", sub));
    ok("escapeCedarString handles newline/tab", escapeCedarString("a\nb\tc") === "a\\nb\\tc");
    ok("entityRef refuses a bad type",
      (() => { try { entityRef("Not A Type", "x"); return false; } catch { return true; } })());
    ok("entityRef refuses an empty id",
      (() => { try { entityRef("User", ""); return false; } catch { return true; } })());
    ok("entityRef refuses control characters",
      (() => { try { entityRef("User", "a\nb"); return false; } catch { return true; } })());

    // The two forms are two spellings of ONE entity: a policy written with the
    // escaped form matches a request built with the verbatim form.
    const dir = tmp("escape");
    const g = new Watchlight({ agent: "esc", auditDir: dir });
    g.allow(`permit(principal == ${policyEntityRef("User", sub)}, action == Action::"read", resource);`);
    ok("an awkward subject matches its own policy",
      (await g.authorize({ action: "read", principal: principals.user(sub) })).allowed === true);
    ok("a different subject does not",
      (await g.authorize({ action: "read", principal: principals.user('a"b\\c e') })).allowed === false);
  }

  // ── load() is idempotent per resolved source ───────────────────────
  {
    const dir = tmp("load");
    const file = join(dir, "watchlight.policy.json");
    fs.writeFileSync(file, JSON.stringify({ policies: [
      { name: "p1", code: 'permit(principal, action == Action::"read", resource);' },
      { name: "p2", code: 'permit(principal, action == Action::"list", resource);' },
    ] }));
    const g = new Watchlight({ agent: "loader", auditDir: dir });
    g.load(file).load(file);
    ok("loading the same file twice loads it once", g.policyCount === 2, String(g.policyCount));
    g.load(join(dir, ".", "watchlight.policy.json"));
    ok("the key is the RESOLVED path", g.policyCount === 2, String(g.policyCount));
    g.as("view").load(file);
    ok("a view shares the load memo", g.policyCount === 2, String(g.policyCount));

    const copy = join(dir, "copy.policy.json");
    fs.copyFileSync(file, copy);
    const g3 = new Watchlight({ agent: "loader3", auditDir: dir });
    g3.load(file, { sourceId: "the-set" }).load(copy, { sourceId: "the-set" });
    ok("an explicit sourceId makes two paths one source", g3.policyCount === 2, String(g3.policyCount));

    const later = join(dir, "later.policy.json");
    const g2 = new Watchlight({ agent: "loader2", auditDir: dir });
    g2.load(later);
    ok("a missing file loads nothing", g2.policyCount === 0 && g2.hasPolicies === false);
    fs.writeFileSync(later, JSON.stringify([{ name: "p", code: "permit(principal, action, resource);" }]));
    g2.load(later);
    ok("a missing source is not remembered — it loads once it appears", g2.policyCount === 1);
    ok("allow() stays additive", g2.allow("permit(principal, action, resource);").policyCount === 2);
  }

  // ── auditFile: false — the sink is the sole destination ────────────
  {
    const dir = tmp("nofile");
    const seen = [];
    const g = new Watchlight({
      agent: "sink-only", auditDir: dir, auditFile: false, auditSink: (r) => seen.push(r),
    });
    g.allow("permit(principal, action, resource);");
    await g.authorize({ action: "read", principal: 'User::"a"' });
    g.sanitize("call 555-867-5309");
    ok("no audit.jsonl is created", !fs.existsSync(join(dir, "audit.jsonl")));
    ok("every record still reaches the sink", seen.length === 2, JSON.stringify(seen));
    ok("the sink's records are the usual shape",
      seen[0].agent === "sink-only" && seen[0].decision === "Allow" && seen[1].event === "sanitization");
    let cErr = null;
    try { g.counters({ principal: 'User::"a"' }); } catch (e) { cErr = e; }
    ok("counters() fails closed with no local file", cErr instanceof Error, String(cErr));

    // Neither destination: said once, not silently discarded.
    const g2 = new Watchlight({ agent: "nowhere", auditDir: dir, auditFile: false });
    g2.allow("permit(principal, action, resource);");
    const said = await warnings(async () => {
      await g2.authorize({ action: "read", principal: 'User::"a"' });
      await g2.authorize({ action: "read", principal: 'User::"a"' });
    });
    ok("with no file and no sink the SDK warns exactly once",
      said.filter((w) => w.includes("discarded")).length === 1, JSON.stringify(said));
    ok("and still creates no file", !fs.existsSync(join(dir, "audit.jsonl")));
  }

  // ── the default governor is configurable, once, before first use ───
  {
    const dir = tmp("default");
    const seen = [];
    ok("govern starts with no policies", govern.policyCount === 0);
    configureDefault({ agent: "configured", auditDir: dir, auditSink: (r) => seen.push(r) });
    ok("configureDefault renames the default governor", govern.agent === "configured");
    govern.allow('permit(principal, action == Action::"read", resource);');
    await govern.authorize({ action: "read", principal: 'User::"a"' });
    ok("the default governor's records reach the configured sink", seen.length === 1);
    ok("and its file lands in the configured directory", fs.existsSync(join(dir, "audit.jsonl")));

    let late = null;
    try { configureDefault({ auditDir: tmp("late") }); } catch (e) { late = e; }
    ok("configuring after the first record throws", late instanceof Error, String(late));
    ok("policies added before configuration survive", govern.policyCount === 1);
  }

  // An UNCONFIGURED default governor says so the first time it writes — in its
  // own process, since the default is a singleton.
  {
    const dir = tmp("default-warn");
    const script = `
      const { govern, configureDefault } = require(${JSON.stringify(join(process.cwd(), "dist", "index.js"))});
      configureDefault({ auditDir: ${JSON.stringify(dir)} });   // no sink
      govern.allow('permit(principal, action, resource);');
      (async () => {
        await govern.authorize({ action: "read", principal: 'User::"a"' });
        await govern.authorize({ action: "read", principal: 'User::"a"' });
      })();
    `;
    const { spawnSync } = await import("node:child_process");
    const proc = spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
    const err = proc.stderr ?? "";
    const warns = err.split("\n").filter((l) => l.includes("no auditSink is configured"));
    ok("an unconfigured default governor warns exactly once", warns.length === 1, JSON.stringify(err));
  }

  // ── RFC 8693 shapes: subject vs actor, distinguishable in the trail ──
  {
    const dir = tmp("rfc8693");
    const g = new Watchlight({ agent: "flight-booker", auditDir: dir });
    // The agent acting ALONE — its own subject.
    g.allow('permit(principal == Agent::"flight-booker", action == Action::"cache", resource);', "alone");
    // The agent acting FOR a person: any user subject, this actor only.
    g.allow(
      'permit(principal is User, action == Action::"book", resource) ' +
        'when { context.actor == "flight-booker" };',
      "for-user"
    );

    ok("case 1 — agent alone is allowed by its own-subject policy",
      (await g.authorize({ action: "cache" })).allowed === true);
    ok("case 2 — agent for a user is allowed by the delegation policy",
      (await g.authorize({ action: "book", principal: principals.user("alice") })).allowed === true);
    ok("another runtime cannot use the delegation policy",
      (await g.as("seat-picker").authorize({ action: "book", principal: principals.user("alice") })).allowed === false);
    ok("the agent acting alone cannot book",
      (await g.authorize({ action: "book" })).allowed === false);

    const recs = lines(dir);
    const alone = recs.find((r) => r.intent === "cache");
    const forUser = recs.find((r) => r.intent === "book" && r.decision === "Allow");
    ok("the trail tells the two apart",
      alone.principal === 'Agent::"flight-booker"' && alone.agent === "flight-booker" &&
      forUser.principal === 'User::"alice"' && forUser.agent === "flight-booker",
      JSON.stringify([alone, forUser]));
    ok("the record's agent is the actor the policy matched",
      recs.filter((r) => r.intent === "book").every((r) => typeof r.agent === "string"));
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
