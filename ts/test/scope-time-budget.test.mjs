// @watchlight/sdk — a sub-agent scope's time budget is granted exactly or
// refused, never shortened. A budget a child NAMES must fit in the whole seconds
// its parent has left (and in the parent's own budget); a larger one is refused
// with a TimeBudget violation whose reason states the seconds available. A child
// that names none inherits the parent's remaining whole seconds. An expired
// parent refuses.
// Cross-lane: tests/fixtures/scope-time-budget.json is shared with the Python
// suite, so both lanes decide every case identically. The wall clock is pinned.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, AttenuationDenied, ScopeTokenError } = require("../dist/index.js");
const { signScopeToken } = require("../dist/scope-token.js");

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(join(here, "..", "..", "tests", "fixtures", "scope-time-budget.json"), "utf8"));

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const caught = (fn) => { try { fn(); return null; } catch (e) { return e; } };
const caughtAsync = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };

const SECRET = "unit-test-secret-0123456789abcdef";
const tmp = () => fs.mkdtempSync(join(os.tmpdir(), "wl-sdk-budget-"));
const gov = (dir = tmp()) => new Watchlight({ agent: "test-agent", auditDir: dir, signingSecret: SECRET });

// A wall clock the test moves by hand (epoch seconds; Date.now is in ms).
const realNow = Date.now;
let clock = 1_800_000_000;
const pin = (seconds) => { clock = seconds; Date.now = () => Math.round(clock * 1000); };
const unpin = () => { Date.now = realNow; };

const attenuate = (scope, budget) =>
  budget === null ? scope.attenuate({ tools: ["t"] }) : scope.attenuate({ tools: ["t"], timeBudgetSeconds: budget });

async function main() {
  // ── the shared cases ──
  for (const c of fixture.cases) {
    pin(c.start);
    let scope = await gov().scope({ tools: ["t"], timeBudgetSeconds: c.root_budget });
    c.steps.forEach((step, i) => {
      pin(c.start + step.at);
      const name = `${c.name} — step ${i}`;
      if (step.expect === "granted") {
        const e = caught(() => { const child = attenuate(scope, step.time_budget_seconds); scope = child; });
        ok(name, !e && scope.timeBudgetSeconds === step.granted, e ? String(e) : String(scope.timeBudgetSeconds));
      } else if (step.expect === "refused") {
        const e = caught(() => attenuate(scope, step.time_budget_seconds));
        ok(
          name,
          e instanceof AttenuationDenied &&
            JSON.stringify(e.violations) === JSON.stringify(step.violations) &&
            e.reason === step.reason,
          e ? `${e.name}: ${e.reason ?? e.message}` : "did not throw"
        );
      } else {
        const e = caught(() => attenuate(scope, step.time_budget_seconds));
        ok(name, e instanceof ScopeTokenError && e.code === "expired", e ? `${e.name}: ${e.message}` : "did not throw");
      }
    });
  }

  // ── the reported probe: refused, never silently shortened ──
  pin(1_800_000_000);
  {
    const root = await gov().scope({ tools: ["t"], timeBudgetSeconds: 10 });
    pin(clock + 2.1);
    const e = caught(() => root.attenuate({ tools: ["t"], timeBudgetSeconds: 10 }));
    ok("the probe is refused with TimeBudget", e instanceof AttenuationDenied && e.violations.includes("TimeBudget"));
    ok("the reason states the seconds available", e && e.reason.includes("at most 7 seconds are available"), e?.reason);
    ok("the reason never echoes the requested value", e && !e.reason.includes("10"), e?.reason);
  }

  // ── remainingSeconds rounds down and never exceeds the budget ──
  pin(1_800_000_000);
  {
    const root = await gov().scope({ tools: ["t"], timeBudgetSeconds: 10 });
    const at = [];
    at.push(root.remainingSeconds());
    pin(clock + 7.1); at.push(root.remainingSeconds());
    pin(clock + 2.0); at.push(root.remainingSeconds());
    pin(clock + 5); at.push(root.remainingSeconds());
    ok("remainingSeconds: 10, then 2 (2.9 left), then 0, then 0", JSON.stringify(at) === "[10,2,0,0]", JSON.stringify(at));
  }

  // ── a refused budget is recorded as a deny; delegate and preview agree ──
  pin(1_800_000_000);
  {
    const dir = tmp();
    const g = gov(dir);
    const root = await g.scope({ tools: ["t"], timeBudgetSeconds: 10 });
    pin(clock + 2.1);
    caught(() => root.attenuate({ tools: ["t"], timeBudgetSeconds: 9, agent: "worker" }));
    const recs = fs.readFileSync(join(dir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
    const deny = recs.filter((r) => r.decision === "Deny");
    ok(
      "a refused budget is recorded as a deny with the fixed reason",
      deny.length === 1 &&
        deny[0].reason === "time_budget_seconds exceeds the parent's remaining time; at most 7 seconds are available" &&
        JSON.stringify(deny[0].actor_chain) === JSON.stringify(["test-agent", "worker"]),
      JSON.stringify(deny)
    );
    const d = caught(() => g.delegate(root, "worker", { tools: ["t"], timeBudgetSeconds: 8 }));
    ok("delegate refuses a budget the parent cannot give", d instanceof AttenuationDenied && d.violations.includes("TimeBudget"));
    const sub = g.delegate(root, "worker", { tools: ["t"] });
    ok("delegate without a budget inherits the remaining seconds", sub.delegatedScope.timeBudgetSeconds === 7, String(sub.delegatedScope?.timeBudgetSeconds));
    const refused = root.previewAttenuate({ tools: ["t"], timeBudgetSeconds: 8 });
    ok("a preview refuses the same budget", !refused.allowed && refused.violations.includes("TimeBudget"));
    const inherited = root.previewAttenuate({ tools: ["t"] });
    ok("a preview inherits the same seconds", inherited.allowed && inherited.timeBudgetSeconds === 7);
  }
  unpin();

  // ── root and child budget validation ──
  for (const bad of [0, -1, 2 ** 32, Number.MAX_SAFE_INTEGER]) {
    const e = await caughtAsync(() => gov().scope({ tools: ["t"], timeBudgetSeconds: bad }));
    ok(`an out-of-range root budget (${bad}) is refused`, e instanceof RangeError, String(e));
    const p = await caughtAsync(() => gov().previewScope({ tools: ["t"], timeBudgetSeconds: bad }));
    ok(`an out-of-range preview root budget (${bad}) is refused`, p instanceof RangeError, String(p));
  }
  for (const bad of [true, 1.5, "5", NaN, Infinity]) {
    const e = await caughtAsync(() => gov().scope({ tools: ["t"], timeBudgetSeconds: bad }));
    ok(`a root budget that is not an integer (${String(bad)}) is refused`, e instanceof TypeError, String(e));
  }
  {
    const root = await gov().scope({ tools: ["t"], timeBudgetSeconds: 600 });
    for (const bad of [0, -1, true, 1.5, "5", NaN, 2 ** 32]) {
      const e = caught(() => root.attenuate({ tools: ["t"], timeBudgetSeconds: bad }));
      ok(`an invalid child budget (${String(bad)}) is still refused`, e !== null, "granted");
    }
  }

  // ── scope tokens ──
  pin(1_800_000_000);
  {
    const g = gov();
    const token = (await g.scope({ tools: ["t"], timeBudgetSeconds: 600 }))
      .attenuate({ tools: ["t"], timeBudgetSeconds: 300 })
      .toToken({ ttlSeconds: 5 });
    const back = await g.scopeFromToken(token);
    pin(clock + 0.5);
    const e = caught(() => back.attenuate({ tools: ["t"], timeBudgetSeconds: 6 }));
    ok(
      "a scope rebuilt from a token gives no more than the token has left",
      back.timeBudgetSeconds === 300 &&
        e instanceof AttenuationDenied &&
        e.reason === "time_budget_seconds exceeds the parent's remaining time; at most 4 seconds are available",
      e ? e.reason ?? String(e) : "did not throw"
    );
    ok("a child of the rebuilt scope inherits what the token has left", back.attenuate({ tools: ["t"] }).timeBudgetSeconds === 4);
  }

  pin(1_800_000_000);
  {
    const g = gov();
    const root = await g.scope({ tools: ["t"], timeBudgetSeconds: 600 });
    pin(clock + 0.5);
    const child = root.attenuate({ tools: ["t"], timeBudgetSeconds: root.remainingSeconds() });
    const grandchild = child.attenuate({ tools: ["t"] });
    const token = grandchild.toToken();
    // Every read of the clock moves it on by 0.6 seconds.
    let moving = clock + 0.3;
    Date.now = () => { moving += 0.6; return Math.round(moving * 1000); };
    const e = await caughtAsync(async () => {
      const back = await g.scopeFromToken(token);
      if (back.depth !== 2 || back.timeBudgetSeconds !== grandchild.timeBudgetSeconds) throw new Error("mismatch");
    });
    ok("a token replay is not refused when the second ticks mid-replay", child.timeBudgetSeconds === 599 && e === null, String(e));
  }
  unpin();

  {
    const now = Math.floor(Date.now() / 1000);
    const widened = signScopeToken({
      agent: "test-agent",
      root: { tools: ["t"], resources: [], intents: [], max_depth: 5, time_budget_seconds: 100 },
      chain: [{ tools: ["t"], resources: [], intents: [], time_budget_seconds: 200 }],
      depth: 1, iat: now, exp: now + 150,
    }, Buffer.from(SECRET));
    const e = await caughtAsync(() => gov().scopeFromToken(widened));
    ok("a signed chain that names more time than its parent is refused", e instanceof AttenuationDenied && e.violations.includes("TimeBudget"), String(e));
    for (const rootBudget of [0, 2 ** 32]) {
      const t = signScopeToken({
        agent: "test-agent",
        root: { tools: ["t"], resources: [], intents: [], max_depth: 5, time_budget_seconds: rootBudget },
        chain: [{ tools: ["t"], resources: [], intents: [], time_budget_seconds: 60 }],
        depth: 1, iat: now, exp: now + 60,
      }, Buffer.from(SECRET));
      const m = await caughtAsync(() => gov().scopeFromToken(t));
      ok(`a signed root budget out of range (${rootBudget}) is malformed`, m instanceof ScopeTokenError && m.code === "malformed", String(m));
    }
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { unpin(); console.error(e); process.exit(1); });
