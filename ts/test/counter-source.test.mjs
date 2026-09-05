// @watchlight/sdk counterSource test — the read-side counterpart of auditSink.
//
// `counters()` folds the local audit file, which is per-container and does not
// survive a deploy. A `counterSource` folds the durable store the sink writes to
// instead, so a quota spans every replica. This asserts: no source → unchanged
// local behaviour; a source → its number, with the SAME validated query; an
// async source is refused by the synchronous path by NAME rather than answered
// with a local count; and every source failure fails the read closed.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, CounterSourceError, AuditTrailUnreadable } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const throws = (fn, Type) => {
  try { fn(); return null; } catch (e) { return e instanceof Type ? e : null; }
};
const rejects = async (p, Type) => {
  try { await p; return null; } catch (e) { return e instanceof Type ? e : null; }
};

const READ = 'permit(principal, action == Action::"read", resource);';
const USER = 'User::"u1"';

const gov = (opts = {}) => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-csrc-"));
  const g = new Watchlight({ agent: "csrc-agent", auditDir, ...opts });
  g.allow(READ, "read");
  return { g, auditDir };
};

/** Three decisions on the local trail, so "local" and "external" differ. */
const seedLocal = async (g) => {
  for (let i = 0; i < 3; i++) await g.authorize({ action: "read", principal: USER, resource: "doc/1" });
};

async function main() {
  console.log("no source configured — unchanged");
  {
    const { g } = gov();
    await seedLocal(g);
    const c = g.counters({ principal: USER, intent: "read", window: "1h" });
    ok("counters() still folds the local file", c.count === 3);
    ok("the result says where the number came from", c.source === "local");
    ok("the local scan still reports what it read", c.records === 3 && c.skipped === 0 && c.truncated === false);
    const a = await g.countersAsync({ principal: USER, intent: "read", window: "1h" });
    ok("countersAsync() reads the same local file, so it can be used unconditionally",
      a.count === 3 && a.source === "local");
  }

  console.log("a synchronous source");
  {
    const seen = [];
    const { g } = gov({ counterSource: (q) => { seen.push(q); return 42; } });
    await seedLocal(g);
    const c = g.counters({ principal: USER, intent: "read", resource: "doc/1", window: "15m", outcome: "all" });
    ok("the source's count is used, not the local file's", c.count === 42);
    ok("the result is marked external", c.source === "external");
    ok("`records` / `skipped` describe the local scan that did not happen",
      c.records === 0 && c.skipped === 0 && c.truncated === false);
    const q = seen[0];
    ok("the source gets the resolved query: principal, intent, resource, outcome",
      q.principal === USER && q.intent === "read" && q.resource === "doc/1" && q.outcome === "all");
    ok("…and the resolved window, start exclusive / end inclusive",
      q.window.seconds === 900 &&
      typeof q.window.start === "string" && typeof q.window.end === "string" &&
      Date.parse(q.window.end) - Date.parse(q.window.start) === 900_000);
    ok("the echoed filter matches the query the source answered",
      c.principal === USER && c.intent === "read" && c.resource === "doc/1");
  }
  {
    const seen = [];
    const { g } = gov({ counterSource: (q) => { seen.push(q); return 0; } });
    const c = g.counters({ principal: USER });
    ok("an unfiltered query omits intent / resource rather than sending undefined",
      !("intent" in seen[0]) && !("resource" in seen[0]) && c.count === 0);
    ok("the window and outcome defaults are applied before the source sees them",
      seen[0].window.seconds === 3600 && seen[0].outcome === "allowed");
  }
  {
    // The source drives a real quota, exactly as the local file does.
    const { g } = gov({
      counterSource: () => 100,
      // no local records at all — the quota comes entirely from the store
    });
    g.allow('forbid(principal, action == Action::"read", resource) when { context.reads_this_hour >= 100 };', "cap");
    const c = g.counters({ principal: USER, intent: "read" });
    const d = await g.authorize({
      action: "read", principal: USER, resource: "doc/1", context: { reads_this_hour: c.count },
    });
    ok("a quota policy denies on the durable store's count", d.decision === "Deny");
  }

  console.log("an asynchronous source");
  {
    const { g } = gov({ counterSource: async () => 7 });
    const err = throws(() => g.counters({ principal: USER }), CounterSourceError);
    ok("the synchronous path REFUSES rather than returning a local count", err !== null);
    ok("…and says which method to use", err && err.message.includes("countersAsync"));
    const c = await g.countersAsync({ principal: USER });
    ok("countersAsync() reads it", c.count === 7 && c.source === "external");
  }
  {
    // Refusing an async source must not leave an unhandled rejection behind.
    const { g } = gov({ counterSource: () => Promise.reject(new Error("late")) });
    throws(() => g.counters({ principal: USER }), CounterSourceError);
    let unhandled = null;
    process.once("unhandledRejection", (e) => { unhandled = e; });
    await new Promise((r) => setTimeout(r, 20));
    ok("the refused promise is not left unhandled", unhandled === null);
  }

  console.log("fail closed");
  {
    const { g } = gov({ counterSource: () => { throw new Error("store down"); } });
    await seedLocal(g);
    const err = throws(() => g.counters({ principal: USER }), CounterSourceError);
    ok("a throwing source raises CounterSourceError", err !== null);
    ok("it never falls back to the local file", err !== null && !("count" in (err ?? {})));
    ok("the message is fixed and value-free", err && !err.message.includes("store down"));
    ok("the source's own error is on `cause`", err && err.cause instanceof Error && err.cause.message === "store down");
  }
  {
    const { g } = gov({ counterSource: async () => { throw new Error("store down"); } });
    const err = await rejects(g.countersAsync({ principal: USER }), CounterSourceError);
    ok("a rejecting async source raises CounterSourceError too", err !== null);
  }
  for (const [name, value] of [
    ["a negative count", -1],
    ["a fraction", 1.5],
    ["NaN", NaN],
    ["Infinity", Infinity],
    ["a string", "12"],
    ["null", null],
    ["undefined", undefined],
    ["an object", { count: 12 }],
    ["past Number.MAX_SAFE_INTEGER", Number.MAX_SAFE_INTEGER + 1],
    ["2^63", 2 ** 63],
  ]) {
    const { g } = gov({ counterSource: () => value });
    ok(`${name} from a source is refused`, throws(() => g.counters({ principal: USER }), CounterSourceError) !== null);
  }
  {
    // The largest accepted count — the same bound the Python lane applies, so an
    // integer one lane would carry cannot sail past the source and fail later
    // inside the engine.
    const { g } = gov({ counterSource: () => Number.MAX_SAFE_INTEGER });
    ok("Number.MAX_SAFE_INTEGER is accepted",
      g.counters({ principal: USER }).count === Number.MAX_SAFE_INTEGER);
  }
  {
    // Option validation happens BEFORE the source is called — a source can never
    // be asked a question the local scan would have rejected.
    let called = 0;
    const { g } = gov({ counterSource: () => { called++; return 1; } });
    ok("an empty principal is still a TypeError", throws(() => g.counters({ principal: "" }), TypeError) !== null);
    ok("a bad window is still a RangeError",
      throws(() => g.counters({ principal: USER, window: "nope" }), RangeError) !== null);
    ok("a bad outcome is still a RangeError",
      throws(() => g.counters({ principal: USER, outcome: "some" }), RangeError) !== null);
    ok("the source is never called for an invalid query", called === 0);
  }
  {
    // With a source configured, an unreadable local file is irrelevant.
    const { g, auditDir } = gov({ counterSource: () => 5 });
    fs.rmSync(join(auditDir, "audit.jsonl"), { force: true });
    fs.mkdirSync(join(auditDir, "audit.jsonl"));
    const c = g.counters({ principal: USER });
    ok("an unreadable local file does not affect a sourced count", c.count === 5);
    const { g: g2, auditDir: dir2 } = gov();
    fs.mkdirSync(join(dir2, "audit.jsonl"));
    ok("…while without a source it still raises AuditTrailUnreadable",
      throws(() => g2.counters({ principal: USER }), AuditTrailUnreadable) !== null);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
