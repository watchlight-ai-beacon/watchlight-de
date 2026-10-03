// @watchlight/sdk counters test — `govern.counters` / `countAuditRecords` fold
// the local audit trail into quota context. Runs the shared fixture at
// tests/fixtures/audit-trail.jsonl (the Python suite asserts the SAME numbers),
// then a live governor with the real @watchlight/engine core.
import { createRequire } from "node:module";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const {
  Watchlight, countAuditRecords, parseWindowSeconds, AuditTrailUnreadable,
  DEFAULT_COUNTERS_MAX_BYTES, MAX_COUNTERS_WINDOW_SECONDS, MAX_COUNTERS_LINE_BYTES, MAX_COUNTERS_NESTING,
  MAX_NAME_BYTES, SanitizeError, ScreenError,
  MAX_AGENT_NAME_BYTES, MAX_SCOPE_ENTRIES, MAX_SCOPE_LIST_BYTES, MAX_ACTOR_CHAIN_BYTES,
  findUnreadableLines, UNREADABLE_REASONS, principals,
  MAX_AUDIT_RECORD_BYTES, governedHooks, DENY_REASON, REFUSED_NAME,
} = require("../dist/index.js");
const { AuditTrail } = require("../dist/audit.js");
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const eq = (name, actual, expected) =>
  ok(name, JSON.stringify(actual) === JSON.stringify(expected), `got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`);
const throws = (name, fn, ctor) => {
  try { fn(); ok(name, false, "did not throw"); }
  catch (e) { ok(name, e instanceof ctor, `threw ${e?.name}: ${e?.message}`); }
};

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "..", "..", "tests", "fixtures", "audit-trail.jsonl");
const NOW = "2026-01-15T12:00:00.000Z";
const ALICE = 'User::"alice"';
const at = (opts) => countAuditRecords(FIXTURE, { principal: ALICE, now: NOW, ...opts });
// The matching well-formed decisions: `count` without the lines counted
// fail-closed because they could not be read.
const wf = (r) => r.count - r.unreadable;
// The fixture holds three lines that cannot be read at all ("not json at all",
// "[1,2,3]", "42"), which count toward EVERY query, and one decision whose `ts`
// cannot be read (alice, read, doc/1, Allow), which counts toward every query it
// matches whatever the window. Same numbers as the Python suite.
const FIXTURE_UNREADABLE_LINES = 3;
const expectedUnreadable = (o) =>
  FIXTURE_UNREADABLE_LINES +
  ((o.principal ?? ALICE) === ALICE &&
  [undefined, "read"].includes(o.intent) &&
  [undefined, "doc/1"].includes(o.resource) &&
  ["allowed", "all"].includes(o.outcome ?? "allowed")
    ? 1
    : 0);
// Asserts the well-formed count AND that the fail-closed part is exactly the
// fixture's unreadable lines, so `count` is their sum.
const counted = (name, opts, want) => {
  const r = countAuditRecords(FIXTURE, { principal: ALICE, now: NOW, ...opts });
  eq(name, [wf(r), r.unreadable, r.count], [want, expectedUnreadable(opts), want + expectedUnreadable(opts)]);
};

console.log("window grammar");
eq("15m", parseWindowSeconds("15m"), 900);
eq("1h", parseWindowSeconds("1h"), 3600);
eq("24h", parseWindowSeconds("24h"), 86400);
eq("7d", parseWindowSeconds("7d"), 604800);
eq("bare digits are seconds", parseWindowSeconds("90"), 90);
eq("number is seconds", parseWindowSeconds(3600), 3600);
eq("366d is the ceiling", parseWindowSeconds("366d"), MAX_COUNTERS_WINDOW_SECONDS);
for (const bad of ["0", "0h", "-1h", "1w", "", "1.5h", "1h ", " 1h", "1H", 0, -5, 1.5, NaN, Infinity, "367d", null, undefined, {}]) {
  throws(`rejects ${JSON.stringify(bad) ?? String(bad)}`, () => parseWindowSeconds(bad), RangeError);
}

console.log("fixture: counting semantics (shared with Python)");
const base = at({ intent: "read", window: "1h" });
eq("alice read allowed 1h", wf(base), 6);
eq("fail-closed: the unreadable lines count", [base.unreadable, base.count], [4, 10]);
eq("window bounds", base.window, { seconds: 3600, start: "2026-01-15T11:00:00.000Z", end: NOW });
eq("filter echoed", [base.principal, base.intent, base.resource, base.outcome], [ALICE, "read", undefined, "allowed"]);
eq("well-formed records of every kind", base.records, 19);
eq("lines that are not well-formed records are skipped", base.skipped, 6);
eq("not truncated", base.truncated, false);
counted("alice read denied 1h (Deny only here)", { intent: "read", window: "1h", outcome: "denied" }, 1);
counted("alice read all 1h", { intent: "read", window: "1h", outcome: "all" }, 7);
counted("alice any intent allowed (incl. write + approved wire)", { window: "1h" }, 8);
counted("alice any intent denied = Deny + NeedsApproval hold", { window: "1h", outcome: "denied" }, 2);
counted("allowed + denied == all", { window: "1h", outcome: "all" }, 10);
counted("resource narrows (exact)", { intent: "read", resource: "doc/1", window: "1h" }, 4);
counted("resource prefix does not match", { intent: "read", resource: "doc", window: "1h" }, 0);
counted("bob", { principal: 'User::"bob"', intent: "read" }, 1);
counted("carol denied", { principal: 'User::"carol"', intent: "read", outcome: "denied" }, 1);
counted("carol allowed", { principal: 'User::"carol"', intent: "read" }, 0);
counted("unknown principal", { principal: 'User::"dave"' }, 0);
counted("principal is exact (no substring)", { principal: "alice" }, 0);
counted("15m window", { intent: "read", window: "15m" }, 3);
counted("24h window includes the start-boundary and older records", { intent: "read", window: "24h" }, 8);
counted("window as number of seconds", { intent: "read", window: 3600 }, 6);
counted("window as digit string", { intent: "read", window: "3600" }, 6);
counted("default window is 1h", { intent: "read" }, 6);
counted("now as Date", { principal: ALICE, intent: "read", now: new Date(NOW) }, 6);
counted("now as epoch ms", { principal: ALICE, intent: "read", now: Date.parse(NOW) }, 6);
counted("now with an offset zone", { intent: "read", now: "2026-01-15T14:00:00.000+02:00" }, 6);
counted("earlier now shifts the window", { intent: "read", now: "2026-01-15T11:30:00.000Z" }, 5);
throws("now: invalid Date", () => at({ now: new Date(NaN) }), RangeError);
throws("now: naive timestamp", () => at({ now: "2026-01-15T12:00:00" }), RangeError);
throws("now: garbage", () => at({ now: "yesterday" }), RangeError);
throws("outcome: unknown", () => at({ outcome: "any" }), RangeError);
throws("principal: required", () => countAuditRecords(FIXTURE, { now: NOW }), TypeError);
throws("principal: empty", () => countAuditRecords(FIXTURE, { principal: "", now: NOW }), TypeError);
throws("intent: non-string", () => at({ intent: 5 }), TypeError);
throws("maxBytes: zero", () => at({ maxBytes: 0 }), RangeError);

console.log("value-free");
{
  const logs = [];
  const origLog = console.log, origWarn = console.warn, origErr = console.error;
  console.log = console.warn = console.error = (...a) => logs.push(a.join(" "));
  let r;
  try { r = at({ intent: "read" }); } finally { console.log = origLog; console.warn = origWarn; console.error = origErr; }
  ok("nothing is logged", logs.length === 0, JSON.stringify(logs));
  const s = JSON.stringify(r);
  ok("no record content in the result", !s.includes("not json") && !s.includes("doc/") && !s.includes("d1"), s);
  ok("timestamps in the result are only the window bounds", !s.includes("11:05"), s);
}

console.log("bounded read");
{
  const size = fs.statSync(FIXTURE).size;
  const firstLine = fs.readFileSync(FIXTURE, "utf8").split("\n")[0].length + 1;
  eq("maxBytes >= size is a full scan", at({ intent: "read", maxBytes: size }), base);
  eq("default maxBytes is 64 MiB", DEFAULT_COUNTERS_MAX_BYTES, 64 * 1024 * 1024);
  const cut = at({ intent: "read", maxBytes: size - 10 });
  // The partial first line the cut lands in is dropped, never counted as unreadable.
  eq("cut inside line 1 drops it silently", [wf(cut), cut.unreadable, cut.records, cut.skipped, cut.truncated], [5, 4, 18, 6, true]);
  const edge = at({ intent: "read", maxBytes: size - firstLine });
  eq("cut exactly on a line boundary keeps line 2 whole", [wf(edge), edge.unreadable, edge.records, edge.skipped, edge.truncated], [5, 4, 18, 6, true]);
  const one = at({ intent: "read", maxBytes: size - 1 });
  eq("cut after the first byte", [wf(one), one.records, one.truncated], [5, 18, true]);
  const tiny = at({ intent: "read", maxBytes: 5 });
  eq("a tail shorter than a line counts nothing", [tiny.count, tiny.records, tiny.skipped, tiny.unreadable, tiny.truncated], [0, 0, 0, 0, true]);
}

console.log("multi-chunk stream");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const p = join(dir, "audit.jsonl");
  const line = JSON.stringify({ ts: "2026-01-15T11:59:00.000Z", agent: "a", principal: ALICE, intent: "read", resource: "doc/x".padEnd(120, "x"), decision: "Allow" });
  const N = 3000; // ~600 KiB → many 64 KiB chunks, lines split across them
  fs.writeFileSync(p, Array(N).fill(line).join("\n") + "\n");
  const r = countAuditRecords(p, { principal: ALICE, intent: "read", now: NOW });
  eq("every line across chunk boundaries counted", [r.count, r.records, r.skipped, r.truncated], [N, N, 0, false]);
  fs.writeFileSync(p, Array(N).fill(line).join("\n")); // no trailing newline
  eq("final line without newline counted", countAuditRecords(p, { principal: ALICE, now: NOW }).count, N);
  fs.writeFileSync(p, "\n\n   \n");
  eq("blank lines are neither records nor skipped", [countAuditRecords(p, { principal: ALICE, now: NOW }).records, countAuditRecords(p, { principal: ALICE, now: NOW }).skipped], [0, 0]);
  fs.writeFileSync(p, Buffer.concat([Buffer.from('{"ts":"2026-01-15T11:59:00.000Z","principal":"'), Buffer.from([0xff, 0xfe]), Buffer.from('","decision":"Allow"}\n')]));
  const bad = countAuditRecords(p, { principal: ALICE, now: NOW });
  eq("invalid UTF-8 is unreadable and counts, fail-closed", [bad.count, bad.skipped, bad.unreadable], [1, 1, 1]);
}

console.log("hostile lines are bounded");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const p = join(dir, "audit.jsonl");
  const rec = (extra = "") => `{"ts":"2026-01-15T11:59:00.000Z","agent":"a","principal":${JSON.stringify(ALICE)},"intent":"read","resource":"doc/1","decision":"Allow"${extra}}`;
  const opts = { principal: ALICE, intent: "read", now: NOW };
  fs.writeFileSync(p, "\uFEFF" + rec() + "\n" + rec() + "\n");
  eq("a BOM-prefixed line cannot be parsed: it counts, fail-closed", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 1]);
  eq("line cap is 1 MiB, nesting cap is 32", [MAX_COUNTERS_LINE_BYTES, MAX_COUNTERS_NESTING], [1024 * 1024, 32]);
  fs.writeFileSync(p, rec(`,"pad":"${"p".repeat(900 * 1024)}"`) + "\n" + rec() + "\n");
  eq("a large but legitimate record still counts", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 0]);
  fs.writeFileSync(p, "x".repeat(MAX_COUNTERS_LINE_BYTES + 1) + "\n" + rec() + "\n" + rec() + "\n");
  eq("an over-cap line is unreadable once, counted, and the rest still counts", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [3, 1]);
  const deep = (d) => "[".repeat(d) + "]".repeat(d);
  fs.writeFileSync(p, rec(`,"x":${deep(5)}`) + "\n" + rec(`,"x":${deep(MAX_COUNTERS_NESTING + 1)}`) + "\n" + rec(`,"x":"${"[".repeat(200)}"`) + "\n");
  eq("nesting past the cap is unreadable and counted; brackets inside strings are not nesting", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [3, 1]);
  fs.writeFileSync(p, "{".repeat(100_000) + "\n" + rec() + "\n");
  eq("100k-deep line is unreadable without parsing", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 1]);
  // A newline-free tail as large as the whole scan bound: must finish quickly
  // and hold at most the line cap in memory.
  const big = 24 * 1024 * 1024;
  fs.writeFileSync(p, Buffer.alloc(big, 0x78));
  const before = process.memoryUsage().rss;
  const t0 = Date.now();
  const r = countAuditRecords(p, { ...opts, maxBytes: big });
  const ms = Date.now() - t0;
  eq("newline-free 24 MiB tail: one unreadable line, counted once", [r.count, r.records, r.skipped, r.unreadable, r.truncated], [1, 0, 1, 1, false]);
  ok("newline-free tail finishes fast", ms < 5000, `${ms}ms`);
  ok("newline-free tail does not buffer the tail", process.memoryUsage().rss - before < 16 * 1024 * 1024, `${process.memoryUsage().rss - before} bytes`);
}

console.log("fail-closed: a line that cannot be read never lowers a count");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const p = join(dir, "audit.jsonl");
  const rec = (extra = "") => `{"ts":"2026-01-15T11:59:00.000Z","agent":"a","principal":${JSON.stringify(ALICE)},"intent":"read","resource":"doc/1","decision":"Allow"${extra}}`;
  // Three Allows whose lines exceed the line limit count as three, for any
  // principal: a quota cannot be under-counted by records too long to read.
  const huge = rec(`,"pad":"${"r".repeat(MAX_COUNTERS_LINE_BYTES + 10)}"`);
  fs.writeFileSync(p, [huge, huge, huge].join("\n") + "\n");
  for (const principal of [ALICE, 'User::"someone-else"']) {
    for (const outcome of ["allowed", "denied", "all"]) {
      const r = countAuditRecords(p, { principal, intent: "read", outcome, now: NOW });
      eq(`over-limit Allows count (${principal}, ${outcome})`, [r.count, r.unreadable, r.skipped, r.records], [3, 3, 3, 0]);
    }
  }
  fs.writeFileSync(p, rec() + "\n" + huge + "\n" + rec() + "\n");
  const mixed = countAuditRecords(p, { principal: ALICE, intent: "read", now: NOW });
  eq("mixed with well-formed records, the two add up", [mixed.count, mixed.unreadable, mixed.records], [3, 1, 2]);
  fs.writeFileSync(p, rec() + "\n" + huge);
  eq("an over-limit last line without a newline counts too", countAuditRecords(p, { principal: ALICE, intent: "read", now: NOW }).count, 2);

  fs.writeFileSync(p, '{"ts":"2026-01-15T11:59:00.000Z","decision":"Allow"\n[1]\n7\nnull\n');
  const junk = countAuditRecords(p, { principal: 'User::"anyone"', intent: "anything", outcome: "denied", now: NOW });
  eq("unparseable lines count toward every query", [junk.count, junk.unreadable, junk.skipped], [4, 4, 4]);

  fs.writeFileSync(p, rec().replace("2026-01-15T11:59:00.000Z", "yesterday") + "\n");
  const badTs = countAuditRecords(p, { principal: ALICE, intent: "read", window: "15m", now: NOW });
  eq("a matching decision with an unreadable time counts", [badTs.count, badTs.unreadable, badTs.records, badTs.skipped], [1, 1, 0, 1]);
  eq("... not for another principal", countAuditRecords(p, { principal: 'User::"bob"', now: NOW }).count, 0);
  eq("... not for another intent", countAuditRecords(p, { principal: ALICE, intent: "write", now: NOW }).count, 0);
  const deniedBadTs = countAuditRecords(p, { principal: ALICE, outcome: "denied", now: NOW });
  eq("... not for another outcome", [deniedBadTs.count, deniedBadTs.unreadable, deniedBadTs.skipped], [0, 0, 1]);

  // A JSON object with no string `decision` (a framework run's lifecycle line,
  // say) is readable and is not a decision: skipped, never counted.
  fs.writeFileSync(p,
    JSON.stringify({ ts: "2026-01-15T11:59:00.000Z", event_type: "execution_started", principal: ALICE, execution_id: "e1" }) + "\n" +
    JSON.stringify({ ts: "2026-01-15T11:59:00.000Z", principal: ALICE, decision: true }) + "\n");
  for (const outcome of ["allowed", "denied", "all"]) {
    const r = countAuditRecords(p, { principal: ALICE, outcome, now: NOW });
    eq(`a well-formed non-decision never counts (${outcome})`, [r.count, r.unreadable, r.skipped], [0, 0, 2]);
  }

  throws("a filter intent longer than any name is refused", () => at({ intent: "i".repeat(MAX_NAME_BYTES + 1) }), TypeError);
  throws("a filter resource longer than any name is refused", () => at({ resource: "r".repeat(MAX_NAME_BYTES + 1) }), TypeError);
  throws("a principal longer than any name is refused", () => countAuditRecords(FIXTURE, { principal: "p".repeat(MAX_NAME_BYTES + 1), now: NOW }), TypeError);
  eq("a filter at the bound is accepted", at({ intent: "i".repeat(MAX_NAME_BYTES) }).count, FIXTURE_UNREADABLE_LINES);
}

console.log("names are bounded (shared with Python)");
{
  const OVER = "x".repeat(MAX_NAME_BYTES + 1);
  const AT_LIMIT = "x".repeat(MAX_NAME_BYTES);
  eq("the bounds (shared with Python)", [MAX_NAME_BYTES, MAX_AGENT_NAME_BYTES, MAX_SCOPE_ENTRIES, MAX_SCOPE_LIST_BYTES, MAX_ACTOR_CHAIN_BYTES], [4096, 4087, 256, 65536, 65536]);
  const fresh = (agent = "bounded") => {
    const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-names-"));
    const g = new Watchlight({ agent, auditDir });
    g.allow("permit(principal, action, resource);", "all");
    return { g, auditDir };
  };
  const lines = (auditDir) => {
    const f = join(auditDir, "audit.jsonl");
    return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean) : [];
  };
  const rejects = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };
  const quiet = async (fn) => {
    const orig = console.log;
    console.log = () => {};
    try { return await fn(); } finally { console.log = orig; }
  };

  for (const [label, req, field] of [
    ["action", { action: OVER }, "action"],
    ["resource", { action: "read", resource: OVER }, "resource"],
    ["principal", { action: "read", principal: `User::"${OVER}"` }, "principal"],
  ]) {
    const { g, auditDir } = fresh();
    const e = await quiet(() => rejects(() => g.authorize(req)));
    eq(`authorize refuses an oversized ${label}, value-free`, [e?.name, e?.message], ["TypeError", `${field} is longer than the maximum of ${MAX_NAME_BYTES} bytes`]);
    eq(`... and writes no record (${label})`, lines(auditDir).length, 0);
  }

  {
    const { g, auditDir } = fresh();
    const e2 = "é"; // two bytes of UTF-8
    const e4 = "\u{1F600}"; // four bytes of UTF-8 (two UTF-16 code units)
    await quiet(async () => {
      eq("the bound is UTF-8 bytes: 2-byte chars at the bound", (await g.authorize({ action: "read", resource: e2.repeat(MAX_NAME_BYTES / 2) })).allowed, true);
      eq("... one over", (await rejects(() => g.authorize({ action: "read", resource: e2.repeat(MAX_NAME_BYTES / 2 + 1) })))?.name, "TypeError");
      eq("... 4-byte chars at the bound", (await g.authorize({ action: "read", resource: e4.repeat(MAX_NAME_BYTES / 4) })).allowed, true);
      eq("... one byte over", (await rejects(() => g.authorize({ action: "read", resource: e4.repeat(MAX_NAME_BYTES / 4) + "x" })))?.name, "TypeError");
    });
    eq("only the two in-bound decisions were recorded", lines(auditDir).length, 2);
  }

  {
    const { g, auditDir } = fresh();
    await quiet(async () => {
      for (let i = 0; i < 3; i++) await g.authorize({ action: "read", principal: ALICE, resource: AT_LIMIT });
    });
    eq("a name at the bound is recorded verbatim", lines(auditDir).map((l) => JSON.parse(l).resource), [AT_LIMIT, AT_LIMIT, AT_LIMIT]);
    const c = g.counters({ principal: ALICE, intent: "read", resource: AT_LIMIT });
    eq("... and counted", [c.count, c.unreadable, c.skipped], [3, 0, 0]);
  }

  {
    const { g, auditDir } = fresh();
    const ran = [];
    const fetchIt = g.tool(async (name) => { ran.push(name); return "ok"; }, { intent: "read", resource: (name) => name });
    const other = g.tool(async () => { ran.push("other"); }, { intent: OVER });
    const third = g.tool(async () => { ran.push("third"); }, { intent: "read", principal: () => `User::"${OVER}"` });
    const errs = await quiet(async () => [await rejects(() => fetchIt(OVER)), await rejects(() => other()), await rejects(() => third())]);
    eq("a governed tool with an oversized name is refused", errs.map((e) => e?.name), ["TypeError", "TypeError", "TypeError"]);
    eq("... its body never runs and nothing is recorded", [ran, lines(auditDir).length], [[], 0]);
  }

  {
    const { g, auditDir } = fresh();
    throws("an oversized agent name is refused at construction", () => new Watchlight({ agent: OVER, auditDir }), TypeError);
    throws("... by as()", () => g.as(OVER), TypeError);
    eq("... by authorize({ agent })", (await rejects(() => g.authorize({ action: "read", agent: OVER })))?.name, "TypeError");
    throws("... by delegate()", () => g.delegate(g, OVER), TypeError);
    const atAgentLimit = "a".repeat(MAX_AGENT_NAME_BYTES);
    eq("an agent name at its bound is accepted", new Watchlight({ agent: atAgentLimit, auditDir }).agent, atAgentLimit);
    throws("... one byte over is refused", () => new Watchlight({ agent: atAgentLimit + "a", auditDir }), TypeError);
    const prev = process.env.WATCHLIGHT_AGENT;
    process.env.WATCHLIGHT_AGENT = OVER;
    try { throws("... from the environment", () => new Watchlight({ auditDir }), TypeError); }
    finally { if (prev === undefined) delete process.env.WATCHLIGHT_AGENT; else process.env.WATCHLIGHT_AGENT = prev; }
    eq("no record written by any of them", lines(auditDir).length, 0);
  }

  {
    const { g, auditDir } = fresh();
    throws("sanitize refuses an oversized intent", () => g.sanitize("mail a@example.com", { intent: OVER }), SanitizeError);
    throws("sanitize refuses an oversized resource", () => g.sanitize("mail a@example.com", { resource: OVER }), SanitizeError);
    throws("screen refuses an oversized intent", () => g.screen("hello", { intent: OVER }), ScreenError);
    throws("screen refuses an oversized resource", () => g.screen("hello", { resource: OVER }), ScreenError);
    eq("... before any record", lines(auditDir).length, 0);
  }

  {
    // The end-to-end shape of the hardening: Allows cannot slip past a quota by
    // making their records too long to count.
    const { g, auditDir } = fresh();
    await quiet(async () => {
      for (let i = 0; i < 3; i++) await rejects(() => g.authorize({ action: "read", principal: ALICE, resource: "r".repeat(MAX_COUNTERS_LINE_BYTES + 1) }));
    });
    eq("oversized requests were refused, so nothing was allowed", g.counters({ principal: ALICE, intent: "read" }).count, 0);
    await quiet(async () => {
      for (let i = 0; i < 2; i++) await g.authorize({ action: "read", principal: ALICE, resource: "doc/1" });
    });
    fs.appendFileSync(join(auditDir, "audit.jsonl"), JSON.stringify({ ts: "2026-01-15T11:59:00.000Z", principal: ALICE, intent: "read", resource: "r".repeat(MAX_COUNTERS_LINE_BYTES), decision: "Allow" }) + "\n");
    const c = g.counters({ principal: ALICE, intent: "read" });
    eq("an over-limit line in the trail counts toward the quota", [c.count, c.unreadable], [3, 1]);
  }
}

console.log("every write path is bounded (shared with Python)");
{
  const OVER = "x".repeat(MAX_NAME_BYTES + 1);
  const SECRET = "k".repeat(48);
  const dirOf = () => fs.mkdtempSync(join(os.tmpdir(), "wl-bounds-"));
  const trailLines = (auditDir) => {
    const f = join(auditDir, "audit.jsonl");
    return fs.existsSync(f) ? fs.readFileSync(f).toString("latin1").split("\n").slice(0, -1) : [];
  };
  const rejects = async (fn) => { try { await fn(); return null; } catch (e) { return e; } };
  const quiet = async (fn) => {
    const orig = console.log, origErr = console.error;
    console.log = console.error = () => {};
    try { return await fn(); } finally { console.log = orig; console.error = origErr; }
  };
  const allReadable = (name, auditDir) => {
    const longest = Math.max(0, ...trailLines(auditDir).map((l) => l.length)); // latin1: one char per byte
    const found = findUnreadableLines(join(auditDir, "audit.jsonl"));
    ok(name, longest < MAX_COUNTERS_LINE_BYTES && found.total === 0, `longest ${longest}, ${JSON.stringify(found.findings)}`);
    return longest;
  };
  const fill = (ch, nbytes) => ch.repeat(Math.floor(nbytes / Buffer.byteLength(ch)));
  const pad2 = (i) => String(i).padStart(2, "0");

  // An agent at its bound derives a principal within the name bound, so the
  // decision is recorded and an approval token is never spent on a decision
  // that then fails to record.
  {
    const auditDir = dirOf();
    const agent = "a".repeat(MAX_AGENT_NAME_BYTES);
    const g = new Watchlight({ agent, auditDir });
    g.allow('@enforcement_effect("require_approval") permit(principal, action == Action::"wire", resource);', "hold");
    g.allow('permit(principal, action == Action::"read", resource);', "read");
    await quiet(async () => {
      eq("agent at its bound: the decision is recorded", (await g.authorize({ action: "read" })).allowed, true);
      const held = await g.authorize({ action: "wire" });
      const token = g.mintApproval({ action: "wire" });
      eq("... an approved decision is recorded too", [held.needsApproval, (await g.authorize({ action: "wire", approval: token })).approved], [true, true]);
    });
    eq("... under Agent::\"<name>\", which fits the name bound",
      [trailLines(auditDir).map((l) => JSON.parse(l).principal), Buffer.byteLength(principals.agent(agent))],
      [[principals.agent(agent), principals.agent(agent), principals.agent(agent)], MAX_NAME_BYTES]);
  }

  // Non-string and control-character names are refused before the engine.
  {
    const auditDir = dirOf();
    const g = new Watchlight({ agent: "w", auditDir });
    g.allow("permit(principal, action, resource);", "all");
    for (const bad of [{ k: "v" }, ["a"], 5, 3.5, true]) {
      const e1 = await rejects(() => g.authorize({ action: bad }));
      const e2 = await rejects(() => g.authorize({ action: "read", resource: bad }));
      eq(`a non-string action / resource is refused (${JSON.stringify(bad)})`, [e1?.message, e2?.message], ["action must be a string", "resource must be a string"]);
    }
    const ran = [];
    const fetchIt = g.tool(async () => { ran.push(1); }, { intent: "read", resource: () => ({ blob: "x".repeat(2 * MAX_COUNTERS_LINE_BYTES) }) });
    eq("a tool whose resource binding returns a structure is refused", (await rejects(() => fetchIt()))?.message, "resource must be a string");
    for (const field of ["action", "resource"]) {
      const e = await rejects(() => g.authorize({ action: "read", [field]: "a\nb" }));
      eq(`control characters in ${field} are refused`, e?.message, `${field} must not contain control characters`);
    }
    eq("... the body never ran and nothing was recorded", [ran, trailLines(auditDir).length], [[], 0]);
  }

  // attenuate() checks the sub-agent's name; scope lists and the chain are bounded.
  {
    const auditDir = dirOf();
    const g = new Watchlight({ agent: "w", auditDir, maxDelegationDepth: 64 });
    g.allow("permit(principal, action, resource);", "all");
    const root = await g.scope({ tools: ["a", "b"] });
    for (const bad of ["x".repeat(MAX_AGENT_NAME_BYTES + 1), "a\nb", "a\u0000b", 5, "   "]) {
      throws(`attenuate refuses the sub-agent name ${JSON.stringify(bad).slice(0, 12)}`, () => root.attenuate({ tools: ["a"], agent: bad }), TypeError);
      throws("... and so does previewAttenuate", () => root.previewAttenuate({ tools: ["a"], agent: bad }), TypeError);
    }
    for (const [label, opts] of [
      ["too many tools", { tools: Array(MAX_SCOPE_ENTRIES + 1).fill("t") }],
      ["too many resources", { resources: Array(MAX_SCOPE_ENTRIES + 1).fill("r") }],
      ["too many intents", { intents: Array(MAX_SCOPE_ENTRIES + 1).fill("i") }],
      ["too many bytes", { tools: Array(17).fill("x".repeat(MAX_NAME_BYTES)) }],
      ["one entry too long", { tools: [OVER] }],
      ["a control character", { tools: ["a\nb"] }],
      ["a non-string entry", { tools: [{ name: "t" }] }],
      ["a bare string", { tools: "search" }],
    ]) {
      eq(`scope() refuses ${label}`, (await rejects(() => g.scope(opts)))?.name, "TypeError");
      eq(`previewScope() refuses ${label}`, (await rejects(() => g.previewScope(opts)))?.name, "TypeError");
    }
    throws("attenuate() refuses an over-long list", () => root.attenuate({ tools: Array(MAX_SCOPE_ENTRIES + 1).fill("a") }), TypeError);
    throws("delegate() refuses an over-long tool name", () => g.delegate(root, "sub", { tools: [OVER] }), TypeError);
    eq("lists at their bounds are accepted", [
      (await g.scope({ tools: Array.from({ length: MAX_SCOPE_ENTRIES }, (_, i) => `t${i}`) })).allowedTools.length,
      (await g.scope({ tools: Array(16).fill("x".repeat(MAX_NAME_BYTES)) })).allowedTools.length,
    ], [MAX_SCOPE_ENTRIES, 16]);
    const name = "n".repeat(4000);
    let gov = g.delegate(await g.scope({ tools: ["a"] }), name + "0");
    let hops = 1;
    let err;
    try { for (;;) { gov = g.delegate(gov, name + hops); hops++; } } catch (e) { err = e; }
    eq("the delegation chain is bounded in bytes", [err?.message?.includes("the delegation chain is longer than the maximum of 65536 bytes"), hops], [true, Math.floor(MAX_ACTOR_CHAIN_BYTES / 4002)]);
    allReadable("nothing written by a refusal", auditDir);
  }

  // The worst case of every record kind fits the line limit. TypeScript writes
  // non-ASCII raw, so a quote or backslash (doubled when escaped, and again
  // inside the engine's reason text) costs the most here.
  for (const ch of ["é", '"', "\\", "\u{1F600}"]) {
    const auditDir = dirOf();
    const perName = Math.floor(MAX_ACTOR_CHAIN_BYTES / 65);
    const names = Array.from({ length: 65 }, (_, i) => fill(ch, perName - 2) + pad2(i));
    const g = new Watchlight({ agent: names[0], auditDir, maxDelegationDepth: 64, signingSecret: SECRET });
    g.allow("permit(principal, action, resource);", "all");
    const tools = Array.from({ length: MAX_SCOPE_LIST_BYTES / MAX_NAME_BYTES }, (_, i) => fill(ch, MAX_NAME_BYTES - 2) + pad2(i));
    let gov = g.delegate(await g.scope({ tools, resources: tools, intents: tools }), names[1]);
    for (const n of names.slice(2)) gov = g.delegate(gov, n);
    const name = fill(ch, MAX_NAME_BYTES);
    const principal = 'User::"' + fill(ch, MAX_NAME_BYTES - 9) + '"';
    await quiet(async () => {
      await gov.authorize({ action: name, principal, resource: name });
      const body = gov.tool(async () => "ok", {
        intent: name, principal: () => principal, resource: () => name,
        onResult: (_r, info) => { info.intent = info.resource = "x".repeat(2 * MAX_COUNTERS_LINE_BYTES); },
      });
      await body();
      gov.sanitize("mail a@example.com", { intent: name, resource: name, principal: "p".repeat(128), decisionId: "d".repeat(128) });
      gov.screen("hello", { intent: name, resource: name, principal: "p".repeat(128), decisionId: "d".repeat(128) });
    });
    const outside = Array.from({ length: MAX_SCOPE_LIST_BYTES / MAX_NAME_BYTES }, (_, i) => fill(ch, MAX_NAME_BYTES - 3) + "z" + pad2(i));
    throws(`worst case (${JSON.stringify(ch)}): the refused attenuation throws`, () => gov.delegatedScope.attenuate({ tools: outside, resources: outside, intents: outside, timeBudgetSeconds: 1e9 }), Error);
    eq(`worst case (${JSON.stringify(ch)}): the chain is the longest there is`, gov.actorChain.length, 65);
    const longest = allReadable(`worst case (${JSON.stringify(ch)}): every record fits the line limit`, auditDir);
    ok(`worst case (${JSON.stringify(ch)}): well inside it`, longest < 0.5 * MAX_COUNTERS_LINE_BYTES, String(longest));
  }

  // Every public write path, driven with odd inputs: no line it writes is one
  // the counters cannot read.
  {
    const auditDir = dirOf();
    const HUGE = "h".repeat(2 * MAX_COUNTERS_LINE_BYTES);
    const ODD = [HUGE, "a\nb", "\u0000", " ", "\ud800", "", "   ", { blob: HUGE }, [HUGE], 10n ** 5000n, 3.5, NaN, null, undefined, true];
    const g = new Watchlight({ agent: "w", auditDir, signingSecret: SECRET });
    g.allow("permit(principal, action, resource);", "all");
    const root = await g.scope({ tools: ["a", "b"] });
    const sub = g.delegate(root, "sub", { tools: ["a"] });
    const attempt = async (fn) => { try { await fn(); } catch { /* refusals are expected; the trail is what is checked */ } };
    await quiet(async () => {
      for (const x of ODD) {
        await attempt(() => new Watchlight({ agent: x, auditDir }));
        await attempt(() => g.as(x));
        await attempt(() => g.authorize({ action: x }));
        await attempt(() => g.authorize({ action: "read", resource: x }));
        await attempt(() => g.authorize({ action: "read", principal: x }));
        await attempt(() => g.authorize({ action: "read", agent: x }));
        await attempt(() => g.authorize({ action: "read", context: { k: x } }));
        await attempt(() => g.authorize({ action: "read", approval: x }));
        await attempt(() => sub.authorize({ action: x, resource: x }));
        await attempt(() => g.check(x, x));
        await attempt(() => g.mintApproval({ action: x, resource: x, principal: x }));
        await attempt(() => g.tool(async () => "r", { intent: x })());
        await attempt(() => g.tool(async () => "r", { intent: "read", resource: () => x })());
        await attempt(() => g.tool(async () => "r", { intent: "read", principal: () => x })());
        const mutate = (_r, info) => { for (const k of ["intent", "resource", "principal", "decisionId"]) info[k] = x; };
        await attempt(() => g.tool(async () => "r", { intent: "read", onResult: mutate })());
        for (const k of ["intent", "resource", "principal", "decisionId", "agent"]) {
          await attempt(() => g.sanitize("a@example.com", { [k]: x }));
          await attempt(() => g.screen("hello", { [k]: x }));
        }
        await attempt(() => g.sanitize(x));
        await attempt(() => g.screen(x));
        for (const k of ["tools", "resources", "intents"]) {
          await attempt(() => g.scope({ [k]: x }));
          await attempt(() => g.scope({ [k]: [x] }));
          await attempt(() => root.attenuate({ [k]: [x] }));
          await attempt(() => g.delegate(root, "d", { [k]: [x] }));
        }
        await attempt(() => g.scope({ tools: ["a"], timeBudgetSeconds: x }));
        await attempt(() => root.attenuate({ tools: ["a"], agent: x }));
        await attempt(() => root.attenuate({ tools: ["a"], timeBudgetSeconds: x }));
        await attempt(() => g.delegate(root, x));
        await attempt(() => g.delegate(sub, x));
        await attempt(() => g.scopeFromToken(x));
        await attempt(() => g.sanitize("a@example.com", { mode: x }));
        await attempt(() => g.sanitize("a@example.com", { types: x }));
        await attempt(() => g.sanitize("a@example.com", { types: [x] }));
        await attempt(() => g.sanitize("a@example.com", { known: x }));
        await attempt(() => g.sanitize("a@example.com", { known: [x] }));
        await attempt(() => g.sanitize("a@example.com", { personExclusions: x }));
        await attempt(() => g.sanitize("a@example.com", { personExclusions: [x] }));
        await attempt(() => g.screen("hello", { mode: x }));
        await attempt(() => g.screen("hello", { families: x }));
        await attempt(() => g.screen("hello", { families: [x] }));
        // The Claude hooks' PostToolUse fallback: no PreToolUse decision on
        // record, so its names were never checked by a decision.
        for (const bindings of [{ intentFor: () => x }, { resourceFor: () => x }, { principal: () => x }]) {
          const { hooks } = governedHooks({ governor: g, onResult: () => undefined, ...bindings });
          await attempt(() => hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: "t", tool_input: {}, tool_response: "r" }, undefined));
        }
        await attempt(async () => {
          const { hooks } = governedHooks({ governor: g, onResult: () => undefined });
          await hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: x, tool_input: {}, tool_response: "r" }, undefined);
        });
      }
      // Iterables that change between passes.
      const flip = (first, later) => { let passes = 0; return { [Symbol.iterator]() { passes++; return (passes === 1 ? first : later)[Symbol.iterator](); } }; };
      for (const make of [() => flip(["a"], [HUGE]), () => flip(["a"], Array(10000).fill("a"))]) {
        for (const k of ["tools", "resources", "intents"]) {
          await attempt(() => g.scope({ [k]: make() }));
          await attempt(() => root.attenuate({ [k]: make() }));
          await attempt(() => g.delegate(root, "f", { [k]: make() }));
          await attempt(() => g.previewScope({ [k]: make() }));
        }
      }
    });
    ok("the battery wrote records", trailLines(auditDir).length > 0);
    allReadable("no public write path writes an unreadable line", auditDir);
  }

  // A list is read once, and the checked list is the one used.
  {
    const auditDir = dirOf();
    const g = new Watchlight({ agent: "w", auditDir });
    g.allow("permit(principal, action, resource);", "all");
    let passes = 0;
    const flip = (first, later) => { passes = 0; return { [Symbol.iterator]() { passes++; return (passes === 1 ? first : later)[Symbol.iterator](); } }; };
    const root = await g.scope({ tools: flip(["a", "b"], ["x".repeat(2 * MAX_COUNTERS_LINE_BYTES)]) });
    eq("a list that changes between passes: the checked one is used", [root.allowedTools, passes], [["a", "b"], 1]);
    const child = root.attenuate({ tools: flip(["a"], ["b"]) });
    eq("... in attenuate too", [child.allowedTools, passes], [["a"], 1]);
    eq("... and in previewScope", (await g.previewScope({ tools: flip(["a"], []) })).allowedTools, ["a"]);
    const gen = function* (items) { yield* items; };
    eq("a generator is read once and used", [
      (await g.scope({ tools: gen(["a", "b"]) })).allowedTools,
      root.attenuate({ tools: gen(["a"]) }).allowedTools,
      g.delegate(root, "sub", { tools: gen(["b"]) }).delegatedScope.allowedTools,
    ], [["a", "b"], ["a"], ["b"]]);
    allReadable("... and nothing unreadable was written", auditDir);
  }

  // sanitize and screen options are checked before any record.
  {
    const auditDir = dirOf();
    const g = new Watchlight({ agent: "w", auditDir });
    for (const mode of ["x".repeat(2 * MAX_COUNTERS_LINE_BYTES), "TAG", "", 5, ["tag"]]) {
      throws(`sanitize refuses mode ${JSON.stringify(mode).slice(0, 12)}`, () => g.sanitize("a@example.com", { mode }), SanitizeError);
    }
    for (const types of ["EMAIL", [5], 7]) {
      throws(`sanitize refuses types ${JSON.stringify(types)}`, () => g.sanitize("a@example.com", { types }), SanitizeError);
    }
    for (const opts of [{ mode: "x".repeat(5000) }, { mode: 5 }, { families: "ROLE_SWITCH" }, { families: [5] }, { families: 7 }, { families: ["x".repeat(5000)] }]) {
      throws(`screen refuses ${JSON.stringify(opts).slice(0, 30)}`, () => g.screen("hello", opts), ScreenError);
    }
    eq("... and nothing was recorded", trailLines(auditDir).length, 0);
  }

  // The Claude hooks' PostToolUse fallback checks the names it records.
  {
    const auditDir = dirOf();
    const g = new Watchlight({ agent: "w", auditDir });
    for (const [label, bindings] of [["intent", { intentFor: () => OVER }], ["resource", { resourceFor: () => ({ blob: OVER }) }]]) {
      const { hooks } = governedHooks({ governor: g, onResult: () => "replaced", ...bindings });
      const orig = console.error;
      console.error = () => {};
      let out;
      try { out = await hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: "t", tool_input: {}, tool_response: "raw" }, undefined); }
      finally { console.error = orig; }
      eq(`PostToolUse fallback with a bad ${label}: the output is withheld`, out.hookSpecificOutput.updatedToolOutput, DENY_REASON);
    }
    // Each refusal leaves a value-free trace: placeholder names, this agent as
    // the subject, withheld.
    const traces = trailLines(auditDir).map((l) => JSON.parse(l));
    eq("... and leaves a value-free trace, withheld", traces.map(({ ts, ...r }) => r), [1, 2].map(() => ({
      agent: "w", principal: 'Agent::"w"', intent: REFUSED_NAME, event: "egress", resource: REFUSED_NAME, replaced: false, withheld: true,
    })));
    ok("... that carries no raw value", trailLines(auditDir).every((l) => !l.includes("xxxx") && l.length < 400));
    for (const outcome of ["allowed", "denied", "all"]) {
      const c = g.counters({ principal: 'Agent::"w"', outcome });
      eq(`... and counts toward no quota (${outcome})`, [c.count, c.unreadable, c.records], [0, 0, 2]);
    }
    const { hooks } = governedHooks({ governor: g, onResult: () => undefined });
    await quiet(() => hooks.PostToolUse[0].hooks[0]({ hook_event_name: "PostToolUse", tool_name: "t", tool_input: {}, tool_response: "raw" }, undefined));
    eq("a well-formed fallback still records its egress", JSON.parse(trailLines(auditDir).at(-1)).intent, "t");
  }

  // The funnel backstop: called directly, past every entry check.
  {
    const dir = dirOf();
    const p = join(dir, "audit.jsonl");
    const seen = [];
    const trail = new AuditTrail(p, (r) => seen.push(r));
    const huge = "p".repeat(2 * 1024 * 1024);
    trail.write({ ts: "2026-01-15T11:59:00.000Z", agent: "a", principal: huge, intent: "read", event: "decision", resource: "doc/1", decision: "Allow" });
    const [line] = trailLines(dir);
    const rec = JSON.parse(line);
    eq("the funnel shortens an oversized record instead of dropping it", rec, {
      ts: "2026-01-15T11:59:00.000Z", agent: "a",
      principal: { omitted: "oversized", bytes: huge.length, sha256: createHash("sha256").update(huge).digest("hex") },
      intent: "read", event: "decision", resource: "doc/1", decision: "Allow", oversized: true,
    });
    ok("... within the bound, value-free", line.length <= MAX_AUDIT_RECORD_BYTES && !line.includes(huge.slice(0, 64)) && MAX_AUDIT_RECORD_BYTES === 512 * 1024);
    eq("... the sink gets exactly the line", JSON.stringify(seen[0]), line);
    for (const [principal, outcome] of [["p", "allowed"], ['User::"x"', "denied"], ["q", "all"]]) {
      const r = countAuditRecords(p, { principal, intent: "anything", outcome, now: "2026-01-15T12:00:00Z" });
      eq(`... and counts toward every query (${principal}, ${outcome})`, [r.count, r.unreadable], [1, 1]);
    }
    eq("... audit check reports it", findUnreadableLines(p).findings, [{ line: 1, reason: "oversized-record" }]);

    const p2 = join(dir, "many.jsonl");
    const record = { ts: "t", event: "attenuation", bad: 10n };
    for (let i = 0; i < 10; i++) record[`f${i}`] = "v".repeat(100 * 1024 + i);
    new AuditTrail(p2).write(record);
    const r2 = JSON.parse(fs.readFileSync(p2, "utf8").trim());
    const shortened = Object.keys(r2).filter((k) => k.startsWith("f") && typeof r2[k] === "object");
    const kept = Object.keys(r2).filter((k) => k.startsWith("f") && typeof r2[k] === "string");
    ok("the largest fields are shortened first", r2.oversized === true && kept.length > 0 &&
      shortened.every((a) => kept.every((b) => Number(a.slice(1)) > Number(b.slice(1)))) &&
      JSON.stringify(r2.bad) === JSON.stringify({ omitted: "unserializable" }), JSON.stringify(Object.keys(r2)));
    const p3 = join(dir, "fits.jsonl");
    const fits = { ts: "t", principal: "p".repeat(MAX_AUDIT_RECORD_BYTES - 64) };
    new AuditTrail(p3).write(fits);
    eq("a record within the bound is written unchanged", JSON.parse(fs.readFileSync(p3, "utf8")), fits);
  }

  // The backstop: linear, depth-bounded, collision-free, same threshold as Python.
  {
    const { boundedLine } = require("../dist/audit.js");
    const record = {};
    for (let i = 0; i < 6000; i++) record[`k${i}`] = "v".repeat(300);
    const t0 = process.hrtime.bigint();
    const line = boundedLine(record);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    ok("shortening 6000 fields is linear (well under a second)", ms < 500 && Buffer.byteLength(line) <= MAX_AUDIT_RECORD_BYTES && JSON.parse(line).oversized === true, `${ms}ms`);

    const nested = (depth) => { let v = []; for (let i = 1; i < depth; i++) v = [v]; return v; };
    const dir = dirOf();
    const p = join(dir, "audit.jsonl");
    const trail = new AuditTrail(p);
    trail.write({ ts: "t", x: nested(31) });
    trail.write({ ts: "t", x: nested(32), y: "kept" });
    trail.write({ ts: "t", x: nested(5000) });
    const [first, second, third] = trailLines(dir).map((l) => JSON.parse(l));
    eq("a value 31 deep is kept (32 in the record: the counters' limit)", first, { ts: "t", x: nested(31) });
    eq("one level deeper is replaced, the rest kept", [second.x.omitted, second.y, second.oversized], ["too-deep", "kept", true]);
    ok("a very deep value is replaced", ["too-deep", "unserializable"].includes(third.x.omitted) && third.oversized === true, JSON.stringify(third).slice(0, 100));
    eq("the backstop never writes a line the counters call too deep", findUnreadableLines(p).findings,
      [{ line: 2, reason: "oversized-record" }, { line: 3, reason: "oversized-record" }]);

    const collide = JSON.parse(boundedLine({ ["k".repeat(65)]: "long key", field_0: "kept", big: "x".repeat(600 * 1024) }));
    eq("a renamed key never overwrites another", [collide.field_0, Object.values(collide).filter((v) => typeof v === "string").sort(), Object.keys(collide).length],
      ["kept", ["kept", "long key"], 4]);

    for (const [count, shortened] of [[87000, false], [88000, true]]) {
      const out = JSON.parse(boundedLine({ ts: "t", principal: "é".repeat(count) }));
      eq(`the threshold is measured as Python writes it (${count} x é)`, "oversized" in out, shortened);
    }
  }

  // The two lanes classify crafted lines identically.
  {
    const PARITY = join(here, "..", "..", "tests", "fixtures", "counters-parity.jsonl");
    const expected = JSON.parse(fs.readFileSync(join(here, "..", "..", "tests", "fixtures", "counters-parity.expected.json"), "utf8"));
    const found = findUnreadableLines(PARITY);
    eq("crafted lines classify as in Python", [found.lines, found.findings], [expected.lines, expected.expected]);
    const r = countAuditRecords(PARITY, { principal: ALICE, intent: "read", now: NOW });
    eq("... and count as in Python", [r.count, r.unreadable], [14, 9]);
    for (const spec of ["1h\n", "١h", "１h", "1١"]) {
      throws(`the window grammar is ASCII-only (${JSON.stringify(spec)})`, () => parseWindowSeconds(spec), RangeError);
    }
  }

  // `watchlight audit check`: line numbers and reasons, never content.
  {
    const dir = dirOf();
    const p = join(dir, "audit.jsonl");
    const secretWord = "s3cr3t-value";
    fs.writeFileSync(p, Buffer.concat([
      Buffer.from('{"ts":"2026-01-15T11:59:00Z","principal":"p","decision":"Allow"}\n'),
      Buffer.from(`{"x":"${secretWord}"\n`),
      Buffer.from(`{"pad":"${"p".repeat(MAX_COUNTERS_LINE_BYTES)}"}\n`),
      Buffer.from([0x22, 0xff, 0x22, 0x0a]),
      Buffer.from("[".repeat(40) + "]".repeat(40) + "\n"),
      Buffer.from("[1]\n"),
      Buffer.from(`{"ts":"never","principal":"p","decision":"Allow","note":"${secretWord}"}\n`),
      Buffer.from('{"event_type":"execution_started"}\n'),
    ]));
    const cli = (...args) => spawnSync(process.execPath, [join(here, "..", "dist", "cli.js"), "audit", "check", ...args], { encoding: "utf8" });
    const r = cli(p);
    const want = [[2, "not JSON"], [3, `longer than ${MAX_COUNTERS_LINE_BYTES} bytes`], [4, "not valid UTF-8"],
      [5, "nested deeper than 32 levels"], [6, "not a JSON object"], [7, "a decision whose ts cannot be read"]];
    ok("audit check lists every unreadable line with its reason", r.status === 1 && want.every(([n, why]) => r.stdout.includes(`line ${n}: ${why}`)), r.stdout + r.stderr);
    ok("... and nothing else", !r.stdout.includes("line 1:") && !r.stdout.includes("line 8:"), r.stdout);
    ok("... value-free", !r.stdout.includes(secretWord) && !r.stdout.includes("ppp"), r.stdout);
    ok("... says the lines never age out", r.stdout.includes("never age out of a window"), r.stdout);
    eq("... the reasons are the shared ones", Object.keys(UNREADABLE_REASONS), ["oversized", "not-utf8", "too-deep", "not-json", "not-an-object", "unreadable-ts", "oversized-record"]);
    eq("... the counters see exactly those lines", countAuditRecords(p, { principal: "p", now: "2026-01-15T12:00:00Z" }).unreadable, 6);
    const limited = cli(p, "--limit", "2");
    ok("--limit caps the listing", limited.status === 1 && limited.stdout.includes("and 4 more"), limited.stdout);
    const clean = join(dir, "clean.jsonl");
    fs.writeFileSync(clean, '{"ts":"2026-01-15T11:59:00Z","principal":"p","decision":"Allow"}\n');
    eq("a clean file exits 0, a missing one 0, a directory 2", [cli(clean).status, cli(join(dir, "missing.jsonl")).status, cli(dir).status], [0, 0, 2]);
    eq("--limit -1 exits 2", cli(clean, "--limit", "-1").status, 2);
    const bare = spawnSync(process.execPath, [join(here, "..", "dist", "cli.js"), "audit"], { encoding: "utf8" });
    ok("`watchlight audit` alone exits 2 with usage", bare.status === 2 && bare.stderr.includes("missing subcommand") && bare.stderr.includes("usage:"), bare.stderr);
  }
}

console.log("missing vs unreadable");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const none = countAuditRecords(join(dir, "nope", "audit.jsonl"), { principal: ALICE, now: NOW, intent: "read" });
  eq("missing file is zero counts, not an error", [none.count, none.records, none.skipped, none.unreadable, none.truncated, none.window.seconds], [0, 0, 0, 0, false, 3600]);
  throws("a directory is unreadable", () => countAuditRecords(dir, { principal: ALICE, now: NOW }), AuditTrailUnreadable);
  try { countAuditRecords(dir, { principal: ALICE, now: NOW }); } catch (e) { eq("typed error: name + path on the object, fixed message", [e.name, e.path, e.message], ["AuditTrailUnreadable", dir, "audit trail is not readable"]); }
}

console.log("live governor");
{
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const g = new Watchlight({ agent: "quota-agent", auditDir });
  g.allow('permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 3 };', "quota");
  const verdicts = [];
  for (let i = 0; i < 5; i++) {
    const c = g.counters({ principal: ALICE, intent: "read", window: "1h" });
    const d = await g.authorize({ action: "read", principal: ALICE, resource: "doc/1", context: { reads_this_hour: c.count } });
    verdicts.push(`${c.count}:${d.decision}`);
  }
  eq("quota of 3 reads/hour enforced from the trail", verdicts, ["0:Allow", "1:Allow", "2:Allow", "3:Deny", "3:Deny"]);
  const all = g.counters({ principal: ALICE, intent: "read", outcome: "all" });
  eq("allowed + denied == all on a live trail", [g.counters({ principal: ALICE, intent: "read" }).count, g.counters({ principal: ALICE, intent: "read", outcome: "denied" }).count, all.count], [3, 2, 5]);
  g.sanitize("mail a@b.com", { resource: "doc/1" });
  eq("a sanitization record is read but never counted", [g.counters({ principal: ALICE, intent: "read", outcome: "all" }).count, g.counters({ principal: ALICE, intent: "read" }).records], [5, 6]);
  eq("another principal sees zero", g.counters({ principal: 'User::"bob"', intent: "read" }).count, 0);
  eq("governed tool context binding drives the quota", await (async () => {
    const read = g.tool(async () => "body ran", {
      intent: "read", principal: () => 'User::"bob"', resource: () => "doc/2",
      context: () => ({ reads_this_hour: g.counters({ principal: 'User::"bob"', intent: "read" }).count }),
    });
    const out = [];
    for (let i = 0; i < 4; i++) { try { out.push(await read()); } catch (e) { out.push(e.name); } }
    return out;
  })(), ["body ran", "body ran", "body ran", "Denied"]);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
