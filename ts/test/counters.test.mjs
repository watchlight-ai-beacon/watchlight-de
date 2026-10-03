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
} = require("../dist/index.js");

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
  eq("the bound is 4096 bytes and far below the line limit", [MAX_NAME_BYTES, 16 * MAX_NAME_BYTES * 6 < MAX_COUNTERS_LINE_BYTES], [4096, true]);
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
    eq("an agent name at the bound is accepted", new Watchlight({ agent: AT_LIMIT, auditDir }).agent, AT_LIMIT);
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
