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
eq("alice read allowed 1h", base.count, 6);
eq("window bounds", base.window, { seconds: 3600, start: "2026-01-15T11:00:00.000Z", end: NOW });
eq("filter echoed", [base.principal, base.intent, base.resource, base.outcome], [ALICE, "read", undefined, "allowed"]);
eq("well-formed records of every kind", base.records, 19);
eq("malformed lines skipped", base.skipped, 6);
eq("not truncated", base.truncated, false);
eq("alice read denied 1h (Deny only here)", at({ intent: "read", window: "1h", outcome: "denied" }).count, 1);
eq("alice read all 1h", at({ intent: "read", window: "1h", outcome: "all" }).count, 7);
eq("alice any intent allowed (incl. write + approved wire)", at({ window: "1h" }).count, 8);
eq("alice any intent denied = Deny + NeedsApproval hold", at({ window: "1h", outcome: "denied" }).count, 2);
eq("allowed + denied == all", at({ window: "1h", outcome: "all" }).count, 10);
eq("resource narrows (exact)", at({ intent: "read", resource: "doc/1", window: "1h" }).count, 4);
eq("resource prefix does not match", at({ intent: "read", resource: "doc", window: "1h" }).count, 0);
eq("bob", countAuditRecords(FIXTURE, { principal: 'User::"bob"', intent: "read", now: NOW }).count, 1);
eq("carol denied", countAuditRecords(FIXTURE, { principal: 'User::"carol"', intent: "read", outcome: "denied", now: NOW }).count, 1);
eq("carol allowed", countAuditRecords(FIXTURE, { principal: 'User::"carol"', intent: "read", now: NOW }).count, 0);
eq("unknown principal", countAuditRecords(FIXTURE, { principal: 'User::"dave"', now: NOW }).count, 0);
eq("principal is exact (no substring)", countAuditRecords(FIXTURE, { principal: "alice", now: NOW }).count, 0);
eq("15m window", at({ intent: "read", window: "15m" }).count, 3);
eq("24h window includes the start-boundary and older records", at({ intent: "read", window: "24h" }).count, 8);
eq("window as number of seconds", at({ intent: "read", window: 3600 }).count, 6);
eq("window as digit string", at({ intent: "read", window: "3600" }).count, 6);
eq("default window is 1h", at({ intent: "read" }).count, 6);
eq("now as Date", countAuditRecords(FIXTURE, { principal: ALICE, intent: "read", now: new Date(NOW) }).count, 6);
eq("now as epoch ms", countAuditRecords(FIXTURE, { principal: ALICE, intent: "read", now: Date.parse(NOW) }).count, 6);
eq("now with an offset zone", at({ intent: "read", now: "2026-01-15T14:00:00.000+02:00" }).count, 6);
eq("earlier now shifts the window", at({ intent: "read", now: "2026-01-15T11:30:00.000Z" }).count, 5);
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
  eq("cut inside line 1 drops it silently", [cut.count, cut.records, cut.skipped, cut.truncated], [5, 18, 6, true]);
  const edge = at({ intent: "read", maxBytes: size - firstLine });
  eq("cut exactly on a line boundary keeps line 2 whole", [edge.count, edge.records, edge.skipped, edge.truncated], [5, 18, 6, true]);
  const one = at({ intent: "read", maxBytes: size - 1 });
  eq("cut after the first byte", [one.count, one.records, one.truncated], [5, 18, true]);
  const tiny = at({ intent: "read", maxBytes: 5 });
  eq("a tail shorter than a line counts nothing", [tiny.count, tiny.records, tiny.skipped, tiny.truncated], [0, 0, 0, true]);
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
  eq("invalid UTF-8 is skipped", countAuditRecords(p, { principal: ALICE, now: NOW }).skipped, 1);
}

console.log("hostile lines are bounded");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const p = join(dir, "audit.jsonl");
  const rec = (extra = "") => `{"ts":"2026-01-15T11:59:00.000Z","agent":"a","principal":${JSON.stringify(ALICE)},"intent":"read","resource":"doc/1","decision":"Allow"${extra}}`;
  const opts = { principal: ALICE, intent: "read", now: NOW };
  fs.writeFileSync(p, "\uFEFF" + rec() + "\n" + rec() + "\n");
  eq("a BOM-prefixed line is skipped, not counted", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [1, 1]);
  eq("line cap is 1 MiB, nesting cap is 32", [MAX_COUNTERS_LINE_BYTES, MAX_COUNTERS_NESTING], [1024 * 1024, 32]);
  fs.writeFileSync(p, rec(`,"pad":"${"p".repeat(900 * 1024)}"`) + "\n" + rec() + "\n");
  eq("a large but legitimate record still counts", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 0]);
  fs.writeFileSync(p, "x".repeat(MAX_COUNTERS_LINE_BYTES + 1) + "\n" + rec() + "\n" + rec() + "\n");
  eq("an over-cap line is skipped once and the rest still counts", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 1]);
  const deep = (d) => "[".repeat(d) + "]".repeat(d);
  fs.writeFileSync(p, rec(`,"x":${deep(5)}`) + "\n" + rec(`,"x":${deep(MAX_COUNTERS_NESTING + 1)}`) + "\n" + rec(`,"x":"${"[".repeat(200)}"`) + "\n");
  eq("nesting past the cap is skipped; brackets inside strings are not nesting", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [2, 1]);
  fs.writeFileSync(p, "{".repeat(100_000) + "\n" + rec() + "\n");
  eq("100k-deep line is skipped without parsing", [countAuditRecords(p, opts).count, countAuditRecords(p, opts).skipped], [1, 1]);
  // A newline-free tail as large as the whole scan bound: must finish quickly
  // and hold at most the line cap in memory.
  const big = 24 * 1024 * 1024;
  fs.writeFileSync(p, Buffer.alloc(big, 0x78));
  const before = process.memoryUsage().rss;
  const t0 = Date.now();
  const r = countAuditRecords(p, { ...opts, maxBytes: big });
  const ms = Date.now() - t0;
  eq("newline-free 24 MiB tail: one skipped line, nothing counted", [r.count, r.records, r.skipped, r.truncated], [0, 0, 1, false]);
  ok("newline-free tail finishes fast", ms < 5000, `${ms}ms`);
  ok("newline-free tail does not buffer the tail", process.memoryUsage().rss - before < 16 * 1024 * 1024, `${process.memoryUsage().rss - before} bytes`);
}

console.log("missing vs unreadable");
{
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-ctr-"));
  const none = countAuditRecords(join(dir, "nope", "audit.jsonl"), { principal: ALICE, now: NOW, intent: "read" });
  eq("missing file is zero counts, not an error", [none.count, none.records, none.skipped, none.truncated, none.window.seconds], [0, 0, 0, false, 3600]);
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
