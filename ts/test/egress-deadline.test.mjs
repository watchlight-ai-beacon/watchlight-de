// @watchlight/sdk egress deadline test — an `onResult` hook is bounded on EVERY
// path that runs one, so `EgressRecord.withheld` ("the hook threw, or outran its
// deadline — the payload was never released") is true wherever it is written.
//
// The regression this file was written for: `govern.tool()` and the LangChain
// adapters had no deadline at all. A hook that slept 12 s released the payload
// after 12 s and the egress record said nothing was withheld, while the same
// hook under `governedHooks` was withheld at 8 s. One documented guarantee, one
// of three paths enforcing it.
//
// Every test here uses a SMALL explicit deadline (tens of ms). The 8 s default
// is asserted as a value shared by the three paths, never waited on.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const {
  Watchlight,
  governTool,
  governTools,
  EgressTimeout,
  DEFAULT_ON_RESULT_TIMEOUT_MS,
} = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const tmpDir = (tag) => fs.mkdtempSync(join(os.tmpdir(), `wl-deadline-${tag}-`));
const egressRecords = (dir) =>
  fs
    .readFileSync(join(dir, "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l))
    .filter((r) => r.event === "egress");

const governor = (dir) => {
  const gov = new Watchlight({ agent: "deadline-agent", auditDir: dir });
  gov.allow('permit(principal, action == Action::"read", resource);', "allow-read");
  return gov;
};

// A LangChain `StructuredTool` look-alike.
const mockTool = (name, value = "SECRET") => ({ name, invoke: async () => value });

const call = async (fn) => {
  const started = Date.now();
  try {
    return { value: await fn(), elapsed: Date.now() - started };
  } catch (e) {
    return { error: e, elapsed: Date.now() - started };
  }
};

// ── the deadline, on all three paths ─────────────────────────────────
async function deadlineHolds() {
  console.log("the deadline holds on every path that runs a hook");

  const dir = tmpDir("hold");
  const gov = governor(dir);
  const slow = async () => { await sleep(400); return "REDACTED"; };

  // 1. govern.tool()
  const leaky = gov.tool(async function leaky() { return "SECRET"; }, {
    intent: "read",
    onResult: slow,
    onResultTimeoutMs: 30,
  });
  const t = await call(() => leaky());
  ok("tool(): a hook past its deadline rejects with EgressTimeout",
    t.error instanceof EgressTimeout && t.error.name === "EgressTimeout", String(t.error));
  ok("tool(): the payload is NOT returned", t.value === undefined);
  ok("tool(): the call returns at the deadline, not at the hook's own pace",
    t.elapsed < 300, `${t.elapsed}ms`);

  // 2. governTool
  const lc = governTool(mockTool("leaky_lc"), {
    governor: gov,
    intent: "read",
    onResult: slow,
    onResultTimeoutMs: 30,
  });
  const g = await call(() => lc.invoke({}));
  ok("governTool: a hook past its deadline rejects with EgressTimeout",
    g.error instanceof EgressTimeout, String(g.error));
  ok("governTool: the payload is NOT returned", g.value === undefined);

  // 3. governTools
  const [arr] = governTools([mockTool("leaky_arr")], {
    governor: gov,
    intentFor: () => "read",
    onResult: slow,
    onResultTimeoutMs: 30,
  });
  const a = await call(() => arr.invoke({}));
  ok("governTools: a hook past its deadline rejects with EgressTimeout",
    a.error instanceof EgressTimeout, String(a.error));
  ok("governTools: the payload is NOT returned", a.value === undefined);

  // The record says what the type documents.
  const eg = egressRecords(dir);
  ok("three egress records, one per withheld call", eg.length === 3, String(eg.length));
  ok("every record says withheld: true",
    eg.every((r) => r.withheld === true), JSON.stringify(eg));
  ok("a withheld record never claims a replacement",
    eg.every((r) => r.replaced === false));
  ok("the record is value-free — the payload is nowhere in it",
    !JSON.stringify(eg).includes("SECRET") && !JSON.stringify(eg).includes("REDACTED"));
  ok("the withheld call is still joined to its decision",
    eg.every((r) => typeof r.decision_id === "string" && r.decision_id.length > 0));

  // The error is safe to log: nothing from the payload rides on it.
  ok("EgressTimeout carries no payload-derived data",
    t.error.message === "egress hook deadline exceeded" &&
    !JSON.stringify(t.error.stack ?? "").includes("SECRET"));
}

// ── a hook within the deadline is untouched ──────────────────────────
async function withinDeadline() {
  console.log("a hook within its deadline is unaffected");

  const dir = tmpDir("within");
  const gov = governor(dir);

  const passthrough = gov.tool(async function fast_pass() { return "PAYLOAD"; }, {
    intent: "read",
    onResult: async () => { await sleep(5); },
    onResultTimeoutMs: 500,
  });
  ok("a fast hook passes the payload through", (await passthrough()) === "PAYLOAD");

  const replacing = gov.tool(async function fast_replace() { return "PAYLOAD"; }, {
    intent: "read",
    onResult: async () => { await sleep(5); return "REDACTED"; },
    onResultTimeoutMs: 500,
  });
  ok("a fast hook still replaces the payload", (await replacing()) === "REDACTED");

  const synchronous = gov.tool(async function sync_hook() { return "PAYLOAD"; }, {
    intent: "read",
    onResult: () => "REDACTED",
  });
  ok("a synchronous hook under the default deadline is unaffected",
    (await synchronous()) === "REDACTED");

  const eg = egressRecords(dir);
  ok("no record claims a withhold", eg.length === 3 && eg.every((r) => r.withheld === undefined),
    JSON.stringify(eg));
  ok("passthrough and replacement are recorded as before",
    eg[0].replaced === false && eg[1].replaced === true && eg[2].replaced === true);
}

// ── a throwing hook and a timed-out hook agree ───────────────────────
async function throwAndTimeoutAgree() {
  console.log("a timeout behaves exactly as a throw already did");

  const dir = tmpDir("agree");
  const gov = governor(dir);

  const thrower = gov.tool(async function thrower() { return "SECRET"; }, {
    intent: "read",
    onResult: () => { throw new Error("screen failed"); },
  });
  const th = await call(() => thrower());
  const timer = gov.tool(async function timer_out() { return "SECRET"; }, {
    intent: "read",
    onResult: () => sleep(400),
    onResultTimeoutMs: 30,
  });
  const to = await call(() => timer());

  ok("both refuse by rejecting the call", th.error !== undefined && to.error !== undefined);
  ok("neither returns the payload", th.value === undefined && to.value === undefined);
  const eg = egressRecords(dir);
  ok("both write one withheld egress record",
    eg.length === 2 && eg.every((r) => r.withheld === true && r.replaced === false));
  const shape = (r) => JSON.stringify({ ...r, ts: 0, decision_id: 0, resource: 0 });
  ok("the records are indistinguishable — the trail records the disposition, not the cause",
    shape(eg[0]) === shape(eg[1]), JSON.stringify(eg));
  ok("the caller can still tell them apart, where it is actionable",
    to.error instanceof EgressTimeout && !(th.error instanceof EgressTimeout) &&
      th.error.message === "screen failed");
}

// ── a hook that outruns the deadline can never release the payload ───
async function lateHookNeverReleases() {
  console.log("a hook that settles late is ignored, and leaves nothing behind");

  const dir = tmpDir("late");
  const gov = governor(dir);
  let settled = false;

  const late = gov.tool(async function late_hook() { return "SECRET"; }, {
    intent: "read",
    onResult: async () => { await sleep(120); settled = true; return "TOO-LATE"; },
    onResultTimeoutMs: 20,
  });
  const r = await call(() => late());
  ok("the call rejects at the deadline", r.error instanceof EgressTimeout);

  // The deadline's own timer must not survive the call — a pending timer keeps
  // the event loop alive and holds the payload and the hook's frame with it.
  // Measured as a DELTA around a hook that never settles and arms no timer of
  // its own, so the only timer that could appear is the deadline's.
  const timers = () => process.getActiveResourcesInfo().filter((k) => k === "Timeout").length;
  const before = timers();
  const never = gov.tool(async function never_settles() { return "SECRET"; }, {
    intent: "read",
    onResult: () => new Promise(() => {}),
    onResultTimeoutMs: 20,
  });
  const n = await call(() => never());
  ok("a hook that never settles is withheld too", n.error instanceof EgressTimeout);
  ok("the deadline's timer is cleared when it fires — none is left behind",
    timers() <= before, `${before} -> ${timers()}`);

  await sleep(200);
  ok("the hook did settle after the deadline", settled === true);
  ok("its value is discarded — a late hook cannot release a payload", r.value === undefined);
  const eg = egressRecords(dir);
  ok("and it is never audited twice", eg.length === 2 && eg.every((x) => x.withheld === true),
    JSON.stringify(eg));
}

// A hook that NEVER settles must not keep the process alive: the deadline is
// the only timer, it is cleared when it fires, and nothing else is retained.
// (Asserted from a child process, since only a fresh process can prove that the
// event loop drains on its own.)
async function neverSettlingHookDoesNotHangTheProcess() {
  console.log("a hook that never settles does not keep the process alive");
  const { spawnSync } = await import("node:child_process");
  const script = `
    const { Watchlight } = require(${JSON.stringify(join(process.cwd(), "dist/index.js"))});
    const gov = new Watchlight({ agent: "never", auditFile: false });
    gov.allow('permit(principal, action, resource);', "all");
    const t = gov.tool(async function never() { return "SECRET"; }, {
      intent: "read",
      onResult: () => new Promise(() => {}),   // never settles, ever
      onResultTimeoutMs: 20,
    });
    t().then(
      () => { console.log("RELEASED"); },
      (e) => { console.log("WITHHELD:" + e.name); }
    );
  `;
  const started = Date.now();
  const out = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 10_000 });
  const elapsed = Date.now() - started;
  ok("the never-settling hook withheld the payload",
    out.stdout.includes("WITHHELD:EgressTimeout"), out.stdout + out.stderr);
  ok("the process exited on its own — no timer, no promise kept it alive",
    out.status === 0 && out.signal === null, `status=${out.status} signal=${out.signal}`);
  ok("and it exited promptly", elapsed < 5_000, `${elapsed}ms`);
}

// ── the default, and the refusal to disable it ───────────────────────
async function defaultAndValidation() {
  console.log("one default, three paths — and no way to switch it off by accident");

  const root = require("../dist/index.js");
  const claudeAgent = require("../dist/claude-agent.js");
  const egress = require("../dist/egress.js");
  ok("the default is 8 s", DEFAULT_ON_RESULT_TIMEOUT_MS === 8000);
  ok("the Claude Agent path reads the SAME constant, not a copy",
    claudeAgent.DEFAULT_ON_RESULT_TIMEOUT_MS === egress.DEFAULT_ON_RESULT_TIMEOUT_MS &&
      root.DEFAULT_ON_RESULT_TIMEOUT_MS === egress.DEFAULT_ON_RESULT_TIMEOUT_MS);

  const dir = tmpDir("valid");
  const gov = governor(dir);
  const body = async function v() { return "SECRET"; };
  const rejected = (fn) => {
    try { fn(); return null; } catch (e) { return e; }
  };
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    const label = String(bad);
    ok(`tool(): onResultTimeoutMs ${label} is refused, at wrap time`,
      rejected(() => gov.tool(body, { intent: "read", onResult: () => {}, onResultTimeoutMs: bad }))
        instanceof RangeError);
    ok(`governTool: onResultTimeoutMs ${label} is refused, at wrap time`,
      rejected(() =>
        governTool(mockTool(`t_${label}`), { governor: gov, intent: "read", onResult: () => {}, onResultTimeoutMs: bad })
      ) instanceof RangeError);
    ok(`governTools: onResultTimeoutMs ${label} is refused, at wrap time`,
      rejected(() =>
        governTools([mockTool(`a_${label}`)], { governor: gov, intentFor: () => "read", onResult: () => {}, onResultTimeoutMs: bad })
      ) instanceof RangeError);
  }
  ok("a deliberately long deadline IS allowed — the opt-out is explicit",
    typeof gov.tool(body, { intent: "read", onResult: () => {}, onResultTimeoutMs: 300_000 }) ===
      "function");
}

console.log("egress deadline (#120)\n");
await deadlineHolds();
await withinDeadline();
await throwAndTimeoutAgree();
await lateHookNeverReleases();
await neverSettlingHookDoesNotHangTheProcess();
await defaultAndValidation();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
