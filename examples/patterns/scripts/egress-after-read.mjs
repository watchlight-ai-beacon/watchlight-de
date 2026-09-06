// egress-after-read — the hook semantics of the pattern, run against the real SDK.
//
// The pattern's policy verdicts are covered by `suites/egress-after-read.suite.json`.
// This script covers the half that is not a policy verdict: what the hook's
// return, throw and DEADLINE do to the payload, and what the `egress` record
// says about each — the four dispositions the doc claims, on both the
// hand-written `tool()` and the LangChain adapter.
//
// The deadline uses a small explicit value (tens of ms); the 8 s default is
// asserted as a value, never waited on.
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";
import { loadSdk, checks } from "./_sdk.mjs";

const { Watchlight, governTool, EgressTimeout, DEFAULT_ON_RESULT_TIMEOUT_MS } = loadSdk();
const t = checks("egress-after-read (hook dispositions)");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-pattern-egress-"));
const egress = () =>
  fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse)
    .filter((r) => r.event === "egress");

const govern = new Watchlight({ agent: "doc-agent", auditDir });
govern.allow('permit(principal, action == Action::"read", resource);', "read");

const readDoc = (opts) =>
  govern.tool(async function read_doc() { return "SECRET-42"; }, {
    intent: "read",
    resource: "doc/42",
    ...opts,
  });

const run = async (fn) => {
  try { return { value: await fn() }; } catch (e) { return { error: e }; }
};

// 1. return a value → it replaces the payload.
t.ok("a returned value replaces the payload",
  (await readDoc({ onResult: (doc) => doc.replace("SECRET", "<REDACTED>") })()) === "<REDACTED>-42");

// 2. return nothing → passthrough.
t.ok("returning nothing passes the payload through",
  (await readDoc({ onResult: () => undefined })()) === "SECRET-42");

// 3. throw → withheld, fail-closed.
const thrown = await run(readDoc({ onResult: () => { throw new Error("release denied"); } }));
t.ok("a throwing hook withholds the payload (the error propagates, the raw result is not returned)",
  thrown.error?.message === "release denied" && thrown.value === undefined);

// 4. outrun the deadline → withheld the same way, and never released late.
let settledLate = false;
const timedOut = await run(readDoc({
  onResult: async () => { await sleep(300); settledLate = true; return "TOO-LATE"; },
  onResultTimeoutMs: 25,
}));
t.ok("a hook past its deadline withholds the payload (EgressTimeout)",
  timedOut.error instanceof EgressTimeout && timedOut.value === undefined, String(timedOut.error));
await sleep(400);
t.ok("a hook that settles after the deadline is discarded, never released",
  settledLate === true && timedOut.value === undefined);

// The same deadline is on the LangChain adapter — the doc says every path.
const adapter = governTool({ name: "read_doc", invoke: async () => "SECRET-42" }, {
  governor: govern,
  intent: "read",
  resource: "doc/42",
  onResult: () => sleep(300),
  onResultTimeoutMs: 25,
});
const viaAdapter = await run(() => adapter.invoke({ id: 42 }));
t.ok("governTool bounds its hook by the same deadline",
  viaAdapter.error instanceof EgressTimeout && viaAdapter.value === undefined, String(viaAdapter.error));
t.ok("the default deadline is 8 s, and it is the value the adapters share",
  DEFAULT_ON_RESULT_TIMEOUT_MS === 8000);

// The trail: one value-free record per hook run, three dispositions.
const records = egress();
t.ok("one egress record per hook run", records.length === 5, `got ${records.length}`);
t.ok("replaced / passthrough / withheld are recorded as the doc shows",
  records[0].replaced === true && records[0].withheld === undefined &&
  records[1].replaced === false && records[1].withheld === undefined &&
  records.slice(2).every((r) => r.withheld === true && r.replaced === false),
  JSON.stringify(records));
t.ok("a throw and a timeout are indistinguishable in the trail — it records the disposition, not the cause",
  JSON.stringify({ ...records[2], ts: 0, decision_id: 0 }) ===
    JSON.stringify({ ...records[3], ts: 0, decision_id: 0 }));
t.ok("every record joins its decision on decision_id",
  records.every((r) => typeof r.decision_id === "string" && r.decision_id.length > 0));
t.ok("the records are value-free — no payload, no replacement, no error text",
  !JSON.stringify(records).includes("SECRET") && !JSON.stringify(records).includes("TOO-LATE") &&
  !JSON.stringify(records).includes("release denied"));

t.done();
