// Denied before it executed — a governed transfer against a stub bank (Node).
//
//   npm i -g @watchlight/sdk          # or: cd ts && npm install && npm run build
//   node examples/showcase/denied-before-execute/agent.mjs
//
// Runs offline: no API key, no network. A stub "bank" stands in for a payments
// API; the only thing it does is count the calls it receives. The `transfer`
// tool is governed, so the engine authorizes every call against
// policy.suite.json BEFORE the function body runs:
//
//   * a transfer above the threshold matches a `forbid` — the call is refused
//     and the stub's counter stays at 0;
//   * a small transfer matches the `permit` — the stub is called exactly once.
//
// For each attempt the script prints the verdict, the decision id and the exact
// audit line the engine wrote, and exits non-zero if the stub's counter
// contradicts either verdict or if the audit line carries the call's arguments.
//
// The same file that the agent loads is also a policy test suite:
//
//   watchlight policy test examples/showcase/denied-before-execute/policy.suite.json
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as fs from "node:fs";

const require = createRequire(import.meta.url);

// Resolve the SDK from an installed package first, then from the in-repo build.
function loadSdk() {
  const candidates = ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", import.meta.url))];
  for (const spec of candidates) {
    try { return require(spec); } catch (e) { if (e?.code !== "MODULE_NOT_FOUND") throw e; }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}
const { Watchlight, Denied } = loadSdk();

const here = dirname(fileURLToPath(import.meta.url));
const auditDir = join(here, ".watchlight");
const auditPath = join(auditDir, "audit.jsonl");

/** Stands in for the payments API. Every call increments `calls`. */
class StubBank {
  calls = 0;
  transfer(to, _amount) {
    this.calls += 1;
    return `transfer #${this.calls} settled to account/${to}`;
  }
}
const bank = new StubBank();

const govern = new Watchlight({ agent: "payments-agent", auditDir });
govern.load(join(here, "policy.suite.json")); // {"policies": [...]} — the file the suite tests

// Runs only after the engine returns Allow for (payments-agent, transfer,
// account/<to>) with context.amount. On Deny the SDK throws before the body.
const transfer = govern.tool(async function transfer(to, amount) {
  return bank.transfer(to, amount);
}, {
  intent: "transfer",
  resource: (to) => `account/${to}`,
  context: (_to, amount) => ({ amount }),
});

// ── assertions ───────────────────────────────────────────────────────────────

const failures = [];
function check(condition, what) {
  console.log(`  ${condition ? "✓" : "✗"} ${what}`);
  if (!condition) failures.push(what);
}

function auditLines() {
  if (!fs.existsSync(auditPath)) return [];
  return fs.readFileSync(auditPath, "utf8").split("\n").filter((l) => l.trim());
}

/** Make one governed call and compare what happened with the verdict. */
async function attempt(to, amount, expect) {
  console.log(`\nattempt: transfer amount=${amount} → account/${to}`);
  const linesBefore = auditLines().length;
  const callsBefore = bank.calls;

  let verdict;
  try {
    const outcome = await transfer(to, amount);
    verdict = "Allow";
    console.log(`result:  ${outcome}`);
  } catch (e) {
    if (!(e instanceof Denied)) throw e;
    verdict = "Deny";
    console.log(`refused: ${e.message}`);
  }

  const newLines = auditLines().slice(linesBefore);
  const line = newLines.at(-1) ?? "";
  const record = line ? JSON.parse(line) : {};
  console.log(`verdict: ${verdict}    decision_id: ${record.decision_id}`);
  console.log(`audit:   ${line || "(no record written)"}`);

  check(verdict === expect, `verdict is ${expect}`);
  check(newLines.length === 1 && record.decision === expect,
    "exactly one decision record was written for this call");
  check(!("amount" in record) && !("context" in record),
    "the audit line is value-free (no amount, no arguments)");
  if (expect === "Deny") {
    check(bank.calls === callsBefore, `the stub bank never received the call (calls=${bank.calls})`);
  } else {
    check(bank.calls === callsBefore + 1, `the stub bank received the call exactly once (calls=${bank.calls})`);
  }
}

async function main() {
  console.log(`stub bank calls at start: ${bank.calls}`);

  // 1. The large transfer: forbidden by policy, refused before the body runs.
  await attempt("acct-b", 25000, "Deny");
  check(bank.calls === 0, "stub bank calls == 0 after the denied transfer");

  // 2. A small transfer: permitted, reaches the stub exactly once.
  await attempt("acct-b", 250, "Allow");
  check(bank.calls === 1, "stub bank calls == 1 after the allowed transfer");

  console.log();
  if (failures.length) {
    console.log(`FAILED: ${failures.length} assertion(s) did not hold`);
    return 1;
  }
  console.log("OK — the large transfer was denied before it executed; the small one ran once.");
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => { console.error(e); process.exit(1); });
