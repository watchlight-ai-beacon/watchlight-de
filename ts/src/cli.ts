#!/usr/bin/env node
// The `watchlight` command for the Node/TypeScript lane.
//
//   npx watchlight policy test <suite.json>
//
// Runs a policy test suite (golden fixtures → expected Allow/Deny/NeedsApproval)
// against the DE engine and exits non-zero if any fixture fails — drop it into
// CI to gate a policy change before it can gate a real action. The suite file is
//
//   { "policyFile": "watchlight.policy.json",       // and/or inline "policies"
//     "tests": [ { "name": "...", "action": "book",
//                  "context": { "amount": 200, "limit": 500 },
//                  "expect": "Allow" } ] }
//
// The dashboard lives in the Python package (`watchlight dev`); this Node CLI is
// scoped to policy testing.

import * as path from "node:path";
import { PolicyError, Watchlight } from "./index";
import { loadTestSuite, type PolicyTestReport } from "./policytest";

const USAGE = `watchlight — Watchlight Developer Edition (Node)

usage:
  watchlight policy test <suite.json>   run policy fixtures, exit 1 on failure

suite.json:
  { "policyFile": "watchlight.policy.json",
    "policies":   [ { "name": "...", "code": "permit(...);" } ],
    "tests":      [ { "name": "under limit", "action": "book",
                      "principal": "User::\\"alice\\"", "resource": "trip/42",
                      "context": { "amount": 200, "limit": 500 },
                      "expect": "Allow" } ] }
`;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const green = (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s);
const red = (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s);
const dim = (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s);

function printReport(file: string, report: PolicyTestReport): void {
  console.log(`watchlight policy test — ${file}\n`);
  for (const r of report.results) {
    if (r.ok) {
      console.log(`  ${green("✓")} ${r.name} ${dim("→ " + r.actual)}`);
    } else {
      const why = r.reason ? dim(`  (${r.reason})`) : "";
      const what =
        r.expected === r.actual && r.expectedObligations !== undefined
          ? `— expected obligations ${JSON.stringify(r.expectedObligations)}, got ${JSON.stringify(r.obligations ?? {})}`
          : `— expected ${r.expected}, got ${r.actual}`;
      console.log(`  ${red("✗")} ${r.name} ${red(what)}${why}`);
    }
  }
  const summary = `${report.passed} passed, ${report.failed} failed (${report.total} total)`;
  console.log("\n" + (report.failed ? red(summary) : green(summary)));
}

async function policyTest(file: string | undefined): Promise<number> {
  if (!file) {
    console.error("watchlight policy test: missing <suite.json>\n");
    console.error(USAGE);
    return 2;
  }
  let suite;
  try {
    suite = loadTestSuite(file);
  } catch (e) {
    console.error(`watchlight: could not read suite '${file}': ${(e as Error).message}`);
    return 2;
  }
  // Fresh, policy-free governor (fail-closed); load only what the suite declares.
  // No audit is written — `test()` uses the engine's decision core directly.
  const gov = new Watchlight({ agent: "policy-test" });
  try {
    if (suite.policyFile) {
      gov.load(path.resolve(path.dirname(file), suite.policyFile));
    }
    for (const p of suite.policies ?? []) gov.allow(p.code, p.name);
  } catch (e) {
    if (!(e instanceof PolicyError)) throw e;
    // A policy the engine could not honour as written — reported here rather
    // than run, since the suite would otherwise be testing a different policy
    // from the one on the page.
    console.error(`watchlight: ${e.message}`);
    return 2;
  }

  if (!suite.tests || suite.tests.length === 0) {
    console.error(`watchlight: suite '${file}' has no tests`);
    return 2;
  }
  let report;
  try {
    report = await gov.test(suite.tests);
  } catch (e) {
    // malformed fixture (missing action/expect)
    console.error(`watchlight: ${(e as Error).message}`);
    return 2;
  }
  printReport(file, report);
  return report.failed > 0 ? 1 : 0;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, sub, ...rest] = argv;
  if (cmd === "policy" && sub === "test") return policyTest(rest[0]);
  if (cmd === "--help" || cmd === "-h" || cmd === undefined) {
    console.log(USAGE);
    return 0;
  }
  console.error(`watchlight: unknown command '${[cmd, sub].filter(Boolean).join(" ")}'\n`);
  console.error(USAGE);
  return 2;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(`watchlight: ${e?.message ?? e}`);
    process.exit(1);
  });
