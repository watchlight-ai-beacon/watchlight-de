#!/usr/bin/env node
// The `watchlight` command for the Node/TypeScript lane.
//
//   npx watchlight policy test <suite.json>
//   npx watchlight audit check [audit.jsonl] [--limit N]
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
// `audit check` lists the lines of an audit file that `counters()` cannot read,
// by line number and reason, never content — each counts toward quotas until
// the file is repaired.
//
// The dashboard lives in the Python package (`watchlight dev`).

import * as path from "node:path";
import * as fs from "node:fs";
import { AuditTrailUnreadable, findUnreadableLines, UNREADABLE_REASONS, Watchlight } from "./index";
import { policyEntries } from "./policy-file";
import { loadTestSuite, type PolicyTestReport } from "./policytest";

const USAGE = `watchlight — Watchlight Developer Edition (Node)

usage:
  watchlight policy test <suite.json>   run policy fixtures, exit 1 on failure
  watchlight audit check [audit.jsonl] [--limit N]
                                        list the lines counters() cannot read,
                                        exit 1 if there are any (default file:
                                        $WATCHLIGHT_AUDIT_DIR/audit.jsonl, else
                                        .watchlight/audit.jsonl)

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
    console.error(`watchlight: could not read suite '${file}': ${errorText(e)}`);
    return 2;
  }
  // Fresh, policy-free governor (fail-closed); load only what the suite declares.
  // No audit is written — `test()` uses the engine's decision core directly.
  const gov = new Watchlight({ agent: "policy-test" });
  if (!suite.policyFile && suite.policies == null) {
    // Zero policies would deny every fixture, and a suite of Deny fixtures
    // would pass green against nothing.
    console.error(
      `watchlight: suite '${file}' declares no policies: give it a policyFile or inline policies`
    );
    return 2;
  }
  try {
    if (suite.policyFile) {
      gov.load(path.resolve(path.dirname(file), suite.policyFile));
    }
    if (suite.policies != null) {
      const inline = policyEntries(suite.policies, `suite '${file}'`, {
        op: "policy test",
        allowEmpty: Boolean(suite.policyFile),
      });
      for (const p of inline) gov.allow(p.code, p.name);
    }
    // Compile now, so a Cedar error is reported as itself rather than as the
    // first fixture's failure.
    await gov.ready();
  } catch (e) {
    // A policy file that is missing, malformed or empty, a policy the engine
    // refused to compile, or a policy it could not honour as written —
    // reported here rather than run, since the suite would otherwise be
    // testing a different policy set from the one on the page.
    console.error(`watchlight: ${errorText(e)}`);
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
    console.error(`watchlight: ${errorText(e)}`);
    return 2;
  }
  printReport(file, report);
  return report.failed > 0 ? 1 : 0;
}

function defaultAuditPath(): string {
  const dir = process.env.WATCHLIGHT_AUDIT_DIR?.trim();
  return path.join(dir ? dir : ".watchlight", "audit.jsonl");
}

function auditCheck(args: string[]): number {
  let file: string | undefined;
  let limit = 100;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--limit") {
      const n = Number(args[++i]);
      if (!Number.isSafeInteger(n) || n < 0) {
        console.error("watchlight audit check: --limit takes a non-negative integer");
        return 2;
      }
      limit = n;
    } else if (file === undefined) {
      file = args[i];
    } else {
      console.error(USAGE);
      return 2;
    }
  }
  file ??= defaultAuditPath();
  let found;
  try {
    found = findUnreadableLines(file, { limit });
  } catch (e) {
    if (e instanceof AuditTrailUnreadable) {
      console.error(`watchlight: audit trail '${file}' is not readable`);
      return 2;
    }
    throw e;
  }
  if (!fs.existsSync(file)) {
    console.log(`watchlight audit check — ${file}: no such file, nothing to check`);
    return 0;
  }
  console.log(`watchlight audit check — ${file} (${found.lines} lines)`);
  for (const f of found.findings) console.log(`  line ${f.line}: ${UNREADABLE_REASONS[f.reason]}`);
  if (found.truncated) {
    console.log(`  … and ${found.total - found.findings.length} more (raise --limit to list them)`);
  }
  if (found.total === 0) {
    console.log("no unreadable lines: every line counts as what it is");
    return 0;
  }
  console.log(
    `${found.total} unreadable line(s). They count toward quotas: a line that ` +
      "cannot be read at all toward every quota, a decision with an unreadable ts " +
      "toward every quota it matches. They never age out of a window. Remove or " +
      "repair them, or rotate the file."
  );
  return 1;
}

/** A thrown value as text: an Error's message, or the value itself — never
 *  `undefined` for a throw that is not an Error. */
function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  try {
    return typeof e === "string" ? e : (JSON.stringify(e) ?? String(e));
  } catch {
    return String(e);
  }
}

async function main(argv: string[]): Promise<number> {
  const [cmd, sub, ...rest] = argv;
  if (cmd === "policy" && sub === "test") return policyTest(rest[0]);
  if (cmd === "audit" && sub === "check") return auditCheck(rest);
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
    console.error(`watchlight: ${errorText(e)}`);
    process.exit(1);
  });
