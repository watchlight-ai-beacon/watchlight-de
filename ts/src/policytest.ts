// Policy test harness — golden tests for DE policies.
//
// A policy is the only thing standing between an agent and a real action, so it
// deserves the same unit-testing discipline as the code around it. This module
// runs a list of fixtures against the loaded policies and reports which pass:
// each case asserts the expected verdict (Allow / Deny / NeedsApproval) for a
// `(principal, action, resource, context)`. It contains ZERO decision logic —
// every verdict comes from the engine, via the same decision core `authorize`
// uses — and it never writes to the audit trail, so CI runs leave no residue.
//
//   import { govern } from "@watchlight/sdk";
//   govern.load("watchlight.policy.json");
//   const r = await govern.test([
//     { name: "under limit allows", action: "book",
//       context: { amount: 200, limit: 500, refundable: true }, expect: "Allow" },
//   ]);
//   if (r.failed) throw new Error(`${r.failed} policy tests failed`);
//
// Or from CI, with the `watchlight` CLI:  npx watchlight policy test suite.json

import * as fs from "node:fs";

/** A single policy fixture: an input and the verdict it must produce. */
export interface PolicyTestCase {
  /** Human-readable label (defaults to `"<action> on <resource>"`). */
  name?: string;
  /** The intent / action being authorized (Cedar `action == Action::"<action>"`). */
  action: string;
  /** Acting principal, e.g. `User::"alice"`. Defaults to the governor's agent. */
  principal?: string;
  /** Cedar resource entity. Defaults to `"resource"`. */
  resource?: string;
  /** Attributes exposed to Cedar `context.*`. */
  context?: Record<string, unknown>;
  /** Mint a valid single-use approval token for this case and assert the
   *  human-confirmed downgrade (turns a `NeedsApproval` into `Allow`). */
  approved?: boolean;
  /** The verdict this case must produce. Case-insensitive. */
  expect: "Allow" | "Deny" | "NeedsApproval";
}

/** The outcome of one fixture. */
export interface PolicyTestResult {
  name: string;
  expected: "Allow" | "Deny" | "NeedsApproval";
  actual: "Allow" | "Deny" | "NeedsApproval";
  ok: boolean;
  /** Engine reason — surfaced to explain an unexpected verdict. */
  reason: string;
}

/** The aggregate report. `failed === 0` means the suite passed. */
export interface PolicyTestReport {
  total: number;
  passed: number;
  failed: number;
  results: PolicyTestResult[];
}

/** A suite file: inline policies and/or a policy file, plus the fixtures. */
export interface PolicyTestSuite {
  /** Inline Cedar policies. */
  policies?: { name?: string; code: string }[];
  /** Path to a `watchlight.policy.json` (resolved relative to the suite file). */
  policyFile?: string;
  /** The fixtures to run. */
  tests: PolicyTestCase[];
}

type Verdict = "Allow" | "Deny" | "NeedsApproval";

/** The pure decision function the harness drives — the same core `authorize`
 *  uses, minus the audit write. */
export type DecideFn = (req: {
  action: string;
  principal?: string;
  resource?: string;
  context?: Record<string, unknown>;
  approval?: string;
}) => Promise<{ decision: Verdict; reason: string }>;

/** Mints a single-use approval token bound to a challenge — used when a fixture
 *  sets `approved: true` to exercise the human-confirmed path. */
export type MintFn = (challenge: {
  action: string;
  principal?: string;
  resource?: string;
}) => string;

/** Normalize a caller-supplied verdict string to the canonical spelling.
 *  Anything unrecognized is returned verbatim so a typo fails loudly. */
function normalizeVerdict(v: unknown): Verdict {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "allow" || s === "permit") return "Allow";
  if (s === "deny") return "Deny";
  if (s === "needsapproval" || s === "needs_approval" || s === "approve" || s === "approval")
    return "NeedsApproval";
  return (v as Verdict) ?? "Deny";
}

/**
 * Run policy fixtures through a decision function and report pass/fail. A
 * verdict mismatch is recorded as a failed result rather than thrown — inspect
 * {@link PolicyTestReport.failed}. A fixture missing a required key (`action` or
 * `expect`) is a malformed suite and throws.
 */
export async function runPolicyTests(
  decide: DecideFn,
  mint: MintFn,
  cases: readonly PolicyTestCase[]
): Promise<PolicyTestReport> {
  const results: PolicyTestResult[] = [];
  let index = 0;
  for (const c of cases) {
    for (const required of ["action", "expect"] as const) {
      if (c[required] === undefined) {
        throw new Error(
          `fixture ${index} (${c.name ?? "?"}): missing required key '${required}'`
        );
      }
    }
    index += 1;
    const expected = normalizeVerdict(c.expect);
    const approval = c.approved
      ? mint({ action: c.action, principal: c.principal, resource: c.resource })
      : undefined;
    const d = await decide({
      action: c.action,
      principal: c.principal,
      resource: c.resource,
      context: c.context,
      approval,
    });
    const actual = normalizeVerdict(d.decision);
    results.push({
      name: c.name ?? `${c.action} on ${c.resource ?? "resource"}`,
      expected,
      actual,
      ok: actual === expected,
      reason: d.reason ?? "",
    });
  }
  const passed = results.filter((r) => r.ok).length;
  return { total: results.length, passed, failed: results.length - passed, results };
}

/**
 * Load a suite file. Accepts `{ policies?, policyFile? | policy_file?, tests }`
 * (a bare array of tests is also accepted). Throws on malformed JSON so a broken
 * suite fails the CI step rather than silently passing.
 */
export function loadTestSuite(file: string): PolicyTestSuite {
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  if (Array.isArray(data)) return { tests: data };
  return {
    policies: data.policies,
    policyFile: data.policyFile ?? data.policy_file,
    tests: data.tests ?? data.cases ?? [],
  };
}
