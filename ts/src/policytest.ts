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
import type { Obligations } from "./backend";

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
  /** The obligations the `Allow` must carry — compared exactly: `redact` as a
   *  set, `maxItems` and `logValues` by value, `extra` by key and value, and a
   *  key absent here must be absent on the result. `{}` asserts the Allow
   *  carries none. The wire spellings `max_items` / `log_values` are accepted
   *  too, so one suite file serves both SDK lanes. Only meaningful with
   *  `expect: "Allow"` — a non-empty expectation on any other verdict is a
   *  malformed fixture. */
  obligations?: ExpectedObligations;
}

/** The obligations a fixture expects an `Allow` to carry. */
export interface ExpectedObligations {
  redact?: string[];
  maxItems?: number;
  logValues?: boolean;
  extra?: Record<string, string>;
  /** Wire spelling of `maxItems`, accepted in suite files. */
  max_items?: number;
  /** Wire spelling of `logValues`, accepted in suite files. */
  log_values?: boolean;
}

/** The outcome of one fixture. */
export interface PolicyTestResult {
  name: string;
  expected: "Allow" | "Deny" | "NeedsApproval";
  actual: "Allow" | "Deny" | "NeedsApproval";
  ok: boolean;
  /** Engine reason — surfaced to explain an unexpected verdict. */
  reason: string;
  /** The obligations the verdict actually carried (an `Allow` only). */
  obligations?: Obligations;
  /** The normalized obligations the fixture expected, when it stated any. */
  expectedObligations?: Obligations;
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
}) => Promise<{ decision: Verdict; reason: string; obligations?: Obligations }>;

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

const EXPECTED_OBLIGATION_KEYS = new Set([
  "redact",
  "maxItems",
  "max_items",
  "logValues",
  "log_values",
  "extra",
]);

/** Pick one of two spellings of the same key; both given with different values
 *  is a contradiction and therefore malformed. */
function oneSpelling(o: Record<string, unknown>, camel: string, snake: string, where: string): unknown {
  const a = o[camel];
  const b = o[snake];
  if (a !== undefined && b !== undefined && a !== b) {
    throw new Error(`${where}: '${camel}' and '${snake}' disagree`);
  }
  return a !== undefined ? a : b;
}

/**
 * Validate and canonicalize a fixture's `obligations` expectation. Strict: an
 * unknown key, an ill-typed value, or a contradiction between spellings is a
 * malformed suite and throws — a typo must never pass as "no expectation".
 * Returns `{}` for an expectation of "no obligations".
 */
export function normalizeExpectedObligations(raw: unknown, where: string): Obligations {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`${where}: 'obligations' must be an object`);
  }
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) {
    if (!EXPECTED_OBLIGATION_KEYS.has(k)) throw new Error(`${where}: unknown obligations key '${k}'`);
  }
  const out: Obligations = {};
  if (o.redact !== undefined) {
    if (!Array.isArray(o.redact) || o.redact.length === 0 ||
        o.redact.some((v) => typeof v !== "string" || !v.trim())) {
      throw new Error(`${where}: 'obligations.redact' must be a non-empty array of non-blank strings`);
    }
    out.redact = [...new Set((o.redact as string[]).map((v) => v.trim()))];
  }
  const maxItems = oneSpelling(o, "maxItems", "max_items", where);
  if (maxItems !== undefined) {
    if (typeof maxItems !== "number" || !Number.isInteger(maxItems) || maxItems < 1) {
      throw new Error(`${where}: 'obligations.maxItems' must be a positive integer`);
    }
    out.maxItems = maxItems;
  }
  const logValues = oneSpelling(o, "logValues", "log_values", where);
  if (logValues !== undefined) {
    if (typeof logValues !== "boolean") {
      throw new Error(`${where}: 'obligations.logValues' must be a boolean`);
    }
    out.logValues = logValues;
  }
  if (o.extra !== undefined) {
    if (!o.extra || typeof o.extra !== "object" || Array.isArray(o.extra) ||
        Object.values(o.extra as Record<string, unknown>).some((v) => typeof v !== "string")) {
      throw new Error(`${where}: 'obligations.extra' must be an object of string values`);
    }
    const extra = { ...(o.extra as Record<string, string>) };
    if (Object.keys(extra).length) out.extra = extra;
  }
  return out;
}

/** JSON with every object's keys sorted, at every depth. */
function sortedJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(sortedJson).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${sortedJson(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

/** Canonical, order-independent rendering of an obligations object, for exact
 *  comparison: `redact` as a sorted set, `extra` with sorted keys. */
function canonicalObligations(o: Obligations | undefined): string {
  if (!o) return "{}";
  const c: Record<string, unknown> = {};
  if (o.redact?.length) c.redact = [...new Set(o.redact)].sort();
  if (o.maxItems !== undefined) c.maxItems = o.maxItems;
  if (o.logValues !== undefined) c.logValues = o.logValues;
  if (o.extra && Object.keys(o.extra).length) c.extra = o.extra;
  return sortedJson(c);
}

/**
 * Run policy fixtures through a decision function and report pass/fail. A
 * verdict mismatch — or, when the fixture states `obligations`, an obligations
 * mismatch — is recorded as a failed result rather than thrown — inspect
 * {@link PolicyTestReport.failed}. A fixture missing a required key (`action` or
 * `expect`), or carrying an ill-typed `obligations` expectation, is a malformed
 * suite and throws.
 */
export async function runPolicyTests(
  decide: DecideFn,
  mint: MintFn,
  cases: readonly PolicyTestCase[]
): Promise<PolicyTestReport> {
  const results: PolicyTestResult[] = [];
  let index = 0;
  for (const c of cases) {
    const where = `fixture ${index} (${c.name ?? "?"})`;
    for (const required of ["action", "expect"] as const) {
      if (c[required] === undefined) {
        throw new Error(`${where}: missing required key '${required}'`);
      }
    }
    index += 1;
    const expected = normalizeVerdict(c.expect);
    const expectedObligations =
      c.obligations !== undefined ? normalizeExpectedObligations(c.obligations, where) : undefined;
    if (expectedObligations && Object.keys(expectedObligations).length && expected !== "Allow") {
      throw new Error(`${where}: 'obligations' can only be expected on an Allow, not ${expected}`);
    }
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
    const obligationsOk =
      expectedObligations === undefined ||
      canonicalObligations(expectedObligations) === canonicalObligations(d.obligations);
    const result: PolicyTestResult = {
      name: c.name ?? `${c.action} on ${c.resource ?? "resource"}`,
      expected,
      actual,
      ok: actual === expected && obligationsOk,
      reason: d.reason ?? "",
    };
    if (d.obligations) result.obligations = d.obligations;
    if (expectedObligations !== undefined) result.expectedObligations = expectedObligations;
    results.push(result);
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
