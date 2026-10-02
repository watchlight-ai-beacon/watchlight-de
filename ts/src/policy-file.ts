// Reading a policy file into the entries a governor loads.
//
// One reader for every entry point that takes a policy file — `load`, `reload`
// and `watchlight policy test` — so they accept the same shapes and refuse the
// same mistakes. The Python twin is `watchlight/_policy_file.py`.
//
// A policy file is JSON in one of three shapes:
//
//   * a list of policy objects: `[{"name", "code"}, ...]`
//   * an object holding that list: `{"policies": [...]}` (a policy test suite
//     has this shape, so a suite file loads as a policy file)
//   * ONE policy object: `{"name", "code"}` — the shape the MCP PEP
//     (`watchlight-mcp`) reads, one policy per file, so one file serves both
//
// A policy object needs a non-empty string `code`; `name` is optional. Other
// keys (`id`, `description`, …) are ignored, except `active`: a policy marked
// `"active": false` is refused, because the governor has no inactive state and
// loading it would enforce it.
//
// FAIL LOUDLY, NEVER EMPTY BY ACCIDENT. A missing path, a directory, invalid
// JSON, an unrecognised shape and a malformed entry all throw, naming the file.
// So does a file that holds no policies, unless the caller opts in with
// `allowEmpty`. Cedar denies by default, so none of these was ever permissive,
// but each one used to load nothing without a word, and a governor that
// silently holds no policy denies every call for a reason nobody can see.
import * as fs from "node:fs";

/** One policy as a governor loads it. */
export interface PolicyEntry {
  name?: string;
  code: string;
}

/** @internal */
export const EXPECTED_SHAPE =
  'a list of {"name", "code"} objects, {"policies": [...]}, or a single {"name", "code"} object';

function codedError(message: string, code: string): Error {
  return Object.assign(new Error(message), { code });
}

/** Read `file` and return its policy entries, validated. Throws for a missing
 *  path (`code: "ENOENT"`), a directory (`code: "EISDIR"`), invalid JSON, an
 *  unrecognised shape, a malformed entry, and — without `allowEmpty` — a file
 *  that holds no policies. `op` prefixes every message.
 *  @internal */
export function readPolicyFile(
  file: string,
  opts: { op: string; allowEmpty?: boolean }
): PolicyEntry[] {
  const { op } = opts;
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch {
    throw codedError(`${op}: no such policy file: ${file}`, "ENOENT");
  }
  if (stat.isDirectory()) {
    throw codedError(
      `${op}: ${file} is a directory, not a policy file. Load each policy file in it by name.`,
      "EISDIR"
    );
  }
  let data: unknown;
  try {
    data = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    throw new Error(`${op}: ${file} is not valid JSON: ${(e as Error).message}`);
  }
  return policyEntries(data, file, opts);
}

/** The policy entries of parsed policy-file `data`, validated. `where` names
 *  the source in every message.
 *  @internal */
export function policyEntries(
  data: unknown,
  where: string,
  opts: { op: string; allowEmpty?: boolean }
): PolicyEntry[] {
  const { op } = opts;
  let entries: unknown[];
  if (Array.isArray(data)) {
    entries = data;
  } else if (data !== null && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    const hasPolicies = "policies" in obj;
    const hasCode = "code" in obj;
    if (hasPolicies && hasCode) {
      throw new Error(
        `${op}: ${where} has both "policies" and "code", so it is not clear whether it ` +
          `is one policy or a set. Expected ${EXPECTED_SHAPE}.`
      );
    }
    if (hasPolicies) {
      if (!Array.isArray(obj.policies)) {
        throw new Error(
          `${op}: ${where}: "policies" must be a list of {"name", "code"} objects, ` +
            `not ${kind(obj.policies)}.`
        );
      }
      entries = obj.policies;
    } else if (hasCode) {
      entries = [obj];
    } else {
      const hint =
        "policyFile" in obj || "policy_file" in obj
          ? " It looks like a policy test suite that names its policies in policyFile; " +
            "load that file instead."
          : "";
      throw new Error(
        `${op}: ${where} has neither "policies" nor "code", so it holds no policy. ` +
          `Expected ${EXPECTED_SHAPE}.${hint}`
      );
    }
  } else {
    throw new Error(`${op}: ${where} is ${kind(data)}. Expected ${EXPECTED_SHAPE}.`);
  }

  entries.forEach((entry, index) => checkEntry(entry, index, where, op));

  if (!entries.length && !opts.allowEmpty) {
    throw new Error(
      `${op}: ${where} defines no policies, so every governed call would be denied. ` +
        `Expected ${EXPECTED_SHAPE}. To load an empty set on purpose, pass { allowEmpty: true }.`
    );
  }
  return entries as PolicyEntry[];
}

function checkEntry(entry: unknown, index: number, where: string, op: string): void {
  let label = `policy #${index + 1} in ${where}`;
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error(`${op}: ${label} is ${kind(entry)}, not a {"name", "code"} object.`);
  }
  const e = entry as Record<string, unknown>;
  if (e.name !== undefined && e.name !== null && typeof e.name !== "string") {
    throw new Error(`${op}: ${label}: "name" must be a string, not ${kind(e.name)}.`);
  }
  if (e.name) label = `policy "${e.name}" in ${where}`;
  if (typeof e.code !== "string" || !e.code.trim()) {
    throw new Error(`${op}: ${label} has no Cedar "code" (a non-empty string is required).`);
  }
  if ("active" in e && e.active !== true) {
    throw new Error(
      `${op}: ${label} is marked "active": ${JSON.stringify(e.active)}. Every policy a ` +
        `governor loads is enforced, so an inactive policy cannot be loaded; remove it ` +
        `from the file, or set "active": true.`
    );
  }
}

function kind(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return "a list";
  switch (typeof value) {
    case "boolean":
      return "a boolean";
    case "number":
      return "a number";
    case "string":
      return "a string";
    case "object":
      return "an object";
    default:
      return typeof value;
  }
}
