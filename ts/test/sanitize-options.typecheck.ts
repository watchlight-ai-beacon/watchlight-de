// Compile-time check (run by sanitize.test.mjs via tsc --noEmit): the exported
// SanitizeOptions type accepts the documented call shape — `resource`, `intent`,
// and the `decisionId` that joins the sanitization audit line to its decision —
// and the report echoes `decisionId`. Not part of the package build.
import { govern, sanitize, Watchlight, type SanitizeOptions, type SanitizeResult } from "../dist/index";

const opts: SanitizeOptions = { resource: "statement.pdf", intent: "read", decisionId: "dec-123" };
const governed: SanitizeResult = govern.sanitize("text", opts);
const pure: SanitizeResult = sanitize("text", { resource: "statement.pdf", intent: "read", decisionId: "dec-123" });
const echoed: string | undefined = governed.report.decisionId ?? pure.report.decisionId;

async function documented(g: Watchlight): Promise<string | undefined> {
  const { decisionId } = await g.authorize({ action: "read", resource: "statement.pdf" });
  return g.sanitize("text", { resource: "statement.pdf", decisionId }).report.decisionId;
}

export { echoed, documented };
