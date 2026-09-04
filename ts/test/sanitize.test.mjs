// @watchlight/sdk sanitize test — deterministic PII detection + redaction modes,
// value-free report, consistent tagging, Luhn validation, fail-closed, and the
// governed Watchlight.sanitize value-free audit record.
import { createRequire } from "node:module";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { sanitize, SanitizeError, Watchlight, DECISION_ID_MAX_LENGTH } = require("../dist/index.js");
const here = dirname(fileURLToPath(import.meta.url));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const SAMPLE =
  "Contact alice@acme.com or bob@acme.com. Card 4111 1111 1111 1111, SSN 123-45-6789, " +
  "phone (415) 555-0132, IP 10.0.0.5, IBAN GB82 WEST 1234 5698 7654 32, key sk-ABCDEFGHIJKLMNOP1234.";

async function main() {
  // ── detection + value-free report ──
  const { text, report } = sanitize(SAMPLE);
  ok("detects email", report.counts.EMAIL === 2, JSON.stringify(report.counts));
  ok("detects credit card (Luhn ok)", report.counts.CREDIT_CARD === 1);
  ok("detects SSN", report.counts.SSN === 1);
  ok("detects phone", report.counts.PHONE === 1);
  ok("detects IPv4", report.counts.IPV4 === 1);
  ok("detects IBAN", report.counts.IBAN === 1);
  ok("detects API key", report.counts.API_KEY === 1);
  ok("report has total + version, no values", report.total >= 8 && report.detectorVersion && !JSON.stringify(report).includes("acme.com"));

  // ── redacted text contains no raw PII ──
  ok("no raw email in output", !text.includes("alice@acme.com") && !text.includes("bob@acme.com"));
  ok("no raw card/ssn/key in output", !text.includes("4111") && !text.includes("123-45-6789") && !text.includes("sk-ABCDEFG"));

  // ── consistent tagging: same value → same tag; distinct → distinct ──
  const t = sanitize("x alice@acme.com y alice@acme.com z bob@acme.com", { mode: "tag" }).text;
  ok("same email → same tag", (t.match(/<EMAIL_1>/g) || []).length === 2);
  ok("distinct email → distinct tag", t.includes("<EMAIL_2>"));

  // ── modes ──
  ok("mask mode", sanitize("a@b.com", { mode: "mask" }).text === "[EMAIL]");
  ok("hash mode deterministic", sanitize("a@b.com", { mode: "hash" }).text === sanitize("a@b.com", { mode: "hash" }).text);

  // ── Luhn rejects an invalid card-shaped number ──
  ok("invalid Luhn not flagged as card", (sanitize("num 1234 5678 9012 3456").report.counts.CREDIT_CARD ?? 0) === 0);

  // ── types filter ──
  ok("types filter restricts detection", (sanitize(SAMPLE, { types: ["EMAIL"] }).report.counts.SSN ?? 0) === 0);

  // ── fail-closed ──
  let threw = false;
  try { sanitize(12345); } catch (e) { threw = e instanceof SanitizeError; }
  ok("non-string input is fail-closed (throws SanitizeError)", threw);

  // ── governed: value-free audit ──
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-san-"));
  const g = new Watchlight({ agent: "doc-agent", auditDir });
  const r = g.sanitize(SAMPLE, { intent: "read", resource: "statement.pdf" });
  ok("govern.sanitize returns redacted text", !r.text.includes("alice@acme.com"));
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("audit records sanitization event + counts", raw.includes('"event":"sanitization"') && raw.includes('"EMAIL":2'));
  ok("audit is value-free (no PII values)", !raw.includes("acme.com") && !raw.includes("123-45-6789") && !raw.includes("4111"));
  ok("audit line without decisionId carries no decision_id", !JSON.parse(raw.trim().split("\n").pop()).decision_id);

  // ── decisionId: echoed on the report, never interpreted ──
  const echoed = sanitize("a@b.com", { decisionId: "dec-123" });
  ok("pure sanitize echoes decisionId on the report", echoed.report.decisionId === "dec-123");
  ok("report has no decisionId when none supplied", !("decisionId" in sanitize("a@b.com").report));

  // ── decisionId: fail-closed validation (bounded, no control characters) ──
  const rejects = (id) => {
    try { sanitize("a@b.com", { decisionId: id }); return false; } catch (e) { return e instanceof SanitizeError; }
  };
  ok("rejects decisionId with newline (audit-line injection)", rejects("dec-1\n{\"decision\":\"Allow\"}"));
  ok("rejects decisionId with other control chars", rejects("dec\u0000id") && rejects("dec\u007fid") && rejects("dec\u0085id"));
  ok("rejects decisionId with Unicode line separators", rejects("dec\u2028id") && rejects("dec\u2029id"));
  ok("rejects over-long decisionId", rejects("x".repeat(DECISION_ID_MAX_LENGTH + 1)));
  ok("accepts decisionId at the length bound", !rejects("x".repeat(DECISION_ID_MAX_LENGTH)));
  ok("rejects empty / non-string decisionId", rejects("") && rejects(42) && rejects({}));
  const badDir = fs.mkdtempSync(join(os.tmpdir(), "wl-san-bad-"));
  const gBad = new Watchlight({ agent: "doc-agent", auditDir: badDir });
  let governedRejected = false;
  try { gBad.sanitize("a@b.com", { decisionId: "a\nb" }); } catch (e) { governedRejected = e instanceof SanitizeError; }
  ok("governed sanitize is fail-closed on a malformed decisionId (nothing written)", governedRejected && !fs.existsSync(join(badDir, "audit.jsonl")));

  // ── acceptance: authorize → sanitize({ decisionId }) share one decision_id ──
  const corrDir = fs.mkdtempSync(join(os.tmpdir(), "wl-san-corr-"));
  const gc = new Watchlight({ agent: "doc-agent", auditDir: corrDir });
  gc.allow('permit(principal, action == Action::"read", resource);', "allow-read");
  const decision = await gc.authorize({ action: "read", resource: "statement.pdf" });
  ok("authorize returns a decisionId", typeof decision.decisionId === "string" && decision.decisionId.length > 0);
  const sr = gc.sanitize(SAMPLE, { intent: "read", resource: "statement.pdf", decisionId: decision.decisionId });
  ok("governed sanitize echoes decisionId on the report", sr.report.decisionId === decision.decisionId);
  const lines = fs.readFileSync(join(corrDir, "audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const authLine = lines.find((l) => l.decision === "Allow" && !l.event);
  const sanLine = lines.find((l) => l.event === "sanitization");
  ok("two audit lines share decision_id", authLine && sanLine && authLine.decision_id === decision.decisionId && sanLine.decision_id === decision.decisionId);
  ok("sanitization line keeps its existing fields", sanLine.mode === "tag" && sanLine.detector && sanLine.total >= 8 && sanLine.counts.EMAIL === 2);
  ok("correlated audit is still value-free", !JSON.stringify(lines).includes("acme.com"));

  // ── type check: the documented call shape compiles against dist/index.d.ts ──
  let typesOk = true, typesErr = "";
  try {
    execFileSync(process.execPath, [
      join(here, "..", "node_modules", "typescript", "bin", "tsc"),
      "--noEmit", "--strict", "--target", "ES2020", "--module", "commonjs", "--moduleResolution", "node",
      "--esModuleInterop", "--skipLibCheck", "--types", "node", join(here, "sanitize-options.typecheck.ts"),
    ], { stdio: "pipe" });
  } catch (e) { typesOk = false; typesErr = String(e.stdout || e.message).slice(0, 400); }
  ok("SanitizeOptions type accepts { resource, intent, decisionId }", typesOk, typesErr);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
