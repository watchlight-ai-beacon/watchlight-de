// @watchlight/sdk sanitize test — deterministic PII detection + redaction modes,
// value-free report, consistent tagging, Luhn validation, fail-closed, and the
// governed Watchlight.sanitize value-free audit record.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { sanitize, SanitizeError, Watchlight } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const SAMPLE =
  "Contact alice@acme.com or bob@acme.com. Card 4111 1111 1111 1111, SSN 123-45-6789, " +
  "phone (415) 555-0132, IP 10.0.0.5, IBAN GB82 WEST 1234 5698 7654 32, key sk-ABCDEFGHIJKLMNOP1234.";

function main() {
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

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
