// pii-before-read — the sanitize half of the pattern (the policy half is
// suites/pii-before-read.suite.json).
//
// Asserts: structured PII and every `known` value are removed from the text the
// agent would read; the report and the audit record are value-free (counts by
// type only — never a value); `decisionId` is echoed onto the report and written
// as `decision_id` on the `sanitization` audit line so it joins the `authorize`
// decision; and sanitization is fail-closed on a malformed correlation id.
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";
import { loadSdk, checks } from "./_sdk.mjs";

const { Watchlight, SanitizeError } = loadSdk();
const t = checks("pii-before-read (sanitize)");

// Illustrative values only. The SSN and card number are the standard test
// patterns; the "known" values stand in for what the application already holds.
const applicant = { fullName: "Jordan Example", street: "12 Sample Lane" };
const text =
  `Applicant ${applicant.fullName}, DOB: 1990-04-12, of ${applicant.street}. ` +
  `SSN 123-45-6789, card 4111 1111 1111 1111. Reference: JORDAN EXAMPLE.`;
const decisionId = "dec-7f1c9e";

const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-pattern-pii-"));
try {
  const govern = new Watchlight({ agent: "doc-agent", auditDir });
  const { text: safe, report } = govern.sanitize(text, {
    resource: "intake-form.txt",
    known: [applicant.fullName, applicant.street],
    decisionId,
  });

  // The agent never sees a value.
  const leaked = [applicant.fullName, applicant.street, "123-45-6789", "4111 1111 1111 1111", "1990-04-12"];
  t.ok("no structured PII or known value survives in the sanitized text",
    leaked.every((v) => !safe.toLowerCase().includes(v.toLowerCase())), safe);
  t.ok("known values are replaced by stable KNOWN tags (case-insensitive, every occurrence)",
    (safe.match(/<KNOWN_\d+>/g) ?? []).length === 3 && (report.counts.KNOWN ?? 0) === 3, JSON.stringify(report.counts));
  t.ok("SSN, credit card and DOB are each counted once",
    report.counts.SSN === 1 && report.counts.CREDIT_CARD === 1 && report.counts.DOB === 1, JSON.stringify(report.counts));

  // The report is value-free and carries the correlation id.
  const reportJson = JSON.stringify(report);
  t.ok("report carries counts and total, never a value",
    report.total === 6 && leaked.every((v) => !reportJson.toLowerCase().includes(v.toLowerCase())), reportJson);
  t.ok("report echoes decisionId unchanged", report.decisionId === decisionId);

  // The audit line joins the authorize decision and is value-free too.
  const lines = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const rec = lines.find((r) => r.event === "sanitization");
  t.ok("a sanitization record is written", rec !== undefined);
  t.ok("audit record carries decision_id", rec?.decision_id === decisionId);
  t.ok("audit record is value-free (counts + mode + detector only)",
    rec && rec.counts?.KNOWN === 3 && !("text" in rec) &&
      leaked.every((v) => !JSON.stringify(rec).toLowerCase().includes(v.toLowerCase())), JSON.stringify(rec));

  // Fail-closed: a malformed correlation id is refused, raw text is never returned.
  let threw = false;
  try { govern.sanitize(text, { decisionId: "bad\nid" }); } catch (e) { threw = e instanceof SanitizeError; }
  t.ok("a decisionId with control characters is refused (SanitizeError)", threw);
} finally {
  fs.rmSync(auditDir, { recursive: true, force: true });
}
t.done();
