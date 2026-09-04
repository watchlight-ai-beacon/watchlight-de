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
const { sanitize, SanitizeError, Watchlight, DECISION_ID_MAX_LENGTH, DETECTOR_VERSION, DEFAULT_PII_TYPES, HEURISTIC_PII_TYPES } = require("../dist/index.js");
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

  // ── de-rules-2: detector set + defaults ──
  ok("detector version is de-rules-2", DETECTOR_VERSION === "de-rules-2" && report.detectorVersion === "de-rules-2");
  ok("heuristics are not in the default set", HEURISTIC_PII_TYPES.every((t) => !DEFAULT_PII_TYPES.includes(t)));
  ok("PASSPORT + DOB are in the default set", DEFAULT_PII_TYPES.includes("PASSPORT") && DEFAULT_PII_TYPES.includes("DOB"));
  ok("existing callers see no new types on the sample", !("KNOWN" in report.counts) && !("PERSON" in report.counts) && !("ADDRESS" in report.counts));

  // ── PASSPORT: labelled numbers + MRZ; bare numbers are NOT flagged ──
  const pp = sanitize("Passport No: X1234567, passport #: AB123456, PASSPORT NUMBER 987654321.");
  ok("PASSPORT: labelled numbers redacted (3)", pp.report.counts.PASSPORT === 3, JSON.stringify(pp.report.counts));
  ok("PASSPORT: label kept, number gone", pp.text.startsWith("Passport No: <PASSPORT_1>") && !pp.text.includes("X1234567") && !pp.text.includes("AB123456"));
  ok("PASSPORT: negative — label without a digit-bearing token", (sanitize("passport renewal office 123456").report.counts.PASSPORT ?? 0) === 0);
  ok("PASSPORT: negative — bare number is not a passport", (sanitize("ref AB123456 / 987654321").report.counts.PASSPORT ?? 0) === 0);
  const mrz1 = "P<UTOERIKSSON<<ANNA<MARIA".padEnd(44, "<");
  const mrz2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10";
  const mrz = sanitize(`scan:\n${mrz1}\n${mrz2}\n`);
  ok("PASSPORT: both MRZ lines redacted", mrz.report.counts.PASSPORT === 2 && !mrz.text.includes("ERIKSSON") && !mrz.text.includes("L898902C3"));
  ok("PASSPORT: negative — a 44-char upper-case word run is not an MRZ line", (sanitize("A".repeat(44)).report.counts.PASSPORT ?? 0) === 0);

  // ── DOB: labelled dates only; plausibility-checked ──
  const dob = sanitize("DOB: 03/15/1985. Date of birth 1985-03-15; born on 15 March 1985; birthday March 15th, 1985; D.O.B. 15.03.85");
  ok("DOB: five labelled shapes redacted", dob.report.counts.DOB === 5, JSON.stringify(dob.report.counts));
  ok("DOB: labels kept, dates gone", dob.text.includes("DOB: <DOB_1>") && !dob.text.includes("1985") && !dob.text.includes("15.03.85"));
  ok("DOB: negative — unlabelled dates untouched", (sanitize("Statement date 03/15/2024, due 04/01/2024").report.counts.DOB ?? 0) === 0);
  ok("DOB: negative — implausible dates untouched", (sanitize("DOB: 13/45/1985 dob 99/99/99 DOB: 01/01/1850").report.counts.DOB ?? 0) === 0);
  ok("DOB: negative — 'born in <year>' is not a date", (sanitize("the project was born in 2019").report.counts.DOB ?? 0) === 0);

  // ── KNOWN: application-supplied dictionary ──
  const kn = sanitize("Ada Lovelace lives at 12 Oak Lane; contact ada lovelace or ADA LOVELACE.", { known: ["Ada Lovelace", "Oak Lane"] });
  ok("KNOWN: every occurrence redacted, case-insensitive", kn.report.counts.KNOWN === 4 && !/ada lovelace|oak lane/i.test(kn.text));
  ok("KNOWN: same value (any case) → same tag", (kn.text.match(/<KNOWN_1>/g) || []).length === 3 && kn.text.includes("<KNOWN_2>"));
  ok("KNOWN: report carries counts only, never the values", !JSON.stringify(kn.report).includes("Lovelace") && !JSON.stringify(kn.report).includes("Oak"));
  const ov = sanitize("Ann Lee Smith and ANN LEE", { known: ["Ann Lee", "Lee Smith"] });
  ok("KNOWN: overlapping values merge — no fragment survives", !/smith|lee|ann/i.test(ov.text) && ov.report.counts.KNOWN === 2);
  ok("KNOWN: nested self-overlap merges (aa in aaaa)", sanitize("aaaa", { known: ["aa"] }).text === "<KNOWN_1>");
  const clip = sanitize("a@b.com Ltd", { known: ["com Ltd"] });
  ok("KNOWN: span past a structured span is clipped, not dropped", clip.text === "<EMAIL_1><KNOWN_1>" && clip.report.counts.EMAIL === 1);
  // union: a structured span that STARTS inside a KNOWN span keeps its tail
  ok("UNION: card starting inside a known span", sanitize("ACC 4111 1111 1111 1111", { known: ["ACC 4111"] }).text === "<KNOWN_1><CREDIT_CARD_1>");
  ok("UNION: SSN starting inside a known span", sanitize("SSN 123-45-6789", { known: ["SSN 123"] }).text === "<KNOWN_1><SSN_1>");
  ok("UNION: email starting inside a known span", sanitize("Ann Lee@example.com", { known: ["Ann Lee"] }).text === "<KNOWN_1><EMAIL_1>");
  ok("UNION: dictionary never reduces structured coverage", !/\d/.test(sanitize("ACC 4111 1111 1111 1111 / SSN 123-45-6789", { known: ["ACC 4111", "SSN 123"] }).text.replace(/<[A-Z_]+_\d+>/g, "")));
  const meta = sanitize("see (a.b)*c$ and (a.b)*c$", { known: ["(a.b)*c$"] });
  ok("KNOWN: regex metacharacters are literal", meta.report.counts.KNOWN === 2 && !meta.text.includes("(a.b)"));
  ok("KNOWN: empty / blank entries are ignored", sanitize("nothing here", { known: ["", "   "] }).text === "nothing here");
  ok("KNOWN: honoured even under a restrictive types filter", sanitize("SSN 123-45-6789 alice", { known: ["alice"], types: ["EMAIL"] }).text === "SSN 123-45-6789 <KNOWN_1>");
  ok("KNOWN: no dictionary → no KNOWN in report", !("KNOWN" in sanitize("alice").report.counts));
  ok("KNOWN: hash mode is deterministic and value-free", sanitize("Ada", { known: ["ada"], mode: "hash" }).text === sanitize("Ada", { known: ["ada"], mode: "hash" }).text && /^<KNOWN_[0-9a-f]{8}>$/.test(sanitize("Ada", { known: ["ada"], mode: "hash" }).text));
  const hk = sanitize("Ada ADA ada", { known: ["ada"], mode: "hash" }).text.split(" ");
  ok("KNOWN: hash mode is case-unified (one hash for Ada/ADA/ada)", new Set(hk).size === 1 && hk.length === 3);
  ok("KNOWN: 10k-entry dictionary over 200k chars stays fast", (() => {
    const dict = Array.from({ length: 10000 }, (_, i) => `name${i} street${i}`);
    const t = Date.now(); sanitize("lorem ipsum ".repeat(16000).slice(0, 200000), { known: dict }); return Date.now() - t < 3000;
  })());
  let badKnown = false;
  try { sanitize("x", { known: ["ok", 42] }); } catch (e) { badKnown = e instanceof SanitizeError && !String(e.message).includes("42"); }
  ok("KNOWN: non-string entry is fail-closed and value-free", badKnown);

  // ── PERSON / ADDRESS: opt-in heuristics, OFF by default ──
  const people = "Dr. Ada Lovelace met Patient: Grace Hopper and ATTN: Alan M. Turing. Alan Turing wrote it. The Cedar is neat.";
  ok("PERSON: off by default", !("PERSON" in sanitize(people).report.counts) && sanitize(people).text.includes("Ada Lovelace"));
  const per = sanitize(people, { types: ["PERSON"] });
  ok("PERSON: honorific / label / bare Title Case names redacted", per.report.counts.PERSON === 4 && !per.text.includes("Lovelace") && !per.text.includes("Hopper") && !per.text.includes("Turing"), JSON.stringify(per.report.counts) + " " + per.text);
  ok("PERSON: a stop word followed by a single word is not a name", per.text.includes("The Cedar is neat"), per.text);
  const trimmed = sanitize("Dear Ada Lovelace, Thanks Grace Hopper. From Alan Turing", { types: ["PERSON"] });
  ok("PERSON: leading stop word is trimmed, the name is still redacted", trimmed.text === "Dear <PERSON_1>, Thanks <PERSON_2>. From <PERSON_3>", trimmed.text);
  const irish = sanitize("Dr. Sam O'Neil met Kim McDonald-Lee and Jean-Luc D'Angelo", { types: ["PERSON"] });
  ok("PERSON: apostrophe / camel-case / hyphenated names", irish.text === "Dr. <PERSON_1> met <PERSON_2> and <PERSON_3>", irish.text);
  ok("PERSON: negative — lower-case words are not names", (sanitize("alice met bob at the cafe", { types: ["PERSON"] }).report.counts.PERSON ?? 0) === 0);
  const where = "Ship to 123 Main Street, Apt 4B, Springfield, IL 62704 or P.O. Box 987. Meet at 10 Downing St.";
  ok("ADDRESS: off by default", !("ADDRESS" in sanitize(where).report.counts));
  const addr = sanitize(where, { types: ["ADDRESS"] });
  ok("ADDRESS: numbered street, PO box and short form redacted", addr.report.counts.ADDRESS === 3 && !addr.text.includes("Main Street") && !addr.text.includes("Box 987") && !addr.text.includes("Downing"), JSON.stringify(addr.report.counts) + " " + addr.text);
  ok("ADDRESS: negative — no street suffix / no number", (sanitize("Meet on Main at noon; 5 apples", { types: ["ADDRESS"] }).report.counts.ADDRESS ?? 0) === 0);
  ok("ADDRESS beats PERSON on the same street", sanitize("123 Main Street", { types: ["PERSON", "ADDRESS"] }).text === "<ADDRESS_1>");

  // ── regex safety: adversarial long inputs stay fast ──
  const adversarial = [
    "passport" + " ".repeat(50000) + "x", "DOB:" + " ".repeat(50000), "Aa ".repeat(20000),
    "1 ".repeat(30000) + "Main St", "born on " + "1/".repeat(30000), "<".repeat(50000), "x".repeat(200000),
  ];
  const t0 = Date.now();
  for (const a of adversarial) sanitize(a, { types: ["PASSPORT", "DOB", "PERSON", "ADDRESS", "PHONE", "CREDIT_CARD"], known: ["zzz"] });
  ok("adversarial inputs complete quickly (no catastrophic backtracking)", Date.now() - t0 < 2000, `${Date.now() - t0}ms`);
  const t1 = Date.now();
  for (const a of ["a.".repeat(100000) + "@", "a@".repeat(50000), "x@" + "a.".repeat(100000)]) sanitize(a);
  ok("EMAIL: 100k-char local-part run without a domain is linear (< 100 ms)", Date.now() - t1 < 100, `${Date.now() - t1}ms`);
  ok("EMAIL: leading dot / hyphenated / plus-tag addresses still detected", sanitize(".alice@acme.com x-bob@acme.com plus+tag@acme.co.uk").report.counts.EMAIL === 3);

  // ── governed: known values never reach the audit trail ──
  const auditDir2 = fs.mkdtempSync(join(os.tmpdir(), "wl-san-"));
  const g2 = new Watchlight({ agent: "doc-agent", auditDir: auditDir2 });
  g2.sanitize("Ada Lovelace, DOB: 03/15/1985", { resource: "intake.txt", known: ["Ada Lovelace"] });
  const raw2 = fs.readFileSync(join(auditDir2, "audit.jsonl"), "utf8");
  ok("govern.sanitize audit: KNOWN + DOB counted, de-rules-2 recorded", raw2.includes('"KNOWN":1') && raw2.includes('"DOB":1') && raw2.includes('"detector":"de-rules-2"'));
  ok("govern.sanitize audit is value-free (no known values, no dates)", !raw2.includes("Lovelace") && !raw2.includes("1985"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
