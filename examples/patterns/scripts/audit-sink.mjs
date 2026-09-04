// audit-sink — the sink contract, run against the real engine.
//
// Asserts: every record kind (decision, sanitization, attenuation) reaches the
// sink with exactly the fields the audit.jsonl line carries; the copy is frozen;
// the file is written whether or not the sink works; and a throwing sink never
// changes a verdict.
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";
import { loadSdk, checks } from "./_sdk.mjs";

const { Watchlight, AttenuationDenied } = loadSdk();
const t = checks("audit-sink");

async function exercise(sink) {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-pattern-sink-"));
  try {
    const govern = new Watchlight({ agent: "billing-agent", auditDir, auditSink: sink });
    govern.allow('permit(principal, action == Action::"read", resource);', "reads");
    const allow = await govern.authorize({ action: "read", resource: "doc/42" });
    const deny = await govern.authorize({ action: "transfer", resource: "acct/1", context: { amount: 987654 } });
    govern.sanitize("SSN 123-45-6789", { resource: "doc/42", decisionId: allow.decisionId ?? "dec-1" });
    const root = await govern.scope({ tools: ["read", "write"] });
    root.attenuate({ tools: ["read"] });
    try { root.attenuate({ tools: ["delete"] }); } catch (e) { if (!(e instanceof AttenuationDenied)) throw e; }
    const lines = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
    return { allow, deny, lines };
  } finally {
    fs.rmSync(auditDir, { recursive: true, force: true });
  }
}

// A working sink receives every line, verbatim and frozen.
const received = [];
const { allow, deny, lines } = await exercise((r) => received.push(r));
t.ok("the sink receives one record per audit line", received.length === lines.length, `${received.length} vs ${lines.length}`);
t.ok("each record carries exactly the fields of its file line",
  received.every((r, i) => JSON.stringify(r) === JSON.stringify(lines[i])));
t.ok("decision, sanitization and attenuation records all arrive",
  ["decision", "sanitization", "attenuation"].every((k) => received.some((r) => (r.event ?? "decision") === k)));
t.ok("the sanitization record joins the decision on decision_id",
  received.find((r) => r.event === "sanitization")?.decision_id === (allow.decisionId ?? "dec-1"));
t.ok("records are value-free — no argument values, no text",
  !JSON.stringify(received).includes("123-45-6789") && !JSON.stringify(received).includes("987654"));
t.ok("the sink's copy is frozen", received.every((r) => Object.isFrozen(r)));

// A failing sink changes nothing: same verdicts, same file.
const warnings = [];
const origWarn = console.warn;
console.warn = (m) => warnings.push(String(m));
let broken;
try {
  broken = await exercise(() => { throw new Error("store unavailable"); });
} finally {
  console.warn = origWarn;
}
t.ok("verdicts are unchanged when the sink throws", broken.allow.allowed && !broken.deny.allowed);
t.ok("the file is still written when the sink throws", broken.lines.length === lines.length);
t.ok("the failure is reported once, by error type only",
  warnings.length === 1 && warnings[0].includes("(Error)") && !warnings[0].includes("store unavailable"), warnings.join(" | "));
t.done();
