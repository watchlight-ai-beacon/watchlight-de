// Configuring the default governor — `configureDefault`, `canConfigureDefault`,
// and the environment layer. The Python twin is tests/test_default_governor.py;
// the two lanes must answer identically.
//
// The exported `govern` is a module singleton, so every scenario runs in its own
// process: what is being tested is precisely the once-per-process state that a
// second import cannot reset.
//
// Two things are proven here:
//
//   * asking whether the default governor can still be configured is a QUESTION
//     (`canConfigureDefault()`), and re-applying the configuration already in
//     force is a no-op rather than an exception path; and
//   * a process can send the default governor's trail somewhere else — or turn
//     the local file off entirely — with an environment variable, so a test run
//     stops depositing its verdicts into the `audit.jsonl` an application is
//     writing in the same working directory.
//
// What is deliberately NOT changed: the default governor still writes
// `.watchlight/audit.jsonl` on its first governed call with no opt-in. That file
// IS the quickstart, so a default that wrote nothing until configured would
// break the first five minutes.
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const require = createRequire(import.meta.url);
const SDK = require.resolve("../dist/index.js");
const { AUDIT_DIR_ENV, AUDIT_FILE_ENV } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

function workdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "wl-default-"));
}

/** Run `body` in a fresh process, in `cwd`, with `env` layered on. Returns
 *  { stdout, stderr, code }; never throws on a non-zero exit. */
function run(body, cwd, env = {}) {
  const source = `import { govern, Watchlight, configureDefault, canConfigureDefault } from ${JSON.stringify(SDK)};\n${body}`;
  const file = path.join(cwd, `case-${Math.random().toString(36).slice(2)}.mjs`);
  fs.writeFileSync(file, source, "utf8");
  const environ = { ...process.env, ...env };
  // Never let the developer's own environment decide a test's answer.
  for (const name of [AUDIT_DIR_ENV, AUDIT_FILE_ENV]) {
    if (!(name in env)) delete environ[name];
  }
  try {
    const r = spawnSync(process.execPath, [file], {
      cwd, env: environ, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    });
    return { stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status ?? 1 };
  } finally {
    fs.rmSync(file, { force: true });
  }
}

/** The same probe both lanes use: did a trail land here, or over there? */
const WRITE = `
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
console.log("here:", fs.existsSync(".watchlight/audit.jsonl"));
console.log("there:", fs.existsSync("elsewhere/audit.jsonl"));
`;
const WITH_FS = `import * as fs from "node:fs";`;

function wrote(cwd, env = {}) {
  const out = run(WITH_FS + WRITE, cwd, env);
  // Anchored: "there: true" contains "here: true".
  return {
    here: /^here: true$/m.test(out.stdout),
    there: /^there: true$/m.test(out.stdout),
    ...out,
  };
}

async function main() {
  // ── the environment variable names are part of the contract ──────
  console.log("the environment variable names follow the existing scheme");
  ok("WATCHLIGHT_AUDIT_DIR", AUDIT_DIR_ENV === "WATCHLIGHT_AUDIT_DIR");
  ok("WATCHLIGHT_AUDIT_FILE", AUDIT_FILE_ENV === "WATCHLIGHT_AUDIT_FILE");

  // ── canConfigureDefault: the question, not the exception ─────────
  console.log("canConfigureDefault answers before and after the first record");
  {
    const cwd = workdir();
    const out = run(`
if (canConfigureDefault() !== true) throw new Error("expected true before any record");
if (canConfigureDefault() !== true) throw new Error("asking must not mutate");
configureDefault({ agent: "asked" });
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (canConfigureDefault() !== false) throw new Error("expected false after the first record");
console.log("OK");
`, cwd);
    ok("true before, false after", out.stdout.includes("OK"), out.stderr);
  }

  // ── configureDefault is idempotent-safe ──────────────────────────
  console.log("re-applying the configuration already in force is a no-op");
  {
    const cwd = workdir();
    const out = run(`
const sink = () => {};
configureDefault({ agent: "billing-agent", auditSink: sink, auditDir: "trail" });
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (canConfigureDefault() !== false) throw new Error("expected the governor to be locked");
// The SAME options, applied again — the common defensive call.
if (configureDefault({ agent: "billing-agent", auditSink: sink, auditDir: "trail" }) !== govern) {
  throw new Error("expected the one governor back");
}
configureDefault({});                     // naming nothing is trivially a no-op
configureDefault({ auditDir: "./trail" }); // an equivalent spelling of the same directory
if (govern.agent !== "billing-agent") throw new Error("agent changed");
console.log("OK");
`, cwd);
    ok("identical options, a subset, and {} are all accepted", out.stdout.includes("OK"), out.stderr);
  }

  console.log("a genuine conflict names the option and never a secret");
  {
    const cwd = workdir();
    const out = run(`
const sink = () => {};
configureDefault({ agent: "billing-agent", auditSink: sink, auditDir: "trail" });
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });

const conflict = (opts) => {
  try { configureDefault(opts); } catch (e) { return e.message; }
  throw new Error("expected a conflict for " + JSON.stringify(Object.keys(opts)));
};
const must = (message, needle) => {
  if (!message.includes(needle)) throw new Error("missing " + JSON.stringify(needle) + " in: " + message);
};
must(conflict({ agent: "other" }), 'agent would change from "billing-agent" to "other"');
must(conflict({ auditDir: "elsewhere" }), 'auditDir would change from "trail" to "elsewhere"');
must(conflict({ auditFile: false }), "auditFile would change from true to false");
// A sink BUILT a second time is a different sink: silently keeping the first
// would discard the records the caller believed it had just redirected.
must(conflict({ auditSink: () => {} }), "auditSink would change");
must(conflict({ strictPrincipal: false }), "strictPrincipal would change from true to false");
const secret = conflict({ signingSecret: "a-different-signing-secret-32-by" });
must(secret, "signingSecret would change");
if (secret.includes("a-different-signing-secret")) throw new Error("the secret leaked into the message");
must(secret, "canConfigureDefault()");
// A bearer token is a credential too.
const token = conflict({ token: "a-different-bearer-token" });
must(token, "token would change");
if (token.includes("a-different-bearer-token")) throw new Error("the token leaked into the message");
console.log("OK");
`, cwd);
    ok("each message names WHICH option, values stay out", out.stdout.includes("OK"), out.stderr);
  }

  console.log("a method read off the same object twice is the same sink");
  {
    // The TS twin of the Python bound-method case. A method read off an object
    // is ONE reference here, so `===` already matches it; `.bind()` returns a
    // new function on every call and is a different sink, which is the line the
    // docs call out.
    const cwd = workdir();
    const out = run(`
class Store {
  constructor() { this.rows = []; }
  insert(record) { this.rows.push(record); }
  count() { return this.rows.length; }
}
const store = new Store();
if (store.insert !== store.insert) throw new Error("a method read twice must be one reference");
if (store.insert.bind(store) === store.insert.bind(store)) throw new Error(".bind() must be new");

const records = [];
const sink = (r) => records.push(r);
configureDefault({ agent: "rpt", auditSink: sink, auditDir: "trail", counterSource: store.count });
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (records.length !== 1) throw new Error("expected one record, got " + records.length);

// Re-applying byte-identical configuration, every callable read a SECOND time.
configureDefault({ agent: "rpt", auditSink: sink, auditDir: "trail", counterSource: store.count });
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (records.length !== 2) throw new Error("the original sink stopped receiving records");

const refuse = (opts) => {
  try { configureDefault(opts); } catch (e) { return e.message; }
  throw new Error("expected a conflict for " + JSON.stringify(Object.keys(opts)));
};
const must = (message, needle) => {
  if (!message.includes(needle)) throw new Error("missing " + JSON.stringify(needle) + " in: " + message);
};
// Anything BUILT a second time is a different sink — a fresh arrow, an
// unrelated method, and a new .bind() of the very same function.
must(refuse({ auditSink: (r) => records.push(r) }), "auditSink would change");
must(refuse({ auditSink: new Store().insert }), "auditSink would change");
must(refuse({ auditSink: sink.bind(null) }), "auditSink would change");
must(refuse({ counterSource: () => 0 }), "counterSource would change");

// A language difference worth stating rather than papering over: a JS class
// method lives on the prototype and is NOT bound to an instance, so
// \`new Store().count === store.count\`. It is genuinely the same function, and
// re-applying it is a no-op. Python's bound methods carry their instance, so the
// Python lane refuses another instance's method — each lane answers correctly
// for what its own callables ARE, and every case a caller can hit (the same
// method re-read, a rebuilt callable) agrees across both.
configureDefault({ counterSource: new Store().count });
console.log("OK");
`, cwd);
    ok("a method re-read is a no-op; a rebuilt callable conflicts", out.stdout.includes("OK"), out.stderr);
  }

  // ── the environment layer ────────────────────────────────────────
  console.log("zero configuration still writes the quickstart file");
  {
    const cwd = workdir();
    const r = wrote(cwd);
    ok("the file appears with no opt-in", r.here && !r.there, r.stderr);
    ok(
      "and it has a record in it",
      fs.readFileSync(path.join(cwd, ".watchlight", "audit.jsonl"), "utf8").trim().length > 0
    );
  }

  console.log("the audit-file switch writes nothing into the working directory");
  {
    const cwd = workdir();
    const r = wrote(cwd, { [AUDIT_FILE_ENV]: "0" });
    ok("no trail anywhere", !r.here && !r.there, r.stderr);
    ok("not even a directory", fs.readdirSync(cwd).length === 0);
  }

  for (const off of ["0", "false", "FALSE", "no", "off", " Off "]) {
    const cwd = workdir();
    ok(`${JSON.stringify(off)} turns the file off`, !wrote(cwd, { [AUDIT_FILE_ENV]: off }).here);
  }
  for (const on of ["1", "true", "yes", "on"]) {
    const cwd = workdir();
    ok(`${JSON.stringify(on)} keeps the file`, wrote(cwd, { [AUDIT_FILE_ENV]: on }).here);
  }

  console.log("an unrecognized switch is ignored, reported once, and keeps the trail");
  {
    const cwd = workdir();
    const r = wrote(cwd, { [AUDIT_FILE_ENV]: "of" });
    ok("the trail is kept", r.here, r.stderr);
    ok("said once", (r.stderr.match(/does not recognize/g) ?? []).length === 1, r.stderr);
    ok("and it names the variable", r.stderr.includes(AUDIT_FILE_ENV));
  }

  console.log("the audit directory redirects the trail");
  {
    const cwd = workdir();
    const r = wrote(cwd, { [AUDIT_DIR_ENV]: "elsewhere" });
    ok("there, not here", r.there && !r.here, r.stderr);
  }

  console.log("the environment is read lazily, at first use");
  {
    // Read at import time, the variable's effect would depend on whether the
    // application imported the SDK before or after setting it.
    const cwd = workdir();
    const out = run(`${WITH_FS}
process.env.WATCHLIGHT_AUDIT_DIR = "elsewhere";   // set AFTER the import above
${WRITE}`, cwd);
    ok(
      "set after the import, still honored",
      /^there: true$/m.test(out.stdout) && /^here: false$/m.test(out.stdout),
      out.stderr
    );
  }

  console.log("a governor you construct names its own options and ignores the environment");
  {
    // The environment layer exists for the ONE governor an application never
    // constructs. Letting it override an explicit constructor argument would
    // invert the precedence every other option in this SDK resolves in.
    const cwd = workdir();
    const out = run(`${WITH_FS}
const g = new Watchlight({ agent: "mine", auditDir: "mine" });
g.allow('permit(principal, action, resource);');
await g.authorize({ action: "read", principal: 'User::"u"' });
console.log("mine:", fs.existsSync("mine/audit.jsonl"));
console.log("elsewhere:", fs.existsSync("elsewhere/audit.jsonl"));
`, cwd, { [AUDIT_DIR_ENV]: "elsewhere", [AUDIT_FILE_ENV]: "0" });
    ok("its own directory, and the file stays on", /^mine: true$/m.test(out.stdout) && /^elsewhere: false$/m.test(out.stdout), out.stderr);
  }

  // ── precedence: option > environment > default ───────────────────
  console.log("an explicit option beats the environment");
  {
    const cwd = workdir();
    const out = run(`${WITH_FS}
configureDefault({ auditDir: "chosen" });   // against WATCHLIGHT_AUDIT_DIR=elsewhere
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (!fs.existsSync("chosen/audit.jsonl")) throw new Error("the explicit directory lost");
if (fs.existsSync("elsewhere/audit.jsonl")) throw new Error("the environment won");
if (fs.existsSync(".watchlight/audit.jsonl")) throw new Error("the default won");
console.log("OK");
`, cwd, { [AUDIT_DIR_ENV]: "elsewhere" });
    ok("auditDir", out.stdout.includes("OK"), out.stderr);
  }
  {
    const cwd = workdir();
    const out = run(`${WITH_FS}
configureDefault({ auditFile: true, auditDir: "chosen" });   // against WATCHLIGHT_AUDIT_FILE=0
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
if (!fs.existsSync("chosen/audit.jsonl")) throw new Error("the explicit switch lost");
console.log("OK");
`, cwd, { [AUDIT_FILE_ENV]: "0" });
    ok("auditFile", out.stdout.includes("OK"), out.stderr);
  }

  console.log("the environment becomes what a later call is compared against");
  {
    const cwd = workdir();
    const out = run(`
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u"' });
configureDefault({ auditDir: "elsewhere" });       // matches the environment: a no-op
try {
  configureDefault({ auditDir: "third" });
  throw new Error("a different directory must conflict");
} catch (e) {
  if (!e.message.includes('auditDir would change from "elsewhere" to "third"')) throw e;
}
console.log("OK");
`, cwd, { [AUDIT_DIR_ENV]: "elsewhere" });
    ok("in force = what the environment chose", out.stdout.includes("OK"), out.stderr);
  }

  // ── the contamination case the issue reported ────────────────────
  console.log("a test process can opt out of the directory an application uses");
  {
    const cwd = workdir();
    const app = `
configureDefault({ agent: "statements-api" });
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"u1"' });
console.log("OK");
`;
    // A test process that authorizes directly — a perfectly reasonable thing to
    // write in a test, and the case `govern.test()` never covered because policy
    // tests write nothing at all.
    const tests = `
govern.allow('permit(principal, action, resource);');
await govern.authorize({ action: "read", principal: 'User::"fixture"' });
await govern.authorize({ action: "write", principal: 'User::"fixture"' });
console.log("OK");
`;
    const trail = path.join(cwd, ".watchlight", "audit.jsonl");
    ok("the application writes its trail", run(app, cwd).stdout.includes("OK"));
    const before = fs.readFileSync(trail, "utf8");

    ok("without the variable, a test run contaminates it", run(tests, cwd).stdout.includes("OK"));
    const contaminated = fs.readFileSync(trail, "utf8");
    ok("…demonstrably", contaminated !== before);

    ok("with it, the test run writes nothing", run(tests, cwd, { [AUDIT_FILE_ENV]: "0" }).stdout.includes("OK"));
    ok("the application's trail is untouched", fs.readFileSync(trail, "utf8") === contaminated);

    ok("or keeps its own, elsewhere", run(tests, cwd, { [AUDIT_DIR_ENV]: "test-run" }).stdout.includes("OK"));
    ok("still untouched", fs.readFileSync(trail, "utf8") === contaminated);
    ok("and the test run has a trail of its own", fs.existsSync(path.join(cwd, "test-run", "audit.jsonl")));
  }

  console.log("policy tests already wrote nothing");
  {
    // `govern.test()` runs the engine's decision core directly; it has never
    // written a record. Pinned so it stays that way.
    const cwd = workdir();
    const out = run(`${WITH_FS}
govern.allow('permit(principal, action == Action::"read", resource);');
const report = await govern.test([{ name: "read", action: "read", expect: "Allow" }]);
if (report.failed !== 0) throw new Error(JSON.stringify(report));
console.log("here:", fs.existsSync(".watchlight/audit.jsonl"));
`, cwd);
    ok("no file from a policy-test run", /^here: false$/m.test(out.stdout), out.stderr + out.stdout);
  }

  // ── the file-off notice is the trail's own, not the default's ────
  console.log("with the file off and no sink, only the no-destination notice is printed");
  {
    const cwd = workdir();
    const r = wrote(cwd, { [AUDIT_FILE_ENV]: "0" });
    ok("said once", (r.stderr.match(/audit records are discarded/g) ?? []).length === 1, r.stderr);
    ok(
      "and never the untrue one",
      !r.stderr.includes("writes only to the local audit file"),
      r.stderr
    );
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
