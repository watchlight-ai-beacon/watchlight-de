// Drive the governed Express backend and assert verdicts and attribution.
//
//     npm i -g @watchlight/sdk            (or, in this repo: cd ts && npm install && npm run build)
//     (cd examples/showcase/web-backend && npm install)   # Express — optional extra for this example only
//     node examples/showcase/web-backend/check.mjs
//
// Starts `app.mjs` on an ephemeral 127.0.0.1 port with its audit trail pointed at a
// scratch directory, sends an allowed request (alice, her account), a denied one
// (bob, the same account), a second denied one (alice, another account), three
// unauthenticated ones and a malformed one, shuts the server down, then reads the
// trail the server wrote and asserts that every decision carries the acting user
// as its principal. Exits non-zero on any failed assertion; exits 2 with a message
// if the optional web extras are not installed.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = new URL(".", import.meta.url);
const APP = fileURLToPath(new URL("app.mjs", HERE));
const STARTUP_TIMEOUT_MS = 30_000;

function loadSdk() {
  for (const spec of ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", HERE))]) {
    try { return require(spec); } catch (e) { if (e?.code !== "MODULE_NOT_FOUND") throw e; }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}
const { Watchlight, DENY_REASON } = loadSdk();

const TOKENS = { alice: "demo-token-alice", bob: "demo-token-bob" }; // the stand-in table in app.mjs

async function get(base, path, token) {
  const resp = await fetch(base + path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  const text = await resp.text();
  return [resp.status, text ? JSON.parse(text) : {}];
}

/** Start the server; resolve with its base URL once it prints the port it bound. */
function startServer(auditDir) {
  const proc = spawn(process.execPath, [APP], { env: { ...process.env, WEB_BACKEND_AUDIT_DIR: auditDir }, stdio: ["ignore", "pipe", "pipe"] });
  const lines = [];
  const base = new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => { proc.kill("SIGKILL"); reject(new Error("server did not start:\n  " + lines.join("\n  "))); }, STARTUP_TIMEOUT_MS);
    const onData = (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1); lines.push(line);
        const m = /^listening on (http:\/\/127\.0\.0\.1:\d+)$/.exec(line.trim());
        if (m) { clearTimeout(timer); resolve(m[1]); }
      }
    };
    proc.stdout.setEncoding("utf8").on("data", onData);
    proc.stderr.setEncoding("utf8").on("data", onData);
    proc.on("exit", (code) => { clearTimeout(timer); reject(new Error(`server exited early (${code}):\n  ` + lines.join("\n  "))); });
  });
  const exited = new Promise((resolve) => proc.on("exit", (code, signal) => resolve({ code, signal })));
  return { proc, base, exited };
}

async function main() {
  try {
    require.resolve("express");
  } catch (e) {
    if (e?.code !== "MODULE_NOT_FOUND") throw e;
    console.error("check.mjs needs Express (optional extra, not part of @watchlight/sdk):\n" +
      "    cd examples/showcase/web-backend && npm install");
    process.exit(2);
  }

  const auditDir = mkdtempSync(join(tmpdir(), "web-backend-audit-"));
  const { proc, base: baseP, exited } = startServer(auditDir);
  let failures = 0;
  const check = (name, cond, detail = "") => {
    console.log(`  ${cond ? "✓" : "✗"} ${name}${cond || !detail ? "" : " — " + detail}`);
    if (!cond) failures++;
  };

  let allowed, deniedUser, deniedAccount, noToken, badToken, protoToken, badPath, exit;
  let forced = false; // set if the server ignored SIGTERM and had to be killed
  try {
    const base = await baseP;
    console.log(`server: ${base} (pid ${proc.pid}); audit trail → scratch directory\n`);

    // ── requests ──
    allowed = await get(base, "/accounts/acct-100/statement", TOKENS.alice);
    deniedUser = await get(base, "/accounts/acct-100/statement", TOKENS.bob);
    deniedAccount = await get(base, "/accounts/acct-200/statement", TOKENS.alice);
    noToken = await get(base, "/accounts/acct-100/statement");
    badToken = await get(base, "/accounts/acct-100/statement", "demo-token-nobody");
    protoToken = await get(base, "/accounts/acct-100/statement", "constructor"); // must not resolve via the prototype chain
    badPath = await get(base, "/accounts/acct_100!/statement", TOKENS.alice);
    for (const [label, [status, body]] of [["alice  → acct-100", allowed], ["bob    → acct-100", deniedUser],
      ["alice  → acct-200", deniedAccount], ["no token", noToken], ["unknown token", badToken], ["token 'constructor'", protoToken],
      ["malformed account id", badPath]]) {
      const keys = body && typeof body === "object" ? "[" + Object.keys(body).sort().map((k) => `'${k}'`).join(", ") + "]" : body;
      console.log(`  ${label.padEnd(22)} HTTP ${status}  ${keys}`);
    }
  } finally {
    proc.kill("SIGTERM");
    const killer = setTimeout(() => { forced = true; proc.kill("SIGKILL"); }, 10_000);
    exit = await exited;
    clearTimeout(killer);
  }

  // ── the trail the server wrote ──
  const trailPath = join(auditDir, "audit.jsonl");
  const trail = existsSync(trailPath)
    ? readFileSync(trailPath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)) : [];
  rmSync(auditDir, { recursive: true, force: true });
  const decisions = trail.filter((r) => "decision" in r);
  const egress = trail.filter((r) => r.event === "egress");

  console.log("\n=== audit trail (written by the server) ===");
  for (const d of decisions) {
    console.log(`  …${(d.decision_id ?? "").slice(-6)}  ${d.decision.padEnd(5)}  principal=${d.principal}  ${d.intent}  ${d.resource}`);
  }

  console.log("\n=== assertions ===");
  const opaque = (b) => JSON.stringify(b) === JSON.stringify({ error: DENY_REASON });
  check("alice reading her account → 200 with the statement and a decision_id",
    allowed[0] === 200 && "statement" in allowed[1] && Boolean(allowed[1].decision_id));
  check("bob reading the same account → 403 with the opaque reason, no statement",
    deniedUser[0] === 403 && opaque(deniedUser[1]));
  check("alice reading another account → 403 (the policy is scoped to her account)",
    deniedAccount[0] === 403 && opaque(deniedAccount[1]));
  check("no token / unknown token / a prototype-chain name as token → 401 before any governed call",
    noToken[0] === 401 && badToken[0] === 401 && protoToken[0] === 401);
  check("a malformed account id → 400 before any governed call", badPath[0] === 400);
  check("exactly three decisions: one per authenticated request, none for the 401s and the 400",
    decisions.length === 3 && decisions.every((d) => ['User::"alice"', 'User::"bob"'].includes(d.principal)));
  const byKey = Object.fromEntries(decisions.map((d) => [`${d.principal} ${d.resource}`, d]));
  check('Allow for User::"alice" on account/acct-100', byKey['User::"alice" account/acct-100']?.decision === "Allow");
  check('Deny for User::"bob" on account/acct-100', byKey['User::"bob" account/acct-100']?.decision === "Deny");
  check('Deny for User::"alice" on account/acct-200', byKey['User::"alice" account/acct-200']?.decision === "Deny");
  check("every decision is attributed to the acting user, never to the service",
    decisions.every((d) => d.principal.startsWith('User::"') && d.principal !== d.agent));
  const allow = byKey['User::"alice" account/acct-100'] ?? {};
  check("the decision_id in alice's response is the Allow record's — the response joins the trail",
    allowed[1].decision_id === allow.decision_id);
  check("one egress record, joined to the Allow, replaced (the hook attached the decision_id)",
    egress.length === 1 && egress[0].decision_id === allow.decision_id && egress[0].replaced === true && egress[0].principal === 'User::"alice"');
  const blob = JSON.stringify(trail);
  check("the trail is value-free — no bearer token and no statement text in it",
    Object.values(TOKENS).every((t) => !blob.includes(t)) && !blob.includes("closing balance"));
  check("the server stopped on SIGTERM within 10s without being killed", !forced, `exit ${exit.code ?? exit.signal}`);

  // The policy the server loaded, executed in-process (same as `watchlight policy test`).
  const suitePath = fileURLToPath(new URL("policy.suite.json", HERE));
  const suite = JSON.parse(readFileSync(suitePath, "utf8"));
  const suiteDir = mkdtempSync(join(tmpdir(), "web-backend-suite-"));
  let report;
  try {
    report = await new Watchlight({ agent: "check", auditDir: suiteDir }).load(suitePath).test(suite.tests);
  } finally {
    rmSync(suiteDir, { recursive: true, force: true });
  }
  check(`policy.suite.json: ${report.passed}/${report.total} fixtures pass`, report.failed === 0);

  console.log(`\n${failures === 0 ? "ALL CHECKS OK" : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
