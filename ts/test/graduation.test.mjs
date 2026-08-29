// M4 graduation test — WATCHLIGHT_APDP_URL flips the SAME govern code from the
// in-process engine to the networked control plane. A local HTTP stub stands in
// for APDP: it echoes the request, checks auth headers, and returns the same
// {decision, reason} shape the in-process engine returns.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import * as http from "node:http";

const require = createRequire(import.meta.url);
const { Watchlight } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

// A stand-in APDP: permits action "research", denies everything else. Records
// the last request's headers + body so we can assert the transport is correct.
function startStubApdp() {
  const seen = { auth: null, tenant: null, body: null, hits: 0 };
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      seen.hits++;
      seen.auth = req.headers["authorization"] ?? null;
      seen.tenant = req.headers["x-wl-tenant-id"] ?? null;
      seen.body = JSON.parse(raw || "{}");
      const allow = seen.body.action === "research";
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(
        allow ? { decision: "Allow", reason: "permitted by control plane" }
              : { decision: "Deny", reason: "no matching policy (control plane)" }
      ));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, seen, port: server.address().port }));
  });
}

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-grad-"));
  const { server, seen, port } = await startStubApdp();
  const url = `http://127.0.0.1:${port}`;

  // Graduate: point at the stub APDP. Same code, different backend.
  const g = new Watchlight({
    agent: "grad-agent",
    auditDir,
    apdpUrl: url,
    token: "plugin-token-abc",
    tenantId: "tenant-xyz",
  });
  ok("mode is networked when apdpUrl is set", g.mode === "networked", g.mode);

  // Local allow() is ignored in networked mode (policies are server-side) — must
  // not crash, and the decision still comes from the control plane.
  g.allow('permit(principal, action == Action::"research", resource);');

  const research = g.tool(async function research() { return "ok"; }, { intent: "research" });
  const transfer = g.tool(async function transfer() { return "sent"; }, { intent: "transfer" });

  ok("permitted intent allowed via control plane", (await research()) === "ok");
  ok("APDP received the request", seen.hits >= 1);
  ok("bearer token forwarded", seen.auth === "Bearer plugin-token-abc", String(seen.auth));
  ok("tenant header forwarded", seen.tenant === "tenant-xyz", String(seen.tenant));
  ok("request carried principal/action/resource", seen.body.principal === "grad-agent"
    && seen.body.action === "research" && seen.body.resource === "tool/research", JSON.stringify(seen.body));

  let denied = false;
  try { await transfer(); } catch { denied = true; }
  ok("unpermitted intent denied via control plane", denied);

  // Audit still written locally, value-free.
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("networked decisions audited locally", raw.includes('"decision":"Allow"') && raw.includes('"decision":"Deny"'));

  // scope() is in-process only — must throw a clear error when graduated.
  let scopeErr = null;
  try { await g.scope({ tools: ["read"] }); } catch (e) { scopeErr = e; }
  ok("scope() throws when networked (attenuation is server-side)", scopeErr instanceof Error);

  server.close();

  // Fail-closed: an unreachable control plane denies rather than throwing.
  const dead = new Watchlight({ agent: "grad-agent", auditDir, apdpUrl: "http://127.0.0.1:1" });
  const t = dead.tool(async () => "ran", { intent: "research" });
  let failClosed = false;
  try { await t(); } catch { failClosed = true; }
  ok("unreachable APDP is fail-closed (deny)", failClosed);

  // And no-url = in-process (default) still holds.
  const local = new Watchlight({ agent: "local", auditDir });
  ok("no apdpUrl → in-process mode", local.mode === "in-process");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
