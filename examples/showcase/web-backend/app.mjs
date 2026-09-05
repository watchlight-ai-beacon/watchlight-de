// Governed web backend — the request's authenticated user is the acting principal.
//
//     npm i -g @watchlight/sdk            (or, in this repo: cd ts && npm install && npm run build)
//     (cd examples/showcase/web-backend && npm install)   # Express — optional extra for this example only
//     node examples/showcase/web-backend/app.mjs          # ephemeral 127.0.0.1 port, printed on start
//     node examples/showcase/web-backend/app.mjs 8000     # fixed port
//
//     curl -H 'Authorization: Bearer demo-token-alice' http://127.0.0.1:<port>/accounts/acct-100/statement   # 200
//     curl -H 'Authorization: Bearer demo-token-bob'   http://127.0.0.1:<port>/accounts/acct-100/statement   # 403
//
// One endpoint, `GET /accounts/:accountId/statement`. The bearer token is looked up
// in an in-memory table — a stand-in for whatever authenticates requests in a real
// service — and the user it resolves to becomes the PRINCIPAL of the governed tool
// call: `principal: (user) => \`User::"${user}"\``. The policy in `policy.suite.json`
// permits `read_statement` for `User::"alice"` on her account and nothing else, so
// the same endpoint answers 200 to alice and 403 to bob, and every decision in the
// audit trail carries the user it was made for, never the service.
//
// Order of checks: authenticate (401) → validate the path (400) → authorize with
// the acting principal (403, before any lookup) → look up the statement (404). A
// denied user learns nothing about whether the account exists. The response to an
// allowed request carries the `decision_id` of the decision that released it, so
// the record a client quotes joins the trail. `check.mjs` drives all of this.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = new URL(".", import.meta.url);

// Resolve the SDK: an installed @watchlight/sdk, else this repo's build (ts/dist).
function loadSdk() {
  for (const spec of ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", HERE))]) {
    try { return require(spec); } catch (e) { if (e?.code !== "MODULE_NOT_FOUND") throw e; }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}
const { Watchlight, Denied, DENY_REASON } = loadSdk();

// Express is an optional extra for this example only (see package.json here).
let express;
try {
  express = require("express");
} catch (e) {
  if (e?.code !== "MODULE_NOT_FOUND") throw e;
  console.error("this example needs Express (optional extra, not part of @watchlight/sdk):\n" +
    "    cd examples/showcase/web-backend && npm install");
  process.exit(2);
}

// ── the stand-ins ────────────────────────────────────────────────────
// Real services get the user from a session, an IdP token, or mTLS. Whatever the
// source, the value that matters is the one the request AUTHENTICATED as — the
// principal must never come from a header the client fills in freely.
const USERS = { "demo-token-alice": "alice", "demo-token-bob": "bob" }; // bearer token → user id (synthetic)
const STATEMENTS = { // what the endpoint returns; synthetic
  "acct-100": "acct-100: 3 transactions, closing balance 42.00",
  "acct-200": "acct-200: 1 transaction, closing balance 7.50",
};
const ACCOUNT_ID = /^[a-z0-9-]{1,32}$/; // the path segment enters the Cedar resource string

// ── the governed tool ────────────────────────────────────────────────
const govern = new Watchlight({
  agent: "statements-api",
  auditDir: process.env.WEB_BACKEND_AUDIT_DIR ?? fileURLToPath(new URL(".watchlight", HERE)),
});
govern.load(fileURLToPath(new URL("policy.suite.json", HERE))); // the same policies `watchlight policy test` verifies

/** Egress hook: the response carries the id of the decision that released it. */
function attachDecisionId(text, { resource, decisionId }) {
  return { account: resource.split("/", 2)[1], statement: text, decision_id: decisionId };
}

class NotFound extends Error {}

const readStatement = govern.tool(function readStatement(user, accountId) {
  if (!(accountId in STATEMENTS)) throw new NotFound(accountId); // only reachable AFTER the principal was authorized
  return STATEMENTS[accountId];
}, {
  intent: "read_statement",
  principal: (user) => `User::"${user}"`, // the acting user, per call — not the service
  resource: (user, accountId) => `account/${accountId}`,
  onResult: attachDecisionId,
});

// ── the web app ──────────────────────────────────────────────────────
/** Bearer token → user id, or null. Anything else is 401 — before any governed call. */
function authenticate(authorization) {
  const [scheme, ...rest] = (authorization ?? "").split(" ");
  return scheme.toLowerCase() === "bearer" ? USERS[rest.join(" ").trim()] ?? null : null;
}

const app = express();
app.get("/accounts/:accountId/statement", async (req, res, next) => {
  const user = authenticate(req.get("authorization"));
  if (user === null) return res.status(401).json({ detail: "authentication required" });
  const { accountId } = req.params;
  if (!ACCOUNT_ID.test(accountId)) return res.status(400).json({ detail: "invalid account id" });
  try {
    res.json(await readStatement(user, accountId)); // authorized for User::"<user>" before the body runs
  } catch (e) {
    if (e instanceof Denied) return res.status(403).json({ error: DENY_REASON }); // opaque: never why
    if (e instanceof NotFound) return res.status(404).json({ detail: "no such account" });
    next(e);
  }
});

const port = process.argv[2] ? Number(process.argv[2]) : 0; // 0 → the OS picks an ephemeral port
const server = app.listen(port, "127.0.0.1", () => { // loopback only
  console.log(`listening on http://127.0.0.1:${server.address().port}`);
});
process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
