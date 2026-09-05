# Showcase: governed web backend — the acting user flows from the request into the policy

A minimal HTTP service with **one governed endpoint**. The request's
authenticated user becomes the *principal* of the governed tool call, the
policy is scoped to that user, and every decision in the audit trail carries the
user it was made for — never the service. FastAPI and Express, identical
behaviour, each driven by a check script that starts the server, sends the
requests, reads the trail and exits non-zero if anything contradicts the verdicts.

| File | What it is |
|---|---|
| [`app.py`](./app.py) | The FastAPI app — token table, governed `read_statement` tool, one route |
| [`app.mjs`](./app.mjs) | The same app on Express |
| [`check.py`](./check.py) / [`check.mjs`](./check.mjs) | Start the app on an ephemeral `127.0.0.1` port, drive it, assert verdicts + attribution, stop it |
| [`policy.suite.json`](./policy.suite.json) | The policy the app loads **and** the fixtures `watchlight policy test` checks |
| [`requirements.txt`](./requirements.txt) / [`package.json`](./package.json) | The optional web extras — FastAPI + uvicorn, Express — for this example only |

## Run it

The web frameworks are **optional extras**: neither the `watchlight` package nor
`@watchlight/sdk` depends on them. Install them for this example only; without
them the scripts exit `2` and print the install line.

```bash
# Python
pip install watchlight
pip install -r examples/showcase/web-backend/requirements.txt     # FastAPI + uvicorn
python examples/showcase/web-backend/check.py                     # start → drive → assert → stop

# TypeScript / Node
npm i -g @watchlight/sdk            # or, in this repo: cd ts && npm install && npm run build
(cd examples/showcase/web-backend && npm install)                 # Express
node examples/showcase/web-backend/check.mjs

# The policy suite, in either CLI (they agree)
watchlight policy test examples/showcase/web-backend/policy.suite.json
```

To poke at the server by hand, start it on its own — it binds `127.0.0.1` only
and prints the port it picked (pass a port to fix it):

```bash
python examples/showcase/web-backend/app.py          # or: node examples/showcase/web-backend/app.mjs
# listening on http://127.0.0.1:54321
curl -H 'Authorization: Bearer demo-token-alice' http://127.0.0.1:54321/accounts/acct-100/statement   # 200
curl -H 'Authorization: Bearer demo-token-bob'   http://127.0.0.1:54321/accounts/acct-100/statement   # 403
```

## The endpoint

`GET /accounts/{account_id}/statement`, in this order:

1. **Authenticate** — the bearer token is looked up in an in-memory table
   (`demo-token-alice` → `alice`, `demo-token-bob` → `bob`). This is a stand-in
   for a session, an IdP token or mTLS; what matters is that the user id is what
   the request *authenticated as*, never a header the client fills in. Anything
   else is `401`, before any governed call.
2. **Validate** the path segment (`^[a-z0-9-]{1,32}$`) — it becomes part of the
   Cedar resource string. `400` otherwise, again before any governed call.
3. **Authorize** the governed call *as that user*. `Deny` → `403` with the
   uniform `{"error": "not authorized"}` — the caller never learns *why*, nor
   whether the account exists.
4. **Look up** the statement — only reachable after the principal was
   authorized. `404` if there is no such account.

The governed tool binds the principal and the resource per call:

```python
@govern.tool(
    "read_statement",
    principal=lambda user, account_id: f'User::"{user}"',   # the acting user — not the service
    resource=lambda user, account_id: f"account/{account_id}",
    on_result=attach_decision_id,
)
def read_statement(user, account_id): ...
```

```ts
const readStatement = govern.tool(function readStatement(user, accountId) { ... }, {
  intent: "read_statement",
  principal: (user) => `User::"${user}"`,                   // the acting user — not the service
  resource: (user, accountId) => `account/${accountId}`,
  onResult: attachDecisionId,
});
```

The `on_result` / `onResult` hook wraps the statement with the `decision_id` of
the decision that released it, so the response a client keeps joins the trail:

```json
{"account": "acct-100", "statement": "…", "decision_id": "…"}
```

## The policy

```cedar
permit(principal == User::"alice", action == Action::"read_statement", resource == Resource::"account/acct-100");
```

Scoped to the acting user *and* her account. The suite asserts the four ways
that can go: alice on her account → Allow; bob on it → Deny; alice on another
account → Deny; a call with no principal (the service itself) → Deny.

## What the check asserts

```
server: http://127.0.0.1:60025 (pid 66990); audit trail → scratch directory

  alice  → acct-100      HTTP 200  ['account', 'decision_id', 'statement']
  bob    → acct-100      HTTP 403  ['error']
  alice  → acct-200      HTTP 403  ['error']
  no token               HTTP 401  ['detail']
  unknown token          HTTP 401  ['detail']
  token 'constructor'    HTTP 401  ['detail']
  malformed account id   HTTP 400  ['detail']

=== audit trail (written by the server) ===
  …5efc3a  Allow  principal=User::"alice"  read_statement  account/acct-100
  …fc0055  Deny   principal=User::"bob"  read_statement  account/acct-100
  …213606  Deny   principal=User::"alice"  read_statement  account/acct-200

=== assertions ===
  ✓ alice reading her account → 200 with the statement and a decision_id
  ✓ bob reading the same account → 403 with the opaque reason, no statement
  ✓ alice reading another account → 403 (the policy is scoped to her account)
  ✓ no token / unknown token / a prototype-chain name as token → 401 before any governed call
  ✓ a malformed account id → 400 before any governed call
  ✓ exactly three decisions: one per authenticated request, none for the 401s and the 400
  ✓ Allow for User::"alice" on account/acct-100
  ✓ Deny for User::"bob" on account/acct-100
  ✓ Deny for User::"alice" on account/acct-200
  ✓ every decision is attributed to the acting user, never to the service
  ✓ the decision_id in alice's response is the Allow record's — the response joins the trail
  ✓ one egress record, joined to the Allow, replaced (the hook attached the decision_id)
  ✓ the trail is value-free — no bearer token and no statement text in it
  ✓ the server stopped on SIGTERM within 10s without being killed
  ✓ policy.suite.json: 5/5 fixtures pass

ALL CHECKS OK
```

The check runs the server as a child process with `WEB_BACKEND_AUDIT_DIR`
pointed at a scratch directory, so the trail it reads is exactly what *this*
server wrote — the same `audit.jsonl` records `watchlight dev` shows.

## The audit trail

Three decision records, one per authenticated request, each with the acting
user as `principal`:

```json
{"agent":"statements-api","principal":"User::\"alice\"","intent":"read_statement","resource":"account/acct-100","decision":"Allow","decision_id":"…"}
{"agent":"statements-api","principal":"User::\"bob\"","intent":"read_statement","resource":"account/acct-100","decision":"Deny","decision_id":"…"}
{"agent":"statements-api","principal":"User::\"alice\"","intent":"read_statement","resource":"account/acct-200","decision":"Deny","decision_id":"…"}
```

plus one `egress` record joined to the Allow (`"replaced": true` — the hook
attached the decision id). The 401s and the 400 produce **no** record: they were
refused before governance ran. Nothing in the trail is a token or a statement.

## Notes

- **Per-call principals are for attribution and policy.** They do not count
  against the free-tier governed-agent limit, which counts distinct `agent`
  identities (here, one: `statements-api`).
- **Own-property lookups only.** In JavaScript, `USERS[token]` on a plain
  object walks the prototype chain, so a token such as `constructor` would
  resolve to a function and reach governance as a bogus principal. The Express
  app looks tokens and account ids up as own properties only (`Object.hasOwn`;
  a Python `dict` has no such chain), and both checks send exactly that token
  and assert `401` with no decision record.
- **Authorize before you look up.** The body that touches data runs only after
  the decision; a denied user gets the same `403` for an account that exists
  and one that does not.
- **Loopback only.** Both apps bind `127.0.0.1`; there is no TLS here because
  nothing leaves the machine. A real deployment terminates TLS in front.
- Related pattern: [per-user attribution](../../patterns/per-user-attribution.md).
