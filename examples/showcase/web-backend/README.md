# Governed web backend

The app exposes one HTTP endpoint. The user the request authenticated as becomes
the principal of the governed tool call, and every decision in the trail carries
that user — never the service.

```bash
pip install -r requirements.txt      # FastAPI + uvicorn, for this example only
python check.py                      # start → drive → assert → stop

npm install                          # Express
node check.mjs
```

The web frameworks are optional extras: neither `watchlight` nor
`@watchlight/sdk` depends on them. Without them the scripts exit `2` and print
the install line, and the showcase is reported as skipped rather than passed.

To poke at it by hand, start the server on its own. It binds `127.0.0.1` and
prints the port it picked:

```bash
python app.py            # or: node app.mjs
# listening on http://127.0.0.1:54321
curl -H 'Authorization: Bearer demo-token-alice' http://127.0.0.1:54321/accounts/acct-100/statement   # 200
curl -H 'Authorization: Bearer demo-token-bob'   http://127.0.0.1:54321/accounts/acct-100/statement   # 403
```

## The endpoint

`GET /accounts/{account_id}/statement`, in this order:

1. **Authenticate.** The bearer token is looked up in an in-memory table — a
   stand-in for a session, an IdP token or mTLS. What matters is that the user
   id is what the request authenticated *as*, never a header the client fills
   in. Anything else is `401`, before any governed call.
2. **Validate** the path segment against `^[a-z0-9-]{1,32}$`; it becomes part of
   the Cedar resource string. `400` otherwise, again before governance.
3. **Authorize** as that user. `Deny` → `403` and the uniform
   `{"error": "not authorized"}`. The caller never learns why, nor whether the
   account exists.
4. **Look up** the statement, reachable only after the Allow. `404` if there is
   no such account.

```python
@govern.tool(
    "read_statement",
    principal=lambda user, account_id: f'User::"{user}"',   # the acting user — not the service
    resource=lambda user, account_id: f"account/{account_id}",
    on_result=attach_decision_id,
)
def read_statement(user, account_id): ...
```

`app.mjs` binds the same two lambdas as `principal` and `resource`. The
`on_result` / `onResult` hook stamps the response with the `decision_id` that
released it, so what the client keeps joins the trail:

```json
{"account": "acct-100", "statement": "…", "decision_id": "…"}
```

## The policy

```cedar
permit(principal == User::"alice", action == Action::"read_statement", resource == Resource::"account/acct-100");
```

The policy is scoped to the acting user *and* her account. The suite asserts all
four ways that goes: alice on her account allows; bob on it denies; alice on
another account denies; and a call with no principal — the service itself —
denies.

## What you see

```text
server: http://127.0.0.1:54343 (pid 36457); audit trail → scratch directory

  alice  → acct-100      HTTP 200  ['account', 'decision_id', 'statement']
  bob    → acct-100      HTTP 403  ['error']
  alice  → acct-200      HTTP 403  ['error']
  no token               HTTP 401  ['detail']
  unknown token          HTTP 401  ['detail']
  token 'constructor'    HTTP 401  ['detail']
  malformed account id   HTTP 400  ['detail']

=== audit trail (written by the server) ===
  …b6775e  Allow  principal=User::"alice"  read_statement  account/acct-100
  …3fd91a  Deny   principal=User::"bob"  read_statement  account/acct-100
  …84deb8  Deny   principal=User::"alice"  read_statement  account/acct-200

=== assertions ===
  ✓ exactly three decisions: one per authenticated request, none for the 401s and the 400
  ✓ every decision is attributed to the acting user, never to the service
  ✓ the decision_id in alice's response is the Allow record's — the response joins the trail
  ✓ the trail is value-free — no bearer token and no statement text in it
  ✓ the server stopped on SIGTERM within 10s without being killed
  … 15 assertions in all

ALL CHECKS OK
```

The check runs the server as a child process with `WEB_BACKEND_AUDIT_DIR`
pointed at a scratch directory, so the trail it reads is exactly what this
server wrote. The 401s and the 400 produce no record at all: they were refused
before governance ran.

## Worth knowing

- **One governor, one agent name, many principals.** The per-call principal is
  attribution and policy input; it does not make a second governor.
- **Own-property lookups only.** In JavaScript `USERS[token]` walks the
  prototype chain, so a token such as `constructor` resolves to a function and
  reaches governance as a bogus principal. The Express app uses `Object.hasOwn`
  (a Python `dict` has no such chain), and both checks send exactly that token
  and assert `401` with no decision record.
- **Authorize before you look up.** A denied user gets the same `403` for an
  account that exists and one that does not.
- **Loopback only.** Both apps bind `127.0.0.1` and there is no TLS, because
  nothing leaves the machine. A real deployment terminates TLS in front.

Verified by [`check.sh`](./check.sh). Related:
[per-user attribution](../../patterns/per-user-attribution.md) ·
[using the governor in a request handler](../../../docs/using-the-governor.md#in-a-request-handler).
