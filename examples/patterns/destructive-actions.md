# Pattern: destructive actions

Reads are free, deletes need a human, and some resources cannot be deleted at
all.

```cedar
permit(principal, action == Action::"read", resource);

@enforcement_effect("require_approval")
permit(principal, action == Action::"delete", resource);

// a hard boundary: a forbid wins, even over the approval permit above
forbid(principal, action == Action::"delete", resource)
when { context.protected == true };
```

## Govern the tool

```ts
const del = govern.tool(deleteRecord, {
  intent: "delete",
  resource: (o) => `record/${o.id}`,
  context:  (o) => ({ protected: o.isProtected }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

## Verdicts

Proved by [`suites/destructive-actions.suite.json`](./suites/destructive-actions.suite.json).

| action | `protected` | verdict |
|---|---|---|
| `read` | — | **Allow** |
| `delete` | false | **NeedsApproval** |
| `delete` | true | **Deny** — the `forbid` beats the approval permit |
| `drop_table` (unlisted) | — | **Deny** — nothing permits it |

The third row is the point: a protected resource returns a flat `Deny`, not a
"click to approve". No human can cross that boundary.

## Approvals across processes

`onNeedsApproval` returning `true` mints a token bound to that exact
`(principal, action, resource)`, single-use and valid for 2 minutes. Two
defaults make it a **per-process** token:

- The signing key is random per process, so a worker refuses a token a web
  process minted, and a redeploy invalidates every outstanding approval.
- "Used once" is reserved in an in-process map, so behind two replicas the same
  token can be consumed once on **each**.

Configure both when the approving process is not the acting one, or when you run
more than one replica:

```ts
const govern = new Watchlight({
  agent: "ops-agent",
  approvalSecret: process.env.APPROVAL_SECRET,   // >= 16 bytes; or WATCHLIGHT_APPROVAL_SECRET
  approvalStore: {
    // SET … NX is the atomic step; a null reply means the id was already there.
    // PXAT expires the row at the token's own deadline.
    add: (id, expiresAt) =>
      redis.set(`wl:appr:${id}`, "1", { NX: true, PXAT: expiresAt }).then((r) => r !== null),
  },
});
```

```python
govern = Watchlight(
    agent="ops-agent",
    approval_secret=os.environ["APPROVAL_SECRET"],
    approval_store=redis_store,   # .add(id, expires_at) -> bool; synchronous
)
```

**`add` must be one atomic check-and-set.** It reserves the id only if it is
absent and returns `true` when the reservation was new. A read followed by an
unconditional write cannot enforce single use: an agent fanning out parallel
calls after one human confirmation sees the token unused on every one of them.
In SQL that is an insert that fails on a duplicate key; in Redis, `SET … NX`.

### Cleaning up reservations

The SDK never deletes a reservation. `expiresAt` is the epoch-millisecond
deadline after which an id is safe to drop, and an expired token is refused
before the store is consulted, so keeping every row is correct.

Redis expires its own rows with `PXAT`. A SQL table does not, so give it an
indexed deadline column and the optional `prune(before)`:

```ts
approvalStore: {
  add: (id, expiresAt) =>
    db.query(
      "INSERT INTO approvals (id, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [id, expiresAt],
    ).then((r) => r.rowCount === 1),          // 0 rows = the id was already there
  prune: (before) =>
    db.query("DELETE FROM approvals WHERE expires_at <= $1", [before]),
}
```

```python
class ApprovalTable:
    def add(self, id, expires_at):
        with self._db.cursor() as cur:
            cur.execute(
                "INSERT INTO approvals (id, expires_at) VALUES (%s, %s) "
                "ON CONFLICT DO NOTHING",
                (id, expires_at),
            )
            return cur.rowcount == 1          # 0 rows = the id was already there

    def prune(self, before):
        with self._db.cursor() as cur:
            cur.execute("DELETE FROM approvals WHERE expires_at <= %s", (before,))
```

## Worth knowing

- **Everything about an approval fails closed.** `false`, a raise, a non-boolean
  return, or (in TypeScript) a store slower than 2 seconds all refuse it.
- **Every refusal reads the same.** Expired, tampered, wrong key, already
  consumed, store unreachable — all come back as `NeedsApproval` with
  `approval required`, so probing the boundary teaches a caller nothing.
- **The stored id is `<exp>.<nonce>`**, never the signature, so a leaked table
  yields no usable approval.
- **`prune` is opportunistic** — at most once a minute per governor, after a
  reservation, with a cutoff a minute behind now. Its failure is ignored and
  reported once: a row that stays can only refuse a replay, never admit one.
