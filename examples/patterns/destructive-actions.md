# Pattern: destructive actions

**Problem.** An agent can delete, drop, or deploy. Reads should be free, deletes
should require a human, and some resources must be **undeletable** — a boundary no
approval can cross.

**Policy** — [`suites/destructive-actions.suite.json`](./suites/destructive-actions.suite.json):

```cedar
permit(principal, action == Action::"read", resource);

@enforcement_effect("require_approval")
permit(principal, action == Action::"delete", resource);

// a hard boundary: forbid always wins, even over the approval permit above
forbid(principal, action == Action::"delete", resource)
when { context.protected == true };
```

**Govern the tool:**

```ts
const del = govern.tool(deleteRecord, {
  intent: "delete",
  resource: (o) => `record/${o.id}`,
  context:  (o) => ({ protected: o.isProtected }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

**Verdicts** (verified):

| action | `protected` | verdict |
|---|---|---|
| `read` | — | **Allow** |
| `delete` | false | **NeedsApproval** |
| `delete` | true | **Deny** — the `forbid` overrides the approval permit |
| `drop_table` (unlisted) | — | **Deny** — fail-closed |

**Why it's high-stakes.** The key move is that a `forbid` **beats** a
`require_approval` permit: a protected resource returns a flat `Deny`, not a
"click to approve." That's the difference between "a human *can* delete this" and
"this *cannot* be deleted." Unlisted actions (`drop_table`) are denied because
nothing permits them — you never have to enumerate every dangerous verb.

## The approval token, and where it is valid

`onNeedsApproval` returning `true` mints a token bound to that exact
`(principal, action, resource)`, single-use and TTL-bounded (2 minutes by
default), and re-authorizes with it. Two defaults decide where that token is
valid, and **both are per-process**:

- **The signing key** is random and per-process. A token minted in a web process
  is refused by a worker, and a redeploy invalidates every outstanding
  approval — indistinguishably from a genuine hold, because every refusal returns
  the same uniform reason.
- **"Used once"** is reserved in an in-process map. That map is atomic — of N
  concurrent `authorize` calls carrying one token, exactly one is approved — but
  it is this process's map. Behind two replicas the same token can therefore be
  consumed once on *each*: single-use is per-replica, not per token, and it
  degrades silently the first time you scale out.

Configure both when the approving process is not the acting one, or when there is
more than one replica:

```ts
const govern = new Watchlight({
  approvalSecret: process.env.APPROVAL_SECRET,   // >= 16 bytes; or WATCHLIGHT_APPROVAL_SECRET,
                                                 // or reuse signingSecret, which
                                                 // covers approvals too
  approvalStore: {
    // SET … NX is the atomic step; a null reply means the id was already there
    add: (id, expiresAt) =>
      redis.set(`wl:appr:${id}`, "1", { NX: true, PXAT: expiresAt }).then((r) => r !== null),
  },
});
```

```python
govern = Watchlight(
    approval_secret=os.environ["APPROVAL_SECRET"],
    approval_store=redis_store,   # .add(id, expires_at) -> bool; synchronous
)
```

**`add` must be an atomic check-and-set.** It reserves the id only if it is not
already present, and returns `true` when the reservation was new, `false` when it
was not. A separate "does it exist?" read followed by an unconditional write
**cannot** enforce single use: authorization is asynchronous, so the gap between
the two is a window in which N concurrent consumes of the same token all see it
unused and every one of them is approved. That is not a hypothetical — it is one
agent fanning out parallel tool calls after a single human confirmation. In SQL
it is an insert that fails on a duplicate key; in Redis, `SET … NX`.

The id handed to the store is `<exp>.<nonce>` — unique per mint, and never the
signature, so a store whose rows leak yields no usable approval. `expires_at` is
epoch milliseconds, so the row can carry its own TTL.

**Fail-closed throughout.** `false`, a raise, a return that is not a boolean, or
(in TypeScript, where the store may be async) outrunning the 2-second deadline
all **refuse** the approval; none of them admits one, and a store that never
answers is refused rather than left hanging on the decision path. Every refusal —
expired, tampered, signed with another key, already consumed, or a store that
could not answer — surfaces as the *same* `NeedsApproval` with the uniform
`approval required` reason, so a caller probing the boundary learns nothing about
which check refused it.

Graduate with `WATCHLIGHT_APDP_URL`; in Enterprise the same `forbid` boundaries
are centrally managed, approval tokens are KMS-signed and recorded in signed
lineage, and the approval step becomes a full workflow.
