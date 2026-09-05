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
- **"Used once"** is recorded in an in-process map. Behind two replicas the same
  token can therefore be consumed once on *each*: single-use is per-replica, not
  per token, and it degrades silently the first time you scale out.

Configure both when the approving process is not the acting one, or when there is
more than one replica:

```ts
const govern = new Watchlight({
  approvalSecret: process.env.APPROVAL_SECRET,   // >= 16 bytes; or WATCHLIGHT_APPROVAL_SECRET,
                                                 // or reuse tokenSecret — the approval key is
                                                 // derived from it with a distinct separator
  approvalStore: {
    has: (id) => redis.exists(`wl:appr:${id}`).then(Boolean),
    // a conditional write makes single-use atomic; `false` refuses the replay
    add: (id, expiresAt) =>
      redis.set(`wl:appr:${id}`, "1", { NX: true, PXAT: expiresAt }).then((r) => r !== null),
  },
});
```

```python
govern = Watchlight(
    approval_secret=os.environ["APPROVAL_SECRET"],
    approval_store=redis_store,   # .has(id) -> bool, .add(id, expires_at); synchronous
)
```

The id handed to the store is `<exp>.<nonce>` — unique per mint, and never the
signature, so a store whose rows leak yields no usable approval. `expires_at` is
epoch milliseconds, so the row can carry its own TTL.

**Fail-closed throughout.** A store that raises **refuses** the approval; it never
admits one. And every refusal — expired, tampered, signed with another key,
already consumed, or a store that could not answer — surfaces as the *same*
`NeedsApproval` with the uniform `approval required` reason, so a caller probing
the boundary learns nothing about which check refused it.

Graduate with `WATCHLIGHT_APDP_URL`; in Enterprise the same `forbid` boundaries
are centrally managed, approval tokens are KMS-signed and recorded in signed
lineage, and the approval step becomes a full workflow.
