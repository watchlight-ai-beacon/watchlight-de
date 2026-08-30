# Pattern: per-user attribution

**Problem.** One agent serves many end-users. A decision must be attributed to the
*acting user* — for liability and reconstruction — and policy must be scoped to
them, not to the agent as a whole.

**Policy** — [`suites/per-user.suite.json`](./suites/per-user.suite.json):

```cedar
permit(principal == User::"alice", action == Action::"pay", resource);
```

**Govern the tool** — bind the principal per call from the acting user:

```ts
const pay = govern.tool(payOut, {
  intent: "pay",
  principal: (o) => `User::"${o.userId}"`,   // resolved per call, not the agent
});
```

```python
@govern.tool("pay", principal=lambda o: f'User::"{o["userId"]}"')
def pay_out(o): ...
```

**Verdicts** (verified):

| principal | verdict |
|---|---|
| `User::"alice"` | **Allow** |
| `User::"bob"` | **Deny** |
| *(unset — the agent itself)* | **Deny** — an unattributed call can't pay |

**Why it matters.** The per-call `principal` is what lands in the audit line and
what `principal == User::"…"` matches — so decisions are scoped to and recorded
against the real user, and an action with no attributed user is denied rather than
falling back to the agent's identity. Per-call principals are for attribution and
policy; they do **not** count against the free-tier "governed agent" limit (that
counts distinct `agent_id`s — see the
[overview](https://docs.watchlight.ai/de/overview)).

Combine with [money-bounded](./money-bounded-agent.md) to enforce *this user's*
limit on *this user's* spend, and join the returned `decisionId` to your record
for a per-user audit trail.
