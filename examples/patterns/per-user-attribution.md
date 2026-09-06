# Pattern: per-user attribution

One agent serves many end-users. Each decision names the acting user, and policy
is scoped to them rather than to the agent.

```cedar
permit(principal == User::"alice", action == Action::"pay", resource);
```

## Govern the tool

Bind the principal per call, from the user your application already
authenticated.

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

## Verdicts

Proved by [`suites/per-user-attribution.suite.json`](./suites/per-user-attribution.suite.json).

| principal | verdict |
|---|---|
| `User::"alice"` | **Allow** |
| `User::"bob"` | **Deny** |
| *(unset — the agent itself)* | **Deny** — an unattributed call cannot pay |

## Worth knowing

- The per-call `principal` is what lands on the audit line and what
  `principal == User::"…"` matches.
- **Write the type.** A bare `alice` matches a policy naming that id under
  `User`, `Agent`, `Group` or `Role`, and when it matches more than one an allow
  beats a forbid.
- **Never derive it from client-controlled input**, and use a stable internal id
  rather than an email — see the [identity model](../../docs/identity-model.md).

Combine with [money-bounded](./money-bounded-agent.md) to bound *this user's*
spend, and join the returned `decisionId` to your own record.
