# Pattern: external messaging

An agent can send email, chat or webhooks. Internal recipients are free; going
outside is limited to an allowlist, with a human in the way.

```cedar
permit(principal, action == Action::"send_message", resource)
when { context.recipient_internal == true };

@enforcement_effect("require_approval")
permit(principal, action == Action::"send_message", resource)
when { context.recipient_internal == false
    && ["partner.example", "vendor.example"].contains(context.recipient_domain) };
```

## Govern the tool

```ts
const send = govern.tool(sendMessage, {
  intent: "send_message",
  context: (m) => ({
    recipient_internal: m.domain === myOrgDomain,
    recipient_domain:   m.domain,
  }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

## Verdicts

Proved by [`suites/external-messaging.suite.json`](./suites/external-messaging.suite.json).

| recipient | domain | verdict |
|---|---|---|
| internal | `internal.example` | **Allow** |
| external | `partner.example` | **NeedsApproval** |
| external | `unknown.example` | **Deny** |

## Worth knowing

- **Allowlist with a set literal.** `["a", "b"].contains(context.x)` resolves in
  the engine; entity-hierarchy `in` does not. On `context.*` the engine resolves
  `==`, `is`, `like` and set `contains`, and nothing else.
- Anything off the list falls through to `Deny`, so a new destination is
  reachable only after you add it to the policy.
- Decide `recipient_internal` from the address your code parsed, never from what
  the model said the recipient was.
