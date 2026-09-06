# Attribute-based access control

A role answers *who someone is*. An attribute answers *what is true right now* —
the amount on this transfer, the region this record lives in, whether the
session was re-authenticated a minute ago. Both travel the same way, in
`context`.

```cedar
permit(principal, action == Action::"transfer", resource)
when { context.amount <= 1000 && context.mfa == true };
```

The engine compares what you pass. It has no view of your database, so an
attribute it was not given is an attribute it cannot read.

```python
@govern.tool(intent="transfer", context=lambda **kw: {
    "amount": kw["amount"],
    "mfa": kw["session"].mfa_verified,
})
def transfer(session, to, amount):
    ...
```

## What you can compare

| Kind | Example |
|---|---|
| String | `context.department == "finance"` |
| Number | `context.clearance >= 3`, `context.amount <= 1000` |
| Boolean | `context.mfa == true` |
| String pattern | `context.email like "*@acme.com"` |
| Set membership | `context.regions.contains("eu")` |
| Nested object | `context.user.department == "finance"` |

Combine them with `&&`, `||` and `!`. A nested object is fine, so you can pass a
shape your code already has rather than flattening it.

## Attributes belong in context, not on the principal

```cedar
// Denies silently. There is no entity store to read `clearance` from.
when { principal.clearance >= 3 }
```

`principal` names the subject and nothing more. Pass the attribute:
`context.clearance >= 3`. This holds in both editions and in both language
lanes, so a policy written this way behaves identically everywhere it runs.

## Relating one attribute to another

Two facts you pass can be compared with each other, which is how ownership rules
are usually written:

```cedar
permit(principal, action == Action::"read", resource)
when { context.owner == context.requester };
```

## Excluding on an attribute

`forbid` is the right tool for a condition that must hold no matter which permit
matched — a data-residency rule, a frozen account, a maintenance window.

```cedar
forbid(principal, action, resource)
when { context.region == "eu" && context.destination != "eu" };
```

## Optional attributes

An attribute that is not always present needs a guard, because a rule that reads
a missing key denies:

```cedar
when { context has clearance && context.clearance >= 3 }
```

Without the guard the rule denies whenever the key is absent. That is the safe
direction, and it is also indistinguishable from a policy that meant to deny —
so decide deliberately which you want, and assert it in a fixture.

## Combining with roles

Most policies end up using both: a role to say who may attempt the action, and
attributes to bound it.

```cedar
permit(principal, action == Action::"transfer", resource)
when {
  context.roles.contains("treasurer")
  && context.amount <= 50000
  && context.mfa == true
};
```

Read that as a sentence — a treasurer, under fifty thousand, with MFA — which is
the property that makes a policy reviewable by someone who does not write Cedar.

## Next

- **[Role-based access control](rbac.md)** — roles, multiple roles, and the `in`
  trap worth knowing about.
- **[Testing your policies](testing-policies.md)** — fixtures that pin an
  attribute boundary so a later edit cannot move it quietly.
