# How policy works

Every decision is one [Cedar](https://www.cedarpolicy.com/) evaluation: *may this
principal take this action on this resource, in this context?* Policies are
`permit` and `forbid` rules you keep in a file.

```cedar
permit(principal, action == Action::"read", resource)
when { context.tier == "gold" };
```

## The request

| You pass | A policy names it | Example |
|---|---|---|
| `principal` — on whose behalf | `principal`, or `principal == User::"alice"` | `User::"db:4412"` |
| `action` — the verb | `action`, or `action == Action::"read"` | `read` |
| `resource` — what it acts on | `resource`, or `resource == Resource::"doc-1"` | `trip/AX8821` |
| `context` — the runtime facts | `context.amount`, `context.mfa`, … | `{"amount": 500}` |

A bare word — `principal`, `action`, `resource` — matches anything. `==` pins it.

## Default deny

No rule that permits a request means `Deny`. You open access one `permit` at a
time, and a governor with no policies at all denies everything.

```python
govern.load("watchlight.policy.json")
assert govern.has_policies, "no policies loaded — every call would be denied"
```

## `when` and `unless`

`when { … }` must be true for a rule to apply; `unless { … }` must be false.
Both read `context`, which is where every runtime fact lives.

```cedar
// spend cap
permit(principal, action == Action::"transfer", resource)
when { context.amount <= 1000 };

// kill switch: normal authority, revoked by a flag
permit(principal == Agent::"payments", action, resource)
unless { context.quarantined == true };
```

## `forbid` wins

A request is allowed **iff** some `permit` matches and no `forbid` does.

```cedar
permit(principal == User::"admin", action, resource);
forbid(principal, action == Action::"delete", resource);   // admin still can't delete
```

That is why a `forbid` is the right shape for a hard boundary — a compliance
rule, a quarantine — that must hold whatever else is granted.

## Name the entity type

The accepted principal types are `User`, `Agent`, `Group`, `Role`, `Tool`,
`Resource` and `Workflow`. Write the type on both sides:

```python
from watchlight import principals

govern.authorize(action="book", principal=principals.user("db:4412"))
```

A **bare** identifier — `db:4412`, with no `Type::` — is accepted but opaque. It
matches a policy naming that id under `User`, `Agent`, `Group` **or** `Role`, and
when it matches more than one, an **allow beats a forbid** — the opposite of
Cedar's usual rule. A `forbid` naming an agent can be defeated by a `permit`
naming a user with the same id. Only a typed reference discriminates.

The action is always type `Action`; a policy giving it another type is rejected.
Full detail is in [the identity model](identity-model.md).

## What the engine resolves

For policies that decide on **runtime facts** — the common case — the reliable
building blocks are:

- **`context.*`** — any field you pass, compared with `==` `!=` `<` `<=` `>`
  `>=`, combined with `&&` `||` `!`;
- **identity `==`** on the request triple;
- **`is`** (entity-type test), **`like`** (glob on strings), and **`.contains()`**
  on a set you put in `context`.

Two things do **not** resolve, in either edition, and deny silently: entity
relationships (`principal in Group::"admins"`) and app-defined entity attributes
(`principal.clearance`). There is no entity store to consult. Pass those facts in
`context` instead — `context.groups.contains("admins")`, `context.role ==
"editor"` — and the policy behaves identically everywhere.

:::note String matching uses `like`, not `.startsWith()`
Cedar has no `.startsWith()` / `.endsWith()` / `.contains()` on **strings**, and a
policy using them fails to load. Use a glob: `like "analyze_*"`, `like "*_report"`,
`like "*write*"`. `.contains()` is for sets only.
:::

## Cheat sheet

| You want to… | Write |
|---|---|
| Match a specific user | `principal == User::"alice"` |
| Match any user | `principal is User` |
| Match one action | `action == Action::"read"` |
| Match one resource | `resource == Resource::"doc-1"` |
| Require a condition | `when { context.mfa == true }` |
| Exclude a condition | `unless { context.quarantined == true }` |
| Match a string pattern | `when { context.path like "public/*" }` |
| Numeric guard | `when { context.amount <= 1000 }` |
| Hard block, beats any permit | `forbid(...)` |
| Guard a key that may be absent | `when { context has owner && … }` |

A rule that reads a key nothing supplied falls through to `Deny`, so write `has`
before the comparison.

The full language is documented at
[docs.cedarpolicy.com](https://docs.cedarpolicy.com/policies/syntax-operators.html).

## Next

- [Governance patterns](../examples/patterns/README.md) — a policy for each
  high-stakes decision, each one run against the real engine on every commit.
- [The identity model](identity-model.md) — what `principal` and `context.actor`
  contain, and what a policy can name.
- [Testing your policies](testing-policies.md) — golden fixtures, and the CLI
  that fails a CI run.
