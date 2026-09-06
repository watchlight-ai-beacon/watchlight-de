# Role-based access control

A role is a runtime fact about the person on whose behalf the call is made, so
it travels in `context`, not on the principal. The principal names *who*; the
context carries *what they are allowed to be* at the moment of the call.

```cedar
permit(principal, action == Action::"read_ledger", resource)
when { context.role == "accountant" };
```

You supply the role from whatever your app already trusts — a session, a JWT
claim, a database lookup. The engine never fetches it.

```python
from watchlight import govern

@govern.tool(intent="read_ledger", context=lambda **kw: {"role": kw["user"].role})
def read_ledger(user, account_id):
    ...
```

```ts
const readLedger = govern.tool(fn, {
  intent: "read_ledger",
  context: ({ user }) => ({ role: user.role }),
});
```

## More than one role

Most real users have several. Put them in a list and ask whether the list holds
what the policy needs.

```cedar
permit(principal, action == Action::"read_ledger", resource)
when { context.roles.contains("accountant") };
```

`.contains()` asks for one role. When any of several will do, use
`containsAny`; when all are required, `containsAll`.

```cedar
when { context.roles.containsAny(["accountant", "auditor"]) }
when { context.roles.containsAll(["accountant", "on_call"]) }
```

## Do not use `in` for this

This is the mistake worth knowing about, because it fails in the direction that
looks like your policy working:

```cedar
// Denies even when the role IS "admin".
when { context.role in ["admin", "ops"] }
```

`in` is Cedar's entity-hierarchy operator. Against a list of plain strings it
does not match, and nothing reports an error — the call simply denies. Write
`context.roles.containsAny(["admin", "ops"])` instead.

The same applies to `principal in Group::"admins"`. There is no entity store to
consult, so a group test denies silently too. Pass the group as a role.

## Roles that imply other roles

Cedar has no role hierarchy here, and that is usually a relief: expand the
hierarchy where you already know it, in the code that builds the context.

```python
ROLE_IMPLIES = {"admin": ["admin", "editor", "viewer"], "editor": ["editor", "viewer"]}

def roles_for(user):
    return sorted({r for role in user.roles for r in ROLE_IMPLIES.get(role, [role])})
```

The policy stays a flat membership test, which is far easier to read in an
audit six months later than a hierarchy that has to be reconstructed.

## Denying by role

A `forbid` beats every permit, so a role that must never do something is one
rule regardless of how many permits exist.

```cedar
forbid(principal, action == Action::"delete_ledger", resource)
when { context.roles.contains("contractor") };
```

## When the role is missing

A rule that reads a key nothing supplied denies. That is the safe direction,
but it means a bug in your context builder looks exactly like a policy denial.
Guard an optional key:

```cedar
when { context has roles && context.roles.contains("accountant") }
```

Assert both halves in a fixture — the allow for a user who has the role, and the
deny for one who does not. See [testing your policies](testing-policies.md).

## Next

- **[Attribute-based access control](abac.md)** — deciding on facts other than
  roles, and combining the two.
- **[How policy works](policies.md)** — the request shape, default deny, and
  every operator the engine resolves.
