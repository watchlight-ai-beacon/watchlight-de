# The identity model, running

Three governed calls, three identities, **one engine and one policy set**:

| Case | `principal` (the subject) | `context.actor` (the runtime) | `context.actor_chain` |
|---|---|---|---|
| An agent acting alone | `Agent::"flight-booker"` | `flight-booker` | `[flight-booker]` (not recorded) |
| The same agent for a person | `User::"db:4412"` | `flight-booker` | `[flight-booker]` (not recorded) |
| A sub-agent under it | `User::"db:4412"` | `seat-picker` | `["flight-booker","seat-picker"]` |

The script prints each verdict next to the audit record it produced, so the
three are visibly different in one trail, and exits non-zero if any verdict or
record shape changes. This is [`docs/identity-model.md`](../../../docs/identity-model.md)
made executable.

| File | Purpose |
|---|---|
| [`identity.py`](identity.py) / [`identity.mjs`](identity.mjs) | The whole example, one per lane. Same policies, same verdicts, same record shape. |
| [`policy.suite.json`](policy.suite.json) | The seven Cedar policies **and** their eleven golden tests, in one file. The scripts load `policies`; `watchlight policy test` runs `tests`. |

## Run

```bash
# Python
pip install watchlight
python examples/showcase/identity/identity.py

# TypeScript
npm i -g @watchlight/sdk            # or, in a clone: cd ts && npm install && npm run build
node examples/showcase/identity/identity.mjs

# The policies on their own (either CLI)
watchlight policy test examples/showcase/identity/policy.suite.json
```

Both lanes run offline: no API key, no network, no identity provider. The audit
trail is written to `.watchlight/audit.jsonl` next to the scripts, and every
record is also handed to an in-process `audit_sink` / `auditSink` so the script
can read back exactly what was recorded.

## What you see

```
one engine, one policy set, many named agents
    policies loaded              7
    named agents                 flight-booker, memory-writer (views of one engine)
    policies after naming them   7
  OK  naming agents did not reload or recompile a single policy

case 1 — the agent acting alone (no principal: the agent is the subject)
    cache          -> Allow  agent=flight-booker  chain=(none)     principal=Agent::"flight-booker"
    book           -> Deny   agent=flight-booker  chain=(none)     principal=Agent::"flight-booker"

case 2 — the same agent acting for a person (same actor, different subject)
    book           -> Allow  agent=flight-booker  chain=(none)     principal=User::"db:4412"

case 3 — a sub-agent under the booking agent (subject unchanged, chain extended)
    pick_seat      -> Allow  agent=seat-picker    chain=[flight-booker > seat-picker]  principal=User::"db:4412"
    book           -> Deny   agent=seat-picker    chain=[flight-booker > seat-picker]  principal=User::"db:4412"
  …
the three cases, side by side in the one audit stream
    alone         {"agent":"flight-booker","principal":"Agent::\"flight-booker\"","intent":"cache","decision":"Allow"}
    for a person  {"agent":"flight-booker","principal":"User::\"db:4412\"","intent":"book","decision":"Allow"}
    sub-agent     {"agent":"seat-picker","actor_chain":["flight-booker","seat-picker"],"principal":"User::\"db:4412\"","intent":"pick_seat","decision":"Allow"}

OK — three cases, three identities, one engine and one policy set.
```

## One engine, many named agents

The example constructs **one** governor, loads the policy set **once**, and
names agents with a view:

```python
govern = Watchlight(agent="trip-platform", audit_dir=AUDIT_DIR, audit_sink=records.append)
govern.load(HERE / "policy.suite.json")

booker = govern.as_("flight-booker")     # same engine, same policies, same trail
memory = govern.as_("memory-writer")
```

`policy_count` / `policyCount` is printed before and after naming — and after
delegating — and asserted unchanged. Naming is not a reason to construct a
second engine; a *different policy set* is. Because the views share the trail
and the sink, every record below lands in one stream, told apart by `agent` and
`actor_chain`.

## The policies, one per field

```cedar
// a person's own authority — the acting runtime is irrelevant
permit(principal == User::"db:4412", action == Action::"cancel_trip", resource);

// a tool restricted to one runtime — whoever it acts for
permit(principal, action == Action::"write_memory", resource)
when { context.actor == "memory-writer" };

// membership anywhere in the delegation, at any depth
permit(principal is User, action == Action::"trace", resource)
when { context.actor_chain.contains("flight-booker") };

// a narrower grant for the agent alone than for the same agent acting for a person
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };
permit(principal == Agent::"flight-booker", action == Action::"cache", resource);
```

Each is exercised in both directions: the runtime that holds the grant, and one
that does not with the *same* subject.

## What a caller cannot do

The SDK owns `context.actor` and `context.actor_chain` and sets both on every
call. Four refusals are asserted, each also checked to have written **no** audit
record — they are refused before anything reaches the engine:

| Attempt | Refusal |
|---|---|
| `context={"actor": "memory-writer"}` on a `flight-booker` call | `ReservedContextError` |
| `context={"actor_chain": [...]}` claiming a delegation that did not happen | `ReservedContextError` |
| `picker.as_("row-checker")` — renaming a delegate | `TypeError` |
| the same rename through the per-call `agent=` override | `TypeError` |

A context value *identical* to the SDK's own is accepted — the guard refuses
disagreement, not the key — and that is asserted too. Through the context, a
caller can neither invent a delegation nor extend one.

## Both identity sources, one call

Many applications have no identity provider, and none is needed. The example
derives a subject two ways and makes the identical call with each:

```python
# a token your application has already verified: use the subject claim
principals.user(f"sso:{claims['sub']}")

# a local session and users table: use the row's primary key
principals.user(f"db:{row['id']}")
```

Nothing here verifies a token or implies a particular provider — the claims are
an obviously synthetic dict. The two records are asserted to differ in the
subject id and in nothing else. Ids are namespaced (`sso:` / `db:`) so two
sources cannot collide, and neither is a username or an email: those get
reassigned, which would point an old audit record at a different person.

## Why no fixture sets `context.actor`

`watchlight policy test` runs fixtures through its own governor, so the same
guard applies to a fixture as to a caller: a fixture that set `actor` to some
other runtime would be refused, not honoured. The suite therefore covers the
subject-keyed rules positively and the actor-keyed rules in the fail-closed
direction — *a runtime that is not `memory-writer` may not write memory*. The
positive direction is proven by the scripts, where the acting runtime really is
`memory-writer`, because that is the only way to produce the value at all.

## Notes

- **`actor_chain` appears only under a delegation.** Outside one the chain is
  the single-element `[agent]`, so the record keeps the shape it always had.
  Both policy forms still work: `context.actor == "…"` and
  `context.actor_chain.contains("…")`.
- **A delegate is not a rename.** `as_` / `as` gives a name to an agent acting
  alone; `delegate` narrows a scope *and* extends the chain. The chain is
  bounded at `MAX_ACTOR_CHAIN` = 6 entries.
- **Value-free trail.** The records carry who acted, through whose delegation,
  on whose behalf, the intent, the resource and the verdict — never an argument
  value.
