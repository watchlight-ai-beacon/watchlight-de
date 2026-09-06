# The identity model

Three identities through one engine and one policy set, printed side by side in
one audit trail.

| Case | `principal` — the subject | `context.actor` — the runtime | `context.actor_chain` |
|---|---|---|---|
| An agent acting alone | `Agent::"flight-booker"` | `flight-booker` | not recorded |
| The same agent for a person | `User::"db:4412"` | `flight-booker` | not recorded |
| A sub-agent under it | `User::"db:4412"` | `seat-picker` | `["flight-booker","seat-picker"]` |

```bash
python identity.py       # or: node identity.mjs
```

No API key, no network, no identity provider. The script asserts every verdict
and record shape and exits non-zero if one changes.

## What you see

```text
case 1 — the agent acting alone (no principal: the agent is the subject)
    cache          -> Allow  agent=flight-booker  chain=[flight-booker]               principal=Agent::"flight-booker"
    book           -> Deny   agent=flight-booker  chain=[flight-booker]               principal=Agent::"flight-booker"

case 2 — the same agent acting for a person (same actor, different subject)
    book           -> Allow  agent=flight-booker  chain=[flight-booker]               principal=User::"db:4412"

case 3 — a sub-agent under the booking agent (subject unchanged, chain extended)
    pick_seat      -> Allow  agent=seat-picker    chain=[flight-booker > seat-picker] principal=User::"db:4412"
    book           -> Deny   agent=seat-picker    chain=[flight-booker > seat-picker] principal=User::"db:4412"

the three cases, side by side in the one audit stream
    alone         {"agent": "flight-booker", "principal": "Agent::\"flight-booker\"", "intent": "cache", "decision": "Allow"}
    for a person  {"agent": "flight-booker", "principal": "User::\"db:4412\"", "intent": "book", "decision": "Allow"}
    sub-agent     {"agent": "seat-picker", "actor_chain": ["flight-booker", "seat-picker"], "principal": "User::\"db:4412\"", "intent": "pick_seat", "decision": "Allow"}

OK — three cases, three identities, one engine and one policy set.
```

## One engine, many names

```python
govern = Watchlight(agent="trip-platform", audit_dir=AUDIT_DIR)
govern.load(HERE / "policy.suite.json")

booker = govern.as_("flight-booker")     # same engine, same policies, same trail
memory = govern.as_("memory-writer")
```

A name costs no second policy load. The script proves it by behaviour: a policy
added through `flight-booker` decides a call made through `memory-writer`.

## Where the actor comes from

The actor is the governor you called through. You pick it by picking the handle,
never by passing a field. The script makes the same `trace` call four ways:

| Called through | actor | chain | verdict |
|---|---|---|---|
| the governor as constructed | `trip-platform` | `[trip-platform]` | Deny |
| `.as_("flight-booker")` | `flight-booker` | `[flight-booker]` | Allow |
| `authorize(..., agent="itinerary-mailer")` | `itinerary-mailer` | `[itinerary-mailer]` | Deny |
| `delegate(scope, "seat-picker")` | `seat-picker` | `[flight-booker > seat-picker]` | Allow |

Renaming always yields a fresh single-element chain — the third row was made
*through* `flight-booker` and still did not inherit its chain. Only `delegate`
appends.

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

Each is exercised in both directions, and the run asserts that every permit
granted something — delete one and the script goes red.

## What a caller cannot do

The SDK owns `context.actor` and `context.actor_chain`. Four attempts are
refused before anything reaches the engine, so none writes a record:

- `context={"actor": "memory-writer"}` on a `flight-booker` call →
  `ReservedContextError`
- `context={"actor_chain": [...]}` claiming a delegation that never happened →
  `ReservedContextError`
- `picker.as_("row-checker")` — a delegate cannot be renamed → `TypeError`
- the same rename through the per-call `agent=` override → `TypeError`

A context *identical* to the SDK's own values is accepted. A caller can neither
invent a delegation nor extend one.

## Worth knowing

- **A scope is not consulted when a call is authorized.** It limits what
  `delegate` may hand a sub-agent, and it is checked there. Confining a
  sub-agent means narrowing the scope *and* writing the policy.
- **`actor_chain` is recorded only under a delegation.** Outside one the chain
  is the single-element `[agent]`. Both policy forms still work. The chain is
  bounded at six entries.
- **Namespace your subject ids** — `sso:8f3c2b7e` from a verified token claim,
  `db:4412` from a users row. Never a username or an email: those get
  reassigned, and an old record would then point at a different person.
- No fixture in the suite sets `context.actor`, because the guard applies to a
  fixture too. The suite covers actor rules in the fail-closed direction; the
  scripts cover the positive one, where the runtime really is that agent.

Verified by [`check.sh`](./check.sh). The reference is
[the identity model](../../../docs/identity-model.md); the words are in the
[glossary](../../../docs/glossary.md).
