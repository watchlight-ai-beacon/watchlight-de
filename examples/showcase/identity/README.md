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
made executable; the words it uses are defined in the
[glossary](../../../docs/glossary.md).

| File | Purpose |
|---|---|
| [`identity.py`](identity.py) / [`identity.mjs`](identity.mjs) | The whole example, one per lane. Same policies, same verdicts, same record shape; 49 assertions each. |
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

The engine's own `watchlight:` decision lines interleave with the script's:

```
one engine, one policy set, many named agents
    policies loaded              7
    named agents                 flight-booker, memory-writer (one engine, renamed)
    policies after naming them   7
  OK  the policy set is the 7 policies in policy.suite.json
  OK  naming agents did not reload or recompile a single policy
  OK  every name reports the same policy count
  OK  loading the same policy source again added nothing — the memo is shared too

    a policy added through one name is in force for all of them
  OK  every name sees the added policy in its count
watchlight: governing 'memory-writer' (dev mode, in-process engine)
watchlight: ALLOW  check_in  trip/AX8821
    check_in       -> Allow  agent=memory-writer     chain=[memory-writer]        principal=User::"db:4412"
  OK  a policy added through flight-booker decided a call made through memory-writer — one engine, not two holding the same file

case 1 — the agent acting alone (no principal: the agent is the subject)
watchlight: ALLOW  cache     route/AMS-LIS
    cache          -> Allow  agent=flight-booker     chain=[flight-booker]        principal=Agent::"flight-booker"
watchlight: DENY   book      trip/AX8821     not authorized
    book           -> Deny   agent=flight-booker     chain=[flight-booker]        principal=Agent::"flight-booker"

case 2 — the same agent acting for a person (same actor, different subject)
watchlight: ALLOW  book      trip/AX8821
    book           -> Allow  agent=flight-booker     chain=[flight-booker]        principal=User::"db:4412"

case 3 — a sub-agent under the booking agent (subject unchanged, chain extended)
watchlight: ALLOW  pick_seat seat/AX8821
    pick_seat      -> Allow  agent=seat-picker       chain=[flight-booker > seat-picker]  principal=User::"db:4412"
watchlight: DENY   book      trip/AX8821     not authorized
    book           -> Deny   agent=seat-picker       chain=[flight-booker > seat-picker]  principal=User::"db:4412"
  OK  case 1: the agent alone may warm the cache
  OK  case 1: the agent alone may not book
  ...
  OK  case 3: the ordered chain is [flight-booker > seat-picker], root first
  OK  case 3: the subject is unchanged — delegation adds an actor, not a subject
  ...

actions this run reached an Allow on
    book, cache, cancel_trip, check_in, pick_seat, read_itinerary, trace, write_memory
  OK  every policy in the set granted something — deleting any permit fails here

the three cases, side by side in the one audit stream
    alone         {"agent": "flight-booker", "principal": "Agent::\"flight-booker\"", "intent": "cache", "decision": "Allow"}
    for a person  {"agent": "flight-booker", "principal": "User::\"db:4412\"", "intent": "book", "decision": "Allow"}
    sub-agent     {"agent": "seat-picker", "actor_chain": ["flight-booker", "seat-picker"], "principal": "User::\"db:4412\"", "intent": "pick_seat", "decision": "Allow"}

OK — three cases, three identities, one engine and one policy set.
```

## One engine, many named agents

The example constructs **one** governor, loads the policy set **once**, and
names agents with `as`, which returns another `Watchlight` backed by the same
engine:

```python
govern = Watchlight(agent="trip-platform", audit_dir=AUDIT_DIR, audit_sink=records.append)
govern.load(HERE / "policy.suite.json")

booker = govern.as_("flight-booker")     # same engine, same policies, same trail
memory = govern.as_("memory-writer")
```

Counting policies is not enough to prove that — two governors each loading the
same file would count the same. So the example proves it by behaviour: it adds
one policy through `flight-booker` and then has `memory-writer` decide a call
with it. That only works if there is one engine, and it is the assertion that
fails if someone replaces the names with separate governors. Loading the same
source twice is also asserted to add nothing.

Because renaming shares the trail and the sink, every record below lands in one
stream, told apart by `agent` and `actor_chain`.

## Where the actor comes from

The actor is the identity of the **governor you called through** — you choose it
by choosing the handle, not by passing a field. The example makes the same call
(`trace`) four ways:

| Called through | actor | chain | verdict |
|---|---|---|---|
| the governor as constructed | `trip-platform` | `[trip-platform]` | Deny |
| `.as_("flight-booker")` | `flight-booker` | `[flight-booker]` | Allow |
| `authorize(..., agent="itinerary-mailer")` | `itinerary-mailer` | `[itinerary-mailer]` | Deny |
| `delegate(scope, "seat-picker")` | `seat-picker` | `[flight-booker > seat-picker]` | Allow |

```
  Watchlight(agent="trip-platform")   <- one engine, one policy set
    |
    |-- (called directly) --->   actor  trip-platform
    |                            chain  [trip-platform]
    |
    |-- .as("flight-booker") ->  actor  flight-booker
    |      |                     chain  [flight-booker]
    |      |
    |      |-- .authorize(agent="itinerary-mailer")
    |      |     `--------->     actor  itinerary-mailer
    |      |                     chain  [itinerary-mailer]
    |      |
    |      `-- .delegate(scope, "seat-picker")
    |            `--------->     actor  seat-picker
    |                            chain  [flight-booker > seat-picker]
    |
    `-- .as("memory-writer") ->  actor  memory-writer
                                 chain  [memory-writer]

  the request  --X-->  actor / actor_chain
      no field of the call reaches either key: a differing value
      raises, an identical one is accepted
```

Three things fall out of that output. Renaming — with `as` or with the per-call
override — always produces a fresh single-element chain: the override was made
*through* `flight-booker` and still did not inherit its chain, which is why it
is denied. Only `delegate` appends. And the caller's context is merged, not
trusted: supplying the derived `actor` and `actor_chain` verbatim is accepted,
while a value that differs raises.

## The whole flow

```
  a traveller signs in         the subject does not change
        |                      on the way down
        v
  User::"db:4412"
        |
        v
  +- flight-booker ----------------------------------------------+
  | actor  flight-booker    chain  [flight-booker]               |
  |                                                              |
  | read_itinerary itinerary/AX8821       ALLOW                  |
  | book           trip/AX8821            ALLOW                  |
  | write_memory   memory/traveller-notes DENY   (wrong actor)   |
  |                                                              |
  | delegates seat selection --------------+                     |
  +----------------------------------------|---------------------+
                                           v
  +- seat-picker ------------------------------------------------+
  | actor  seat-picker  chain  [flight-booker > seat-picker]     |
  | subject still User::"db:4412"                                |
  |                                                              |
  | pick_seat      seat/AX8821            ALLOW                  |
  | trace          trace/AX8821           ALLOW                  |
  | book           trip/AX8821            DENY   (wrong actor)   |
  | cache          route/AMS-LIS          DENY   (wrong subject) |
  +--------------------------------------------------------------+
```

- The **subject** answers on whose behalf, and it does not change as work is
  delegated — the traveller is still the subject when the sub-agent acts.
- The **actor** answers which runtime made this particular call, and the
  **chain** shows how it got the authority.
- A policy can key on any of the three. The two denials above show two of them:
  `write_memory` and `book` fail an **actor** rule, `cache` fails a **subject**
  rule. Neither is the narrowed scope — a scope limits what `delegate` may hand
  a sub-agent and is checked when you delegate, never when a call is authorized,
  so confining a sub-agent means narrowing the scope *and* writing the policy.

Those six rows are these calls:

```python
booker.authorize(action="read_itinerary", resource="itinerary/AX8821", principal=traveller)
booker.authorize(action="book", resource="trip/AX8821", principal=traveller)
booker.authorize(action="write_memory", resource="memory/traveller-notes", principal=traveller)

root = booker.scope(tools=["search", "book", "pick_seat", "trace"])
picker = booker.delegate(root, "seat-picker", tools=["search", "pick_seat", "trace"])

picker.authorize(action="pick_seat", resource="seat/AX8821", principal=traveller)
picker.authorize(action="trace", resource="trace/AX8821", principal=traveller)
picker.authorize(action="book", resource="trip/AX8821", principal=traveller)
picker.authorize(action="cache", resource="route/AMS-LIS", principal=traveller)
```

```ts
await booker.authorize({ action: "read_itinerary", resource: "itinerary/AX8821", principal: traveller });
await booker.authorize({ action: "book", resource: "trip/AX8821", principal: traveller });
await booker.authorize({ action: "write_memory", resource: "memory/traveller-notes", principal: traveller });

const root = await booker.scope({ tools: ["search", "book", "pick_seat", "trace"] });
const picker = booker.delegate(root, "seat-picker", { tools: ["search", "pick_seat", "trace"] });

await picker.authorize({ action: "pick_seat", resource: "seat/AX8821", principal: traveller });
await picker.authorize({ action: "trace", resource: "trace/AX8821", principal: traveller });
await picker.authorize({ action: "book", resource: "trip/AX8821", principal: traveller });
await picker.authorize({ action: "cache", resource: "route/AMS-LIS", principal: traveller });
```

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
that does not with the *same* subject. At the end the script asserts that every
action some policy permits was in fact allowed at least once, so deleting any
permit fails the run.

## What a caller cannot do

The SDK owns `context.actor` and `context.actor_chain` and sets both on every
call. Four refusals are asserted — each on the error's own message, and each
also checked to have written **no** audit record, since they are refused before
anything reaches the engine:

| Attempt | Refusal |
|---|---|
| `context={"actor": "memory-writer"}` on a `flight-booker` call | `ReservedContextError` |
| `context={"actor_chain": [...]}` claiming a delegation that did not happen | `ReservedContextError` |
| `picker.as_("row-checker")` — renaming a delegate | `TypeError` |
| the same rename through the per-call `agent=` override | `TypeError` |

Both halves of the rule are asserted: a value that *disagrees* raises, and a
value *identical* to the SDK's own is accepted. Through the context, a caller
can neither invent a delegation nor extend one.

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
`memory-writer`, because that is the only way to produce the value at all — and
the scripts assert that every permit granted something, which is what fails if
one is deleted.

## Notes

- **`actor_chain` appears only under a delegation.** Outside one the chain is
  the single-element `[agent]`, so the record keeps the shape it always had.
  Both policy forms still work: `context.actor == "…"` and
  `context.actor_chain.contains("…")`.
- **Renaming versus delegating.** `as_` / `as` gives a name to an agent acting
  alone; `delegate` narrows a scope *and* extends the chain. The chain is
  bounded at `MAX_ACTOR_CHAIN` = 6 entries.
- **Value-free trail.** The records carry who acted, through whose delegation,
  on whose behalf, the intent, the resource and the verdict — never an argument
  value.
