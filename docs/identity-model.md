# The identity model

What to pass, what gets recorded, and what a policy can name. Terms are defined
in the [glossary](glossary.md).

```python
from watchlight import govern, principals

govern.authorize(action="book", principal=principals.user("db:4412"))
```

That call answers four questions:

| Question | Where it goes | Example value |
|---|---|---|
| On whose behalf does this run? | `principal` — the **subject** | `User::"db:4412"` |
| Which runtime is acting? | `context.actor` | `context.actor == "flight-booker"` |
| Through whose delegation? | `context.actor_chain` | `context.actor_chain.contains("flight-booker")` |
| Under what narrowed authority? | the attenuation **scope** | `govern.scope(tools=[…])` → `delegate(…)` |

The subject and the actor are independent. An agent working for a person has
both; an agent working for itself has one identity in both roles.

## The three cases

| Case | `principal` | `context.actor` | How you make it |
|---|---|---|---|
| Agent acting alone | `Agent::"flight-booker"` | `flight-booker` | omit `principal` |
| Agent acting for a user | `User::"db:4412"` | `flight-booker` | pass `principal=principals.user("db:4412")` |
| Sub-agent under a parent | `User::"db:4412"` | leaf `seat-picker`, chain `["flight-booker", "seat-picker"]` | `govern.delegate(scope, "seat-picker")` |

```python
from watchlight import govern, principals

govern.authorize(action="cache")                                       # agent alone
govern.authorize(action="book", principal=principals.user("db:4412"))  # for a user

seat_picker = govern.as_("seat-picker")     # same engine, same policies, same trail
seat_picker.authorize(action="pick_seat", principal=principals.user("db:4412"))
```

```ts
import { govern, principals } from "@watchlight/sdk";

await govern.authorize({ action: "cache" });                                       // agent alone
await govern.authorize({ action: "book", principal: principals.user("db:4412") }); // for a user

const seatPicker = govern.as("seat-picker");   // same engine, same policies, same trail
await seatPicker.authorize({ action: "pick_seat", principal: principals.user("db:4412") });
```

## Where the actor comes from

You choose the actor by choosing the handle, not by passing a field:

| Called through | `context.actor` | `context.actor_chain` |
|---|---|---|
| the governor as constructed | its constructed name | `[name]` |
| `as("flight-booker")` / `as_(…)` | `flight-booker` | `[flight-booker]` |
| a per-call `agent` override | that name | `[that name]` |
| `delegate(scope, "seat-picker")` | `seat-picker` | `[flight-booker, seat-picker]` |
| **a governor with no name configured** | **not set** | **not set** |

`context.actor` and `context.actor_chain` are reserved and set by the SDK on
every call. A caller-supplied value that differs raises `ReservedContextError`;
an identical one is accepted.

`as` and the per-call `agent` override always start a fresh single-element
chain. Only `delegate` appends.

| Ask | Write |
|---|---|
| Did *this* agent make the call? | `context.actor == "seat-picker"` |
| Was this agent anywhere in the delegation? | `context.actor_chain.contains("flight-booker")` |

`context.actor_chain` is set-valued, so `contains` resolves. Outside any
delegation it is the single-element `[agent]`, so both forms always work.

Do not use a context key of your own called `agent`. The engine overwrites
`context.agent` with an object, so a policy comparing it to a string never
matches and the call silently denies.

## An agent you did not name

A governor built with neither an `agent` option nor `WATCHLIGHT_AGENT` (blank
counts as unset) has no name. It still runs — the quickstart needs no
configuration — but it sets **neither** actor key, so a `permit` reading
`context.actor` cannot match it and a `forbid` reading it still denies. It
records the reserved placeholder `<unconfigured>` and says so once, on its first
record.

A policy naming `Agent::"<unconfigured>"` as its **principal** does match an
unconfigured governor, so do not treat the placeholder as a guard. Passing
`<unconfigured>` as an agent name raises, so that value on an audit row always
means the agent was never configured.

```python
from watchlight import Watchlight

anon = Watchlight()                    # no agent, no WATCHLIGHT_AGENT
anon.unconfigured                      # True
anon.agent                             # "<unconfigured>"
named = anon.as_("flight-booker")      # naming it configures it
named.unconfigured                     # False
```

```ts
import { Watchlight } from "@watchlight/sdk";

const anon = new Watchlight();         // no agent, no WATCHLIGHT_AGENT
anon.unconfigured;                     // true
anon.agent;                            // "<unconfigured>"
const named = anon.as("flight-booker");
named.unconfigured;                    // false
```

Any of these names it: `Watchlight({ agent })`, `WATCHLIGHT_AGENT`,
`configure_default(agent=…)` / `configureDefault({ agent })`, `as` / `as_`, and
`delegate`. An **explicit** empty or null name raises instead:
`Watchlight(agent=None)` and `new Watchlight({ agent: null })` both fail with
`agent must be a non-empty string`.

## What `principal` contains

`principal` holds a typed Cedar entity reference. The accepted types are `User`,
`Agent`, `Group`, `Role`, `Tool`, `Resource` and `Workflow`; an unrecognised one
fails the request rather than silently denying it.

| Shape | Meaning |
|---|---|
| `User::"<subject>"` | a person the call runs on behalf of |
| `Agent::"<name>"` | the agent on its own behalf — what an omitted `principal` records |
| `Group::"<id>"`, `Role::"<id>"`, `Workflow::"<id>"` | other subjects the vocabulary accepts |

Build the reference with the helpers. A subject id is an arbitrary string, and
the request form and the policy form escape it differently:

```python
from watchlight import principals
from watchlight.principals import for_policy

principals.user('a"b')             # request form → User::"a"b"      (id verbatim)
principals.agent("flight-booker")  # → Agent::"flight-booker"
for_policy("User", 'a"b')          # policy form  → User::"a\"b"     (escaped)
```

```ts
import { principals, policyEntityRef } from "@watchlight/sdk";

principals.user('a"b');                 // request form → User::"a"b"
principals.agent("flight-booker");      // → Agent::"flight-booker"
policyEntityRef("User", 'a"b');         // policy form  → User::"a\"b"
```

A request built with `principals.user(sub)` matches a policy written with
`for_policy("User", sub)` — the pair to use when a policy is generated from
data.

### What every `principal` must satisfy

Two rules, at every boundary that takes one — `authorize`, `tool`,
`mint_approval` / `mintApproval`, `counters`, `sanitize`, `screen`, and the
`principal` binding on every framework adapter:

* **A non-empty string.** `""` or whitespace-only raises. `user?.id ?? ""` used
  to record the *agent* as the subject.
* **No control characters.** A newline in a JSONL audit line splits one record
  into two, so one raises.

To name no subject at all, omit `principal` (or pass `None` / `undefined`). That
records the agent as its own subject.

### The bare form is opaque

A bare identifier — `team-42`, with no `Type::` — is accepted and recorded
exactly as given. It is not typed, and it is not inert.

A bare identifier matches a policy naming that id under `User`, `Agent`, `Group`
or `Role`. It does not match one naming it under `Tool`, `Resource` or
`Workflow`. When it matches more than one, an **allow beats a forbid** — the
opposite of Cedar's usual rule. A `forbid` naming an agent can be defeated by a
`permit` naming a user with the same id.

**Name the type.** Only a typed reference discriminates, which is what
`principals.user` / `principals.agent` are for. Treat `principal` in the audit
trail the same way: a string to compare, not a shape to parse.

## Naming several agents

`as` returns another `Watchlight` on the same engine — the same compiled
policies, the same trail and sink, the same secrets — with a different stamped
name. Six named agents cost one engine and one policy load.

| Way to name an agent | Use it when |
|---|---|
| `as(name)` / `as_(name)` | a long-lived named agent shares the policy set |
| the per-call or per-tool `agent` override | one call or one tool acts under another name |
| `delegate(scope, name, …)` | a sub-agent acts under a parent's narrowed authority |
| `configure_default(agent=…)` / `configureDefault({ agent })` | the exported `govern` is the one governor you use |

Wanting a different name is never a reason for a second governor. When you do
need one is in [using the governor](using-the-governor.md#how-many-governors).

## Delegating to a sub-agent

`delegate` narrows a scope for the sub-agent and extends the actor chain, so one
call produces both the confined authority and the delegated identity.

```python
root = govern.scope(tools=["search", "book"])                    # chain ("flight-booker",)
picker = govern.delegate(root, "seat-picker", tools=["search"])  # chain (…, "seat-picker")

picker.authorize(action="pick_seat", principal=principals.user("db:4412"))
govern.delegate(picker, "row-checker")                           # one level deeper
```

```ts
const root = await govern.scope({ tools: ["search", "book"] });
const picker = govern.delegate(root, "seat-picker", { tools: ["search"] });

await picker.authorize({ action: "pick_seat", principal: principals.user("db:4412") });
govern.delegate(picker, "row-checker");                          // one level deeper
```

The subject does not change on the way down. The actor does:

```
  a traveller signs in  ->  User::"db:4412"
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

Worth knowing:

* **A scope is checked when you delegate, never when a call is authorized.** So
  confining a sub-agent means narrowing the scope *and* writing the policy.
* **A scope token does not carry the chain.** `to_token()` / `toToken()`
  serialises capabilities only, so a scope re-established in another process
  starts a fresh chain from the receiving governor's agent. Call `delegate`
  there if the receiving side must record the delegation.
* A delegate cannot widen what its parent held (`AttenuationDenied`), and the
  chain is at most **`MAX_ACTOR_CHAIN` = 6** entries. Past that, `delegate`
  raises `DevEditionCeiling`.
* A delegate cannot be renamed, because renaming it would drop the chain. Spawn
  a further sub-agent with `delegate` instead.
* `picker.delegated_scope` / `picker.delegatedScope` is the narrowed scope it
  acts under.

Each case is distinct in the trail — `principal` and `agent` on the same line:

```json
{"agent":"flight-booker","principal":"Agent::\"flight-booker\"","intent":"cache","decision":"Allow"}
{"agent":"flight-booker","principal":"User::\"db:4412\"","intent":"book","decision":"Allow"}
{"agent":"seat-picker","actor_chain":["flight-booker","seat-picker"],"principal":"User::\"db:4412\"","intent":"pick_seat","decision":"Allow"}
```

`agent` is the leaf actor on every record. `actor_chain` appears only on records
produced through a delegate.

## Writing policies against them

A user's own authority — the agent is irrelevant:

```cedar
permit(principal == User::"db:4412", action == Action::"book", resource);
```

A tool restricted to one runtime, whoever it acts for:

```cedar
permit(principal, action == Action::"write_memory", resource)
when { context.actor == "memory-writer" };
```

A narrower grant when the agent acts alone than when it acts for a person:

```cedar
// acting for a person: any user subject, this runtime, real bookings
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };

// acting on its own behalf: cache warming only, never a booking
permit(principal == Agent::"flight-booker", action == Action::"cache", resource);
```

Anything this booking agent delegated, at any depth — the leaf may be a
sub-agent the policy has never heard of:

```cedar
permit(principal is User, action == Action::"trace", resource)
when { context.actor_chain.contains("flight-booker") };
```

On `context.*` the engine resolves `==`, `is`, `like` and set `contains`. That
is the whole operator surface.

## Where the values come from

The principal is a **stable identifier for a subject your application already
authenticated** — a session cookie, an API key mapped to an account, a verified
token. The shape of the reference does not change with the mechanism.

```python
# a verified token: use the subject claim, never the email in it
claims = verify_token(request.headers["authorization"])     # your verification
govern.authorize(action="read", principal=principals.user(f"sso:{claims['sub']}"))

# a local session: use the row's primary key, not the display name
user = users.get(session["user_id"])                        # your session store
govern.authorize(action="read", principal=principals.user(f"db:{user.id}"))
```

```ts
const claims = await verifyToken(req.headers.authorization);    // your verification
await govern.authorize({ action: "read", principal: principals.user(`sso:${claims.sub}`) });

const user = await users.get(req.session.userId);               // your session store
await govern.authorize({ action: "read", principal: principals.user(`db:${user.id}`) });
```

**Never derive a principal from client-controlled input** — a header, a query
parameter, a body field, or anything the model produced.

**Use a stable internal identifier, not an email or a username.** An email
changes and every policy written against it stops matching. A username can be
released and reused, which makes an old audit row point at a different person.
Namespace the id when more than one identity source can produce subjects:
`User::"db:4412"`, `User::"sso:8f3c…"`.

**When there is no human subject** — a scheduled job, a CLI, an autonomous
loop — omit `principal`. The agent is then recorded as `Agent::"<name>"`. Do not
invent `User::"system"`, and do not coalesce a missing subject to `""`, which is
[refused](#what-every-principal-must-satisfy).

The vocabulary matches [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693): `sub`
is the `principal`, `act.sub` is `context.actor`, and the nested `act` chain is
`context.actor_chain`, root first.

The Developer Edition authorizes the identities the application asserts. It
authenticates nothing itself, so establishing who the subject is remains your
job. See *A note on identity* in the
[README](../README.md#a-note-on-identity). Attested identity — federated OIDC
and workload mTLS — is the Enterprise plane;
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise) if your deployment needs it.

Upgrading? Every change on this page that flips a verdict is in [breaking
changes](breaking-changes.md).

## See also

- [`examples/showcase/identity/`](../examples/showcase/identity/README.md) — this page as a
  runnable example in both lanes, with every refusal asserted
- [`README.md`](../README.md) — quickstart, the audit trail, the identity ladder
- [`docs/using-the-governor.md`](using-the-governor.md) — where the governor lives in an
  application, and the request-handler / worker / test shapes
- [The signing secret](signing-secret.md) — what a scope token needs before it
  crosses a process boundary
- [`examples/patterns/per-user-attribution.md`](../examples/patterns/per-user-attribution.md) — a policy that requires a named subject
- [`examples/patterns/subagent-confinement.md`](../examples/patterns/subagent-confinement.md) — scope attenuation
