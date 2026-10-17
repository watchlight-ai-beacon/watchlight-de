# The identity model

Every governed call involves identities: the person or system the work is done
for, and the agent doing it. This page explains what to pass for each, what gets
recorded in the audit trail, and what a policy can refer to. Terms are defined
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

`context.actor` and `context.actor_chain` are reserved: the SDK sets them on
every call. If a caller supplies its own value for either and it differs from
the SDK's, the call raises `ReservedContextError`. An identical value is
accepted.

`as` and the per-call `agent` override always start a fresh single-element
chain. Only `delegate` appends.

| Ask | Write |
|---|---|
| Did *this* agent make the call? | `context.actor == "seat-picker"` |
| Was this agent anywhere in the delegation? | `context.actor_chain.contains("flight-booker")` |

`context.actor_chain` is a set, so `contains` works on it. Outside any
delegation it holds just one element, `[agent]`, so both forms of policy work on
every call.

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

Build the reference with the helpers. A subject id is an arbitrary string that
may contain a quote, a backslash or a space. The engine reads every request
principal, action and resource with the same strict Cedar parser it uses for
policy text, so the id is a Cedar string literal in a request just as it is in a
policy: a quote or a backslash in it must be escaped. The helpers do that for
you, and a request and a policy now spell the same reference the same way:

```python
from watchlight import principals
from watchlight.principals import for_policy

principals.user('a"b')             # → User::"a\"b"
principals.agent("flight-booker")  # → Agent::"flight-booker"
for_policy("User", 'a"b')          # → User::"a\"b"   (the same string)
```

```ts
import { principals, policyEntityRef } from "@watchlight/sdk";

principals.user('a"b');                 // → User::"a\"b"
principals.agent("flight-booker");      // → Agent::"flight-booker"
policyEntityRef("User", 'a"b');         // → User::"a\"b"   (the same string)
```

A request built with `principals.user(sub)` matches a policy written with
`for_policy("User", sub)`. That is the pair to use when a policy is generated
from data. `for_policy` returns the same string as `principals.entity` for every
id the request helpers accept. The only difference is that `for_policy` escapes
a control character instead of refusing it, because policy text is not a
request.

Do not paste an id into a reference by hand. A reference such as
`User::"a"b"`, with the quote left unescaped, is not read as some other entity:
the engine refuses the request as invalid, and the call raises
`AuthorizeRequestError`. The same happens to a reference with anything after
the closing quote, such as `User::"alice" || true`. A crafted id therefore
cannot name another entity or another type; at worst it makes the request fail.

### What every `principal` must satisfy

Three rules apply everywhere a `principal` is accepted: `authorize`, `tool`,
`mint_approval` / `mintApproval`, `counters`, `sanitize`, `screen`, and the
`principal` option on every framework adapter.

* **It must be a non-empty string.** An empty or whitespace-only value raises an
  error. This matters because code such as `user?.id ?? ""` turns a missing user
  into an empty string, and earlier versions then recorded the *agent* as the
  subject instead of failing.
* **It must contain no control characters.** The audit trail is JSONL, one
  record per line, so a newline inside a principal would split one record into
  two. A principal containing a control character raises an error.
* **It must be at most 4096 bytes of UTF-8** (`MAX_NAME_BYTES`). Every record
  that names the principal must stay short enough for `counters()` to read it
  back, so a longer principal raises an error before anything is decided or
  recorded. The same limit applies to the action and the resource. An agent
  name is limited to 4087 bytes, so that `Agent::"<name>"` fits within 4096.
  The limit is measured on the escaped name, where a quote or a backslash takes
  two bytes, so a name made mostly of quotes is refused at a shorter length.
  `principals.user` and the other helpers refuse a reference whose escaped form
  is longer than 4096 bytes in the same way.
  See [using the governor](using-the-governor.md#names-have-a-length-limit).

To name no subject at all, omit `principal` (or pass `None` / `undefined`). That
records the agent as its own subject.

### A bare principal is a `User`

A bare identifier, such as `team-42` with no `Type::`, is accepted and recorded
exactly as the caller wrote it. The engine reads it as a `User`: `team-42` is
the entity `User::"team-42"`. It matches `principal is User` and a policy naming
`User::"team-42"`. It never matches a policy that names the id under another
type, such as `Agent::"team-42"`, and it never matches `principal is Agent`.

In the same way, a bare action is read as an `Action` and a bare resource as a
`Resource`. A bare name that contains a quote, or that contains `::`, is not a
plain id: the engine refuses the request as invalid.

**Name the type** for anything that is not a user, with `principals.agent` or
`principals.entity`. Treat `principal` in the audit trail as a string to compare,
not a shape to parse. The bare `team-42` and the typed `User::"team-42"` are the
same entity to the engine but two different strings on the record, so pick one
form and use it everywhere, for example for `counters()`.

Before `watchlight-engine` 0.2.3 a bare identifier matched a policy naming that
id under `User`, `Agent`, `Group` or `Role`, and when it matched more than one,
an allow beat a forbid. That no longer happens. See the
[breaking-changes log](breaking-changes.md).

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

* **A scope is checked when you delegate, never when a call is authorized.** To
  confine a sub-agent you therefore need both: narrow its scope, *and* write a
  policy that limits what it may do.
* **A scope token does not carry the chain.** `to_token()` / `toToken()`
  serialises only the granted capabilities. A scope rebuilt in another process
  therefore starts a fresh chain from the receiving governor's agent. If the
  receiving side must record the delegation, call `delegate` there.
* A delegate cannot widen what its parent held; trying raises
  `AttenuationDenied`. The chain holds at most **`max_delegation_depth` + 1**
  entries, which is 9 by default. Beyond that, `delegate` raises
  `DelegationDepthExceeded`.
* A delegate cannot be renamed, because renaming it would drop the chain. To
  hand work further down, create another sub-agent with `delegate` instead.
* `picker.delegated_scope` / `picker.delegatedScope` returns the narrowed scope
  the delegate acts under.

Each of the three cases looks different in the audit trail, because `principal`
and `agent` are recorded on the same line:

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

For conditions on `context.*`, the engine supports comparisons with `==`,
`!=`, `<`, `<=`, `>` and `>=`, which you can combine with `&&`, `||` and `!`.
It also supports `like` on strings, and `contains`, `containsAny` and
`containsAll` on sets. Separately, `is` tests the entity type of the
principal, the action or the resource, not a `context` value.
[What the engine resolves](policies.md#what-the-engine-resolves) lists the
forms that do not resolve and deny silently.

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
