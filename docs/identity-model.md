# The identity model

What to pass, what gets recorded, and what a policy can name.

## The three questions a governed call answers

| Question | Where it goes | Example value |
|---|---|---|
| On whose behalf does this run? | `principal` — the **subject** | `User::"alice"` |
| Which runtime is acting? | the reserved **actor** context key | `context.actor == "flight-booker"` |
| Through whose delegation? | the reserved **actor chain** context key | `context.actor_chain.contains("flight-booker")` |
| Under what narrowed authority? | the attenuation **scope** | `govern.scope(tools=[...])` → `delegate(...)` |

The subject and the actor are independent inputs. An agent doing something for a
person has both; an agent doing something for itself has one identity in two
roles. The scope is orthogonal to both — it bounds what the acting runtime may
ask for at all (see [sub-agent confinement](../examples/patterns/subagent-confinement.md)).

The SDK sets both actor keys on **every** call — the leaf from the governor's
agent name, the chain from the scope the call was made through. A
caller-supplied `context.actor` or `context.actor_chain` that disagrees is
refused (`ReservedContextError` / `RESERVED_CONTEXT_MESSAGE`), never silently
overwritten, so a policy that reads either can trust it. An identical value is
accepted; a caller can neither invent a delegation nor extend one.

Which key answers which question:

| Ask | Use | Reads |
|---|---|---|
| Did *this* agent make the call? | `context.actor` | `context.actor == "seat-picker"` |
| Was this agent anywhere in the delegation? | `context.actor_chain` | `context.actor_chain.contains("flight-booker")` |

`context.actor_chain` is set-valued, which is why `contains` resolves. Outside
any delegation the chain is the single-element `[agent]`, so both forms work
uniformly.

Use these keys, not a key of your own called `agent`: the engine's enricher
overwrites `context.agent` with an object of its own, so a policy comparing it
to a string never matches and the call silently denies. `actor` and
`actor_chain` are the caller-writable reserved keys, and the SDK guards both.

## What `principal` contains

Always a typed Cedar entity reference:

| Shape | Meaning |
|---|---|
| `User::"<subject>"` | a person the call runs on behalf of |
| `Agent::"<name>"` | the agent acting on its own behalf (what an omitted `principal` records) |
| `Workflow::"<id>"`, `Group::"<id>"`, `Role::"<id>"` | other subjects the engine's entity vocabulary accepts |

The engine accepts the principal types `User`, `Agent`, `Group`, `Role`, `Tool`,
`Resource` and `Workflow`. A machine caller with no human behind it is an
`Agent`. An unrecognised type fails the request rather than silently denying it.

Build the reference with the helpers — a subject identifier is an arbitrary
string (it comes from an identity you verified, and may contain a quote, a
backslash or a space), and the request form and the policy form are not written
the same way:

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
`for_policy("User", sub)` — that is the pair to use when a policy is generated
from data. Ids carrying control characters are refused rather than mangled.

## The three cases

| Case | `principal` | `context.actor` | How you make it |
|---|---|---|---|
| Agent acting alone | `Agent::"flight-booker"` | `flight-booker` | omit `principal` |
| Agent acting for a user | `User::"alice"` | `flight-booker` | pass `principal=principals.user("alice")` |
| Sub-agent under a parent | `User::"alice"` | leaf `seat-picker`, chain `["flight-booker", "seat-picker"]` | `govern.delegate(scope, "seat-picker")` |

```python
from watchlight import govern, principals

govern.authorize(action="cache")                                     # agent alone
govern.authorize(action="book", principal=principals.user("alice"))  # for a user

seat_picker = govern.as_("seat-picker")     # same engine, same policies, same trail
seat_picker.authorize(action="pick_seat", principal=principals.user("alice"))
```

```ts
import { govern, principals } from "@watchlight/sdk";

await govern.authorize({ action: "cache" });                                    // agent alone
await govern.authorize({ action: "book", principal: principals.user("alice") }); // for a user

const seatPicker = govern.as("seat-picker");   // same engine, same policies, same trail
await seatPicker.authorize({ action: "pick_seat", principal: principals.user("alice") });
```

`as(name)` / `as_(name)` is a view: it shares the engine, the compiled policies,
the audit trail, the sink and the token secret, and only stamps a different
name. Six named agents cost one engine and one policy load. A single call can
also carry `agent="…"` on `authorize`, `sanitize`, `screen` and `tool`. A rename
is not a delegation — a view acts alone, under its own name.

### Delegating to a sub-agent

`delegate` is the third case: it narrows a scope for the sub-agent (the engine's
strict-subset attenuation) **and** extends the actor chain, so one call produces
both the confined authority and the delegated identity.

```python
root = govern.scope(tools=["search", "book"])                  # chain ("flight-booker",)
picker = govern.delegate(root, "seat-picker", tools=["search"])  # chain (…, "seat-picker")

picker.authorize(action="pick_seat", principal=principals.user("alice"))
govern.delegate(picker, "row-checker")                          # one level deeper
```

```ts
const root = await govern.scope({ tools: ["search", "book"] });
const picker = govern.delegate(root, "seat-picker", { tools: ["search"] });

await picker.authorize({ action: "pick_seat", principal: principals.user("alice") });
govern.delegate(picker, "row-checker");                         // one level deeper
```

A delegate shares the engine, the policies, the trail and the sink like any
view; `picker.delegated_scope` / `picker.delegatedScope` is the narrowed scope it
acts under. It cannot widen what its parent held (`AttenuationDenied`), and each
level is one attenuation level, so the chain is at most **`MAX_ACTOR_CHAIN` = 6**
entries — the root agent plus the `DE_MAX_DEPTH` (5) attenuation levels; past
that, `delegate` raises `DevEditionCeiling`. A scope carried to another process
as a token rebuilds capabilities, not names: re-establish the delegation there
with `delegate`.

Each case is distinct in the trail — `principal` and `agent` on the same line:

```json
{"agent":"flight-booker","principal":"Agent::\"flight-booker\"","intent":"cache","decision":"Allow"}
{"agent":"flight-booker","principal":"User::\"alice\"","intent":"book","decision":"Allow"}
{"agent":"seat-picker","actor_chain":["flight-booker","seat-picker"],"principal":"User::\"alice\"","intent":"pick_seat","decision":"Allow"}
```

`agent` is the leaf actor on every record. `actor_chain` appears on records
produced through a delegate — decisions, `egress`, `sanitization`, `screening` —
and is omitted outside any delegation, where the chain is just `[agent]`.

## Writing policies against them

**A user's own authority — the agent is irrelevant.**

```cedar
permit(principal == User::"alice", action == Action::"book", resource);
```

**A tool restricted to one runtime — whoever it acts for.**

```cedar
permit(principal, action == Action::"write_memory", resource)
when { context.actor == "memory-writer" };
```

**A narrower grant when the agent acts alone than when it acts for a person.**

```cedar
// acting for a person: any user subject, this runtime, real bookings
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };

// acting on its own behalf: cache warming only, never a booking
permit(principal == Agent::"flight-booker", action == Action::"cache", resource);
```

**A sub-agent that may only act for a subject, never for itself.**

```cedar
permit(principal is User, action == Action::"pick_seat", resource)
when { context.actor == "seat-picker" };
```

**Anything this booking agent delegated, at any depth.** The leaf may be a
sub-agent the policy has never heard of; what is asserted is whose delegation it
is acting under.

```cedar
permit(principal is User, action == Action::"trace", resource)
when { context.actor_chain.contains("flight-booker") };
```

Use `context.*` with `==`, `is`, `like` and set `contains` for the actor —
that is the operator surface the engine resolves.

## Where the values come from

The principal is a **stable identifier for the subject your application already
authenticated** — whatever did the authenticating. A session cookie backed by a
local users table, an API key mapped to an account, and a verified token all
produce the same call; the entity reference shape does not change with the
mechanism, and none of them is required.

**Never derive a principal from client-controlled input** — a request header, a
query parameter, a field in the body, or anything the model produced. The
library authorizes the identity the application asserts, so the assertion must
come from something the application itself authenticated.

**Use a stable internal identifier, not an email address or a username.** An
email changes, and every policy written against the old one stops matching. A
username can be released and reused, which makes an old audit row point at a
different person — an auditability failure, not a cosmetic one. Prefer the
primary key, the account id, or the subject claim: something that never moves.
If more than one identity source can produce subjects, namespace the id
(`User::"db:4412"`, `User::"sso:8f3c…"`) so two sources cannot collide.

Two sources, one call:

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

**When there is no human subject at all** — a scheduled job, a command-line
tool, a single-user script, an autonomous loop — omit `principal`. The agent is
then recorded as its own subject, `Agent::"<name>"`. Do not invent a stand-in
like `User::"system"`: it claims a person who does not exist, and it collides
with whatever a real user id might be.

The vocabulary matches [RFC 8693 (OAuth 2.0 Token
Exchange)](https://www.rfc-editor.org/rfc/rfc8693) for applications that do
carry tokens:

| RFC 8693 claim | Watchlight input |
|---|---|
| `sub` — the party the request is made on behalf of | `principal` → `User::"<sub>"` |
| `act.sub` — the party doing the acting | `context.actor` (the leaf) |
| nested `act` — the chain of actors | `context.actor_chain`, root first |

RFC 8693 also distinguishes **delegation** (both identities retained) from
**impersonation** (the actor presents as the subject and disappears). Passing
both values is delegation; passing only a subject is impersonation, and the
trail can no longer say which runtime acted.

## The trust boundary

The Developer Edition authorizes the identities the application **asserts**. It
authenticates nothing itself — not a token, not a session, not an API key —
so establishing who the subject is, and deriving the principal from that rather
than from anything a caller sent, is the application's job. See *A note on
identity* in the [README](../README.md#a-note-on-identity) for how strongly the
principal is proven at each rung, and why the policies you write do not change
as you climb.

## Breaking in 0.8.0

**Read this first: an agent-scoped policy not spelled `Agent::` flips from
Allow to Deny.** The substituted principal was an untyped string, and the engine
bound it to whichever entity type the policy set named that id with — verified:
with `permit(principal == User::"bob", …)` in the set, the bare `bob` matched
`User::"bob"`; with an `Agent::"bob"` policy it matched that instead; with both,
the first one added won. So a rule written against a *user* entity could, and
did, authorize the agent. From 0.8.0 the SDK always sends `Agent::"<name>"`, and
those rules stop matching — silently, since a Deny is what fail-closed looks
like.

```cedar
// before — matched the untyped substituted name (whatever type it bound to)
permit(principal == User::"memory-writer", action == Action::"write", resource);

// after — name the agent as an agent …
permit(principal == Agent::"memory-writer", action == Action::"write", resource);

// … or name the runtime, which works whoever the subject is
permit(principal, action == Action::"write", resource)
when { context.actor == "memory-writer" };
```

Audit your policy set for any `principal == <Type>::"<agent-name>"` that is not
`Agent::`, and for `principal is User` rules that were relied on to match an
agent.

**What changed.** A call that names no `principal` now records the agent as a
typed entity reference, `Agent::"<name>"`, at every site — `authorize`, `tool`,
`mint_approval` / `mintApproval` and the audit record. Previously the bare,
untyped agent name was substituted, which read like a user id in the trail and
made "the agent acted" indistinguishable from "a user acted".

A policy already written `principal == Agent::"<name>"` keeps matching, so that
spelling is the safe target for the migration.

**What does break:** anything downstream that compared the audit record's
`principal` to the bare agent name — dashboards, log queries, counters keyed on
the old string — must use `Agent::"<name>"`. `counters()` is keyed on the
principal exactly, so a quota that counted `"my-agent"` now counts
`Agent::"my-agent"`.

**Approval tokens** bind `(principal, action, resource)`, so a token minted
before the change does not verify after it. Mint and consume within one process
and one version, as before.

**The one-release opt-out.** `strict_principal=False` (Python) /
`strictPrincipal: false` (TypeScript) restores the bare-name substitution for
one release and warns once per process. It exists to unblock a deploy, not to
stay on:

```python
Watchlight(agent="my-agent", strict_principal=False)   # transitional
```

```ts
new Watchlight({ agent: "my-agent", strictPrincipal: false });   // transitional
```

## See also

- [`README.md`](../README.md) — quickstart, the audit trail, the identity ladder
- [`examples/patterns/per-user-attribution.md`](../examples/patterns/per-user-attribution.md) — a policy that requires a named subject
- [`examples/patterns/subagent-confinement.md`](../examples/patterns/subagent-confinement.md) — scope attenuation
