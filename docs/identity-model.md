# The identity model

What to pass, what gets recorded, and what a policy can name.

## The three questions a governed call answers

| Question | Where it goes | Example value |
|---|---|---|
| On whose behalf does this run? | `principal` — the **subject** | `User::"alice"` |
| Which runtime is acting? | the reserved **actor** context key | `context.actor == "flight-booker"` |
| Under what narrowed authority? | the attenuation **scope** | `govern.scope(tools=[...])` → `attenuate(...)` |

The subject and the actor are independent inputs. An agent doing something for a
person has both; an agent doing something for itself has one identity in two
roles. The scope is orthogonal to both — it bounds what the acting runtime may
ask for at all (see [sub-agent confinement](../examples/patterns/subagent-confinement.md)).

The SDK sets the actor key on **every** call, from the governor's agent name. A
caller-supplied `context.actor` that disagrees is refused (`ReservedContextError`
/ `RESERVED_CONTEXT_MESSAGE`), never silently overwritten — so a policy that
reads `context.actor` can trust it. An identical value is accepted.

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
| Sub-agent under a parent | `User::"alice"` | `seat-picker` | act through `govern.as_("seat-picker")` (Python) / `govern.as("seat-picker")` (TS) |

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
also carry `agent="…"` on `authorize`, `sanitize`, `screen` and `tool`.

Each case is distinct in the trail — `principal` and `agent` on the same line:

```json
{"agent":"flight-booker","principal":"Agent::\"flight-booker\"","intent":"cache","decision":"Allow"}
{"agent":"flight-booker","principal":"User::\"alice\"","intent":"book","decision":"Allow"}
{"agent":"seat-picker","principal":"User::\"alice\"","intent":"pick_seat","decision":"Allow"}
```

A parent → child actor *chain* is not yet a single field: a sub-agent's calls
record the sub-agent as the actor, and the parent relationship is visible in the
`attenuation` records the scope API writes.

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

Use `context.*` with `==`, `is`, `like` and set `contains` for the actor —
that is the operator surface the engine resolves.

## Where the values come from

The vocabulary is [RFC 8693 (OAuth 2.0 Token Exchange)](https://www.rfc-editor.org/rfc/rfc8693),
which already separates the two identities in a token:

| RFC 8693 claim | Watchlight input |
|---|---|
| `sub` — the party the request is made on behalf of | `principal` → `User::"<sub>"` |
| `act.sub` — the party doing the acting (nests for chains) | the actor context key |

An application that verified an OIDC identity maps that token's `sub` to the
principal; if it performed a token exchange, `act.sub` is the actor. With no
subject at all — a scheduled job, an autonomous loop — omit `principal` and the
agent is recorded as its own subject.

RFC 8693 also distinguishes **delegation** (both identities retained) from
**impersonation** (the actor presents as the subject and disappears). Passing
both values is delegation; passing only a subject is impersonation, and the
trail can no longer say which runtime acted.

## The trust boundary

The Developer Edition authorizes the identities the application **asserts**. It
does not verify tokens: verifying the identity, and extracting `sub` / `act.sub`
from it, is the application's job. See *A note on identity* in the
[README](../README.md#a-note-on-identity) for how that hardens as you grow —
the policies you write do not change.

## Breaking in 0.8.0

**What changed.** A call that names no `principal` now records the agent as a
typed entity reference, `Agent::"<name>"`, at every site — `authorize`, `tool`,
`mint_approval` / `mintApproval` and the audit record. Previously the bare,
untyped agent name was substituted, which read like a user id in the trail and
made "the agent acted" indistinguishable from "a user acted".

**Policies.** The engine already read a bare principal as an `Agent`, so a
policy written `principal == Agent::"<name>"` keeps matching:

```cedar
// before — matched the substituted bare name
permit(principal == Agent::"memory-writer", action == Action::"write", resource);

// after — the same policy still matches; or name the runtime instead, which
// works whoever the subject is
permit(principal, action == Action::"write", resource)
when { context.actor == "memory-writer" };
```

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
