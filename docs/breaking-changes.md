# Breaking changes

Newest first. Every entry can turn a call that worked into an error or a
different verdict. Only some announce themselves; the rest surface as a denial
that looks exactly like a policy of yours doing its job. Read every entry
between the version you are on and the one you are moving to.

## 0.9.1

**An egress hook slower than 8 seconds now withholds the payload** instead of
releasing it late. `govern.tool()` and the LangChain adapters had no deadline
before; all three paths now share one. The call raises `EgressTimeout` and the
`egress` record says `withheld: true`.

Fix, for a hook that is meant to be slow:

```ts
govern.tool(fn, { intent: "read", onResult: slowClassifier, onResultTimeoutMs: 300_000 });
```

```python
@govern.tool("read", on_result=slow_classifier, on_result_timeout_ms=300_000)
async def read_doc(doc_id): ...
```

Nothing changes for a hook that finishes inside 8 seconds. No value turns the
deadline off: `0`, a negative, `NaN` and `Infinity` are refused where the tool is
wrapped. In Python, `on_result_timeout_ms` on a *synchronous* tool body raises
`TypeError`, so put your own time bound on a synchronous hook.

## 0.9.0

### An empty principal raises instead of recording the agent

`principal=""`, whitespace-only, or carrying a control character used to record
the **acting agent** as the subject. All three now raise, at every boundary that
takes a principal: `authorize`, `tool`, `mint_approval` / `mintApproval`,
`counters`, `sanitize`, `screen`, and an adapter's `principal` binding.

Fix — where there may be no subject, pass none rather than an empty string:

```python
govern.authorize(action="read", principal=principals.user(user.id) if user else None)
```

```ts
await govern.authorize({ action: "read", principal: user ? principals.user(user.id) : undefined });
```

An explicit `agent=None` / `agent: null` raises too. Omit it, or pass a name.

### A governor with no name is no longer matchable

A governor with neither an `agent` option nor `WATCHLIGHT_AGENT` (blank now
counts as unset in both lanes) sets **neither** `context.actor` nor
`context.actor_chain`. A `permit` reading the actor stops matching it; a `forbid`
reading the actor denies it. It records the reserved placeholder
`<unconfigured>`.

Fix: name the agent — `Watchlight(agent=…)`, `WATCHLIGHT_AGENT`,
`configure_default(agent=…)` / `configureDefault({ agent })`, or `as` / `as_`.

A policy naming `Agent::"<unconfigured>"` as its principal still matches an
unconfigured governor, so the placeholder is not a guard.

### An unrecognised enforcement effect fails at load

`@enforcement_effect("needs_approval")` used to be dropped, which left a `permit`
as a plain allow. `allow` and `load` now refuse it with `PolicyError`, and `load`
is whole-file or nothing.

Fix: spell it as one of `attenuate`, `escalate`, `observe`, `quarantine`,
`require_approval`, `revoke`, `sever_subtree`, `terminate`. A misspelled
annotation *name* only warns.

### Audit records are typed (TypeScript)

`AuditRecord` is a discriminated union on `event`, so a sink reading a field off
the wrong record shape no longer compiles.

Fix: narrow on `event`, or annotate `UnknownAuditRecord` to keep the untyped bag.

## 0.8.2 — the framework-plugin path only

**Cedar entity types now discriminate on the plugin path.** Every term used to
reach the engine as a bare name, and a bare name matches `User`, `Agent`,
`Group` and `Role` policies for that id. A policy naming the agent under any
type other than `Agent::` goes from allow to deny.

```cedar
// before
permit(principal == User::"<agent uuid>", action == Action::"read", resource);
// after
permit(principal == Agent::"<agent uuid>", action == Action::"read", resource);
```

A typed resource string must match the policy's type too. Every flip is in the
closed direction, and there is no transitional flag. The SDK path, the `tool()`
decorator and the networked control plane are unaffected.

## 0.8.1

No breaking changes.

## 0.8.0

### A call that names no principal records `Agent::"<name>"`

The bare, untyped agent name was substituted before, and the engine bound it to
whichever entity type the policy set happened to name that id with. A rule
written against `User::"my-agent"` sometimes authorized the agent. Now it never
does, and the deny is silent.

```cedar
// before — matched the untyped substituted name
permit(principal == User::"memory-writer", action == Action::"write", resource);

// after — name the agent as an agent …
permit(principal == Agent::"memory-writer", action == Action::"write", resource);

// … or name the runtime, which works whoever the subject is
permit(principal, action == Action::"write", resource)
when { context.actor == "memory-writer" };
```

Audit the policy set for any `principal == <Type>::"<agent-name>"` that is not
`Agent::`, and for `principal is User` rules relied on to match an agent. Do not
audit by policy order: a rule that looks unreachable in this run may be the one
that matched in the last.

Anything comparing an audit record's `principal` to the bare name — a dashboard,
a log query — must use `Agent::"<name>"`. `counters()` is keyed on the principal
exactly, so a quota that counted `"my-agent"` now counts `Agent::"my-agent"`.

`strict_principal=False` / `strictPrincipal: false` restores the old
substitution and warns once per process. It restores the unpredictable binding
with it, so use it to unblock a deploy, not to stay on.

```python
Watchlight(agent="my-agent", strict_principal=False)   # transitional
```

### `context.actor` and `context.actor_chain` are reserved

The SDK sets both on every authorize and refuses a caller-supplied value that
differs, with `ReservedContextError`. An identical value is still accepted. What
breaks is an application that already used `actor` for a value of its own.

Fix — rename yours, at the call site and in the policy:

```python
govern.authorize(action="refund", context={"requested_by": "billing-console"})
```

```ts
await govern.authorize({ action: "refund", context: { requested_by: "billing-console" } });
```

```cedar
permit(principal, action == Action::"refund", resource)
when { context.requested_by == "billing-console" };
```

There is no transitional flag: a flag that let a caller supply the key would
make every rule reading it forgeable while it was on.

### Approval tokens minted before 0.8.0 do not verify

The signed payload gained length prefixes and a version marker.

Fix: the tokens are short-lived, so drain in-flight approvals across the
upgrade.
