# Pattern: context-dependent policy through a framework adapter

**Problem.** The rule that decides depends on runtime facts — the caller owns the
record, the tenant matches, the amount is under the limit — so its verdict is a
function of Cedar `context`. But the tool it guards is not hand-written: it is a
LangChain `StructuredTool`, or a tool the Claude Agent SDK runs for you. If the
adapter that wraps it cannot carry the context the rule reads, the rule denies on
the adapter path and allows on the hand-written one — one policy, two answers,
and the denial explains nothing.

**Policy** — verified by
[`scripts/context-through-an-adapter.mjs`](./scripts/context-through-an-adapter.mjs):

```cedar
permit(principal, action == Action::"read_ticket", resource)
when { context has owner && context has caller && context.caller == context.owner };
```

`has` first, then the comparison: the rule must not depend on a key that may be
absent, and a call that carries neither key falls through to Deny.

**Write the terms once, pass them to every path.** `principal` and `context` are
each a fixed value *or* a function of the call, on `tool()` and on both adapters:

```ts
const principal = ({ caller }) => principals.user(caller);
const context = ({ caller, owner }) => ({ caller, owner });

// hand-written
const readTicket = govern.tool(fetchTicket, { intent: "read_ticket", principal, context });

// LangChain / LangGraph.js — same terms, same verdict
const governed = governTool(ticketTool, { intent: "read_ticket", principal, context });

// Claude Agent SDK — the binding sees the call the SDK is about to make
const { hooks } = governedHooks({
  intentFor: () => "read_ticket",
  principal: ({ toolInput }) => principals.user(toolInput.caller),
  context: ({ toolInput }) => ({ caller: toolInput.caller, owner: toolInput.owner }),
});
```

In Python the same terms are keyword arguments on `@govern.tool`:

```python
@govern.tool(
    "read_ticket",
    principal=lambda **kw: principals.user(kw["caller"]),
    context=lambda **kw: {"caller": kw["caller"], "owner": kw["owner"]},
)
def read_ticket(*, ticket, caller, owner): ...
```

**Verdicts** (verified, on all three paths):

| caller | owner | verdict |
|---|---|---|
| `u1` | `u1` | **Allow** — the owner reads their own record |
| `u2` | `u1` | **Deny** — someone else's record |
| *(context not supplied)* | | **Deny** — the rule reads keys that aren't there |

**Why it matters.** The third row is the one to hold on to: a rule of this shape
is unsatisfiable when nothing carries its context, and it fails **closed** and
silently — a Deny that looks exactly like a policy Deny. Passing `context`
through the adapter is what makes the rule decidable; passing `principal` is what
makes the record answer *for whom* rather than only *which agent*. Both land in
the audit line, so the trail names the acting user on the adapter path exactly as
it does on the hand-written one.

**The Python framework plugins are the exception.**
`watchlight.langgraph` / `.claude_agent` / `.pydantic_ai` `governed_plugin()` is
constructor wiring around a published plugin. Cedar `context` goes on the run
handle, per call:

```python
async with await plugin.start_run("support-agent") as handle:
    ok = await handle.authorize_action(
        "read_ticket", "tool/read_ticket",
        context={"caller": caller, "owner": owner},
    )
```

The **subject** goes the same way, per call:

```python
async with await plugin.start_run("support-agent") as handle:
    ok = await handle.authorize_action(
        "read_ticket", "tool/read_ticket",
        principal=f'User::"{user_id}"',
        context={"caller": caller, "owner": owner},
    )
```

Omitted, it defaults to the agent that runs, so an existing call is unchanged.
This needs `watchlight-agent-sdk` 0.7.0 or later, which the framework extras
require.

Write the entity type. These terms reach the engine exactly as given, so
`User::"u-1"` is not matched by a policy naming `Agent::"u-1"`. A bare name matches a
policy naming that id under `User`, `Agent`, `Group` or `Role`, and when it
matches more than one an allow beats a forbid — the wrong shape for a decision
you rely on.

The factory still refuses `principal=`, `context=` and `resource=` by name: all
three belong to a call, not to the constructor, and accepting them there would
drop them.

Combine with [per-user attribution](./per-user-attribution.md) for the subject
half on its own, and with [quotas](./quotas.md) to fold a counter into the same
`context`.
