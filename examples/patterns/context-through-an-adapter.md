# Pattern: context-dependent policy through a framework adapter

A rule that reads Cedar `context` must reach the same verdict whether the tool is
hand-written or wrapped by a framework adapter.

```cedar
permit(principal, action == Action::"read_ticket", resource)
when { context has owner && context has caller && context.caller == context.owner };
```

`has` first, then the comparison, so a call carrying neither key falls through to
`Deny` instead of erroring.

## Write the terms once, pass them to every path

`principal` and `context` are each a fixed value or a function of the call, on
`tool()` and on both TypeScript adapters.

```ts
const principal = ({ caller }) => principals.user(caller);
const context = ({ caller, owner }) => ({ caller, owner });

// hand-written
const readTicket = govern.tool(fetchTicket, { intent: "read_ticket", principal, context });

// LangChain / LangGraph.js
const governed = governTool(ticketTool, { intent: "read_ticket", principal, context });

// Claude Agent SDK — the binding sees the call the SDK is about to make
const { hooks } = governedHooks({
  intentFor: () => "read_ticket",
  principal: ({ toolInput }) => principals.user(toolInput.caller),
  context: ({ toolInput }) => ({ caller: toolInput.caller, owner: toolInput.owner }),
});
```

```python
@govern.tool(
    "read_ticket",
    principal=lambda **kw: principals.user(kw["caller"]),
    context=lambda **kw: {"caller": kw["caller"], "owner": kw["owner"]},
)
def read_ticket(*, ticket, caller, owner): ...
```

## Verdicts

Proved on all three paths by
[`scripts/context-through-an-adapter.mjs`](./scripts/context-through-an-adapter.mjs).

| caller | owner | verdict |
|---|---|---|
| `u1` | `u1` | **Allow** — the owner reads their own record |
| `u2` | `u1` | **Deny** — someone else's record |
| *(no context)* | | **Deny** — the rule reads keys that are not there |

The third row is the one to remember. A rule of this shape is unsatisfiable when
nothing carries its context, and the denial looks exactly like a policy denial.

## The Python framework plugins take them per call

`watchlight.langgraph` / `.claude_agent` / `.pydantic_ai` `governed_plugin()` is
constructor wiring. The subject and the context go on the run handle instead:

```python
async with await plugin.start_run("support-agent") as handle:
    ok = await handle.authorize_action(
        "read_ticket", "tool/read_ticket",
        principal=f'User::"{user_id}"',
        context={"caller": caller, "owner": owner},
    )
```

Omit `principal` and the running agent is the subject, so existing calls are
unchanged. Needs `watchlight-agent-sdk` 0.7.0 or later, which the framework
extras require.

## Worth knowing

- **Write the entity type.** These terms reach the engine as given. A bare `u-1`
  matches a policy naming that id under `User`, `Agent`, `Group` or `Role`, and
  when it matches more than one an allow beats a forbid.
- `governed_plugin()` refuses `principal=`, `context=` and `resource=` by name.
  All three belong to a call, and accepting them on the constructor would drop
  them.

Combine with [per-user attribution](./per-user-attribution.md) for the subject on
its own, and [quotas](./quotas.md) to fold a counter into the same `context`.
