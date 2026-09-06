# Pattern: kill-switch / quarantine

One flag stops an agent across every action, and beats every grant it otherwise
has.

```cedar
permit(principal == Agent::"assistant", action, resource);   // its normal grants

// one flag halts everything — a forbid overrides any permit
forbid(principal, action, resource) when { context.quarantined == true };
```

## Govern the tool

Supply the flag from your own state — a database column, a cache key, an
incident switch.

```ts
const act = govern.tool(runTool, {
  intent: "act",
  context: () => ({ quarantined: isQuarantined(agentId) }),   // your source of truth
});
```

## Verdicts

Proved by [`suites/kill-switch.suite.json`](./suites/kill-switch.suite.json).

| `quarantined` | action | verdict |
|---|---|---|
| false | `read` | **Allow** |
| true | `read` | **Deny** |
| true | `charge` | **Deny** — the switch beats a broad permit |

## Worth knowing

- **`forbid` is the primitive.** It overrides every `permit`, so one rule
  neutralises an agent whatever else it holds.
- **Always pass `quarantined: false` on the healthy path.** A missing key makes
  the condition unevaluable, which denies — safe, but it denies everything.
- The agent acting on its own behalf is `Agent::"assistant"`, which is what a
  governed tool records when you pass no `principal`. Naming it under `User::`
  would not match.
