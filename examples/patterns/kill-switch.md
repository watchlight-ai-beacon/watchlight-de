# Pattern: kill-switch / quarantine

**Problem.** Something is wrong — a suspected compromise, a runaway loop, an
incident. You need to stop an agent **cold**, across every action, with one flag,
and have that stop beat every grant it otherwise has.

**Policy** — [`suites/kill-switch.suite.json`](./suites/kill-switch.suite.json):

```cedar
permit(principal == User::"assistant", action, resource);   // the agent's normal grants

// one flag halts everything — forbid overrides any permit
forbid(principal, action, resource) when { context.quarantined == true };
```

**Govern the tool** — supply the flag from your own state (a DB column, a cache
key, an incident switch):

```ts
const act = govern.tool(runTool, {
  intent: "act",
  principal: () => `User::"assistant"`,
  context:  () => ({ quarantined: isQuarantined(agentId) }),  // your source of truth
});
```

**Verdicts** (verified):

| `quarantined` | action | verdict |
|---|---|---|
| false | `read` | **Allow** |
| true | `read` | **Deny** |
| true | `charge` | **Deny** — the switch beats even a broad permit |

**Two things to know.**

- **`forbid` is the kill-switch primitive** — it overrides every `permit`, so a
  single quarantine rule neutralizes an agent no matter what else it's granted.
- **It's fail-closed on the flag, too.** The `forbid` reads `context.quarantined`;
  if you *don't* supply that key, the Developer Edition treats the missing input
  as denying (a deliberate, safer-than-raw-Cedar deviation). So always pass
  `quarantined: false` on the healthy path — as the tool above does — and a
  dropped flag fails safe rather than open.

In the Developer Edition the flag is your app's own state. Enterprise makes this a
first-class control plane action — drift/anomaly detection can flip it
automatically, and revocation applies fleet-wide.
