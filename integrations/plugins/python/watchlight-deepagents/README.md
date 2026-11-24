# watchlight-deepagents

Watchlight authorization for DeepAgents tool calls and sub-agent spawns, fail-closed.

```bash
pip install watchlight-deepagents
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** LangChain. `deepagents`, `LangChain`, `LangGraph`, and related names are trademarks of LangChain, used here nominatively only to describe compatibility.

## What it does

`watchlight-deepagents` puts a Watchlight authorization decision in front of the tool calls, virtual-filesystem calls and `task` sub-agent spawns your DeepAgents agent makes, so each one is allowed or denied *before* it runs. It is a thin governance middleware plus a drop-in `create_governed_deep_agent(...)` factory that binds Watchlight's primitives to the DeepAgents `AgentMiddleware` protocol, with no monkey-patching and no changes to your tool code. The policy decisions run on Watchlight's engine, in-process for local development or on the governed control plane in production.

## What it enforces

This section says exactly what the plugin does and does not enforce.

- **Run start.** Every agent run opens a governed Watchlight run before the model loop starts. If the run cannot be opened (unregistered agent, unreachable backend), the agent does not run.
- **Tool and filesystem calls.** Each call is authorized by Watchlight first. A denial, a required approval, or an unreachable backend returns an error to the model and the tool never runs. Only argument names, count and types are sent with the request, never argument values.
- **Sub-agent spawns (`task`).** A spawn opens an attenuated child run under the parent, gated by Watchlight. If the spawn is refused, the sub-agent never runs. The sub-agent runs only on the handle its own spawn produced, and only while that `task` call is running; it never reuses another sub-agent's handle. Spawns are refused unless the agent was built with `create_governed_deep_agent(...)`, which installs governance in every sub-agent.
- **Model turns are not authorized one by one.** The plugin records each model turn and refuses it when there is no governed run or when the run is quarantined. It does not send a per-turn authorization request. Governance of the model's network calls comes from the wl-proxy egress path, when you configure it.
- **Egress.** When a wl-proxy URL is configured (`connect_proxy_url` or `WATCHLIGHT_PROXY_URL`), the run is refused with `GovernanceUnavailable` if Watchlight issued no proxy token or the local sidecar fails to start. It never falls back to direct egress. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its sidecar is stopped and `HTTPS_PROXY` stays on the stopped port, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.
- **Async only.** DeepAgents runs on the async LangGraph runtime. The synchronous invocation path is refused.
- **Agents built inside a tool are refused.** An agent that one of your tools builds and runs itself, such as a plain `create_deep_agent(...)` called inside a tool, has no Watchlight middleware. While a governed run is live in the process, the plugin refuses such an agent's work before it runs, whatever thread, config or callbacks it is given:
  - Each tool call the plugin authorizes may start exactly one tool: the one with that call's id and name, once. Any other tool start is refused before the tool runs.
  - A model call made inside the body of a governed tool is refused. If a tool really needs to call a model directly, for example to summarize text, wrap that call in `with direct_model_use():` (from `watchlight_deepagents`). A model call that binds tools is refused even then, so the escape never covers an agent's turn.
  - A model call that binds tools, local or hosted by the provider, is refused unless it is a governed agent's own turn. Hosted tools run on the provider's side, where no tool start is visible, so this is where they are stopped.
  - Each refusal is recorded in the run's lineage as a denied call, with names only and never argument values.

  This is a change in behaviour: a tool that used to run an inner agent, or call a model directly, now fails with `UngovernedModelCall` or `UngovernedToolCall` (both are `GovernanceUnavailable`). Spawn sub-agents through `task` with `create_governed_deep_agent(...)`, which governs them, or use `direct_model_use()` for a direct, tool-less model call. Governed `task` sub-agents and DeepAgents' own summarization are not affected. With no governed run live, nothing is refused.

  The check is a callback the plugin registers once with LangChain, through LangChain's public configure hook; no framework class is patched. It has limits:
  - The live-run state is shared by the whole process. While a governed run is live, an ungoverned agent running at the same time elsewhere in the same process is refused too.
  - A model call that binds no tools, made on a new thread or in a fresh `contextvars.Context` started from a tool body, is not refused. It can run no tool: its tool starts are refused, and it binds no hosted tool.
  - A governed agent run inside another governed agent's ordinary tool has its own summarization refused. Run it as a `task` sub-agent instead.
  - Each authorized call may start its tool once, so a retry must pass through Watchlight's middleware again. A retry middleware must sit outside Watchlight's: one that runs inside it and calls the tool again within the same call has the retry refused. `create_governed_deep_agent(...)` places Watchlight's middleware ahead of the `middleware=` you pass, so a tool-retry middleware passed there runs inside it. Retry at the model level instead, as a new tool call, which is authorized again.
  - A refusal that cannot be published to lineage still stands. It is logged at warning level and counted in `watchlight_deepagents.backstop.emit_failures()`.
  - Code that calls a tool's private `_run`, a model's private `_generate`, or a provider SDK directly bypasses LangChain's callbacks and is not seen. Neither is code that deliberately removes LangChain's configure hooks or resets the plugin's context variables, which turns governance off on purpose.

## Quickstart

Swap `create_deep_agent` for `create_governed_deep_agent`, add one `agent_slug`, and point the plugin at a backend. Your tool code, sub-agent prompts and the model loop don't change.

For local development, the zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package):

```bash
pip install watchlight-deepagents "watchlight-engine>=0.2.5,<0.3"
```

```python
from watchlight_deepagents import create_governed_deep_agent, WatchlightDeepAgentsPlugin
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may read, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "research-orchestrator" };'},
]

plugin = WatchlightDeepAgentsPlugin()
plugin.apdp = InProcessClient(POLICIES)   # decisions run in-process, no server, no network

agent = create_governed_deep_agent(
    model="anthropic:claude-sonnet-4",
    tools=[search, fetch],
    agent_slug="research-orchestrator",   # the ONE required extra arg
    plugin=plugin,
)

# DeepAgents runs on the async LangGraph runtime — invoke with await.
result = await agent.ainvoke(
    {"messages": [{"role": "user", "content": "Summarize the Q3 filings."}]}
)
```

Every tool call routes through `handle.authorize_action(...)` under the hood and fails closed: a denial, or an unreachable backend, returns an error to the agent instead of running the tool.

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightDeepAgentsPlugin(...)`, or per run to `start_run(...)`, or set `WATCHLIGHT_APPLICATION_ID` in the environment (`from_env()` picks it up too) — an explicit argument wins over the env var. The middleware opens runs with the plugin-level value, so a deployment attributes an agent without a code change. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane — signed lineage, drift detection, fleet-wide governance |

Moving from local to production is a one-line change:

```python
from watchlight_core import ApdpClient, Credential

plugin = WatchlightDeepAgentsPlugin()
plugin.apdp = ApdpClient(
    "https://apdp.your-company.example",
    credential=Credential.from_env(),   # reads WATCHLIGHT_PLUGIN_TOKEN; never inline a key
)
```

In production the plugin also reads its configuration from the environment — `WatchlightDeepAgentsPlugin.from_env()` builds an `ApdpClient` from `WATCHLIGHT_APDP_URL` (and `WATCHLIGHT_TENANT_ID`), so `create_governed_deep_agent(agent_slug=..., ...)` works with no explicit `plugin=`.

## Links

- Documentation: https://docs.watchlight.ai/de
- Source and issues: https://github.com/watchlight-ai-beacon/watchlight-de
- Website: https://watchlight.ai

## License

Apache-2.0
