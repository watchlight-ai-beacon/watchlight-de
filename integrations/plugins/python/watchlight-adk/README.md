# watchlight-adk

Governed Google ADK agents with Watchlight: every tool call, model turn, built-in tool and sub-agent spawn is authorized before it runs, fail-closed.

> **Independent third-party plugin.** Built by Watchlight AI. Not affiliated with, endorsed by, or sponsored by Google. *Agent Development Kit (ADK)* and related names are trademarks of Google, used here nominatively only to describe compatibility.

```bash
pip install watchlight-adk
```

## What it does

`watchlight-adk` puts a Watchlight authorization decision in front of the actions a Google ADK agent takes through ADK's callbacks. Register one plugin on your ADK `Runner` and each tool call, model turn, provider-side tool (Gemini built-in tools, a local code executor) and sub-agent spawn is checked against your policies — `Allow` or `Deny` — *before* it runs, with execution lineage captured along the way. Code a tool runs after it is allowed is not inspected; network egress from inside it is governed only when you route it through wl-proxy.

The plugin is open-source glue: the ADK-specific lifecycle wiring on top of Watchlight's compiled policy engine (Developer Edition, in-process) or a governed Watchlight backend (Enterprise). Same plugin, same agent code — only the backend changes.

## Quickstart

Your agent code doesn't change. You register the plugin on the `Runner` and point it at a backend.

```python
from google.adk.runners import Runner
from watchlight_adk import WatchlightPlugin
from watchlight_core import InProcessClient

# Cedar policies: the research agent may read, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "agent-research-agent" };'},
]

# Zero-infra Developer Edition: decisions run in-process, lineage → .watchlight/audit.jsonl
plugin = WatchlightPlugin(
    agent_slug="agent-research-agent",                  # the root agent's registered slug
    root_agent_name="research_agent",                   # the root ADK agent.name it belongs to
    subagent_slugs={"researcher": "agent-researcher"},  # ADK agent.name → registered slug
)
plugin.apdp = InProcessClient(POLICIES)   # the one line that differs from production

runner = Runner(agent=my_agent, plugins=[plugin, *other_plugins])   # Watchlight first
# Run the agent as usual. Every tool call is authorized before it executes;
# a denied call is returned to the agent as a Watchlight refusal it cannot bypass.
```

The plugin resolves the agent slug to an identity, opens a governance session, and authorizes each tool call through ADK's native plugin callbacks (`before_tool_callback`, `before_model_callback`, `before_agent_callback`, …). A `Deny` becomes an ADK-shaped refusal the agent sees; allowed calls proceed and emit lineage. Tool names map to Cedar action verbs by convention (`get_*`/`read_*` → `read`, `list_*` → `list`, `search_*` → `search`, `create_*` → `create`, `delete_*` → `delete`, `execute_*` → `execute`, and `execute` when no convention matches), overridable per-tool via the `action_map` argument.

> **Warning:** keep `action_map` verbs on the generic verb list (`execute`, `read`, `list`, `search`, `create`, `update`, `delete`, `analyze`, `summarize`, `generate`, `embed`, `approve`, `review` and the others in wl-apdp's `entity_ref::GENERIC_ACTION_VERBS`), or use the tool's own name. A sub-agent's grant and a run's tool grant name tools, not verbs, so wl-apdp reads a custom verb (`"web_search": "lookup"`) on `Tool::"web_search"` as a second, different tool. Under a grant, that call is refused, and for a sub-agent the run handle is invalidated, so the child cannot make any further calls.

The Developer Edition path requires the compiled engine:

```bash
pip install watchlight-adk "watchlight-engine>=0.2.5,<0.3"
```

### Which Watchlight agent is this ADK agent?

A governed identity is configuration, never something read off a framework object. ADK's `agent.name` is a display name your code picked — it is what `transfer_to_agent` addresses — while the Watchlight slug is the registry key the plugin resolves to the agent's id, the principal your policies match (`Agent::"<agent uuid>"`). Tell the plugin the mapping:

- `agent_slug="<registered-slug>"` — the root agent of the run. **Required.**
- `root_agent_name="<adk agent.name>"` — the ADK agent `agent_slug` belongs to. **Required**, so the slug is bound to an identity and not to whichever agent happens to open an invocation.
- `subagent_slugs={"<adk agent.name>": "<registered-slug>", ...}` — every other agent in the tree. Two agents may not share one slug, and no child may be mapped to the root's slug.

Slugs come from the registry, which mints them by slugifying the agent's name and prefixing `agent-`: an agent registered as `research-agent` carries the slug `agent-research-agent`. Use the registered spelling.

The plugin is always strict: an ADK agent it has no slug for is refused before it takes a single action, and the refusal says the agent is *not configured* — a deployment error — rather than *not registered*, so you know to fix the wiring and not the registry. A plugin constructed with no identity raises `ValueError` at construction.

There is no name-derivation fallback and no switch to enable one. A slug guessed from `agent.name` that happens to resolve is worse than one that 404s: the run takes the resolved agent's UUID, passes its trust check, opens a session as it, receives its tool allowlist, authorizes under its Cedar policies and attributes its lineage to it — so whoever writes `LlmAgent(name=...)` would be choosing the governed identity. Configure it instead.

### Declaring what a sub-agent may do

When ADK transfers to a sub-agent the plugin routes the spawn through wl-apdp's `spawn_subagent` chokepoint. It fills in one dimension of the requested scope for you — `allowed_tools`, derived from the tools the child agent declares. Every other dimension comes from your per-spawn default scope, read from `WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE` as JSON:

```bash
export WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE='{"time_budget_seconds": 300, "max_depth": 1}'
```

Declare it. With no value, the default scope is empty: no resources, no intents, and `max_depth: 0`. It also names no time budget, so the sub-agent inherits its parent's remaining time, bounded by the parent's deadline and the tenant ceiling, and never more. A `time_budget_seconds` you set is granted exactly as asked, or refused; it is never shortened. wl-apdp refuses `0`, because a child with no time could make no call. It also refuses a budget above what the parent can give: more than the parent was granted, more than the parent has left, or more than the tenant ceiling. The refusal says how many seconds were available, and the sub-agent does not run. A parent's remaining time shrinks as it works, so leave the budget unset if the sub-agent should simply get what is left.

Every spawn also declares the sub-agent's own intent, derived from its parent's. The plugin uses the child agent's ADK `description` as the objective and the `child_intent_category` constructor option as the intent category (default: the parent's own derived category, else `custom:delegated_task`). wl-apdp refuses a category outside the parent's intent categories or its run goal's allowed categories, so set `child_intent_category` to a category your goals allow. The sub-agent is then granted exactly that category.

A sub-agent whose spawn is refused does not run: it gets no model turn and makes no tool call. The plugin returns a refusal message in its place. That message says why (scope, delegation depth, governance unavailable) and how to fix it. The refusal holds for the rest of the ADK session. A sub-agent only ever runs through a governed spawn from its parent. If it opens an invocation of its own, for example because ADK routed the next user turn to it, it is refused.

This needs google-adk 1.14.0 or later. That is the first release whose `AgentTool` gives the agent it wraps the parent's plugins; on earlier releases an agent used as a tool ran with no governance at all. Leave `AgentTool(include_plugins=...)` at its default, `True`. A call of an `AgentTool` with `include_plugins=False` is refused, because its agent would run in a child Runner without Watchlight.

### Failing closed

The plugin never turns uncertainty into permission.

- **No fail-open option.** An unreachable or failing backend is a `Deny` for every tool call and every model turn. The `fail_closed` constructor argument was removed in 0.4.1; passing it raises `TypeError`.
- **No session, no run.** When the root run's governance session cannot be opened (backend unreachable, session refused, or an empty answer), the root agent is not started: it gets no model turn and makes no tool call, and the run returns a refusal message saying governance is unavailable. `plugin.last_governance_mode` reads `"unavailable"`. A missing constraint manifest refuses the run the same way (and closes its session) unless the operator explicitly set `WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`; only then does the run continue in `"degraded"` mode, with every action still authorized.
- **A configured proxy is required.** When `connect_proxy_url=` (or `WATCHLIGHT_PROXY_URL`) is set, every run must route its egress through wl-proxy. If the backend issues no proxy token for the run, or the local CONNECT route cannot be installed, the run is refused the same way and its session is closed. It never continues with direct egress. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its proxy answers every new CONNECT with 403, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.
- **Provider-hosted tools are authorized.** Built-in tools such as Google Search or code execution run inside the model call on Google's side and never reach `before_tool_callback`. Each model turn reads the request through the shared hosted-tool gate of `watchlight-agent-sdk`, and authorizes every hosted tool it enables before the model is called. Gemini built-ins are authorized as `Tool::"<name>"` (`google_search`, `code_execution`, `url_context`, ...), with the action verb from `action_map` or the naming convention, and with `context.builtin_tool == true` and `context.hosted_tool.kind`. The gate also reads tools passed in `config.http_options.extra_body` and a `config.cached_content`, which can carry tools (`Tool::"cached_content"`). A denial refuses the whole model turn, so your policies must permit the built-in tools an agent is given. A request the gate cannot read is refused too.
- **Remote MCP servers must be registered.** A Gemini `mcp_servers` entry lets the model call a remote MCP server directly. Pass `registered_mcp_servers={"<server url>": "<name>"}` to the plugin; the turn is then authorized for `Resource::"mcp://<name>/"`. A server that is not registered refuses the turn before any decision is asked for.
- **Hosted tools that ran are recorded.** When the model response shows that an allowed hosted tool ran (code execution parts, search or maps grounding), the plugin records a `tool_call_observed` event with `metadata.hosted_tool == true`. The event names the tool only; it carries no query, URL or result.
- **Plan governance.** `WATCHLIGHT_PLAN_GOVERNANCE_MODE` only decides what happens when the plan pipeline fails: a plan that cannot be submitted for validation refuses the model turn (`strict`, the default) or continues with action-time enforcement (`degrade`, explicit opt-in). A model turn without a `/*PLANNING*/` block is not refused, because no policy field says a plan is required; each tool call is still authorized when it is made. A denied plan refuses the turn.
- **Live sessions are refused.** ADK's live mode (`Runner.run_live`) opens the model connection without running the model callbacks, and the connection setup carries the agent's tools, so neither the model-turn decision nor the built-in tool checks could run. Until the live path can be governed, the plugin refuses every live invocation before ADK opens the connection: the session ends with a refusal message, and no Watchlight run is opened. Use `run_async`. `run_async` with `RunConfig(support_cfc=True)` is refused the same way: ADK opens a live connection for it from inside the model call, after `before_model_callback`, so it is a live session too. The refusal runs in `before_run_callback`, again in `before_agent_callback`, and again in `before_model_callback`, so a live agent started without a Runner (`agent.run_live(ctx)`) is refused too.
- **A tool that would run an agent Watchlight cannot reach is refused.** A Runner that a tool body builds gets only the plugins it is given, and ADK has no hook through which Watchlight could reach it, so its agent's tools would run with no decision. Before a tool runs, the plugin reads the tool's code without running it. It always reads the tool function itself, and it follows the functions and classes that code names: through module globals, closures, imports and module attributes (`helpers.run_sub()`), defaults, `functools.partial` arguments and the methods of classes it finds. It follows your application's own code (anything outside the standard library and installed packages, and anything in the tool's own top-level package) and any installed module that imports ADK. The call is refused before the body runs when that code:
  - names `Runner`, `InMemoryRunner`, `App`, `Workflow` or any agent class (`LlmAgent` and every other `BaseAgent` subclass), directly or as a module attribute (`google.adk.runners.InMemoryRunner(...)`);
  - names `PluginManager` or `InvocationContext`, or reaches the run's invocation context (`_invocation_context`, `get_invocation_context()`, `plugin_manager`). From the context, code could run an agent it holds with the plugins stripped, for example `agent.run_async(ctx.model_copy(update={"plugin_manager": PluginManager()}))`;
  - uses `__import__`, `import_module`, `exec` or `eval`, through which it could reach any class by a computed name;
  - cannot be read within 4,096 objects.

  A call of an `AgentTool` with `include_plugins=False` is refused too, and a subclass of `AgentTool` is read like any other tool. A tool that only refers to an agent instance it holds is not refused. Give sub-agents to the root as `sub_agents` or wrap them in `AgentTool` so they run as governed children.
  - **What the read cannot see is stopped while it runs.** The read misses some indirection: a class or the run's invocation context reached by `getattr` with a string, `vars()` or `sys.modules`, a class held in an instance attribute or passed in as an argument, or a factory in an installed package that does not import ADK. For those, the plugin has a runtime backstop. While a governed run is live anywhere in the process, an agent start, a model turn that offers tools, or a tool call that goes through a plugin manager without the Watchlight plugin is refused, as is a run started by a Runner without it. So a Runner built inside a tool body, or an agent run under a copied invocation context with the plugins stripped, never takes a turn and never runs a tool. This also holds when it runs on another thread or under a fresh `contextvars.Context`. The tool's own body still runs; only the inner agent is refused.
  - **Only a constructed Watchlight plugin counts.** A plugin manager is governed only when it holds a `WatchlightPlugin` that was actually constructed. Another plugin that copies its name or attributes does not count, and its runner is refused like one with no plugin.
  - **What the backstop does not see.**
    - It works inside this process only. A tool body that starts a separate process to run an agent is not seen by it. Only egress governance through wl-proxy applies there.
    - Sub-agents run as governed children of the current run when they are given to the root as `sub_agents` or wrapped in `AgentTool`.
  - **One process, one governance boundary.** "Live" is process-wide. While a governed run is live, an unrelated agent in the same process that has no Watchlight plugin is refused too. Run ungoverned agents in a separate process. When no governed run is live, nothing changes.
  - **The backstop is installed once, at class level.** The plugin wraps `PluginManager`'s `run_before_run_callback`, `run_before_agent_callback`, `run_before_model_callback` and `run_before_tool_callback`, and `Runner.run_async`, when the first plugin is constructed. If any of these wraps is later replaced, every run, model turn and tool call of a governed run is refused. Removing the wraps on purpose turns governance off and is not defended against.
  - **A run must start through `Runner.run_async`.** The wrap marks each step of the run it makes, and the plugin checks that mark for this run, not whether some governed run is live in the process. A run that did not start through it (the method called around the wrap, for example) is refused at `before_run_callback`, even while other governed runs are live. Where ADK ignores that run-level refusal (google-adk 2.5.0, with an `LlmAgent` root run through `run_async`), the refusal is enforced at `before_agent_callback`: the root agent is refused before its first model turn. This includes a task agent ADK resumes on its own from a session that holds an unresolved task delegation. Nothing runs, and no run or spawn reaches lineage.
  - **Remote agents.** A held `RemoteA2aAgent` that a tool calls runs on its own server; the call is governed only by A2A governance, not by this check.
- **Refused tool calls are recorded as refused.** Each tool call the plugin refuses is recorded in lineage once, as a value-free `tool_call_observed` with the decision it got (`Deny` or `Quarantine`), at the moment it is refused. This covers a policy Deny, the refusal of a tool that would run an agent outside Watchlight, and a refused sub-agent's calls. Only a call the plugin let through is recorded as an `Allow`. A call the plugin never decided, for example one a plugin registered before Watchlight answered first, is recorded without a decision, never as an `Allow`. One limit: an agent-level `before_tool_callback` on your own agent runs after the plugin, so it can still skip a call the plugin allowed. That call is then recorded as an `Allow`, which is true of the authorization decision, although its body did not run.
- **Install Watchlight first.** Register the Watchlight plugin first in `plugins=[...]`. ADK stops at the first plugin whose callback returns something, so a plugin registered before Watchlight can answer a callback Watchlight never sees. Watchlight's checks that run in a later callback (the live refusal in `before_agent_callback`, the model-turn and tool checks) still apply, but only the first position guarantees that every check runs.
- **A hosted tool the response shows but the turn did not authorize** is logged and recorded in lineage as a `hosted_tool_observed` event with decision `NotAuthorized` (value-free).
- **Local code executors are authorized every turn.** A code executor other than `BuiltInCodeExecutor` (for example `UnsafeLocalCodeExecutor` or a container executor) runs the code the model writes, outside any tool callback. Each model turn of such an agent is authorized for `Tool::"code_executor"` first; a denial refuses the turn. ADK's data-file preprocessing (an executor with `optimize_data_file=True`) runs code before the first model callback, so it is authorized once when the agent starts, as `Tool::"optimize_data_file"`; a denial refuses the agent before ADK reaches it.
- **Late changes to the request are re-checked.** The plugin adds a final agent-level `before_model_callback` that authorizes any built-in tool or raw Python callable (`Tool::"callable:<name>"`) added to the request by your own agent callbacks or a later plugin, just before the model is called. An agent object that carries this re-check still refuses its model turns when a runner without the Watchlight plugin runs it, and the refusal says the plugin is not registered; build a fresh agent object for ungoverned use.
- **Tool arguments stay in the process.** The authorize request carries only value-free argument metadata in `context.tool_arg_metadata` (argument names, count and value types), never the values. The lineage plan event summarises arguments the same way. Policies that read the former `context.tool_args` string no longer receive it.

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightPlugin(...)` (ADK opens the run from its callbacks, so there is no per-run argument) or set `WATCHLIGHT_APPLICATION_ID` in the environment — the constructor argument wins. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or agent names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

The plugin reaches its backend through `plugin.apdp`. Swap that one object to move between editions — the agent code and the plugin wiring are identical.

```python
# Developer Edition — zero infrastructure, decisions in-process
from watchlight_core import InProcessClient
plugin.apdp = InProcessClient(POLICIES)

# Enterprise — the governed Watchlight backend over the network.
# The credential is read from the environment (WATCHLIGHT_PLUGIN_TOKEN and
# its claims), never written into source.
from watchlight_core import ApdpClient, Credential
plugin.apdp = ApdpClient("https://apdp.your-org", credential=Credential.from_default())
```

| Edition | Backend | What it gives you |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The real compiled engine, in-process. No server, no network, no database. Local lineage to `.watchlight/audit.jsonl`. |
| **Enterprise** | `ApdpClient` | The fully governed control plane: signed tamper-evident lineage, multi-tenant scope, agent registry, dashboards, and audit. |

`WatchlightPlugin(apdp_url="https://apdp.your-org")` also constructs an `ApdpClient` for you, so Enterprise deployments can simply pass the endpoint at construction time.

## Links

- Documentation: https://docs.watchlight.ai/de
- Watchlight: https://watchlight.ai

## License

Apache-2.0 © Watchlight AI
