# watchlight-strands

Watchlight authorization for Strands Agents: every tool call, every sub-agent, every Swarm and Graph node, fail-closed. Install it once, on the root.

```bash
pip install watchlight-strands
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** Amazon Web Services. `Strands Agents` and related names are used here only to describe compatibility.

## What it does

`watchlight-strands` puts a Watchlight authorization decision in front of every tool call a Strands agent makes, so each call is allowed or denied *before* it runs. You add one plugin, to the root agent or the root Swarm or Graph. The plugin then attaches itself to every agent and orchestrator the root reaches and governs them too: agents used as tools, agents a tool function calls, and Swarm and Graph nodes, including nested ones. Each child runs as a governed sub-agent under its parent's run, with a narrower scope.

The plugin uses only Strands' public hook API. It registers its callbacks on each agent's public hook registry (`agent.hooks.add_callback`). It does not patch, wrap or replace any Strands function, and your tools, prompts and agent code stay as they are. The policy decisions run on Watchlight's engine, in-process for local development or on the governed control plane in production.

## Setup: one line, at the root

```python
from strands import Agent
from watchlight_strands import WatchlightStrandsPlugin

researcher = Agent(name="researcher", tools=[web_search])
writer = Agent(
    name="writer",
    tools=[researcher.as_tool()],
    plugins=[WatchlightStrandsPlugin(agent_slug="agent-writer")],   # the only line you add
)
writer("Write a short brief on agent governance.")
```

The same plugin attaches as a hook provider (`Agent(hooks=[...])`) and to orchestrators (`Swarm(nodes, plugins=[...])`, `GraphBuilder().set_plugins([...])`). Install it on the root only.

## Identity

Who an agent runs as comes from Watchlight and from configuration, never from your code.

- **The root** runs as the registered agent named by `agent_slug=` or the `WATCHLIGHT_AGENT_SLUG` environment variable, or by an `agent_map` entry for its name. When watchlight-core gains credential-bound roots, the root will run as the agent bound to the process's verified credential (for example the AWS role mapping on Amazon Bedrock AgentCore), and `agent_slug` becomes an optional override.
- **A child** never needs a registered agent of its own. It runs as a governed sub-agent of its parent, with a scope Watchlight narrows to a strict subset of the parent's: by default it asks for its own tool names. Until watchlight-core supports labelled sub-agents, an unmapped child runs under its parent's registered agent.
- **`agent_map`** (or a JSON file named by `WATCHLIGHT_AGENT_MAP`) maps an agent's `name` (an orchestrator's `id`) to a registered agent. A mapped child runs as that agent, with its own policies, and is still spawned and narrowed under its parent. `subagent_scopes` maps a child's name to the scope it asks for.
- **An agent that cannot be identified is refused.** A root with no slug and no map entry does not run. A child invoked on its own, outside any governed run, does not run unless `agent_map` names it.

## What it enforces

- **Run start.** Each invocation (`agent(...)`, `invoke_async`, `stream_async`) opens a governed run before the first model turn: a root run, or a sub-agent run when a governed run is active in the calling context. If the run cannot be opened (no identity, an unregistered agent, a refused spawn, an unreachable backend, a missing pre-flight manifest, egress that cannot be governed), the invocation raises and the agent does not run: no model turn and no tool call.
- **Tool calls.** Every tool call is authorized on the invocation's own run before it runs. That covers Python function tools (sync, async and streaming), MCP tools served through Strands' `MCPClient`, and agents used as tools. A denial, an unreachable backend, a timeout (`authorize_timeout_seconds`, 30 seconds by default) or an unexpected answer cancels the call through Strands' `cancel_tool`, and the tool body never runs. Concurrent tool calls are each authorized separately. Only argument names, count and value types are sent, never argument values.
- **Reaching children.** When the root is built, the plugin attaches to every agent and orchestrator it can already see: agents used as tools, agents and orchestrators a tool function refers to (by closure or module name), and Swarm and Graph nodes, recursively. Before a tool call or a node runs, it attaches again to what that call will run, so agents and nodes added later are covered. A child it cannot attach to is refused before it runs.
- **Run-ending verdicts.** A quarantine, terminate, sever or revoke verdict raises, which ends the invocation.
- **Model calls outside the agent loop.** Strands calls a model in some places that fire no model hook: a summary written by `SummarizingConversationManager`, and the calls listed under What is refused. So before each invocation starts, the plugin authorizes every provider-hosted tool that the configuration of `agent.model` and `agent.aux_model` turns on, on the invocation's run. That covers Bedrock's `additional_request_fields`, the `params` passthrough of OpenAI, Anthropic, Gemini and the other providers, and Gemini's `gemini_tools`. These settings go out with every call of that model, the summary call included. A denial, an unreachable backend or a configuration the plugin cannot read ends the invocation before any model call. A conversation manager's `summarization_agent` runs as a governed sub-agent, and it is refused if the plugin cannot attach to it.
- **Human approval.** An approval-required decision becomes a Strands interrupt named `watchlight-approval`, and the tool has not run. Resume with an interrupt response of `"approved"` (or `True`, or `{"approved": True}`) after an operator has approved the request in Watchlight; the plugin retries the authorization on the same run, and the tool runs only if Watchlight now allows it. Watchlight binds an approval to the intent it was requested under, so a run that uses approvals declares a typed intent: `WatchlightStrandsPlugin(intent_objective="pay the invoice", intent_category="financial_operation")` (a category from `watchlight_core.INTENT_CATEGORIES`, or `custom:<name>`; add `intent_justification` for a category such as `financial_operation` that Watchlight refuses without one). Every authorization of the root run carries it, and the retry carries the approval inside it. A sub-agent's authorizations carry the sub-agent's own derived intent instead (see `child_intent_category`), so a sub-agent's approval is bound to that intent. Without a declared intent, an approved resume is refused with a message that says so, because Watchlight could not redeem the approval. The approval request id never leaves your process.
- **Run end.** The run closes when the invocation ends: completed, failed or cancelled. Sub-agent runs still open under it end with it. An invocation that stops for an interrupt keeps its run for the resume.
- **Component models.** Strands components can take a model of their own and call it outside the agent loop, where no model hook fires: the steering LLM handler, the human-in-the-loop risk classifier, the context manager's summarize strategy, the agentic `web_fetch` tool, a memory `ModelExtractor`, and anything that falls back to `agent.aux_model`. When an invocation's run opens, the plugin finds every model reachable from the agent (its plugins, hooks, interventions, conversation and context managers, memory manager and tools, including what their functions refer to) and authorizes every provider-hosted tool that each model's configuration turns on. A denial, an unreachable backend, a configuration the plugin cannot read, or a set of components too large to check completely ends the invocation before the first model call. So does any agent or orchestrator the plugin finds then but cannot attach to, whether a component holds it or it sits behind a tool, because a component or a tool body can call it directly. The run closes as failed, so the refusal is in its lineage.
  - **The walk runs no code of the objects it visits.** It reads instance attributes, slots, function closures and defaults, the module globals a function names, and the class attributes of a component's class that hold a model, an agent, a weak reference or a built-in container. It reads a class through `type`'s own descriptors, so a metaclass cannot hide its attributes. It reads `dict`, `list`, `tuple`, `set`, `frozenset` and `deque` contents (and those of their subclasses) through the built-in types' own methods, and follows live weak references through `weakref.ref`'s own call, never a subclass's. Any other mapping or iterable is never iterated: its attributes are walked, and one implemented in C (such as a `mappingproxy`) is read through the garbage collector's reference traversal. One whose contents cannot be read that way refuses the invocation. Conversation history is not walked. Transport and SDK client objects (boto3, httpx, the provider SDKs, MCP sessions and similar) are not descended into.
  - **The walk visits at most 50,000 objects.** A component that holds a larger object graph, for example a copy of the conversation or a large data structure that a tool function reaches through a module global, has every invocation refused with `Watchlight refused the invocation: the agent's components are too large to check every model they can call`. Keep large data out of the objects your components and tool functions hold, or load it inside the tool body. On a realistic agent (30 function tools, an MCP client, steering, a human-in-the-loop classifier, the `web_fetch` tool, a summarizing conversation manager and a memory store) the walk visits about 830 objects and takes about 2.2 ms. The model-turn check also runs before every other model hook, so a hook such as proactive summarization never calls a model for a run that is missing, quarantined or severed.
- **Every model call (the backstop).** The plugin also wraps `stream` and `structured_output` on every `strands` model class: the classes already defined when the first plugin is created, and every class defined later. Every call is checked before the model runs:
  - **A call inside a governed run.** A context that opens a governed run is marked. Asyncio tasks and `asyncio.to_thread` inherit the mark. The innermost governed run of a marked context must be open, and not suspended, quarantined or severed, so a call after the run has ended is refused. The mark never resets in that context: a caller that awaits `invoke_async` in its own task keeps it afterwards, and a model call it makes there later is refused like any other call outside a governed run.
  - **A call that lost the governed run.** A plain `threading.Thread`, `loop.run_in_executor`, `ThreadPoolExecutor.submit`, a task created with a fresh `contextvars.Context()` and a child process start without the mark. So while any governed run is live in the process, a model call with no governed run in its context is refused. A run waiting for a human approval stays live until it is resumed and ends, because a thread or pool its tools started keeps running during the wait. A direct model call made while an approval is pending therefore needs `direct_model_use()` too. A wait nobody resumes is abandoned when the run's session expires (one hour), or when the application drops the agent and it is garbage collected. Either way the run leaves the live set, and a warning is logged. Hand such work to `asyncio.to_thread`, or build and invoke a governed agent for it.
  - **A turn of an agent that is not governed in the run.** Strands passes the calling agent with every turn of an agent's loop. Inside a governed run, that agent must have an open governed run of its own, so an agent a tool body builds and runs is refused at its first model turn: it never takes a turn and never calls a tool. The one exception is an agent whose only tool is Strands' structured-output tool, which runs no code (the steering handler and the human-in-the-loop risk classifier run such an agent internally); its model's hosted tools are still checked. An agent set to hot-load tools from a directory counts as holding tools, and the tools are checked again once the model's response is in, before Strands runs any tool it asked for, so a tool registered during the turn is never run. `direct_model_use()` never covers a turn of an agent that holds tools. If a tool passes its own `invocation_state` to an agent it builds, that agent replaces the calling agent recorded in the shared state, so the outer agent's next turn is refused too: the run fails closed. Give an inner agent its own state.
  - **Your own direct model use** while governed runs are live has to be declared: wrap it in `with watchlight_strands.direct_model_use():`. Every entry logs a warning with its call site and the number of live governed runs, and no values, so the escape is auditable. The block never lifts the check for a call inside a live governed run, and it covers its own context only, so a thread you start needs its own block.
  - **Behaviour change.** An application that runs governed agents and makes direct model calls at the same time must wrap those direct calls in `direct_model_use()`. With no governed run live, direct calls are not checked.
  - **Configured hosted tools.** Every provider-hosted tool the model's configuration enables must be allowed on the call's run. The tools decided when the run opened are reused, and anything new (for example a model a tool body builds) is authorized on the run before the call. A refusal or a configuration the plugin cannot read stops the call. When the run opens, and again before each model turn, the plugin also refuses a model whose calls would skip these checks: one that is not a `strands` model, or whose `stream` or `structured_output` was replaced after the plugin wrapped it (on the class, or as an instance attribute), or that Python could resolve to something else: a property or other data descriptor on the class, or a class that redefines `__getattribute__`. Instrumentation that wraps `stream` or `structured_output` (for example wrapt's `wrap_function_wrapper`, or `mock.patch.object`) must be installed before the plugin is created, and the plugin then wraps over it. Applied afterwards, the model call is refused on purpose: the plugin cannot trust that a proxy's `__call__` reaches its check. This covers what the walk cannot see: a model built at call time, a module-level model that a component's method reads, and an attribute an object hides behind a property, a slot descriptor or a metaclass. The check costs 8 to 16 microseconds per model call when nothing new needs a decision, plus under a microsecond per model turn for the replaced-method check.
- **Memory writes after the run.** A `MemoryManager` writes to its extraction stores after the run has ended: extracted facts, or the raw conversation for store-side extraction. When the run opens, the plugin asks for one decision per such store (action `create`, resource `memory:<store name>`). Anything but allow ends the invocation before the first model call.
- **Lineage.** Each run emits its `execution_started` and terminal events, sub-agent runs link to their parent's, and each tool call emits a `tool_call_observed` event with the decision and the value-free argument shape.
- **Provider-hosted tools.** Every provider-hosted tool a model call enables is authorized before the model is called: a web search, code execution, a remote MCP server, or a tool passed through `params`, `extra_body`, `http_options` or Bedrock's `additional_request_fields`. The plugin reads the request the model class builds, so constructor and passthrough settings are included. It reads it at the last step before the call, after every middleware, so a router model that swaps the model, or a middleware that rewrites the tool list, is checked on what it actually sends. Every model call is decided again, so a tool allowed earlier in the run is refused once policy denies it. A model swapped in by middleware must also be a Strands model whose calls go through the plugin's wrap; otherwise the call is refused, as it would be when the run opens. A denial, an unreachable backend or a request the plugin cannot read refuses the model call, and nothing is sent. A remote MCP server must also be listed in `registered_mcp_servers`. For the model classes Strands ships (Bedrock, Anthropic, OpenAI Chat Completions and Responses, Gemini, and their subclasses) the plugin reads the provider request; for any other model class it reads `model.get_config()`. The plugin passes conformance invariant 19 (provider-hosted tools are authorized before the model call), which the shared core checks for every plugin that can put hosted tools on a model call.
- **Egress.** With a wl-proxy URL configured (`connect_proxy_url` or `WATCHLIGHT_PROXY_URL`), each root run installs the `wl-sidecar` with that run's proxy token, so model calls (Amazon Bedrock included) and tool HTTP calls go through wl-proxy. If no proxy token was issued or the sidecar fails to start, the run is refused. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its sidecar is stopped and `HTTPS_PROXY` stays on the stopped port, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.

### What is refused

These never run:

- A child the plugin cannot attach to: an agent type it does not govern (a remote `A2AAgent` node, a `BidiAgent`, any object that is not a `strands.Agent` or a Swarm/Graph orchestrator), or a registry that will not take the callbacks. If the plugin can reach the child when the invocation starts (an agent used as a tool, or one a component or a tool function holds), the invocation is refused before the first model call. A child that only appears later has its tool call or node cancelled.
- An agent with `background_tasks=...`, root or child: a background tool call runs after its governed run has ended.
- A `GoalLoop` with a natural-language goal. Its judge calls a model after the governed run has ended. A `GoalLoop` with a validator function is not refused.
- A tool function that refers to an agent or orchestrator the plugin cannot govern: the call is cancelled, because the plugin cannot tell whether the body would run it.
- A function tool whose code can build an agent or orchestrator. An agent a tool body builds exists only inside the body, where the plugin cannot attach to it, so the tool call is cancelled before the body runs. The plugin reads the tool's code without running it: the names its code uses (including nested functions, lambdas and comprehensions), resolved in its module globals and closure, its defaults, `functools.partial` arguments, and the methods of classes it finds, following functions and classes from any module that imports Strands. The call is cancelled when that code names `strands.Agent`, `Swarm`, `Graph` or a subclass, `GraphBuilder` or `config_to_agent`, directly or as an attribute of a Strands module (`strands.Agent(...)`), or when the read does not finish within 4,096 objects. Build sub-agents outside the tool function, or pass them as tools, so the plugin can govern them as children.
- An agent that cannot be identified (see Identity).
- Direct tool calls (`agent.tool.my_tool(...)`) made outside an invocation, an unknown tool, and a tool selection another hook rewrote inconsistently.
- A second Watchlight plugin on the same agent, and one plugin installed on two roots.
- The deprecated `Agent.structured_output` and `structured_output_async`. They call the model directly, outside the governed model path. Pass `structured_output_model=` to the invocation instead.
- An agent whose `MemoryManager` extracts memories with an extractor. The extractor calls a model in a background task after the governed run has ended, where no decision can be made. Store-side extraction, where the store receives the raw messages and no extractor is set, is not refused.

The two refusals above happen on the invocation's governed run before any model call. The run then closes as failed, so its lineage records the refusal.

### What it does not enforce

- **Agents a tool function builds by indirection.** The code read above does not see an agent class reached through `importlib.import_module`, `getattr` with a computed name, `sys.modules`, `eval` or `exec`, an instance attribute, a tool argument or `invocation_state`, or a factory in a module that does not import Strands. The tool body then runs, but the agent it builds is refused at its first model turn (see the backstop), so it never calls a tool. An agent with no tools may still take model turns; its model's hosted tools are checked, and with wl-proxy configured its network calls go through wl-proxy under the root run.
- **Calling a model directly.** Code that calls a model object itself, for example `agent.model.structured_output(...)` or `agent.model.stream(...)`, outside any governed invocation uses the model directly and is outside the reach of any plugin, as long as no governed run is live in the process. While one is, such a call is refused unless it is inside `direct_model_use()` (see the backstop above), which logs it.
- **Hostile classes.** The walk reads stored values and never runs code of the objects it visits. An object can still hide a model behind a property, a custom slot descriptor or a metaclass that builds attributes on access. The walk does not see such a model, and the backstop checks it when it is called. A model whose `stream` was replaced after the plugin wrapped it is refused wherever the plugin sees it (when the run opens and at each model turn). A replaced model used only inside your own code is direct model use. With wl-proxy configured, the network call still goes through wl-proxy under the root run.
- **Lost context.** An agent invoked from a thread your own code starts (Python threads do not inherit context) has no parent run, so it is refused unless `agent_map` names it.
- **Model turns are not authorized one by one.** A model turn is refused when it belongs to no governed run or its run is quarantined or severed; egress governance comes from wl-proxy.
- **Hooks after the gate.** The gate runs after every other hook. A hook you register after the plugin at an infinite order runs after it; if it changes the tool, the plugin withholds the result and logs an error.
- **Intent declaration** is not wired yet, and a quarantine does not interrupt an in-flight model call; it stops the run at the next model turn or tool call.

## Developer Edition

The zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package):

```bash
pip install watchlight-strands "watchlight-engine>=0.2.5,<0.3"
```

```python
from strands import Agent, tool
from watchlight_core import InProcessClient
from watchlight_strands import WatchlightStrandsPlugin

# Cedar policies: the writer (and the sub-agents it runs) may use these two tools, nothing else.
POLICIES = [
    {"name": "search",
     "code": 'permit(principal is Agent, action == Action::"execute", resource == Resource::"web_search") when { principal.name == "agent-writer" };'},
    {"name": "delegate-to-researcher",
     "code": 'permit(principal is Agent, action == Action::"execute", resource == Resource::"researcher") when { principal.name == "agent-writer" };'},
]

@tool
def web_search(query: str) -> str:
    """Search the web."""
    ...

researcher = Agent(name="researcher", tools=[web_search])
writer = Agent(
    name="writer",
    tools=[researcher.as_tool()],
    plugins=[WatchlightStrandsPlugin(agent_slug="agent-writer", governance=InProcessClient(POLICIES))],
)
writer("Write a short brief on agent governance.")
```

Each tool call is authorized as action `execute` on `Resource::"<tool name>"`. An agent used as a tool is authorized under its tool name (here `researcher`) and then runs as a governed sub-agent under the writer's run, limited to its own tools.

## Configuration

| Argument | Meaning |
|---|---|
| `agent_slug` | The root's registered agent (env `WATCHLIGHT_AGENT_SLUG`). Optional when `agent_map` names the root. |
| `agent_map` | Agent name to registered agent, a mapping or a JSON file path (env `WATCHLIGHT_AGENT_MAP`). |
| `subagent_scopes` | Agent name to the scope it asks for as a sub-agent: `allowed_tools`, `allowed_resources`, `allowed_intents`, `max_depth`, `time_budget_seconds`. A named `time_budget_seconds` is granted exactly or the spawn is refused. |
| `child_intent_category` | The intent category every sub-agent declares when it is spawned. The sub-agent's `description` is its objective. A sub-agent whose `subagent_scopes` entry pins exactly one intent declares that one. When unset, a sub-agent of a spawned sub-agent declares its parent's category, and otherwise `custom:delegated_task`. The category must be one of `watchlight_core.INTENT_CATEGORIES` or `custom:<name>`; any other value is refused when the plugin is constructed. A sub-agent's authorizations carry its own derived intent (its objective and category), never the run's declared intent, so they stay inside what Watchlight granted it. Watchlight refuses a category outside the parent's intent categories or its run goal's allowed categories, and a refused sub-agent never runs. |
| `authorize_timeout_seconds` | Upper bound on each tool authorization (default 30). |
| `registered_mcp_servers` | Remote MCP servers a model call may enable, as server URL to the name policy sees (`Resource::"mcp://<name>/"`). A model call that enables a server not listed is refused before any decision. |
| `connect_proxy_url` | wl-proxy URL for governed egress (env `WATCHLIGHT_PROXY_URL`). |
| `application_id` | The AI application the runs belong to (env `WATCHLIGHT_APPLICATION_ID`). An Enterprise feature: the in-process engine refuses it. |
| `governance` | A governance backend to use as is, such as `InProcessClient`. |

In a Swarm, agents hand over with Strands' built-in `handoff_to_agent` tool; like any tool, your policy must allow it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process**: no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane: signed lineage, drift detection, fleet-wide governance |

Moving from local to production means dropping `governance=` and pointing the plugin at the control plane:

```python
WatchlightStrandsPlugin("https://apdp.your-company.example", agent_slug="agent-writer")
# The credential is loaded from the environment or your credential provider
# (for example WATCHLIGHT_CREDENTIAL_FILE); never put a key in source.
```

## Compatibility

`strands-agents` 1.55 to 1.62. The test suite asserts the Strands hook surface the plugin relies on, so a Strands release that moves it fails the tests instead of silently weakening governance.

The provider-hosted tool check runs inside Strands' invoke-model middleware. Part of what it uses is private to Strands (the agent's middleware registry, and before 1.62 the middleware module itself), so the supported range ends at the newest Strands release the suite has passed on. If a Strands release moves that middleware, the plugin refuses model calls instead of skipping the check.

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0
