# watchlight-langgraph

Governance primitives for LangGraph agents with Watchlight: authorize the actions you gate, validate plans, and spawn attenuated sub-agents.

```bash
pip install watchlight-langgraph
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** LangChain. `LangGraph` and related names are trademarks of LangChain, used here nominatively only to describe compatibility.

## What it does

`watchlight-langgraph` governs a LangGraph agent with no change to its graph. While a governed run is open, every tool that LangGraph's `ToolNode` runs is decided before it runs, every other tool start is refused, and each provider-hosted tool on a model call is decided before the provider request is sent (see [Provider-hosted tools](#provider-hosted-tools)). It also gives you explicit primitives to call from your own nodes: `authorize_action`, `governed_tool_call`, plan checks and governed sub-agents. The policy decisions run on Watchlight's compiled engine, either in-process for local development or against the governed control plane in production.

There is no fail-open setting. A decision that cannot be made refuses the action. That covers an unreachable backend, an unreadable answer and a missing wrap the plugin relies on, and nothing in the plugin's configuration turns it off. The one related setting, `WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`, only lets a run start without a pre-flight manifest; every action in that run is still decided.

What is enforced, and where:

- `handle.authorize_action(...)` and `handle.authorize_action_detailed(...)` ask for a decision before an action. A Deny returns `False` (or a Deny result). If the backend cannot be reached, the call raises, so the action does not run as long as you do not catch and ignore that exception.
- `governed_tool_call(handle, tool_name, ...)` (in `watchlight_langgraph.governance`) wraps a tool implementation: it runs the tool only on Allow, raises `ToolDenied` on Deny, and pauses the graph with LangGraph `interrupt` when a human approval is needed.
- `handle.submit_plan(...)` and `handle.preflight_step(...)` validate a plan or a step and return Allow, Modify or Deny. Your code must act on the result.
- `handle.spawn_subagent(..., child_intent=ChildIntent(category, objective))` asks the backend for an attenuated child run. The child intent is required and must derive from the parent run's intent and goal. A refused spawn raises, and the child gets its own credential and scope, granted exactly the declared intent category.
- `plugin.start_run(...)` refuses to start (raises `AgentNotRegistered` or `GovernanceUnavailable`) when the agent is not registered, the backend does not accept the session, or a wl-proxy URL is configured but governed egress cannot be set up. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its sidecar is stopped and `HTTPS_PROXY` stays on the stopped port, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.
- Every tool that LangGraph's `ToolNode` runs while a governed run is open is authorized before it runs, with no change to your graph. This covers `create_agent`, `create_react_agent` and graphs you build yourself with `ToolNode`. A run is open from the moment `start_run` (or `spawn_subagent`) returns it until it completes or is terminated. The call is decided for the run acting where the graph runs: the sub-agent that `spawn_subagent` bound there, its parent again once that sub-agent has completed, or else the run that `start_run` returned. An allowed tool runs, a denied tool raises `ToolDenied` and its body never runs, a tool that needs a human approval pauses the graph through `interrupt`, and a tool whose decision cannot be made is refused. Decisions need the run entered with `async with handle:`. A graph that runs after a bare `start_run` is refused with an error that says so. If the installed LangGraph does not have the `ToolNode` methods the plugin wraps, `start_run` refuses the run.
- While a governed run is open, any other tool start in the process is refused with `UngovernedToolCall`: a tool called directly with `tool.invoke(...)`, a tool started with `callbacks=[]`, from a raw thread or from a fresh context, and a second tool started inside an allowed tool's body. A model call that binds tools is allowed as the acting run's own turn, and refused inside a tool body (an agent built inside a tool) or where no run acts, with `UngovernedModelCall`. A model call without tools inside a tool body is allowed. Each refusal is recorded in the run's lineage, when the run was entered with `async with`.
- Sub-agents: a sub-agent's graph runs as that sub-agent, never with its parent's authority, whether or not you enter it with `async with child:`. While a live sub-agent is bound in a context, `spawn_subagent` there raises `SiblingSubagentLive` unless that sub-agent is the one spawning (nesting). This covers a sibling, a grandchild and any other live sub-agent. Finish a sub-agent before you spawn its sibling in the same context, or spawn each sub-agent in an asyncio task created before any sub-agent is bound (a task copies the context it was created in).
- Root runs: one live root run per context. Start concurrent root runs in separate asyncio tasks.
- A run that is never completed or terminated stays open for the life of the process, and every tool start outside it stays refused. Use `async with`, or call `complete()` or `terminate()`.

What is not enforced:

- The callback handlers (`WatchlightCallbackHandler`, `WatchlightAsyncCallbackHandler`, `handle.callback_handler()`) only observe. They record tool, model and chain events for lineage and never block a call.
- Plain Python code is not a LangChain tool. A function that your graph calls directly, such as a tool's underlying `tool.func` or any helper in a node, runs in the run's context without a tool start, so neither the `ToolNode` gate nor the backstop sees it. Put actions behind a tool that `ToolNode` runs, or call them through `governed_tool_call`.

## Quickstart

Point the plugin at a backend and wrap your run. Your agent code doesn't change — only the backend does.

For local development, the zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package):

```bash
pip install watchlight-langgraph "watchlight-engine>=0.2.5,<0.3"
```

```python
from watchlight_langgraph import WatchlightLangGraphPlugin
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may read, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "research-agent" };'},
]

plugin = WatchlightLangGraphPlugin()
plugin.apdp = InProcessClient(POLICIES)   # decisions run in-process, no server, no network

async def run_agent(question: str):
    async with await plugin.start_run(agent_slug="research-agent") as handle:
        # Validate a multi-step plan ahead of execution (Allow / Modify / Deny).
        result = await handle.submit_plan(["read dataset", "summarize"])
        if result.is_deny():
            raise PermissionError(f"Plan denied: {result.violations}")

        # Gate each action authoritatively. Returns True on Allow, False on Deny.
        if not await handle.authorize_action("read", "dataset"):
            raise PermissionError("Denied by policy")

        # ... your LangGraph agent runs, every action governed ...
```

`authorize_action` returns `False` on a denial and raises when the backend cannot be reached. Either way the guarded action does not run, as long as your code does not swallow the exception.

### Provider-hosted tools

Some model providers run tools on their own servers, inside the model call: web search, code execution, file search, a remote MCP server or an Anthropic skill. No LangGraph tool node sees them, so the plugin decides them before the request is sent, with no change to your graph.

Inside `async with await plugin.start_run(...)`, the run's context is marked. Every request that a supported provider SDK (`anthropic`, `openai`, `google-genai`) sends from that context is read as it leaves, and each hosted tool in it gets one policy decision, on `Tool::"<kind>"` (a remote MCP server is `Resource::"mcp://<name>/"`). The decision is made on the request the SDK actually sends, so it also covers fields a model class adds on its own, such as `ChatAnthropic(mcp_servers=...)`. A deny, a required approval, an error or a timeout raises `HostedToolRefused`, and nothing is sent. Function tools are not decided here; your tool nodes govern them. The full list of provider APIs, and which are decided or refused, is in the watchlight-core README under "Deciding on the request the provider SDK sends".

- **Chat model classes.** In a run, a LangChain chat model call must use a class whose requests go through one of those SDKs: `ChatAnthropic`, `ChatOpenAI`, `AzureChatOpenAI`, `ChatXAI` or `ChatGoogleGenerativeAI`. Any other class, including a subclass of one of these, is refused with `UnknownModelClassRefused` before it is called. To use another class, list it in `allowed_model_classes=["package.module:ClassName"]` on `WatchlightLangGraphPlugin(...)`. An allowed class is plain chat only: a call of it that binds any tool is refused with `UnknownModelClassRefused`, because its requests may not go through a supported SDK. Listing a class is your statement that it has no hosted capability, including one set on the model itself, such as an MCP server field. Each listed class is logged at WARNING when a run opens.
- **Remote MCP servers.** Pass `registered_mcp_servers={"<server URL>": "<name>"}` to `WatchlightLangGraphPlugin(...)`. A request that enables a server not in that map is refused before any decision.
- **Synchronous calls.** `model.invoke(...)` from a worker thread, the way LangGraph runs a sync node, is decided on the run's event loop while the thread waits. A synchronous call that enables a hosted tool on the run's own event-loop thread is refused, because waiting there would deadlock. Use `ainvoke` in async code.
- **Calls outside the run's context.** While a governed run is live in the process, a request that binds any tool but does not carry a run's context is refused with `UnmarkedToolBindingRefused`. Such a call might come from a raw thread that did not copy the context, or from code outside `async with`. A task that outlives its run is refused the same way. The refusal is logged at WARNING with the reason `unmarked_tool_binding`, and it does not end the live run. A call with no tools passes. With no governed run live, nothing changes, so run unrelated LangChain agents in a separate process.
- **Not covered.** A hosted capability that an allowed class turns on by itself, without binding a tool, is not seen; that is why the allow-list is your statement that the class has none. Governed egress covers its traffic. A direct call of a model's `_generate`, or of a provider client from a tool, reports no LangChain callback, so the class check does not run for it; the SDK gate still decides its request when it goes through a supported SDK.

The plugin supports `langchain-core` 1.3.3 and later (earlier releases carry known advisories), with `anthropic` 0.69, `openai` 1.109 and `google-genai` 1.53 or later.

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightLangGraphPlugin(...)`, or per run to `start_run(...)`, or set `WATCHLIGHT_APPLICATION_ID` in the environment — an explicit argument wins over the env var. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane: signed lineage, drift detection, fleet-wide governance |

Moving from local to production is a one-line change:

```python
from watchlight_core import ApdpClient, Credential

plugin = WatchlightLangGraphPlugin()
# The plugin credential comes from your secret store or the environment
# (WATCHLIGHT_PLUGIN_TOKEN), never from source code.
plugin.apdp = ApdpClient(
    "https://apdp.your-company.example",
    credential=Credential.from_default(),
)
```

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0
