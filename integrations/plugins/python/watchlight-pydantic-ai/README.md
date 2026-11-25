# watchlight-pydantic-ai

Watchlight governance for Pydantic AI agents: the tools you wrap with `guarded_tool()` are authorized before they run, and every `Agent.run` opens a governed run (nested runs as attenuated sub-agents), fail-closed. Undecorated tools and model turns are not authorized.

```bash
pip install watchlight-pydantic-ai
```

It needs Python 3.11 or later; pip refuses to install it on Python 3.10.

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** Pydantic. `Pydantic AI` and related names are trademarks of Pydantic, used here nominatively only to describe compatibility.

## What it does

`watchlight-pydantic-ai` puts a Watchlight authorization decision in front of each tool call you wrap with `guarded_tool()` — the call is allowed or denied *before* it runs, never after — and opens every `Agent.run` as a governed run, with nested runs spawned as attenuated sub-agents. Tools you do not wrap, and the model turns themselves, are not authorized. It's open-source glue: a thin, framework-specific layer that threads Watchlight's governance primitives into Pydantic AI's `@agent.tool` decorators and nested `Agent.run()` composition. The actual policy decisions run on Watchlight's compiled engine — either in-process for local development or against the governed control plane in production.

## Quickstart

Point the plugin at a backend and wrap your agent tools with one decorator. Your agent code stays vanilla Pydantic AI — only the backend changes.

For local development, the zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package):

```bash
pip install watchlight-pydantic-ai "watchlight-engine>=0.2.5,<0.3"
```

```python
from pydantic_ai import Agent
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin, guarded_tool
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may execute web_search, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"execute", resource == Resource::"web_search") when { principal.name == "research-agent" };'},
]

plugin = WatchlightPydanticAIPlugin()
plugin.apdp = InProcessClient(POLICIES)   # decisions run in-process, no server, no network

agent = Agent("openai:gpt-4o-mini", name="research-agent")

@agent.tool
@guarded_tool()                           # ← the governance line
async def web_search(ctx, query: str) -> list[dict]:
    return await fetch(query)

async def run_agent(question: str):
    # Constructing the plugin instruments Agent.run: this call opens the
    # governed run, and the model and every tool call run under it.
    result = await agent.run(question)
    return result.output
```

The `@guarded_tool()` decorator runs `authorize_action("execute", "web_search")` before every invocation of the tool, on the run that is driving the agent at that moment: the root run for a top-level `agent.run`, or the sub-agent's own run when the agent is called from inside another agent's tool. A sub-agent's tools are therefore always authorized on the sub-agent's own credential and scope, never on its parent's. On a policy denial the decorator raises `PermissionError`, which propagates up through Pydantic AI's normal tool-error path — the tool body never runs. `guarded_tool` fails closed: a denial, an unreachable backend, or a call with no live governed run (raised as `GovernanceUnavailable`) stops the action.

Only tools you decorate are authorized; an undecorated tool runs without a Watchlight decision.

> **Warning:** if you pass `guarded_tool(action=…)`, use a generic verb (`execute`, `read`, `search`, `write` and the others in wl-apdp's `entity_ref::GENERIC_ACTION_VERBS`) or the tool's own name. A sub-agent's grant and a run's tool grant name tools, not verbs, so wl-apdp reads a custom verb (`action="lookup"` on the tool `web_search`) as a second, different tool. Under a grant, that call is refused, and for a sub-agent the run handle is invalidated, so the child cannot make any further calls.

`RunHandle.guarded_tool()` (the decorator bound to a handle from `start_run`) is deprecated. It still authorizes each call on the run driving the agent at call time, and falls back to its own handle only when no instrumented run is active.

`functools.wraps` preserves the wrapped function's signature and docstring, so Pydantic AI's tool-schema introspection works unchanged and the decorator composes cleanly with `@agent.tool`.

### Runs that cannot be governed do not run

Governed entry points: `Agent.run`, `run_sync`, `run_stream`, `iter` and `run_stream_sync` are instrumented directly, and `run_stream_events` is governed through `run`, which pydantic-ai drives it with. Each call opens a governed run first: a root session for a top-level call, a sub-agent spawn for a call made inside another agent's tool. If that fails, the call raises before the model is called, and the agent's tools never run. A refusal from Watchlight (for example `ScopeAttenuationDenied` when the delegation depth is exceeded, or `AgentNotRegistered`) is raised as is. Any other failure, such as an unreachable backend, is raised as `GovernanceUnavailable`. A refused sub-agent never runs on its parent's run. A call made from a run that has ended (for example from a task a tool started that outlives the run) is refused with `GovernanceUnavailable`.

**A nested run that loses its run's context does not start as a root.** A tool body that calls another agent through `await`, `iter` or `asyncio.to_thread` keeps the run's context, and the agent is spawned as a governed sub-agent. A call through `loop.run_in_executor`, a `ThreadPoolExecutor`, a `threading.Thread` or a fresh `contextvars.Context` drops that context. Such a call is refused with `NestedRunEscapedError` (a `WatchlightError`) before its first model turn while any governed run is live in the process, including a deferred start that runs after the tool returned and a re-run of the same agent. It is never opened as an independent root. With no governed run live, a top-level call opens a root as before.

Runs that are meant to be independent roots at the same time, such as `asyncio.gather` of two agents or one agent per worker thread, are declared with `root_run()`, a context manager (sync or async) and a decorator:

```python
from watchlight_pydantic_ai import root_run

async def both():
    async def declared(agent, prompt):
        async with root_run():
            return await agent.run(prompt)

    return await asyncio.gather(declared(agent_a, "a"), declared(agent_b, "b"))

@root_run()
def worker(prompt):
    return agent.run_sync(prompt)
```

How a declared root is decided:
- It is decided by the server (`Action::"open_declared_root"`), which receives the root execution ids of the governed runs live in the process and records the declaration.
- A server refusal raises `DeclaredRootRefused` (`declared_root_forbidden`, `declared_root_invalid`), and the agent does not run.
- If the server does not confirm that it decided the declaration (an older server), the session is ended and the run is refused (`declared_root_unsupported`).
- The in-process Developer Edition engine refuses a declared root.
- `root_run()` entered inside a live governed run raises `NestedRunEscapedError`: an agent called there is a governed sub-agent.
- An agent whose sub-agent spawn was refused cannot start through `root_run()` while that run tree is live (`SpawnRefusedRootRunError`).
- There is no setting that turns this off.

A nested agent spawned this way names no time budget by default, so it inherits its parent's remaining time and never gets more. To give nested agents a tighter budget, pass `nested_agent_time_budget_seconds=<seconds>` to `WatchlightPydanticAIPlugin(...)`. The value is sent exactly as you set it and is never shortened. If the parent cannot give that much, because it is more than the parent was granted, more than the parent has left, or more than the tenant's `subagent_time_budget_threshold_seconds` (default 3600), the spawn is refused and the nested agent does not run. A parent's remaining time shrinks as it works, so a budget that fits at the first level may be refused one level down; leave the setting unset to have each nested agent inherit what its parent has left.

If the plugin is configured to route egress through wl-proxy (`connect_proxy_url=` or `WATCHLIGHT_PROXY_URL`), a run is refused with `GovernanceUnavailable` when Watchlight issues no proxy token for it or the local CONNECT sidecar cannot be installed; it never falls back to direct egress. A run whose setup fails after its session was opened has that session terminated. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its proxy answers every new CONNECT with 403, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.

When a run returns, its session is completed and `execution_completed` is emitted; a run that raises is terminated. For `run_stream_sync` the run closes with its result: it completes when the stream is fully consumed or `get_output()` returns, and it is terminated when consuming it raises, when the caller stops iterating before the run finished, or, as a last resort, when the result object is dropped unconsumed (reason `pydantic_ai_stream_abandoned`). Once the run is terminated, reading the result further (`get_output()`, the `stream_*` methods, `validate_response_output()`) raises `GovernanceUnavailable` instead of driving the run. The result is still a `StreamedRunResultSync`.

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightPydanticAIPlugin(...)`, or per run to `start_run(...)`, or set `WATCHLIGHT_APPLICATION_ID` in the environment — an explicit argument wins over the env var. The zero-touch instrumentation opens runs with the plugin-level value, so a deployment attributes an agent without a code change. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane — signed lineage, drift detection, fleet-wide governance |

Moving from local to production is a one-line change — swap the backend, keep your agent code:

```python
from watchlight_core import ApdpClient, Credential

plugin = WatchlightPydanticAIPlugin()
# The credential is loaded from the environment or your credential provider
# (for example WATCHLIGHT_CREDENTIAL_FILE); never put a key in source.
plugin.apdp = ApdpClient("https://apdp.your-company.example", credential=Credential.from_default())
```

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0.
