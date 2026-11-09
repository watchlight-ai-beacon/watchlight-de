# watchlight-claude-agent

Governed Claude Agent SDK agents with Watchlight: every tool call and every sub-agent launch is authorized before it runs, and refused on any doubt.

```bash
pip install watchlight-claude-agent
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** Anthropic. `Claude Agent SDK` and related names are trademarks of Anthropic, used here nominatively only to describe compatibility.

## What it enforces

The Python Claude Agent SDK has no plugin loader, so the plugin ships its enforcement as a hook map. `plugin.governed_options(handle, options)` (or `plugin.governance_hooks(handle)`) adds these hooks to your `ClaudeAgentOptions`:

- **Every tool call** goes through a `PreToolUse` gate. The call is authorized on the handle of the agent that made it: a sub-agent's own handle for a sub-agent's call, the root handle otherwise. A deny, a needs-approval decision, an unreachable backend or any other error returns a `deny` decision, so the tool does not run. Only argument names and value types are sent for authorization, never argument values.
- **Sub-agent launches** (the `Task` / `Agent` tool) perform the governed spawn in the same `PreToolUse` gate, before the tool runs. The child gets its own credential with a scope that the server narrows to a subset of the parent's. When the spawn is refused, the sub-agent type is not a registered agent, or anything else goes wrong, the tool call is denied: the sub-agent never starts and never gets a model turn.
- A sub-agent that starts without a governed spawn, or a tool call from an agent the plugin cannot identify while a sub-agent is running, is denied.
- **Tools that start work elsewhere, and unclassified tools**. Every Claude Code tool is classified against Claude Code 2.1.310 (the CLI the locked `claude-agent-sdk` bundles), from the same list the TypeScript plugin uses. `RemoteTrigger` creates, runs and schedules Claude Code sessions on Anthropic's cloud, whose tool calls never reach these hooks: it is never offered to the model (`disallowed_tools`), and a call that still reaches the gate is refused before any decision and recorded as a `Deny` (`remote_dispatch_refused`). A `Task` / `Agent` call with `isolation: "remote"` is refused the same way. A tool the plugin has not classified is refused (`unclassified_tool`), so a tool added by a later Claude Code release runs only once this plugin classifies it. Your own tools reach the agent through MCP servers (`mcp__<server>__<tool>`) and go to the policy decision.
- A starting sub-agent binds to its governed spawn by tool-use id when the SDK provides one, otherwise by sub-agent type. The SDK's `SubagentStart` input carries no tool-use id, so a second launch of a type that is still starting is denied (the two could not be told apart), including when both launches are gated at the same moment: the first one reserves its slot before the gate does any work. A launch that never starts (a later hook or a permission prompt refused it) is closed on `PostToolUse` / `PostToolUseFailure`, at `Stop`, or after 120 seconds.
- **The gate must be live in every session.** Claude Code has modes and settings that switch SDK hooks off or move the settings Watchlight checks, for example its minimal ("bare") mode. So `governed_options` refuses, with `UngovernableSession`, a session that carries any Claude Code environment variable (names starting `CLAUDE_`, `ANTHROPIC_`, `DISABLE_`, `ENABLE_`, `CCR_` or `SELF_HOSTED_RUNNER_`), or runtime variable (names starting `BUN_` or `NODE_`), that is not on Watchlight's allowlist, wherever it is set: `options.env`, this process's environment, or the `env` of any settings source. The allowlist (`watchlight_claude_agent.cli_surface`) holds only what a session needs: the API key or token, model endpoints, model and provider choice, the output-token limit, `CLAUDE_CONFIG_DIR`, the switches that turn background traffic off, `NODE_ENV`, and `NODE_EXTRA_CA_CERTS`. The runtime variables matter because the compiled CLI runs `BUN_OPTIONS="--preload <file>"` as code in its own process, and `NODE_OPTIONS`, `NODE_PATH` and `NODE_REPL_EXTERNAL_MODULE` load code in any Node process it starts. `extra_args` flags are allowlisted the same way; only `debug-to-stderr` passes. `cli_path` is refused: a program in place of the Claude Code the SDK bundles could drop Watchlight's hooks from what reaches the CLI. A session started from inside Claude Code inherits its variables and is refused; start it from a clean environment.
- **Every settings source is read.** Managed settings (the managed settings file and its `managed-settings.d` drop-ins, an MDM profile on macOS, the policy registry key on Windows or from WSL, and the cached server-managed settings), your user settings, the project and local settings of the working directory and its parents, and `options.settings`. Any of them setting `disableAllHooks`, `allowManagedHooksOnly` or `allowManagedPermissionRulesOnly`, or an environment variable not on the allowlist, is refused, and so is a source that exists but cannot be read. `permission_prompt_tool_name` is refused too: it replaces the permission callback.
- **Every tool call proves the gate ran.** The session's settings get a `permissions.ask` rule for every tool, and `governed_options` installs a `can_use_tool` callback. It allows a tool call only after Watchlight's `PreToolUse` gate allowed that same call: the same tool-use id, the same tool and the same input. If the hooks do not run, or a later hook changed the input, the call is refused and the session ends.
- **A Watchlight allow never widens your configuration.** The callback allows only what the session would have run without a prompt: everything in `bypassPermissions`; in-workspace file edits and reads in `acceptEdits`; in-workspace reads only in `plan`; and in `default`, a tool your `allowed_tools` or settings allow rules name as a whole, or an in-workspace read. Any other call goes to your own `can_use_tool` if you passed one, or is denied, as Claude Code denies a prompt in the SDK. Your callback cannot change permissions or the input: such an answer is refused. An unknown mode or a rule list that cannot be read counts as "would prompt". In `dontAsk` mode Claude Code denies the forced `ask` rule itself, so no tool runs.
- **The session is watched (detection).** `plugin.governed_query(handle, prompt=..., options=...)` runs the SDK's `query()` with these options and watches its messages; `plugin.watch_messages(handle, client.receive_response())` does the same for a `ClaudeSDKClient`. Watchlight's `UserPromptSubmit` hook must have run for a session before Claude Code reports that session started, and every tool result must belong to a call the gate decided. Otherwise the session is ended, the run is terminated, and `GovernanceBypassDetected` is raised. This catches managed settings Watchlight cannot read before the session, such as settings the server delivers at startup. It **detects, it does not prevent**: Claude Code runs the model turn and its tools whether or not your code has read the messages, so by the time the watcher sees the message, tools may already have run. The guarantee comes from the checks above; the watcher only limits how long a session that lost them goes on. It runs only through `governed_query` or `watch_messages`, not when you pass `governed_options` to `query()` yourself.
- **`PermissionRequest` hooks cannot answer for Watchlight.** Claude Code still asks the permission callback when a `PermissionRequest` hook answers allow, and it ignores the hook's rewritten input. Tests run this against the real CLI.
- **Only the SDK's own transport.** `governed_query` refuses a `transport` with `UngovernableSession` before anything starts. A custom transport receives the initialize request that carries Watchlight's hooks and answers the permission callback's messages, so it could drop either.
- Use `governed_query` (or `governed_options` with `watch_messages`); `governance_hooks` alone installs only the hooks.
- **What a session you start yourself does not get.** When you pass `governed_options` to `query()` or a `ClaudeSDKClient` yourself, your code chooses how Claude Code is reached, and Watchlight cannot check that choice. A custom transport there (`query(..., transport=...)`, `ClaudeSDKClient(options, transport=...)`) can drop the hooks and the permission rule, and then only the watcher (`watch_messages`) is left, which detects after tools may have run. Use `governed_query` when you can; if you start the session yourself, use the SDK's own transport and read its messages through `watch_messages`.
- Each `PreToolUse` decision has a 45-second deadline, inside the 60-second timeout the plugin sets on its hook matchers; a decision that is not made in time is a deny.
- **Run start fails closed.** `start_run` raises `AgentNotRegistered` for an unknown agent and `GovernanceUnavailable` when the backend does not open the session. It also refuses the run, and closes the session it opened, when the backend issues no constraint manifest, unless the operator explicitly set `WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`.
- **Egress.** When a wl-proxy URL is configured (`connect_proxy_url=` or `WATCHLIGHT_PROXY_URL`), `start_run` installs a local CONNECT proxy and sets `HTTPS_PROXY` / `HTTP_PROXY` for this process, so Python HTTP clients that honour those variables go through wl-proxy. If the backend issued no proxy token, or the proxy cannot be installed, `start_run` raises `GovernanceUnavailable` instead of running with direct egress. Clients that ignore `HTTPS_PROXY` are not covered. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its proxy answers every new CONNECT with 403, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.

What it does not do: model turns themselves are not authorized (only the tools they call), and plan validation (`handle.submit_plan`) runs only when you call it. Your own hooks are kept, but they run alongside Watchlight's: a deny from any hook stops the call, so they cannot turn a Watchlight deny into an allow.

**A query opened inside a tool is not governed.** The hooks govern only the `query()` or `ClaudeSDKClient` whose options you passed through `governed_options(...)`. If one of your tools opens another `query()` or builds another `ClaudeSDKClient` inside its body with plain options, that inner agent loop runs its tools with no authorization, and its activity is not recorded under your run. The plugin does not see it and does not refuse it. The SDK has no process-wide hook the plugin could use to reach it.

- To delegate work to another agent, use the SDK's own sub-agents (the `Task` / `Agent` tool). Those are governed: the spawn is authorized, the child gets a narrowed scope, and a refused spawn never starts.
- Do not open a nested `query()` or `ClaudeSDKClient` in a tool body. If you must, open it on its own governed run (`plugin.start_run(...)` and `plugin.governed_options(...)`). That run is a separate root run under its own agent identity, not a narrowed child of the outer run, so register and scope that agent explicitly.

The policy decisions run on Watchlight's compiled engine, either in-process for local development or against the governed control plane in production.

## Quickstart

For local development, the zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package):

```bash
pip install watchlight-claude-agent "watchlight-engine>=0.2.5,<0.3"
```

```python
from claude_agent_sdk import ClaudeAgentOptions
from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may execute tools. Anything not
# permitted is denied.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "tools",
     "code": 'permit(principal is Agent, action == Action::"execute", resource) when { principal.name == "research-agent" };'},
]

plugin = WatchlightClaudeAgentSDKPlugin(governance=InProcessClient(POLICIES))

async def run_agent(question: str):
    async with await plugin.start_run("research-agent") as handle:
        # Every tool call and sub-agent launch now goes through Watchlight.
        async for message in plugin.governed_query(
            handle, prompt=question, options=ClaudeAgentOptions()
        ):
            print(message)
```

Each tool call is authorized as action `execute` on a resource named after the tool (for example `Read`, `Bash`, `mcp__server__tool`).

Sub-agents must be registered Watchlight agents (the `subagent_type` of the `Task` call is resolved to a registered agent). Their requested scope comes from `default_subagent_scope=` (or `WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE`); when that is empty the sub-agent starts with no tools and its first tool call is denied.

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightClaudeAgentSDKPlugin(...)`, or per run to `start_run(...)`, or set `WATCHLIGHT_APPLICATION_ID` in the environment — an explicit argument wins over the env var. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane — signed lineage, drift detection, fleet-wide governance |

Moving from local to production means dropping `governance=` and pointing the plugin at the control plane:

```python
plugin = WatchlightClaudeAgentSDKPlugin("https://apdp.your-company.example")
# The credential is loaded from the environment or your credential provider
# (for example WATCHLIGHT_CREDENTIAL_FILE); never put a key in source.
```

With no `apdp_api_key=` and no `governance=` backend, the plugin loads the default Watchlight credential (`Credential.from_default()`): AWS Secrets Manager when `WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID` is set, then `WATCHLIGHT_PLUGIN_TOKEN` with `WATCHLIGHT_TENANT_ID`, then the credential file (`WATCHLIGHT_CREDENTIAL_FILE`, else `/etc/watchlight/plugin.cred`). A credential that is present but cannot be loaded (a malformed token, or a corrupt or unreadable credential file, including one at the default path) raises `CredentialNotFound` when the plugin is built, before any request; it never falls back to no credential. Only when no credential source exists at all does the plugin send no credential, and the server refuses the run. Never put a key in source.

A run is refused with `AgentNotRegistered` only when the agent is not registered. When wl-apdp refuses the credential, refuses the request for its licence, or cannot be reached, `start_run` raises `GovernanceUnavailable` instead, so the reason is not mistaken for a missing agent.

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0
