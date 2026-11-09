# watchlight-bedrock

Watchlight authorization for AWS Bedrock, fail-closed: action-group Lambdas of Bedrock Agents, the hosted capabilities a Bedrock agent runs inside AWS (code interpreter, knowledge bases and others), and the tool loop of workloads that call the Bedrock runtime directly (Converse, ConverseStream, InvokeModel).

```bash
pip install watchlight-bedrock
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** Amazon Web Services (AWS). `Amazon Bedrock` and related names are trademarks of Amazon Web Services (AWS), used here nominatively only to describe compatibility.

## What it does

`watchlight-bedrock` puts a Watchlight authorization decision in front of the action-group tool calls an AWS Bedrock agent makes through your Lambdas. Each call is allowed or denied by Watchlight *before* your Lambda body runs. It is a thin layer over Watchlight's governance primitives; the policy decisions run on Watchlight's engine, in-process for local development or on the governed control plane in production.

## What it enforces today

Read this section before you deploy. It says exactly what the plugin does and does not enforce.

- **Action-group Lambdas (`@watchlight_bedrock_action`).** Every invocation is either authorized by Watchlight or refused. The decorator fails closed: a denial, an unreachable backend, or any error in the enforcement path returns a Bedrock-shaped refusal, and your Lambda body never runs.
- **Standalone root per invocation.** The decorator authorizes a call only under a root run it opens itself for that invocation (`fallback_agent_slug`). This root needs an explicit scope, `fallback_allowed_actions`: the list of `"{actionGroup}/{apiPath}"` names this Lambda may serve (the `apiPath` without its leading slash). A call outside that list is refused before any session opens. A call inside it is still decided by Watchlight policy. The run is closed when the invocation ends. `fallback_allowed_actions` is checked locally only. A grant that wl-apdp checks (the agent's registered `allowed_tools`, an application's tools, or a sub-agent's `allowed_tools`) names a Bedrock action by its full URI, `bedrock://agent/<agentId>/action/<actionGroup><apiPath>`, never by the `"{actionGroup}/{apiPath}"` name.
- **Hosted capabilities of Bedrock Agents.** Calls through `RunHandle.bedrock_agent_runtime()` read the agent's definition and authorize every hosted capability it enables before `invoke_agent` is called. See [Bedrock Agents: hosted capabilities](#bedrock-agents-hosted-capabilities).
- **Orchestrator hand-off is refused today.** `bedrock_agent_runtime()` passes the Watchlight session and agent ids to the Lambda, but no run credential crosses the AWS boundary, by design. Without that credential the Lambda cannot act under the orchestrator's run, so the decorator refuses any invocation that carries Watchlight session attributes. A scoped hand-off token is planned; until it ships, use the standalone root above for Lambdas.
- **Multi-agent collaborators are refused, not run as roots.** A collaborator invoked with a Watchlight parent reference is refused, because a governed cross-process spawn (with an attenuated child scope) is not available yet. A partial parent reference is refused as well. Neither ever falls back to a fresh root.
- **Bedrock Agents' own planning and model turns are not gated.** Bedrock plans server-side. For Bedrock Agents, the plugin governs the hosted capabilities the agent may use and the tool calls that reach your Lambdas, not the model's reasoning. Workloads that call the Bedrock runtime themselves are covered in the next section.
- **Arguments.** The authorization request carries argument names, count and declared types only, never argument values.
- **Egress.** When a wl-proxy URL is configured (`connect_proxy_url` or `WATCHLIGHT_PROXY_URL`), `start_run` refuses the run with `GovernanceUnavailable` if Watchlight issued no proxy token or the local CONNECT sidecar fails to start. It never falls back to direct egress. **One governed run per process.** While a run owns the egress proxy, starting another run in the same process raises `SidecarRunActive` (a `GovernanceUnavailable`) and leaves the running one as it is. The owning run releases it when it ends, or when its session expires (`ttl_seconds`, 3600 by default) if it is never completed. Once the owner has ended, its proxy answers every new CONNECT with 403, so traffic fails rather than going direct. Run concurrent governed runs in separate processes.

## Bedrock Agents: hosted capabilities

A Bedrock agent can run some capabilities inside AWS, where no Lambda of yours is called: the code interpreter, user input, the Anthropic computer, bash and text-editor tools, and knowledge-base retrieval. `@watchlight_bedrock_action` never sees these, so the plugin decides them before the agent is invoked. Invoke the agent through `RunHandle.bedrock_agent_runtime()`:

```python
import boto3

async with await plugin.start_run("research-agent") as run:
    agents = run.bedrock_agent_runtime(
        boto3.client("bedrock-agent-runtime"),
        agent_client=boto3.client("bedrock-agent"),
    )
    response = await agents.invoke_agent(
        agentId=AGENT_ID,
        agentAliasId=ALIAS_ID,
        sessionId=run.session_id,
        inputText=question,
    )
```

On every `invoke_agent` call, the plugin does four things:

1. It resolves the alias to the agent version it points at. It does this on every call, because an alias can be pointed at a new version at any time.
2. It reads that version's action groups and knowledge bases. A numbered version is read once and cached, because a version never changes. The `DRAFT` version is read on every call, because it can change at any time.
3. It asks Watchlight for a decision on every hosted capability the version enables, and on every knowledge base the call names in `sessionState.knowledgeBaseConfigurations`. Each one is authorized as `Tool::"<kind>"` with `builtin_tool: true`. The kinds are `code_interpreter`, `user_input`, `computer_use`, `bash`, `text_editor` and `knowledge_base_retrieval`. Disabled action groups and knowledge bases are skipped. Action groups that call your Lambda or return control are governed by `@watchlight_bedrock_action`, not here.
4. For a numbered version, it asks Watchlight for a decision on action `invoke_agent_version` with resource `bedrock://agent/<agent id>/version/<n>`, on every call. Nothing grants a version by default (see "Granting an agent version" below). `DRAFT` needs no grant; it is checked from its definition, as in step 2.
5. Only when the version and every capability are allowed does it call `invoke_agent`, with the trace on and the Watchlight session attributes your action-group Lambdas read.
6. While you read the response stream, a trace part that shows custom orchestration (`customOrchestrationTrace`) ends the run. See "Custom orchestration seen in the trace" below.

The call is refused, and `invoke_agent` is never made, in these cases:

- policy does not grant the numbered agent version (`reason="agent_version_not_permitted"`), or the decision fails or times out;
- a capability is denied, needs approval, or gets no decision in time;
- the agent's definition can't be read, for example because a permission is missing or a read fails;
- an action group has a signature the plugin does not know;
- a knowledge base on the call has no valid id;
- the agent is a supervisor (multi-agent collaboration is not governed yet);
- the agent runs a custom orchestration Lambda or a prompt override Lambda, which Bedrock calls on every step outside `@watchlight_bedrock_action`;
- the call sets session attributes that start with `watchlight_`.

A refusal raises `HostedToolRefused`, or `BedrockRequestRefused` with a short `reason`. `invoke_inline_agent` is gated the same way, from the action groups and knowledge bases in the request. An inline agent with collaborators is refused.

Only calls made through `bedrock_agent_runtime()` go through. Constructing `WatchlightBedrockPlugin` installs a check on every `bedrock-agent-runtime` client in the process, wrapped or not, including clients created before the plugin (a module-level `boto3.client(...)`, or a client from an earlier `boto3.Session`). On any such client, `invoke_agent`, `invoke_inline_agent`, and every other operation that runs an agent, a flow, a model or a retrieval is refused with `BedrockRequestRefused` (`reason="ungoverned_call"`). So are operations that return stored content (`get_agent_memory`, `get_invocation_step`, `list_invocation_steps`, flow snapshot and event reads), every delete, and flow control (`stop_flow_execution`). The refusal happens before anything is sent. An operation goes through only when `bedrock_agent_runtime()` makes it on that same client. A call to another client made from inside a wrapped call is refused.

Only the lifecycle of a session and of an invocation (`create_session`, `get_session`, `list_sessions`, `update_session`, `end_session`, `create_invocation`, `list_invocations`) and tags are not refused.

The check applies to the whole process: an unrelated `bedrock-agent-runtime` client in the same process is refused too, so run code that must call Bedrock Agents ungoverned in a separate process. A client class that does not go through botocore's `BaseClient._make_api_call` (aiobotocore's, for example) is checked only if it is created after the plugin is constructed.

Two limits come from the Bedrock API itself:

- **Alias repointing.** `invoke_agent` takes an alias, not a version. The plugin resolves the alias and gates that version just before the call, but if someone points the alias at another version in the moment between the two, Bedrock runs a version that was not gated. To close this, give the alias a fixed version and allow `bedrock:UpdateAgentAlias` only to the people who release agents.
- **Custom orchestration on a numbered version.** Bedrock reports the orchestration type only for the working draft, not for a numbered version. So the plugin cannot tell whether a version was created while the draft used a custom orchestration Lambda. That is why a numbered version runs only when your policy grants it: whoever writes the grant attests how that version was built. The plugin also still refuses a numbered version when the current draft uses custom orchestration. Allow `bedrock:UpdateAgent`, `bedrock:CreateAgentVersion` and `bedrock:UpdateAgentAlias` only to the people who also write Watchlight policy, or require a review for them.

### Granting an agent version

A grant attests that the version has **no custom orchestration**. No Bedrock API shows a numbered version's orchestration type, so the grant is the control that comes before the call: grant a version only once you know it uses Bedrock's standard orchestration. Creating a new version grants nothing, and an alias moved to a version without a grant is refused on its next call.

Name the full resource: one agent and one version per grant. Never grant versions with a wildcard or a pattern (`like "bedrock://agent/*"`, or a condition that matches any version), and never use `resource` unconstrained with this action. A wildcard grant would also cover versions created later, which nobody has checked.

Keep the AWS side in step with the grant. Allow `bedrock:UpdateAgent`, `bedrock:CreateAgentVersion` and `bedrock:UpdateAgentAlias` only to the people who also write Watchlight policy, or require a review for them. Do the same for `lambda:UpdateFunctionCode` and `lambda:UpdateFunctionConfiguration` on the Lambdas the agent's action groups call: a grant attests to the version's definition, not to code that changes later.

```cedar
permit(
    principal is Agent,
    action == Action::"invoke_agent_version",
    resource == Resource::"bedrock://agent/AGENT12345/version/3"
) when { principal.name == "research-agent" };
```

The decision is opaque to the caller (`agent_version_not_permitted`) and is recorded in lineage like any other decision.

**One-call window when an alias moves.** The plugin resolves the alias and decides its version just before `invoke_agent`. If someone points the alias at another version in between, that one call runs a version that was not decided. The trace check below covers custom orchestration in that window, and the next call decides the new version. To close the window, invoke a fixed version through an alias only you release (see "Alias repointing" above).

### Custom orchestration seen in the trace

The plugin always calls `invoke_agent` with `enableTrace=True`, whatever the call passes. If a `customOrchestrationTrace` part arrives while you read `response["completion"]`, the plugin stops reading the stream and raises `CustomOrchestrationObserved` (a `BedrockRequestRefused`, `reason="custom_orchestration_observed"`). It ends the run, with that reason, the agent, alias and version on the `execution_failed` event, and refuses every later call through the same `bedrock_agent_runtime()`. This does not stop the Lambda, which runs in AWS, and it only applies to a stream you read. It shows that the case happened and halts the run; it is not prevention. The version grant is the control.

### Permissions for the agent definition read

The `bedrock-agent` client needs these read-only IAM actions on the agents you invoke. If one is missing, the call is refused.

```json
{
  "Effect": "Allow",
  "Action": [
    "bedrock:GetAgent",
    "bedrock:GetAgentVersion",
    "bedrock:GetAgentAlias",
    "bedrock:ListAgentActionGroups",
    "bedrock:GetAgentActionGroup",
    "bedrock:ListAgentKnowledgeBases"
  ],
  "Resource": [
    "arn:aws:bedrock:<region>:<account>:agent/<agent id>",
    "arn:aws:bedrock:<region>:<account>:agent-alias/<agent id>/*"
  ]
}
```

## Bedrock runtime tool use (outside Bedrock Agents)

Many workloads do not use Bedrock Agents. They call `bedrock-runtime` directly with `converse`, `converse_stream` or `invoke_model`, and their own code runs each tool the model asks for. `GovernedBedrockRuntime` governs that loop on a Watchlight run:

```python
import boto3
from watchlight_bedrock import BedrockToolUseRefused, WatchlightBedrockPlugin

plugin = WatchlightBedrockPlugin()          # set plugin.apdp to your backend

async def ask(messages, tool_config):
    async with await plugin.start_run("payments-agent") as run:
        runtime = run.bedrock_runtime(boto3.client("bedrock-runtime"))
        try:
            response = await runtime.converse(
                modelId=MODEL_ID, messages=messages, toolConfig=tool_config
            )
        except BedrockToolUseRefused as refused:
            # None of this turn's tool calls may run. Tell the model so.
            messages.append(refused.assistant_message)
            messages.append({"role": "user", "content": refused.tool_results()})
            ...
        # Every toolUse in `response` was allowed: run them.
```

On every model call, `GovernedBedrockRuntime`:

1. **Gates the request before it is sent.** It checks the final request, `toolConfig` and `additionalModelRequestFields` included, for provider-hosted tools (a Bedrock `systemTool`, an Anthropic server tool). Each is authorized through the same shared gate every Watchlight plugin uses. Anything but an Allow raises `HostedToolRefused`, and the model is never called.
2. **Authorizes every tool use before your code sees it.** Each `toolUse` the model asks for gets one Watchlight decision (`action="execute"`, the tool name as the resource), with argument names and types only, never values. Argument names come from the model, so they are checked first: every name must be declared in the tool's `inputSchema` `properties` and be a short plain name (at most 64 letters, digits, `_`, `-` or `.`; at most 32 of them). A tool whose schema declares no properties accepts only an empty input, so declare the properties of every tool that takes arguments. A denial, an approval requirement, an unreachable or silent policy service, a tool the request never declared, an undeclared argument, or a tool call that cannot be read raises `BedrockToolUseRefused`. The response is withheld, so none of the turn's tool calls run. A run-ending decision (quarantine, termination) raises its own error.
3. **Holds a streamed turn back until every tool use in it is decided.** With `converse_stream`, the turn's events are held until `messageStop`, the same guarantee as `converse`: nothing from the turn reaches your code before every tool use in it is allowed. Each block is tracked by its `contentBlockIndex`. A stream whose blocks cannot be read is refused: a block or delta that is not an object, a tool delta for a block that is not a started tool use, a block started twice, a tool use that never stops, or content after the turn. A refusal raises from the stream and closes it.
4. **Records each decision.** Watchlight's decision log has every allow and deny, with the agent, the tool and the result. The plugin also publishes a value-free `tool_call_observed` event on the run for each decision.

Wrapping a client also locks it. Any model call made on that client directly, outside the wrapper, is refused (`BedrockRequestRefused`, reason `ungoverned_call`). Only operations that invoke no model (`ApplyGuardrail`, `CountTokens`, `GetAsyncInvoke`, `ListAsyncInvokes`) still work directly.

The lock stops mistakes, not deliberate bypass. Code in the same process that creates a second client, unregisters the hook (`client.meta.events.unregister`), or calls botocore's internals (`client._endpoint.make_request`) is using the provider directly, outside this plugin's reach. To make that impossible rather than merely detectable, route the workload's egress through wl-proxy, which governs every outbound request whatever the client code does.

A runnable example, which needs no AWS account in its default self-check mode, is in [`examples/bedrock-authorized-agents/runtime_tool_loop.py`](../../examples/bedrock-authorized-agents/runtime_tool_loop.py).

### Which Bedrock workloads are covered

| Workload | Covered |
|---|---|
| Bedrock Agents action-group Lambdas | Yes, with `@watchlight_bedrock_action` |
| Bedrock Agents hosted capabilities (`invoke_agent`, `invoke_inline_agent`) | Yes, through `bedrock_agent_runtime()` |
| Supervisor agents and inline collaborators | **Refused** |
| `converse` with tools | Yes |
| `converse_stream` with tools | Yes |
| `invoke_model`, Anthropic Claude (Messages API) with tools | Yes |
| `invoke_model` without tools, any model | Passed through (there is no tool use to govern) |
| `invoke_model` with tools, any other model family | **Refused** (use `converse`) |
| `invoke_model_with_response_stream` with tools | **Refused** (use `converse_stream`); without tools it is passed through |
| A Prompt Management ARN as `modelId` | **Refused**: a stored prompt can carry its own tools |
| `invoke_model_with_bidirectional_stream`, `start_async_invoke` | **Refused** on a governed client |
| Frameworks that call Bedrock for you (Strands, LangGraph and others) | Use that framework's Watchlight plugin |
| Tool calls your code parses out of free text | Not visible at this layer; not governed |
| A boto3 client you never wrapped | Not governed: wrap every `bedrock-runtime` client your agent uses |

Refused means the request is never sent: the plugin fails closed on anything it cannot read.

## Quickstart

Wrap your action-group Lambda. The decorator talks to the Watchlight control plane at `apdp_url`:

```python
import os
from watchlight_bedrock import watchlight_bedrock_action

@watchlight_bedrock_action(
    apdp_url=os.environ["APDP_URL"],
    # The registered Watchlight agent this Lambda acts as.
    fallback_agent_slug="research-agent",
    # The only actions this Lambda may serve under that agent.
    fallback_allowed_actions=["research_tools/search"],
)
def lambda_handler(event, context):
    # Runs only if the tool call was allowed. On a refusal the decorator
    # returns a Bedrock-shaped refusal and this body never executes.
    return _do_real_work(event)
```

With no `apdp_api_key=` and no `governance=` backend, the plugin loads the default Watchlight credential (`Credential.from_default()`): AWS Secrets Manager when `WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID` is set, then `WATCHLIGHT_PLUGIN_TOKEN` with `WATCHLIGHT_TENANT_ID`, then the credential file (`WATCHLIGHT_CREDENTIAL_FILE`, else `/etc/watchlight/plugin.cred`). A credential that is present but cannot be loaded (a malformed token, or a corrupt or unreadable credential file, including one at the default path) raises `CredentialNotFound` when the plugin is built, before any request; it never falls back to no credential. Only when no credential source exists at all does the plugin send no credential, and the server refuses the run. Never put a key in source.

Orchestrator side (governs the run that calls `invoke_agent`, and lets you publish the agent trace as Watchlight lineage). For local development, the zero-infrastructure **Developer Edition** runs the compiled engine in-process (requires the `watchlight-engine` package, `pip install watchlight-bedrock "watchlight-engine>=0.2.5,<0.3"`):

```python
import boto3
from watchlight_bedrock import WatchlightBedrockPlugin
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may read, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "research-agent" };'},
]

plugin = WatchlightBedrockPlugin()
plugin.apdp = InProcessClient(POLICIES)   # decisions run in-process, no server, no network

async def run_agent(question: str) -> str:
    async with await plugin.start_run("research-agent") as handle:
        agents = handle.bedrock_agent_runtime(
            boto3.client("bedrock-agent-runtime"),
            agent_client=boto3.client("bedrock-agent"),
        )
        response = await agents.invoke_agent(
            agentId=AGENT_ID,
            agentAliasId=ALIAS_ID,
            sessionId=handle.session_id,
            inputText=question,
        )
        return _consume_event_stream(response)
```

### Attributing runs to an AI application

Every governed run can be attributed to the AI application the agent belongs to. Pass `application_id="<application UUID>"` to `WatchlightBedrockPlugin(...)`, or per run to `start_run(...)`, or set `WATCHLIGHT_APPLICATION_ID` in the environment — an explicit argument wins over the env var. The id is sent on session create and bound to the run credential and to every sub-agent the run spawns; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. The id is explicit configuration, never inferred from prompts or names, and it is an Enterprise feature: the in-process Developer Edition engine refuses it.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane — signed lineage, drift detection, fleet-wide governance |

Moving from local to production means pointing the plugin at the control plane:

```python
plugin = WatchlightBedrockPlugin("https://apdp.your-company.example")
# The credential is loaded from the environment or your credential provider
# (for example WATCHLIGHT_CREDENTIAL_FILE); never put a key in source.
```

A run is refused with `AgentNotRegistered` only when the agent is not registered. When wl-apdp refuses the credential, refuses the request for its licence, or cannot be reached, `start_run` raises `GovernanceUnavailable` instead, so the reason is not mistaken for a missing agent.

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0
