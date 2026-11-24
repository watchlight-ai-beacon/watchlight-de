# watchlight-msaf

Translate Microsoft Agent Framework lifecycle events into canonical Watchlight lineage events.

```bash
pip install watchlight-msaf
```

> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** Microsoft. `Microsoft Agent Framework` and related names are trademarks of Microsoft, used here nominatively only to describe compatibility.

## What it does

`watchlight-msaf` is an event translator. It maps Microsoft Agent Framework lifecycle captures into canonical Watchlight events for lineage, drift detection and SIEM export.

**It does not enforce anything.** The package does not hook into the framework, does not call an authorization backend, and never blocks, modifies or denies a tool call, plan step or sub-agent run. Installing it adds no authorization to your agent. If you want actions authorized, your own code must call a governance backend from [`watchlight-agent-sdk`](https://pypi.org/project/watchlight-agent-sdk/) before each action and refuse the action unless the answer is Allow (see "Wiring in authorization" below).

## Quickstart

The plugin ships two pure functions, `translate_msaf_event` and `translate_msaf_events`, that turn a Microsoft Agent Framework lifecycle "capture" dict into one canonical Watchlight event (or `None` when the event isn't governed). These events feed drift detection, the lineage view, and SIEM export:

```python
from watchlight_msaf import translate_msaf_event

capture = {
    "hook": "tool_invocation_start",
    "tool_name": "fetch_news",
    "tool_args": {"q": "Q3 revenue"},
}

event = translate_msaf_event(
    capture=capture,
    execution_id="exec_root",
    agent_id="agent-1",
    session_id="sess_42",
    tenant_id="acme",
)

# event["event_type"]                → "plan_observed"
# event["payload"]["intended_tools"] → ["fetch_news"]
# event["metadata"]["source"]        → "msaf.callback"
```

For a batch of captures, use `translate_msaf_events(captures=[...])` — order is preserved and ungoverned or malformed captures are dropped.

### Wiring in authorization

The translator only records what happened. Authorization is something your code does: you point `watchlight-agent-sdk` at a backend, open a session, and check each action yourself before it runs. Nothing in this package performs that check for you:

```python
from watchlight_core import InProcessClient
from watchlight_msaf import translate_msaf_events

# A Cedar policy: the research agent may read, nothing else.
# The principal is the agent's id, Agent::"<agent uuid>"; `principal.name` is
# its registered name (under InProcessClient, the slug it was started with).
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "research-agent" };'},
]

# Developer Edition: decisions run in-process — no server, no network.
apdp = InProcessClient(POLICIES)

agent = await apdp.resolve_agent("research-agent")
session = await apdp.create_session(agent_id=agent["id"])

# Gate each action against your Cedar policies before it runs.
decision = await apdp.authorize(
    principal=f'Agent::"{agent["id"]}"',
    action="read",
    resource="dataset",
    session_id=session.session_id,
    run=session.run,
)
if decision["decision"] != "Allow":
    raise PermissionError("Denied by policy")

# ... your Microsoft Agent Framework agent runs; translate its lifecycle
# captures into canonical events and ship them as governed lineage ...
events = translate_msaf_events(
    captures=[...],
    execution_id=session.execution_id,
    agent_id=agent["id"],
)
await apdp.publish_events(session.run, events)
```

In this sample, a denial raises `PermissionError`, and an unreachable backend makes `authorize` raise, so the action does not run. That guarantee comes from your code calling `authorize` and not swallowing the exception; an action your code does not check is not authorized. For an ergonomic run handle (`submit_plan`, `preflight_step`, `authorize_action`, `complete` / `terminate`) over the same backend, see the [`watchlight-agent-sdk`](https://pypi.org/project/watchlight-agent-sdk/) docs.

### Attributing runs to an AI application

With the Enterprise `ApdpClient`, attribute the run to the AI application the agent belongs to by passing `application_id="<application UUID>"` to `apdp.create_session(...)`. The id is sent on session create and bound to the run credential; wl-apdp refuses the session if the agent is not a member of that application. An agent in exactly one application needs nothing here. This package has no run-start of its own, so it does not read `WATCHLIGHT_APPLICATION_ID` for you — read it in your code (`os.environ.get("WATCHLIGHT_APPLICATION_ID")`) and pass it explicitly; never infer it from prompts or names. It is an Enterprise feature: the in-process `InProcessClient` refuses the field.

## Two backends, same code

|  | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network. Requires the `watchlight-engine` package. |
| **Enterprise** | `ApdpClient` | The governed control plane: signed lineage, drift detection, fleet-wide governance |

Moving from local development to production is a one-line change:

```python
from watchlight_core import ApdpClient, Credential

# The plugin credential comes from your secret store or the environment
# (WATCHLIGHT_PLUGIN_TOKEN), never from source code.
apdp = ApdpClient(
    "https://apdp.your-company.example",
    credential=Credential.from_default(),
)
```

## Links

- Documentation: https://docs.watchlight.ai/de
- Website: https://watchlight.ai

## License

Apache-2.0
