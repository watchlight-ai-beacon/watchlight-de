# Examples

Every example is **self-contained and runnable**. You do not need a server, a
database or an account. Each one authorizes its calls with the *real* Watchlight
engine running in-process, and for every call that is denied, it proves that the
tool never executed.

```bash
pip install watchlight          # core: the govern decorator + engine
```

While any example runs, open a second terminal and watch every decision live:

```bash
watchlight dev                  # → http://127.0.0.1:7000
```

Unsure what a word means? → **[Glossary](../docs/glossary.md)**.

## Start here

These four examples cover the basics. Read them in order if you are new.

| Example | What it shows | Install |
|---|---|---|
| [`agent.py`](agent.py) | **The DENY line.** The smallest governed agent, with one allowed tool and one denied tool. | `watchlight` |
| [`governed_research_agent.py`](governed_research_agent.py) | **Realistic multi-tool agent.** The agent has 5 tools, and only `research` and `read` are permitted. The email, transfer and delete tools are **blocked before they run**. | `watchlight` |
| [`context_governance.py`](context_governance.py) | **Fine-grained context gating.** The *same* tool call is allowed or denied depending on the runtime `context` passed with it. If the context is missing, the call fails closed (it is denied). | `watchlight[langgraph]` |
| [`governed_subagents.py`](governed_subagents.py) | **Sub-agent scope attenuation.** Every child agent gets a *strict subset* of its parent's authority, and the real engine refuses any attempt to widen it. A delegation hop past `max_delegation_depth` (a governance control, default 8) is denied. | `watchlight` |

## Showcase — end-to-end setups, proven

Each showcase runs in **both lanes**, with the Python and TypeScript versions side
by side. A showcase exits with a non-zero status if what actually happened
contradicts the verdict the engine gave. The governed-agent showcases ship their
policy and its golden tests (expected verdicts) together in one
`policy.suite.json`.

| Example | What it shows | Run |
|---|---|---|
| [`showcase/denied-before-execute/`](showcase/denied-before-execute/README.md) | **Denied before it executed.** A governed transfer runs against a stub bank that counts its calls. A `forbid` policy refuses any transfer above a threshold, and the showcase asserts the counter is still `0`. A small transfer runs exactly once. It prints the verdict, the decision id and the audit line. | `python examples/showcase/denied-before-execute/agent.py` |
| [`showcase/identity/`](showcase/identity/README.md) | **The identity model, running.** One engine and one policy set serve three cases, printed side by side in one audit stream: the same agent acting alone, acting for a person, and a sub-agent under it through `delegate()`. It also makes the same call four ways to show where the actor comes from. The policies are keyed on the subject, on `context.actor` and on `context.actor_chain`. It asserts four cases where the caller is refused, and shows a token claim and a local session lookup producing the identical call. **This is also the example for naming several agents from one governor** with `as_()` / `as()`. It prints the policy count before and after, to show that adding a name does not load the policies a second time. | `python examples/showcase/identity/identity.py` |
| [`showcase/human-in-the-loop/`](showcase/human-in-the-loop/README.md) | **Human in the loop.** A `NeedsApproval` verdict holds the call and writes a pending request. A separate `approve.py` signs a grant. Then `resume` runs the action once, and writes an `approved: true` record joined to the pending one. Replaying the grant or the token is refused. | `python agent.py request` → `python approve.py` → `python agent.py resume` |
| [`showcase/policy-tests-ci/`](showcase/policy-tests-ci/README.md) | **Policy tests as a CI gate.** It contains a policy set and a suite of 11 test fixtures covering Allow, Deny, NeedsApproval and approved. A GitHub Actions workflow template runs `watchlight policy test` with both the TypeScript and Python CLIs, and a deliberately widened policy shows the run turning red. | `watchlight` or `@watchlight/sdk` |
| [`showcase/audit-forensics/`](showcase/audit-forensics/README.md) | **Audit forensics.** It generates a trail containing every record kind: decisions (including an approved one), sanitizations, egress, attenuations and screenings. Then it uses `forensics.py` or `jq` to join records on `decision_id`, roll them up per principal, and list attenuation chains. It also documents the exact field names of every record kind. | `watchlight` (+ `jq` for the recipes) |

Verify a showcase policy on its own:
`watchlight policy test examples/showcase/<name>/policy.suite.json`.

Every showcase declares how it is checked in an executable `check.sh` of its
own. That script says which programs run, in which order, from what starting
state, and in both lanes. [`showcase/check.sh`](showcase/check.sh) runs all of
them, and it fails if any showcase does not declare a check, so no showcase can
quietly stop working. If a lane needs an optional extra that is not installed,
it is counted and printed as a SKIP, never reported as a pass.
`scripts/preflight.sh` runs this together with the rest of the suites.

Where a governor belongs in an application is covered in
[Using the governor](../docs/using-the-governor.md). In short, construct it once
at start-up, with one governor per policy set; that page also shows the shapes
for a request handler, a worker and a test.

## Governance patterns — high-stakes recipes

These are copy-paste recipes for the decisions people most often want the
Developer Edition to make: spending money, deleting things, messaging the outside
world, moving data and spawning sub-agents. Each recipe describes a *problem
shape* and gives you a policy, the code that governs the tool, and tests. The
policy-driven recipes ship as runnable suites, and
[`patterns/check.sh`](patterns/check.sh) runs them through `watchlight policy
test`, so the recipes cannot drift away from what the engine actually does.

→ **[`patterns/`](patterns/README.md)** has 14 patterns: money-bounded agent,
destructive actions, external messaging, data egress, egress after read,
allow but redact, kill-switch / quarantine, per-user attribution, context
through an adapter, PII before read, screen before model, sub-agent confinement,
audit sink and quotas.

## Showcase — end-to-end pipelines

These are complete, self-checking pipelines that combine several primitives.
Each runs in both lanes and exits non-zero if any assertion fails.

| Example | What it shows |
|---|---|
| [`showcase/poisoned-rag/`](showcase/poisoned-rag/README.md) | **Poisoned-document RAG.** A retrieved document hides a prompt injection and personal data. `screen()` withholds the injected content, the permit's `@obligate_redact` obligation strips personal data from whatever passes, and every step joins the decision on one `decision_id`. |
| [`showcase/web-backend/`](showcase/web-backend/README.md) | **Governed web backend.** A FastAPI app and an Express app each expose one governed endpoint. The request's authenticated user becomes the acting principal, and the policy is scoped to that user and her account. `check.py` / `check.mjs` start the server on an ephemeral loopback port, send allowed, denied and unauthenticated requests, and assert that every decision in the trail carries the acting user. The web frameworks are optional extras. |
| [`showcase/red-team/`](showcase/red-team/README.md) | **Red-team corpus.** 34 synthetic adversarial prompts in 12 families are driven through a governed agent that has a screening `on_result` hook and a deny-by-default policy. It prints, per family, how many prompts were withheld, reached the model, were denied and were executed. It exits non-zero if a prompt gets further than its family allows, or if a family is one that neither layer handles. |

## Govern an existing framework agent

Each of these examples uses the *same* plugin you ship to production, wired to
the in-process engine. Moving to production means setting one environment
variable (`WATCHLIGHT_APDP_URL`), never a rewrite.

| Example | Framework | Install |
|---|---|---|
| [`governed_langgraph_agent.py`](governed_langgraph_agent.py) | LangGraph | `watchlight[langgraph]` |
| [`governed_pydantic_ai_agent.py`](governed_pydantic_ai_agent.py) | Pydantic AI | `watchlight[pydantic-ai]` |
| [`governed_claude_agent.py`](governed_claude_agent.py) | Claude Agent SDK | `watchlight[claude-agent]` |
| [`governed_deepagents.py`](governed_deepagents.py) | deepagents, showing **sub-agent scope attenuation**: each sub-agent gets a strict subset of the parent's tools, bounded by `max_delegation_depth`. It runs without an API key. | `watchlight[deepagents]` |

## Govern an MCP server

| Example | What it shows | Install |
|---|---|---|
| [`governed_mcp_server.py`](governed_mcp_server.py) | **MCP Runtime PEP.** A policy enforcement point (PEP) sits in front of any MCP server that speaks spec version 2026-07-28. A denied `tools/call` never reaches the server. The example is self-contained: it starts a small stand-in MCP server, puts the PEP in front of it, and shows one allowed and one denied call. | `watchlight-mcp` |

## Policies

The `*.policy.json` files are plain [Cedar](https://docs.watchlight.ai/de/policies)
policies. `govern.load()`, `govern.reload()` and `watchlight policy test` read
three shapes:

| Shape | Example |
|---|---|
| a list of policy objects | [`watchlight.policy.json`](watchlight.policy.json), [`research.policy.json`](research.policy.json) |
| `{"policies": [...]}` | every showcase's `policy.suite.json` |
| one policy object | [`mcp.policy.json`](mcp.policy.json) |

A policy object needs a Cedar `code` string; `name` is optional, and other keys
(`id`, `description`) are ignored. The one-object shape is the one
`watchlight-mcp` reads (one policy per file, passed in `policy_files=[...]`), so
`mcp.policy.json` works with both. A policy marked `"active": false` is refused
rather than loaded, because every policy a governor holds is enforced.

A missing file, invalid JSON, an unrecognised shape or a file with no policies
raises and names the file. It never loads nothing quietly. Edit the files and
re-run to see the decisions change.

## Beyond the Developer Edition

These examples show governed allow and deny on your laptop. When you run a
*fleet* of agents in production, the [Agent Runtime Governance Control
Plane](https://www.watchlight.ai) adds guarantees that a single in-process engine
cannot give:

- **Delegation enforced across the fleet** — the Developer Edition already
  confines a sub-agent to a strict subset of its parent's authority, inside one
  process. The control plane enforces that rule server-side, with a
  delegation-depth limit you can set per tenant and per agent, and it can
  durably sever a delegation subtree.
- **Drift & anomaly detection → automatic quarantine** — a misbehaving agent is
  stopped *before* its next action, not flagged after.
- **Signed, tamper-evident audit & lineage** — every decision cryptographically
  signed, so the trail is court-defensible.

→ **[Talk to us — sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise)**

---

Found a rough edge? [Open an issue](https://github.com/watchlight-ai-beacon/watchlight-de/issues/new/choose) — we read every one.
