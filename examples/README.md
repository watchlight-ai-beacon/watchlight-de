# Examples

Every example is **self-contained and runnable** — no server, no database, no
signup. Each one authorizes with the *real* Watchlight engine in-process and, for
the denials, proves the tool never executed.

```bash
pip install watchlight          # core: the govern decorator + engine
```

While any example runs, open a second terminal and watch every decision live:

```bash
watchlight dev                  # → http://127.0.0.1:7000
```

## Start here

| Example | What it shows | Install |
|---|---|---|
| [`agent.py`](agent.py) | **The DENY line** — the smallest governed agent: one allowed tool, one denied. | `watchlight` |
| [`governed_research_agent.py`](governed_research_agent.py) | **Realistic multi-tool agent** — 5 tools, only `research` + `read` permitted; email / transfer / delete are **blocked before they run**. | `watchlight` |
| [`context_governance.py`](context_governance.py) | **Fine-grained context gating** — the *same* tool call is allowed or denied by runtime `context`; missing context fails closed. | `watchlight[langgraph]` |
| [`governed_subagents.py`](governed_subagents.py) | **Sub-agent scope attenuation** — every child gets a *strict subset* of its parent's authority (widening is refused by the real engine); the DE governs the tree up to depth 5, then points to Enterprise. | `watchlight` |

## Showcase — end-to-end setups, proven

Each showcase runs in **both lanes** (Python and TypeScript side by side) and exits
non-zero if what happened contradicts the verdict. The governed-agent showcases ship
their policy and golden tests in one `policy.suite.json`.

| Example | What it shows | Run |
|---|---|---|
| [`showcase/denied-before-execute/`](showcase/denied-before-execute/README.md) | **Denied before it executed** — a governed transfer against a stub bank with a call counter; a `forbid` above a threshold refuses the call and the counter is asserted `0`; a small transfer runs exactly once. Prints verdict, decision id and the audit line. | `python examples/showcase/denied-before-execute/agent.py` |
| [`showcase/human-in-the-loop/`](showcase/human-in-the-loop/README.md) | **Human in the loop** — `NeedsApproval` holds the call and writes a pending request; a separate `approve.py` signs a grant; `resume` runs the action once with an `approved: true` record joined to the pending one. Grant replay and token replay are refused. | `python agent.py request` → `python approve.py` → `python agent.py resume` |
| [`showcase/policy-tests-ci/`](showcase/policy-tests-ci/README.md) | **Policy tests as a CI gate** — a policy set, an 11-fixture suite (Allow / Deny / NeedsApproval / approved), a GitHub Actions workflow template running `watchlight policy test` in the TypeScript and Python CLIs, and a deliberately widened policy that turns the run red. | `watchlight` or `@watchlight/sdk` |
| [`showcase/audit-forensics/`](showcase/audit-forensics/README.md) | **Audit forensics** — generate a trail with every record kind (decisions incl. an approved one, sanitizations, egress, attenuations, screenings), then join on `decision_id`, roll up per principal, and list attenuation chains with `forensics.py` or `jq`. Documents every record kind's exact field names. | `watchlight` (+ `jq` for the recipes) |

Verify a showcase policy on its own:
`watchlight policy test examples/showcase/<name>/policy.suite.json`.

## Governance patterns — high-stakes recipes

Copy-paste recipes for the decisions people reach for the DE to make — spending
money, deleting things, messaging the outside world, moving data, spawning
sub-agents. Each is a *problem shape* (policy + govern-the-tool code + tests), and
the policy-driven ones ship as runnable suites that
[`patterns/check.sh`](patterns/check.sh) runs through `watchlight policy test`, so
the recipes can't drift from the engine.

→ **[`patterns/`](patterns/README.md)** — money-bounded agent, destructive
actions, external messaging, data egress, kill-switch / quarantine, per-user
attribution, PII-before-read, sub-agent confinement.

## Showcase — end-to-end pipelines

Complete, self-checking pipelines that combine several primitives. Each runs in
both lanes and exits non-zero if any assertion fails.

| Example | What it shows |
|---|---|
| [`showcase/poisoned-rag/`](showcase/poisoned-rag/README.md) | **Poisoned-document RAG** — a retrieved document hides a prompt injection and personal data; `screen()` withholds it, the permit's `@obligate_redact` obligation strips personal data from what passes, and every step joins the decision on one `decision_id`. |

## Govern an existing framework agent

The *same* plugin you ship to production, wired to the in-process engine. Going
to production is one environment variable (`WATCHLIGHT_APDP_URL`), never a rewrite.

| Example | Framework | Install |
|---|---|---|
| [`governed_langgraph_agent.py`](governed_langgraph_agent.py) | LangGraph | `watchlight[langgraph]` |
| [`governed_pydantic_ai_agent.py`](governed_pydantic_ai_agent.py) | Pydantic AI | `watchlight[pydantic-ai]` |
| [`governed_claude_agent.py`](governed_claude_agent.py) | Claude Agent SDK | `watchlight[claude-agent]` |
| [`governed_deepagents.py`](governed_deepagents.py) | deepagents — **sub-agent scope attenuation**: each sub-agent gets a strict-subset of the parent's tools, to the depth-5 ceiling (runs without an API key) | `watchlight[deepagents]` |

## Govern an MCP server

| Example | What it shows | Install |
|---|---|---|
| [`governed_mcp_server.py`](governed_mcp_server.py) | **MCP Runtime PEP** — a policy enforcement point in front of any MCP (2026-07-28) server; a denied `tools/call` never reaches the server. Self-demonstrating. | `watchlight-mcp` |

## Policies

The `*.policy.json` files are plain [Cedar](https://docs.watchlight.ai/de/policies)
policies in the shape the engine loads — a list of `{"name", "code"}` objects.
Edit them and re-run to see the decisions change.

## Beyond the Developer Edition

These examples show governed allow/deny on your laptop. When you're running a
*fleet* of agents in production, the [Agent Runtime Governance Control
Plane](https://www.watchlight.ai) adds the guarantees a single in-process engine
can't:

- **Sub-agent scope attenuation & delegation** — a spawned sub-agent can only ever
  *narrow* its parent's authority, and delegated authority is validated end-to-end.
- **Drift & anomaly detection → automatic quarantine** — a misbehaving agent is
  stopped *before* its next action, not flagged after.
- **Signed, tamper-evident audit & lineage** — every decision cryptographically
  signed, so the trail is court-defensible.

→ **[Talk to us — sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise)**

---

Found a rough edge? [Open an issue](https://github.com/watchlight-ai-beacon/watchlight-de/issues/new/choose) — we read every one.
