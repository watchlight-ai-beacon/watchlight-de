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

## Govern an existing framework agent

The *same* plugin you ship to production, wired to the in-process engine. Going
to production is one environment variable (`WATCHLIGHT_APDP_URL`), never a rewrite.

| Example | Framework | Install |
|---|---|---|
| [`governed_langgraph_agent.py`](governed_langgraph_agent.py) | LangGraph | `watchlight[langgraph]` |
| [`governed_pydantic_ai_agent.py`](governed_pydantic_ai_agent.py) | Pydantic AI | `watchlight[pydantic-ai]` |
| [`governed_claude_agent.py`](governed_claude_agent.py) | Claude Agent SDK | `watchlight[claude-agent]` |

## Govern an MCP server

| Example | What it shows | Install |
|---|---|---|
| [`governed_mcp_server.py`](governed_mcp_server.py) | **MCP Runtime PEP** — a policy enforcement point in front of any MCP (2026-07-28) server; a denied `tools/call` never reaches the server. Self-demonstrating. | `watchlight-mcp` |

## Policies

The `*.policy.json` files are plain [Cedar](https://docs.watchlight.ai/de/policies)
policies in the shape the engine loads — a list of `{"name", "code"}` objects.
Edit them and re-run to see the decisions change.

---

Found a rough edge? [Open an issue](https://github.com/watchlight-ai-beacon/watchlight-de/issues/new/choose) — we read every one.
