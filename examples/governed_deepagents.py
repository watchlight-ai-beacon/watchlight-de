#!/usr/bin/env python3
"""Govern a deepagents deep agent with sub-agent scope attenuation.

A deep agent delegates to sub-agents. Watchlight makes every sub-agent's authority
a **strict subset** of the parent's — validated by the real engine — so a sub-agent
can only ever *narrow* what it may do, never widen it. The Developer Edition
governs the tree up to depth 5. Config-only: no deepagents source is touched.

    pip install "watchlight[deepagents]"
    python examples/governed_deepagents.py
    watchlight dev --audit .watchlight/audit.jsonl   # watch the sub-agent tree attenuate

Runs **without an API key** — it builds and governs the sub-agent tree offline.
Set a model key (e.g. ANTHROPIC_API_KEY) to also invoke the deep agent for real.

Expected output (no API key):

    deep agent authority : ['web_search', 'read_file', 'write_file', 'send_email']

      ✓ researcher       tools = ['web_search', 'read_file']  (depth 1)
      ✓ reporter         tools = ['read_file', 'write_file']  (depth 1)
      ✗ over_privileged  refused — ['AllowedTools']: cannot exceed the parent

    nesting deeper — each level attenuates from the one above:
        → depth 1: ['read_file']
        ...
        → depth 5: ['read_file']

    ── Developer-Edition ceiling ──
    Developer Edition governs sub-agent trees up to depth 5; ... sales@watchlight.ai

    set a model key (e.g. ANTHROPIC_API_KEY) to invoke the deep agent for real.
    wiring is one line:
      create_deep_agent(tools=..., subagents=<the governed sub-agents above>)

    watch the attenuation tree:  watchlight dev --audit .watchlight/audit.jsonl
"""
import os

from watchlight import AttenuationDenied, DevEditionCeiling, Watchlight

HERE = os.path.dirname(os.path.abspath(__file__))


# ── the tools the top-level agent may use (its root authority) ──────────
def web_search(query: str) -> str:
    """Search the web for a query."""
    return f"results for {query!r}"


def read_file(path: str) -> str:
    """Read a file from disk."""
    return f"contents of {path}"


def write_file(path: str, content: str) -> str:
    """Write content to a file."""
    return f"wrote {path}"


def send_email(to: str, body: str) -> str:
    """Send an email."""
    return f"sent to {to}"


TOOLS = {t.__name__: t for t in (web_search, read_file, write_file, send_email)}


def _has_model_key() -> bool:
    return any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"))


def main() -> None:
    gov = Watchlight(agent="deep-orchestrator", audit_dir=os.path.join(HERE, ".watchlight"))

    # The top-level agent's authority — the root of the attenuation tree.
    root = gov.scope(tools=list(TOOLS), intents=["research"])
    print("deep agent authority :", root.allowed_tools, "\n")

    # ── 1. Govern the deep agent's sub-agents ──────────────────────────
    # Each sub-agent declares the tools it needs; Watchlight validates that as a
    # STRICT SUBSET of the parent and hands back the clamped set. A sub-agent that
    # asks for a tool the parent lacks is REFUSED — you cannot build one that
    # out-scopes its parent.
    specs = [
        {"name": "researcher", "description": "Research a topic from the web and files",
         "tools": ["web_search", "read_file"]},
        {"name": "reporter", "description": "Summarize findings into a file",
         "tools": ["read_file", "write_file"]},
        {"name": "over_privileged", "description": "Asks for a tool the parent lacks",
         "tools": ["read_file", "delete_everything"]},  # ← refused by the engine
    ]

    governed_subagents = []
    for spec in specs:
        try:
            scope = root.attenuate(tools=spec["tools"])
        except AttenuationDenied as denied:
            print(f"  ✗ {spec['name']:16} refused — {denied.violations}: cannot exceed the parent")
            continue
        print(f"  ✓ {spec['name']:16} tools = {scope.allowed_tools}  (depth {scope.depth})")
        governed_subagents.append(
            {
                "name": spec["name"],
                "description": spec["description"],
                "system_prompt": f"You are the {spec['name']} sub-agent. {spec['description']}.",
                # Hand the sub-agent ONLY its attenuated tools.
                "tools": [TOOLS[name] for name in scope.allowed_tools],
            }
        )

    # ── 2. A deep agent nests sub-agents; the DE governs the tree to depth 5 ──
    print("\nnesting deeper — each level attenuates from the one above:")
    scope = root
    try:
        while True:
            scope = scope.attenuate(tools=["read_file"])
            print(f"    → depth {scope.depth}: {scope.allowed_tools}")
    except DevEditionCeiling as ceiling:
        print("\n── Developer-Edition ceiling ──")
        print(ceiling)

    # ── 3. Build the real deep agent with the governed sub-agents ──────
    print()
    if _has_model_key():
        from deepagents import create_deep_agent

        agent = create_deep_agent(
            tools=list(TOOLS.values()),
            system_prompt="You orchestrate research using your sub-agents.",
            subagents=governed_subagents,  # ← Watchlight-attenuated sub-agents
        )
        print("deep agent built with governed sub-agents; invoking…")
        result = agent.invoke(
            {"messages": [{"role": "user", "content": "Research Watchlight and write a summary."}]}
        )
        print(result["messages"][-1].content[:400])
    else:
        print("set a model key (e.g. ANTHROPIC_API_KEY) to invoke the deep agent for real.")
        print("wiring is one line:")
        print("  create_deep_agent(tools=..., subagents=<the governed sub-agents above>)")

    audit = os.path.join(HERE, ".watchlight", "audit.jsonl")
    print(f"\nwatch the attenuation tree:  watchlight dev --audit {audit}")


if __name__ == "__main__":
    main()
