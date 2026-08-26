#!/usr/bin/env python3
"""A realistic multi-tool agent — every tool governed, the dangerous ones DENIED.

    pip install watchlight
    python examples/governed_research_agent.py
    # in another terminal, watch it live:
    watchlight dev

A research assistant has five tools. Its policy (`research.policy.json`) permits
only the ``research`` and ``read`` intents — so it can search the web and read
files, but it **cannot** email, move money, or delete records. Those three are
governed too; when the agent tries them, the engine refuses **before** the tool
body runs. That refusal — not a code review, not a prompt — is the guarantee.

Run `watchlight dev` in another terminal to watch every decision stream into the
local dashboard as this runs.
"""

import pathlib

from watchlight import Denied, govern

govern.load(pathlib.Path(__file__).parent / "research.policy.json")


# ── the agent's tools, each governed by a declared intent ──────────────────

@govern.tool(intent="research")
def web_search(query: str) -> str:
    return f"top results for {query!r}"


@govern.tool(intent="read")
def read_file(path: str) -> str:
    return f"<contents of {path}>"


@govern.tool(intent="notify")
def send_email(to: str, body: str) -> str:
    raise AssertionError("send_email body ran — the engine failed to deny!")


@govern.tool(intent="transfer")
def transfer_funds(to: str, amount: int) -> str:
    raise AssertionError("transfer_funds body ran — the engine failed to deny!")


@govern.tool(intent="delete")
def delete_records(table: str) -> str:
    raise AssertionError("delete_records body ran — the engine failed to deny!")


# ── a tiny "agent loop": the model wants to call tools; policy decides ──────

def try_tool(fn, *args):
    try:
        result = fn(*args)
        print(f"    ↳ ran: {result}")
    except Denied as denied:
        print(f"    ↳ BLOCKED before execution: {denied.reason or 'no matching policy'}")


def main() -> None:
    print("\nResearch agent — 5 tools, 2 intents permitted (research, read):\n")
    try_tool(web_search, "watchlight developer edition")   # research → ALLOW
    try_tool(read_file, "notes/plan.md")                   # read     → ALLOW
    try_tool(send_email, "ceo@corp", "exfiltrated summary")# notify   → DENY
    try_tool(transfer_funds, "attacker", 5000)             # transfer → DENY
    try_tool(delete_records, "customers")                  # delete   → DENY
    print("\nThe three dangerous tools never executed — denied before the side effect.")
    print("Audit written to .watchlight/audit.jsonl · run `watchlight dev` to watch live.\n")


if __name__ == "__main__":
    main()
