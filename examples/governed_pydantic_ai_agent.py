#!/usr/bin/env python3
"""Govern a Pydantic AI agent's tool calls in-process — zero infrastructure.

    pip install 'watchlight[pydantic-ai]'
    python examples/governed_pydantic_ai_agent.py

Expected output:

    watchlight: research-agent governed in-process (dev mode, zero infra)
    watchlight: ALLOW  read   tool/web_search
    results for: Q1 2026 compliance benchmarks
    watchlight: DENY   write  tool/transfer_funds     (denied before it executed)

This uses the SAME ``WatchlightPydanticAIPlugin`` you ship to production — here
wired to the in-process engine via ``watchlight.pydantic_ai.governed_plugin``.
Only the ``read`` action is permitted by ``framework.policy.json``; the
``transfer_funds`` tool is refused by the Cedar engine BEFORE its body runs.

Going to production is one environment variable, not a rewrite:

    WATCHLIGHT_APDP_URL=https://apdp.your-org:8081 python examples/governed_pydantic_ai_agent.py

``auto_instrument=False`` keeps this example runnable with no model/API key; in a
real agent, drop it and decorate your tools with ``@agent.tool`` — every call
still flows through ``handle.authorize_action(...)`` first.
"""

import asyncio
import pathlib

from watchlight.pydantic_ai import governed_plugin

POLICY = pathlib.Path(__file__).parent / "framework.policy.json"


async def web_search(query: str) -> str:
    return f"results for: {query}"


async def transfer_funds(to: str, amount: int) -> str:  # never runs — denied first
    return f"transferred {amount} to {to}"


async def main() -> None:
    plugin = governed_plugin(POLICY, auto_instrument=False)
    print("watchlight: research-agent governed in-process (dev mode, zero infra)")

    async with await plugin.start_run("research-agent") as handle:
        if await handle.authorize_action("read", "tool/web_search"):
            print("watchlight: ALLOW  read   tool/web_search")
            print(await web_search("Q1 2026 compliance benchmarks"))

        if await handle.authorize_action("write", "tool/transfer_funds"):
            await transfer_funds("acct-999", 10_000)  # unreachable
        else:
            print(
                "watchlight: DENY   write  tool/transfer_funds"
                "     (denied before it executed)"
            )

    print("\nlineage written to .watchlight/audit.jsonl (value-free)")


if __name__ == "__main__":
    asyncio.run(main())
