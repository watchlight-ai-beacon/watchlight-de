#!/usr/bin/env python3
"""Fine-grained governance: allow the SAME tool call only in a safe context.

    pip install watchlight
    python examples/context_governance.py

Runs offline — no API key required.

Expected output:

    Same tool call, governed by runtime context:

      run_query  (tool_class=safe)       -> Allow   ← permitted
      run_query  (tool_class=dangerous)  -> Deny    ← blocked
      run_query  (no context)            -> Deny    ← fail-closed

    One policy, three outcomes — the decision follows the context, not the tool name.

Intent-based gating (see governed_research_agent.py) decides *which verbs* an
agent may use. Sometimes you need finer control: the same action is fine in one
situation and forbidden in another. Policies can gate on **runtime context** —
here, a tool may run only when its ``tool_class`` is ``"safe"``:

    permit(principal, action == Action::"call", resource)
    when { context.tool_class == "safe" };

The agent passes context with each authorization; the engine decides. A missing
context fails closed (denied), exactly like production. This uses the same
in-process engine, via the lower-level ``authorize`` call the framework plugins
use under the hood.
"""

import asyncio

from watchlight.inprocess import in_process_backend

POLICIES = [
    {
        "name": "safe-tools-only",
        "code": 'permit(principal, action == Action::"call", resource) '
        'when { context.tool_class == "safe" };',
    }
]


async def main() -> None:
    # `in_process_backend` returns the real in-process engine client (the same
    # object the framework plugins use). No server, no database.
    engine = in_process_backend(POLICIES, audit_path=None)

    async def decide(tool: str, tool_class: str | None) -> str:
        ctx = {"tool_class": tool_class} if tool_class is not None else {}
        resp = await engine.authorize('Agent::"analyst"', "call", f"tool/{tool}", context=ctx)
        return resp.get("decision", "Deny")

    print("\nSame tool call, governed by runtime context:\n")
    print(f"  run_query  (tool_class=safe)       -> {await decide('run_query', 'safe')}   ← permitted")
    print(f"  run_query  (tool_class=dangerous)  -> {await decide('run_query', 'dangerous')}    ← blocked")
    print(f"  run_query  (no context)            -> {await decide('run_query', None)}    ← fail-closed")
    print("\nOne policy, three outcomes — the decision follows the context, not the tool name.\n")


if __name__ == "__main__":
    asyncio.run(main())
