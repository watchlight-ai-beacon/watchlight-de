#!/usr/bin/env python3
"""The Developer-Edition DENY line — govern an agent's tools with zero infra.

    pip install watchlight          # (locally: pip install -e . after building the engine)
    python examples/agent.py

Runs offline — no API key required.

Expected output:

    watchlight: governing 'my-agent' (dev mode, in-process engine)
    watchlight: ALLOW  research  tool/web_search
    results for: watchlight docs
    watchlight: DENY   transfer  tool/transfer_funds     not authorized
    (denied before it executed: watchlight denied intent 'transfer' on tool/transfer_funds: not authorized)

Only the `research` intent is permitted by `watchlight.policy.json`. The
`transfer_funds` tool is governed but no policy permits it, so the engine
refuses the call BEFORE the function body runs — that is the product.
"""

import pathlib

from watchlight import Denied, govern

# Load the local policy file (fail-closed: without it, everything denies).
govern.load(pathlib.Path(__file__).parent / "watchlight.policy.json")


@govern.tool(intent="research")
def web_search(query: str) -> str:
    return f"results for: {query}"


@govern.tool(intent="transfer")
def transfer_funds(to: str, amount: int) -> str:
    # This body must NEVER run in this example — no policy permits 'transfer'.
    raise AssertionError("transfer_funds body ran — the engine failed to deny!")


def main() -> None:
    # Permitted — a policy allows the 'research' intent.
    print(web_search("watchlight docs"))

    # Denied — no policy permits 'transfer'. The call raises before the body runs.
    try:
        transfer_funds("attacker", 1000)
    except Denied as denied:
        print(f"(denied before it executed: {denied})")


if __name__ == "__main__":
    main()
