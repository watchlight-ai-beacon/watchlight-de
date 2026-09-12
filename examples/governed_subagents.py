#!/usr/bin/env python3
"""Sub-agent scope attenuation — every child gets a STRICT SUBSET of its parent.

A sub-agent can only ever *narrow* authority, never widen it — and the tree is
bounded by ``max_delegation_depth``, a governance control (default 8; this demo
sets 5 to keep the output short). The strict-subset validation is the real
Watchlight engine, at every hop up to the limit.

    pip install watchlight
    python examples/governed_subagents.py
    watchlight dev --audit .watchlight/audit.jsonl   # watch the tree stream in

Runs offline — no API key required.

Expected output:

    root            : ['read_file', 'web_search', 'send_email', 'delete']
    → researcher    : ['read_file', 'web_search'] (depth 1)
      → reader      : ['read_file'] (depth 2)
      ✗ widen denied : ['AllowedTools'] — 1 tool(s) not in parent.allowed_tools (e.g. ["delete"])
        → depth 3
        → depth 4
        → depth 5

    ── max_delegation_depth ──
    DELEGATION_DEPTH_EXCEEDED: delegation depth 6 exceeds max_delegation_depth 5

    watch the tree live:  watchlight dev --audit .watchlight/audit.jsonl
"""
import os

from watchlight import AttenuationDenied, DelegationDepthExceeded, Watchlight

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    gov = Watchlight(
        agent="orchestrator",
        audit_dir=os.path.join(HERE, ".watchlight"),
        # A governance control, like a privilege-escalation depth limit in IAM.
        # The default is 8; 5 keeps this demo's output short.
        max_delegation_depth=5,
    )

    root = gov.scope(
        tools=["read_file", "web_search", "send_email", "delete"],
        intents=["research"],
    )
    print("root            :", root.allowed_tools)

    # A researcher sub-agent — a strict subset (no send_email / delete).
    researcher = root.attenuate(tools=["read_file", "web_search"])
    print("→ researcher    :", researcher.allowed_tools, f"(depth {researcher.depth})")

    # A reader below it — narrower still.
    reader = researcher.attenuate(tools=["read_file"])
    print("  → reader      :", reader.allowed_tools, f"(depth {reader.depth})")

    # A sub-agent CANNOT widen its authority — the engine refuses (strict subset).
    try:
        researcher.attenuate(tools=["read_file", "delete"])
    except AttenuationDenied as denied:
        print("  ✗ widen denied :", denied.violations, "—", str(denied).split(": ", 1)[-1])

    # The tree is bounded by max_delegation_depth; a hop past it is a deny
    # (DelegationDepthExceeded), recorded like any other refused attenuation.
    scope = reader
    try:
        while True:
            scope = scope.attenuate(tools=["read_file"])
            print(f"    → depth {scope.depth}")
    except DelegationDepthExceeded as exceeded:
        print("\n── max_delegation_depth ──")
        print(f"{exceeded.code}: {exceeded.reason}")

    audit = os.path.join(HERE, ".watchlight", "audit.jsonl")
    print(f"\nwatch the tree live:  watchlight dev --audit {audit}")


if __name__ == "__main__":
    main()
