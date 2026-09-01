#!/usr/bin/env python3
"""Sub-agent scope attenuation — every child gets a STRICT SUBSET of its parent.

A sub-agent can only ever *narrow* authority, never widen it — and the Developer
Edition governs the tree up to depth 5. The strict-subset validation is the real
Watchlight engine; the depth ceiling is where DE hands off to Enterprise.

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

    ── Developer-Edition ceiling ──
    Developer Edition governs sub-agent trees up to depth 5; this chain reached the
    ceiling at depth 6. ... Talk to us: sales@watchlight.ai · https://www.watchlight.ai

    watch the tree live:  watchlight dev --audit .watchlight/audit.jsonl
"""
import os

from watchlight import AttenuationDenied, DevEditionCeiling, Watchlight

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    gov = Watchlight(agent="orchestrator", audit_dir=os.path.join(HERE, ".watchlight"))

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

    # Developer Edition governs the tree up to depth 5; going deeper raises
    # DevEditionCeiling (the attenuations so far were all real).
    scope = reader
    try:
        while True:
            scope = scope.attenuate(tools=["read_file"])
            print(f"    → depth {scope.depth}")
    except DevEditionCeiling as ceiling:
        print("\n── Developer-Edition ceiling ──")
        print(ceiling)

    audit = os.path.join(HERE, ".watchlight", "audit.jsonl")
    print(f"\nwatch the tree live:  watchlight dev --audit {audit}")


if __name__ == "__main__":
    main()
