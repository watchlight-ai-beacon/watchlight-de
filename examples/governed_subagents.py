#!/usr/bin/env python3
"""Sub-agent scope attenuation — every child gets a STRICT SUBSET of its parent.

A sub-agent can only ever *narrow* authority, never widen it — and the Developer
Edition governs the tree up to depth 5. The strict-subset validation is the real
Watchlight engine; the depth ceiling is where DE hands off to Enterprise.

    python governed_subagents.py
    watchlight dev --audit .watchlight/audit.jsonl   # watch the tree stream in
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

    # Developer Edition governs the tree up to depth 5; going deeper is the
    # upgrade moment (the attenuations so far were all real).
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
