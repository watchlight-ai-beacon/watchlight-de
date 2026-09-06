#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# Both lanes assert the stub bank's call counter — 0 after the denied transfer,
# 1 after the permitted one — so each is self-checking; the counter is per-run
# state, so each lane starts from a clean .watchlight.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated .watchlight

suite policy.suite.json
lane "python" py agent.py
regenerate
lane "node"   node agent.mjs

finish
