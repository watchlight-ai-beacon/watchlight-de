#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated .watchlight

suite policy.suite.json
lane "python" py rag.py
regenerate
lane "node"   node rag.mjs

finish
