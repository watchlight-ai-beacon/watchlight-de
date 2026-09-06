#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# Each lane makes its own assertions (49 of them) about verdicts and record
# shape and exits non-zero on any change, so the lanes need no help beyond a
# clean trail to read back.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated .watchlight

suite policy.suite.json
lane "python" py identity.py
regenerate
lane "node"   node identity.mjs

finish
