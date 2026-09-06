#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# The runner takes a corpus path, and the folder ships two: corpus.json, which
# both layers handle, and corpus.unhandled.json, which carries a family neither
# layer knows. The README claims the second one goes red — so the check asserts
# it, in both lanes. Each run writes its trail to a scratch directory it removes
# at exit, so there is nothing here to clean up.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

suite policy.suite.json
lane     "python"                    py run.py
lane_red "python: unhandled family"  py run.py corpus.unhandled.json
lane     "node"                      node run.mjs
lane_red "node: unhandled family"    node run.mjs corpus.unhandled.json

finish
