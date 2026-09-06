#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# The web frameworks are OPTIONAL extras — neither `watchlight` nor
# @watchlight/sdk depends on FastAPI or Express. Each lane's check script
# already exits 2 with its install line when its framework is missing, and
# exit 2 is this harness's skip. A skipped lane is counted and printed loudly,
# never mistaken for a pass.
#
#   FastAPI + uvicorn:  pip install -r requirements.txt
#   Express:            npm install
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated .watchlight

suite policy.suite.json
lane "python: FastAPI (start → drive → assert → stop)" py check.py
regenerate
lane "node: Express (start → drive → assert → stop)"   node check.mjs

finish
