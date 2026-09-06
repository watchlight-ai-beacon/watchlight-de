#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh, which runs every showcase's check.sh.
#
# Order matters here more than anywhere else: forensics.py READS the trail that
# generate_trail.py WRITES. Run on its own it exits 1; run after the generator
# it exits 0. That is why this file exists — a runner that simply executed both
# .py files in directory order would pass or fail depending on what the last
# run happened to leave in ./trail, which is exactly how this showcase's field
# map drifted without anyone noticing.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated trail

# 1. With no trail, the analyzer must refuse rather than report on nothing.
lane_red "python: analyzer refuses a missing trail"  py forensics.py

# 2. The Python lane writes the trail and checks every record against the field
#    map in README.md — this is the assertion that had been failing silently.
lane "python: generate the trail"       py generate_trail.py
lane "python: forensics report"         py forensics.py
lane "python: forensics --json"         py forensics.py --json
lane "python: forensics --principal"    py forensics.py --principal 'User::"alice"'

# 3. The Node lane must produce a trail the same analyzer reads — the README's
#    "same records, same fields" claim. It gets a clean directory to write into.
regenerate
lane "node: generate the trail"         node generate-trail.mjs
lane "python: forensics on the node trail" py forensics.py

finish
