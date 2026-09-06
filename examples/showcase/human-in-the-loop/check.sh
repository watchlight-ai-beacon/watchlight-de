#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# This is the showcase a globbing runner gets most wrong. Its files are not
# three independent examples:
#
#   agent.py     needs a subcommand — run bare it exits 2 with usage
#   approve.py   only means anything while a request is pending
#   hitl.py      is a helper MODULE with no entry point: running it exits 0
#                having verified nothing at all, which is worse than failing
#
# The real check is the ordered sequence request → approve → resume, driven to
# completion, once per lane, from a clean .watchlight each time — a leftover
# grant or consumed-nonce file from a previous run changes every verdict.
#
# The approver's secret is generated per run and passed through the environment
# only. It is never written to a file.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

generated .watchlight

if command -v openssl >/dev/null 2>&1; then
  APPROVER_SECRET="$(openssl rand -hex 32)"
else
  APPROVER_SECRET="$(py -c 'import secrets; print(secrets.token_hex(32))')"
fi
export APPROVER_SECRET

suite policy.suite.json

lane "python: request (holds, deletes nothing)" py agent.py request
lane "python: approve (signs a grant)"          py approve.py
lane "python: resume (runs once, replays refused)" py agent.py resume

regenerate
lane "node: request"  node agent.mjs request
lane "node: approve"  node approve.mjs
lane "node: resume"   node agent.mjs resume

# The two lanes share the pending/grant file formats, so a request held by one
# can be approved by the other. The README says so; this asserts it.
regenerate
lane "cross-lane: python holds, node approves, python resumes → request" py agent.py request
lane "cross-lane: … → approve"  node approve.mjs
lane "cross-lane: … → resume"   py agent.py resume

finish
