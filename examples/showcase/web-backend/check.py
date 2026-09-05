#!/usr/bin/env python3
"""Drive the governed FastAPI backend and assert verdicts and attribution.

    pip install watchlight -r examples/showcase/web-backend/requirements.txt
    python examples/showcase/web-backend/check.py

Starts `app.py` on an ephemeral 127.0.0.1 port with its audit trail pointed at a
scratch directory, sends an allowed request (alice, her account), a denied one
(bob, the same account), a second denied one (alice, another account), three
unauthenticated ones and a malformed one, shuts the server down, then reads the
trail the server wrote and asserts that every decision carries the acting user
as its principal. Exits non-zero on any failed assertion; exits 2 with a message
if the optional web extras are not installed.
"""

import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from typing import Optional

from watchlight import DENY_REASON, Watchlight

HERE = pathlib.Path(__file__).parent
APP = HERE / "app.py"
STARTUP_TIMEOUT_S = 30

TOKENS = {"alice": "demo-token-alice", "bob": "demo-token-bob"}  # the stand-in table in app.py


def get(base: str, path: str, token: Optional[str] = None) -> tuple[int, dict]:
    req = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main() -> int:
    if importlib.util.find_spec("fastapi") is None or importlib.util.find_spec("uvicorn") is None:
        print("check.py needs FastAPI and uvicorn (optional extras, not part of the watchlight package):\n"
              "    pip install -r examples/showcase/web-backend/requirements.txt", file=sys.stderr)
        return 2

    audit_dir = pathlib.Path(tempfile.mkdtemp(prefix="web-backend-audit-"))
    env = {**os.environ, "WEB_BACKEND_AUDIT_DIR": str(audit_dir)}
    proc = subprocess.Popen([sys.executable, str(APP)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env)
    failures = 0
    forced = False  # set if the server ignored SIGTERM and had to be killed

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'✓' if cond else '✗'} {name}{'' if cond or not detail else ' — ' + detail}")
        failures += 0 if cond else 1

    try:
        # ── start: the app prints the port it bound ──
        killer = threading.Timer(STARTUP_TIMEOUT_S, proc.kill)
        killer.start()
        base = None
        server_lines: list[str] = []
        for line in proc.stdout:
            server_lines.append(line.rstrip("\n"))
            m = re.match(r"^listening on (http://127\.0\.0\.1:\d+)$", line.strip())
            if m:
                base = m.group(1)
                break
        killer.cancel()
        if base is None:
            print("server did not start:\n  " + "\n  ".join(server_lines), file=sys.stderr)
            return 1
        threading.Thread(target=lambda: server_lines.extend(l.rstrip("\n") for l in proc.stdout), daemon=True).start()
        print(f"server: {base} (pid {proc.pid}); audit trail → scratch directory\n")

        # ── requests ──
        allowed = get(base, "/accounts/acct-100/statement", TOKENS["alice"])
        denied_user = get(base, "/accounts/acct-100/statement", TOKENS["bob"])
        denied_account = get(base, "/accounts/acct-200/statement", TOKENS["alice"])
        no_token = get(base, "/accounts/acct-100/statement")
        bad_token = get(base, "/accounts/acct-100/statement", "demo-token-nobody")
        proto_token = get(base, "/accounts/acct-100/statement", "constructor")  # must not resolve via any prototype/attribute chain
        bad_path = get(base, "/accounts/acct_100!/statement", TOKENS["alice"])
        for label, (status, body) in [("alice  → acct-100", allowed), ("bob    → acct-100", denied_user),
                                      ("alice  → acct-200", denied_account), ("no token", no_token),
                                      ("unknown token", bad_token), ("token 'constructor'", proto_token),
                                      ("malformed account id", bad_path)]:
            print(f"  {label:22} HTTP {status}  {sorted(body) if isinstance(body, dict) else body}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            forced = True
            proc.kill()
            proc.wait()

    # ── the trail the server wrote ──
    trail_path = audit_dir / "audit.jsonl"
    trail = [json.loads(l) for l in trail_path.read_text(encoding="utf-8").splitlines() if l.strip()] if trail_path.exists() else []
    shutil.rmtree(audit_dir, ignore_errors=True)
    decisions = [r for r in trail if "decision" in r]
    egress = [r for r in trail if r.get("event") == "egress"]

    print("\n=== audit trail (written by the server) ===")
    for d in decisions:
        print(f"  …{d.get('decision_id', '')[-6:]}  {d['decision']:5}  principal={d['principal']}  {d['intent']}  {d['resource']}")

    print("\n=== assertions ===")
    check("alice reading her account → 200 with the statement and a decision_id",
          allowed[0] == 200 and "statement" in allowed[1] and bool(allowed[1].get("decision_id")))
    check("bob reading the same account → 403 with the opaque reason, no statement",
          denied_user[0] == 403 and denied_user[1] == {"error": DENY_REASON})
    check("alice reading another account → 403 (the policy is scoped to her account)",
          denied_account[0] == 403 and denied_account[1] == {"error": DENY_REASON})
    check("no token / unknown token / a prototype-chain name as token → 401 before any governed call",
          no_token[0] == 401 and bad_token[0] == 401 and proto_token[0] == 401)
    check("a malformed account id → 400 before any governed call", bad_path[0] == 400)
    check("exactly three decisions: one per authenticated request, none for the 401s and the 400",
          len(decisions) == 3 and all(d["principal"] in ('User::"alice"', 'User::"bob"') for d in decisions))
    by_key = {(d["principal"], d["resource"]): d for d in decisions}
    check('Allow for User::"alice" on account/acct-100',
          by_key.get(('User::"alice"', "account/acct-100"), {}).get("decision") == "Allow")
    check('Deny for User::"bob" on account/acct-100',
          by_key.get(('User::"bob"', "account/acct-100"), {}).get("decision") == "Deny")
    check('Deny for User::"alice" on account/acct-200',
          by_key.get(('User::"alice"', "account/acct-200"), {}).get("decision") == "Deny")
    check("every decision is attributed to the acting user, never to the service",
          all(d["principal"].startswith('User::"') and d["principal"] != d["agent"] for d in decisions))
    allow = by_key.get(('User::"alice"', "account/acct-100"), {})
    check("the decision_id in alice's response is the Allow record's — the response joins the trail",
          allowed[1].get("decision_id") == allow.get("decision_id"))
    check("one egress record, joined to the Allow, replaced (the hook attached the decision_id)",
          len(egress) == 1 and egress[0].get("decision_id") == allow.get("decision_id")
          and egress[0]["replaced"] is True and egress[0]["principal"] == 'User::"alice"')
    blob = json.dumps(trail)
    check("the trail is value-free — no bearer token and no statement text in it",
          not any(t in blob for t in TOKENS.values()) and "closing balance" not in blob)
    # uvicorn re-raises the signal it stopped on, so a graceful stop exits with SIGTERM's status.
    check("the server stopped on SIGTERM within 10s without being killed", not forced, f"exit {proc.returncode}")

    # The policy the server loaded, executed in-process (same as `watchlight policy test`).
    suite = json.loads((HERE / "policy.suite.json").read_text(encoding="utf-8"))
    suite_dir = tempfile.mkdtemp(prefix="web-backend-suite-")
    try:
        report = Watchlight(agent="check", audit_dir=suite_dir).load(HERE / "policy.suite.json").test(suite["tests"])
    finally:
        shutil.rmtree(suite_dir, ignore_errors=True)
    check(f"policy.suite.json: {report['passed']}/{report['total']} fixtures pass", report["failed"] == 0)

    print(f"\n{'ALL CHECKS OK' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
