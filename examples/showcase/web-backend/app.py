#!/usr/bin/env python3
"""Governed web backend — the request's authenticated user is the acting principal.

    pip install watchlight -r examples/showcase/web-backend/requirements.txt   # FastAPI + uvicorn
    python examples/showcase/web-backend/app.py            # ephemeral 127.0.0.1 port, printed on start
    python examples/showcase/web-backend/app.py 8000       # fixed port

    curl -H 'Authorization: Bearer demo-token-alice' http://127.0.0.1:<port>/accounts/acct-100/statement   # 200
    curl -H 'Authorization: Bearer demo-token-bob'   http://127.0.0.1:<port>/accounts/acct-100/statement   # 403

One endpoint, `GET /accounts/{account_id}/statement`. The bearer token is looked up
in an in-memory table — a stand-in for whatever authenticates requests in a real
service — and the user it resolves to becomes the PRINCIPAL of the governed tool
call: `principal=lambda user, account_id: f'User::"{user}"'`. The policy in
`policy.suite.json` permits `read_statement` for `User::"alice"` on her account and
nothing else, so the same endpoint answers 200 to alice and 403 to bob, and every
decision in the audit trail carries the user it was made for, never the service.

Order of checks: authenticate (401) → validate the path (400) → authorize with
the acting principal (403, before any lookup) → look up the statement (404). A
denied user learns nothing about whether the account exists. The response to an
allowed request carries the `decision_id` of the decision that released it, so
the record a client quotes joins the trail. `check.py` drives all of this.
"""

import os
import pathlib
import re
import socket
import sys
from typing import Optional

from watchlight import DENY_REASON, Denied, Watchlight

HERE = pathlib.Path(__file__).parent

# ── the stand-ins ────────────────────────────────────────────────────
# Real services get the user from a session, an IdP token, or mTLS. Whatever the
# source, the value that matters is the one the request AUTHENTICATED as — the
# principal must never come from a header the client fills in freely.
USERS = {"demo-token-alice": "alice", "demo-token-bob": "bob"}  # bearer token → user id (synthetic)
STATEMENTS = {  # what the endpoint returns; synthetic
    "acct-100": "acct-100: 3 transactions, closing balance 42.00",
    "acct-200": "acct-200: 1 transaction, closing balance 7.50",
}
ACCOUNT_ID = re.compile(r"^[a-z0-9-]{1,32}$")  # the path segment enters the Cedar resource string

# ── the governed tool ────────────────────────────────────────────────
govern = Watchlight(agent="statements-api", audit_dir=os.environ.get("WEB_BACKEND_AUDIT_DIR", HERE / ".watchlight"))
govern.load(HERE / "policy.suite.json")  # the same policies `watchlight policy test` verifies


def attach_decision_id(text: str, info: dict) -> dict:
    """Egress hook: the response carries the id of the decision that released it."""
    return {"account": info["resource"].split("/", 1)[1], "statement": text, "decision_id": info["decision_id"]}


@govern.tool(
    "read_statement",
    principal=lambda user, account_id: f'User::"{user}"',  # the acting user, per call — not the service
    resource=lambda user, account_id: f"account/{account_id}",
    on_result=attach_decision_id,
)
def read_statement(user: str, account_id: str) -> str:
    if account_id not in STATEMENTS:
        raise LookupError(account_id)  # only reachable AFTER the principal was authorized
    return STATEMENTS[account_id]


# ── the web app ──────────────────────────────────────────────────────
def create_app():
    from fastapi import FastAPI, Header, HTTPException
    from fastapi.responses import JSONResponse

    app = FastAPI(title="governed statements api")

    def authenticate(authorization: Optional[str]) -> str:
        """Bearer token → user id. Anything else is 401 — before any governed call."""
        scheme, _, token = (authorization or "").partition(" ")
        user = USERS.get(token.strip()) if scheme.lower() == "bearer" else None
        if user is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return user

    @app.get("/accounts/{account_id}/statement")
    def statement(account_id: str, authorization: Optional[str] = Header(default=None)):
        user = authenticate(authorization)
        if not ACCOUNT_ID.match(account_id):
            raise HTTPException(status_code=400, detail="invalid account id")
        try:
            return read_statement(user, account_id)  # authorized for User::"<user>" before the body runs
        except Denied:
            return JSONResponse({"error": DENY_REASON}, status_code=403)  # opaque: never why
        except LookupError:
            raise HTTPException(status_code=404, detail="no such account")

    return app


def main(argv: list[str]) -> int:
    try:
        import uvicorn
        app = create_app()
    except ImportError:
        print("this example needs FastAPI and uvicorn (optional extras, not part of the watchlight package):\n"
              "    pip install -r examples/showcase/web-backend/requirements.txt", file=sys.stderr)
        return 2
    port = int(argv[1]) if len(argv) > 1 else 0  # 0 → the OS picks an ephemeral port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))  # loopback only
    print(f"listening on http://127.0.0.1:{sock.getsockname()[1]}", flush=True)
    uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
