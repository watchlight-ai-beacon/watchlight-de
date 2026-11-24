"""Run grants: the run-scoped credential a launcher hands into a workload.

A **launcher** (for example the process that starts an agent in an NVIDIA
OpenShell sandbox) runs *outside* the workload and holds a Beacon service
credential with the ``workload:bind`` capability. It opens the Beacon run
itself, binding it to the workload (``workload_ref``), and hands the agent
ONLY a :class:`RunGrant`: the run's own ``sst_`` credential, plus the
run's proxy token when wl-proxy is in the path. The tenant-wide plugin
token never enters the workload.

Inside the workload, the plugin adopts the run instead of opening one
(``WatchlightLangGraphPlugin.adopt_run(grant)``). With the grant as its only
credential it can decide and close ITS run — wl-apdp admits an ``sst_``
caller on that run's ``/authorize``, ``/constraints/manifest`` and
``/sessions/<own>/{plan,preflight,complete}`` only, and emits lineage with
it on ``/v1/events`` as before. It cannot open a session, act for another
run or agent, bind or rebind a workload, or reach an admin route.

Delivery: the launcher writes :meth:`RunGrant.to_json` to the agent
process's **stdin** (never argv, an env var visible to the whole workload,
the image, or a file), and the agent reads it with
:meth:`RunGrant.from_stdin`. :meth:`RunGrant.from_env` exists for launchers
whose runtime can only inject environment.

The ids (session, agent, execution, tenant, application, workload) are
decoded from the credential's payload for request construction only. They
are NEVER trusted: wl-apdp verifies the credential's signature and takes
every id from its verified claims.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, Any, ClassVar, Dict, Mapping, MutableMapping, Optional

from .credentials import Credential, InvalidCredential

__all__ = [
    "RUN_GRANT_ENV_VAR",
    "RUN_PROXY_TOKEN_ENV_VAR",
    "RUN_HANDLE_ID_ENV_VAR",
    "RunGrant",
]

#: Env var carrying the run's ``sst_`` credential (see :meth:`RunGrant.from_env`).
RUN_GRANT_ENV_VAR = "WATCHLIGHT_RUN_CREDENTIAL"
#: Env var carrying the run's wl-proxy token, when there is one.
RUN_PROXY_TOKEN_ENV_VAR = "WATCHLIGHT_RUN_PROXY_TOKEN"
#: Env var carrying the run's server-minted root run-handle id (not secret).
RUN_HANDLE_ID_ENV_VAR = "WATCHLIGHT_RUN_HANDLE_ID"

_SST_PREFIX = "sst_"
# A grant is small; refuse anything that is not.
_MAX_GRANT_BYTES = 64 * 1024
_GRANT_FIELDS = frozenset(
    {"session_token", "proxy_token", "proxy_token_expires_at", "root_run_handle_id"}
)


def _decode_claims(token: str) -> Dict[str, Any]:
    """The ``sst_`` payload, UNVERIFIED — for building requests only."""
    if not isinstance(token, str) or not token.startswith(_SST_PREFIX):
        raise InvalidCredential("a run grant needs the run's sst_ credential")
    body, sep, sig = token[len(_SST_PREFIX):].partition(".")
    if not sep or not body or not sig:
        raise InvalidCredential("the run credential is malformed")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        claims = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise InvalidCredential("the run credential is malformed") from exc
    if not isinstance(claims, dict):
        raise InvalidCredential("the run credential is malformed")
    for key in ("sid", "aid"):
        if not isinstance(claims.get(key), str) or not claims[key]:
            raise InvalidCredential("the run credential is malformed")
    return claims


@dataclass(frozen=True, slots=True)
class RunGrant:
    """The run-scoped credentials a launcher hands to the agent it starts.

    Secret fields (``session_token``, ``proxy_token``) never appear in
    ``repr``/``str``/``format`` and a grant does not pickle.
    """

    session_token: str
    """The run's ``sst_`` credential. Secret."""

    proxy_token: Optional[str] = None
    """The run's wl-proxy token, when wl-proxy is in the path. Secret."""

    proxy_token_expires_at: Optional[datetime] = None

    root_run_handle_id: Optional[str] = None
    """The server-minted root run handle (not secret)."""

    claims: Mapping[str, Any] = field(default_factory=dict, compare=False)
    """The credential's payload, UNVERIFIED (see the module docstring)."""

    _REDACTED: ClassVar[str] = "<redacted>"

    def __post_init__(self) -> None:
        if not self.claims:
            object.__setattr__(self, "claims", _decode_claims(self.session_token))

    # ── redaction ────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"RunGrant(session_id={self.session_id!r}, agent_id={self.agent_id!r}, "
            f"execution_id={self.execution_id!r}, session_token={self._REDACTED}, "
            f"proxy_token={self._REDACTED if self.proxy_token else None})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __reduce__(self):  # pragma: no cover - exercised by the pickle test
        raise TypeError("a RunGrant carries secrets and is not picklable")

    # ── ids (unverified; for request construction only) ──────────────

    @property
    def session_id(self) -> str:
        return str(self.claims["sid"])

    @property
    def agent_id(self) -> str:
        return str(self.claims["aid"])

    @property
    def execution_id(self) -> Optional[str]:
        eid = self.claims.get("eid")
        return eid if isinstance(eid, str) else None

    @property
    def tenant_id(self) -> Optional[str]:
        tid = self.claims.get("tid")
        return tid if isinstance(tid, str) else None

    @property
    def application_id(self) -> Optional[str]:
        app = self.claims.get("app")
        return app if isinstance(app, str) else None

    @property
    def workload_ref(self) -> Optional[Dict[str, Any]]:
        wref = self.claims.get("wref")
        return dict(wref) if isinstance(wref, dict) else None

    # ── the caller credential ────────────────────────────────────────

    def credential(self) -> Credential:
        """The run credential as the ApdpClient's caller credential.

        ``kind="run"``: the client sends ``Authorization: Bearer sst_…`` and
        no tenant header (the tenant is inside the signed credential).
        """
        return Credential(
            bearer_token=self.session_token,
            kind="run",  # type: ignore[arg-type]
            identity_claims={"session_id": self.session_id, "agent_id": self.agent_id},
            label="run-grant",
        )

    # ── the launcher side ────────────────────────────────────────────

    @classmethod
    def from_session_response(cls, response: Mapping[str, Any]) -> "RunGrant":
        """Build the grant from wl-apdp's ``POST /sessions`` response."""
        if not isinstance(response, Mapping):
            raise InvalidCredential("not a session response")
        token = response.get("session_token")
        if not isinstance(token, str):
            raise InvalidCredential("the session response carries no run credential")
        proxy = response.get("proxy_token")
        expires = response.get("proxy_token_expires_at")
        handle = response.get("root_run_handle_id")
        return cls(
            session_token=token,
            proxy_token=proxy if isinstance(proxy, str) and proxy else None,
            proxy_token_expires_at=_parse_time(expires),
            root_run_handle_id=handle if isinstance(handle, str) and handle else None,
        )

    def to_json(self) -> str:
        """The grant as ONE line of JSON, for the agent process's stdin.

        Contains secrets: write it only to the agent's stdin pipe.
        """
        body: Dict[str, Any] = {"session_token": self.session_token}
        if self.proxy_token:
            body["proxy_token"] = self.proxy_token
        if self.proxy_token_expires_at is not None:
            body["proxy_token_expires_at"] = self.proxy_token_expires_at.isoformat()
        if self.root_run_handle_id:
            body["root_run_handle_id"] = self.root_run_handle_id
        return json.dumps(body, separators=(",", ":"))

    # ── the agent side ───────────────────────────────────────────────

    @classmethod
    def from_json(cls, text: str) -> "RunGrant":
        """Parse :meth:`to_json` output. Closed shape, bounded size."""
        if not isinstance(text, str) or len(text.encode()) > _MAX_GRANT_BYTES:
            raise InvalidCredential("the run grant is malformed")
        try:
            body = json.loads(text)
        except ValueError as exc:
            raise InvalidCredential("the run grant is malformed") from exc
        if not isinstance(body, dict) or set(body) - _GRANT_FIELDS:
            raise InvalidCredential("the run grant is malformed")
        return cls.from_session_response(body)

    @classmethod
    def from_stdin(cls, stream: Optional[IO[str]] = None) -> "RunGrant":
        """Read the grant the launcher wrote to this process's stdin."""
        line = (stream or sys.stdin).readline(_MAX_GRANT_BYTES + 1)
        return cls.from_json(line.strip())

    @classmethod
    def from_env(cls, environ: Optional[MutableMapping[str, str]] = None) -> "RunGrant":
        """Read the grant from ``WATCHLIGHT_RUN_CREDENTIAL`` (+ optional
        ``WATCHLIGHT_RUN_PROXY_TOKEN``, ``WATCHLIGHT_RUN_HANDLE_ID``), then
        REMOVE those variables, so a child process this agent later starts
        (a tool, a shell) does not inherit the run's credential.

        Prefer :meth:`from_stdin`: every process in a workload can read the
        environment it was started with.
        """
        env = os.environ if environ is None else environ
        token = env.get(RUN_GRANT_ENV_VAR, "").strip()
        if not token:
            raise InvalidCredential(f"{RUN_GRANT_ENV_VAR} is not set")
        proxy = env.get(RUN_PROXY_TOKEN_ENV_VAR, "").strip() or None
        handle = env.get(RUN_HANDLE_ID_ENV_VAR, "").strip() or None
        grant = cls(session_token=token, proxy_token=proxy, root_run_handle_id=handle)
        for name in (RUN_GRANT_ENV_VAR, RUN_PROXY_TOKEN_ENV_VAR, RUN_HANDLE_ID_ENV_VAR):
            env.pop(name, None)
        return grant


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
