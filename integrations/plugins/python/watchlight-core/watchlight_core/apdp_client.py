"""Async HTTP client for WL-APDP — single source of truth.

This client previously lived in three near-identical copies
under ``watchlight_adk``, ``watchlight_langgraph``, and
``watchlight_bedrock``. Now there is exactly one implementation and
every plugin imports it from here.

The wire format with WL-APDP is the contract for every framework
plugin. If a new APDP route is added, it goes in this file; the
plugins inherit it for free.

Design notes:

- Lazy ``httpx.AsyncClient`` so the client binds to whichever event
  loop is in use at first call (matters for notebooks, Streamlit's
  threaded executor, and Lambda warm starts).
- Per-call ``try/except`` for transport errors — every method either
  returns a structured payload, ``None`` (transport / 404), or a
  fail-closed Deny payload (for ``authorize``). Plugins translate
  ``None`` into framework-appropriate errors.
- Authentication: pass ``credential=Credential.from_env()`` (the
  unified credential model).
  The legacy ``api_key=`` parameter still works but emits a
  :class:`DeprecationWarning`; it will be removed in a future release.
- Channel safety: at construction the client rejects ``http://`` URLs
  to non-loopback hosts. HTTPS uses TLS 1.3 minimum
  by default; operators can override via ``tls_min_version=`` and
  pin a custom CA bundle via ``ca_bundle=``.
- mTLS: pass ``mtls_cert_path=`` + ``mtls_key_path=`` to opt into
  client-cert authentication. The customer / operator
  is the sole CA — Watchlight never ships certs. Plain HTTP +
  mTLS is rejected (the cert/key would have nothing to bind to).
- No tool-call secrets are injected by this client; that's the
  secrets broker and wl-proxy's job. The credential header here
  authenticates the *plugin* to APDP, not anything downstream.
"""

import asyncio
import base64
import binascii
import hashlib
import heapq
import json
import logging
import os
import re
import secrets
import ssl
import time
import warnings
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlparse

import httpx

from ._lineage_retry import (
    MAX_IDLE_LANES,
    MAX_PENDING_EVENTS_PER_RUN,
    LineageRetryPolicy,
    RetryRunner,
    RunLane,
    SendOutcome,
    direct_attempt_in_context,
    on_decision_path,
)
from .backend import (
    EgressBinding,
    KillCallback,
    KillNotice,
    KillSubscriptions,
    RunRef,
    SessionInfo,
    Unsubscribe,
    fire_kill_callback,
    public_session_record,
)
from .credentials import Credential
from .errors import (
    CREDENTIAL_BINDS_NO_AGENT,
    CredentialBindsNoAgent,
    CredentialProbeFailed,
    GovernanceRefused,
    GovernanceUnavailable,
    InsecureChannelError,
    ParentRunUncredentialed,
    RunHandleInvalidated,
    RunUncredentialed,
    ScopeAttenuationDenied,
    ScopeViolationDimension,
)
from .log import get_logger
from .results import authorize_response_problem

logger = get_logger("watchlight_core.apdp_client")

#: A typed refusal code the server sends: bounded snake_case, never text.
_REFUSAL_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")

#: wl-apdp's stable codes for an agent it refuses to run.
_TRUST_REFUSAL_CODES = frozenset({"agent_trust_revoked", "agent_quarantined", "agent_unverified"})


def _code(value: Any) -> Optional[str]:
    """``value`` when it is a typed refusal code, else ``None``."""
    if isinstance(value, str) and _REFUSAL_CODE.fullmatch(value):
        return value
    return None


def typed_refusal(body: Any) -> Tuple[Optional[str], Optional[str]]:
    """The ``(error, reason)`` refusal codes in a wl-apdp error body.

    wl-apdp sends a refusal code in one of these shapes:
    ``{"error": "<code>"}`` (a refused spawn), ``{"reason": "<code>"}``,
    or ``{"error": {"code": "<code>", "reason": "<code>", ...}}`` (the
    typed error envelope). Only a bounded snake_case code is returned,
    never free text from the body: a body may carry a message the caller
    must not log.
    """
    if not isinstance(body, dict):
        return None, None
    error = body.get("error")
    reason = _code(body.get("reason"))
    if isinstance(error, dict):
        return _code(error.get("code")), reason or _code(error.get("reason"))
    return _code(error), reason


# Loopback hostnames that are exempt from the HTTPS-required rule.
# Listed once so the test suite can import the constant for parity
# instead of duplicating the literal set.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


def _enforce_channel_safety(base_url: str) -> None:
    """Reject ``http://`` to non-loopback hosts.

    Loopback exemption (``localhost`` / ``127.0.0.1`` / ``::1``) —
    local dev is the only case where plain HTTP is acceptable, and
    even there it is allowed only because the network never leaves
    the host.

    Escape hatch — ``WATCHLIGHT_APDP_ALLOW_PLAINTEXT=true`` bypasses
    the non-loopback rule. This is for compose / k8s sidecar
    topologies where the APDP host is reachable only on a private
    bridge that never leaves the node (the same threat model that
    justifies the loopback exemption). This mirrors the plaintext
    opt-out pattern used by other Watchlight services.
    NEVER set this in production — TLS is mandatory across any
    network boundary the customer doesn't control.

    Raises :class:`InsecureChannelError` on misconfiguration so the
    failure surfaces at constructor time, not the first request.
    """
    parsed = urlparse(base_url)
    if parsed.hostname is None:
        raise InsecureChannelError(
            f"ApdpClient: base_url {base_url!r} has no hostname. "
            "Expected an absolute URL like 'https://apdp.example.com'."
        )
    if parsed.hostname in _LOOPBACK_HOSTS:
        return  # local dev / sidecar — TLS not required
    if parsed.scheme == "https":
        return
    if os.environ.get("WATCHLIGHT_APDP_ALLOW_PLAINTEXT", "").lower() in ("1", "true"):
        return  # operator-explicit opt-out for private-bridge deployments
    raise InsecureChannelError(
        f"ApdpClient: base_url {base_url!r} uses scheme {parsed.scheme!r} "
        "to a non-loopback host. Plain HTTP would expose the bearer "
        "credential on the wire. Use 'https://', set the host to "
        "'localhost' / '127.0.0.1' for local dev, or set "
        "WATCHLIGHT_APDP_ALLOW_PLAINTEXT=true for private-bridge "
        "deployments (compose / sidecar) where the link never leaves "
        "the node."
    )


def mtls_paths_from_env(
    prefix: str = "WATCHLIGHT_APDP_",
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Read the standard mTLS-path env vars.

    Returns ``(cert_path, key_path, ca_bundle)`` — each ``None`` when
    the corresponding env var is unset or empty after stripping
    whitespace. The default prefix matches the documented
    convention:

    - ``WATCHLIGHT_APDP_MTLS_CERT_PATH``
    - ``WATCHLIGHT_APDP_MTLS_KEY_PATH``
    - ``WATCHLIGHT_APDP_TLS_CA_BUNDLE``

    Pass a different ``prefix`` (e.g. ``"WATCHLIGHT_PROXY_"``) for
    other Watchlight services that adopt the same convention.

    Empty / whitespace-only values are treated as unset because
    ``.env`` loaders (and CI matrix generators) commonly leave the
    variable defined as ``""`` when the operator deliberately chose
    not to configure mTLS, and a literal empty path would error at
    file-open time with no helpful context.
    """

    def _read(name: str) -> Optional[str]:
        raw = os.environ.get(prefix + name)
        if raw is None:
            return None
        stripped = raw.strip()
        return stripped if stripped else None

    return (_read("MTLS_CERT_PATH"), _read("MTLS_KEY_PATH"), _read("TLS_CA_BUNDLE"))


def _validate_mtls_config(
    *,
    is_https: bool,
    cert_path: Optional[Path],
    key_path: Optional[Path],
) -> None:
    """Validate the mTLS pair before the SSL context tries to load it.

    Three rules:

    1. Cert and key are paired — passing one without the other is a
       programmer error. The ``ssl`` module would happily accept just
       a cert and produce undefined behaviour at handshake time;
       explicit early refusal makes the misconfiguration obvious.
    2. mTLS requires HTTPS. A plain-HTTP loopback channel has no TLS
       handshake to bind the cert to; refusing the combination
       prevents accidentally configuring "encrypted client identity"
       on an unencrypted channel.
    3. Both files must be readable. ``ssl.SSLContext.load_cert_chain``
       raises a fairly opaque error if the path is missing; we
       surface a clean :class:`InsecureChannelError` with the offending
       path so ops triage doesn't require reading the ``ssl`` source.

    Raises :class:`InsecureChannelError` on any rule violation.
    """
    if cert_path is None and key_path is None:
        return  # mTLS not configured

    if cert_path is None or key_path is None:
        missing = "mtls_key_path" if cert_path is not None else "mtls_cert_path"
        raise InsecureChannelError(
            f"ApdpClient: mTLS requires both mtls_cert_path and mtls_key_path; "
            f"{missing} was not supplied. Pass both paths together."
        )

    if not is_https:
        raise InsecureChannelError(
            f"ApdpClient: mTLS configured (cert={cert_path}, key={key_path}) "
            "but base_url is plain HTTP. Client certificates only authenticate "
            "during a TLS handshake — pass an https:// URL."
        )

    for label, path in (("cert", cert_path), ("key", key_path)):
        if not path.is_file():
            raise InsecureChannelError(
                f"ApdpClient: mTLS {label} path {str(path)!r} does not exist "
                "or is not a regular file."
            )


def _build_ssl_context(
    tls_min_version: ssl.TLSVersion,
    ca_bundle: Optional[Path],
    mtls_cert_path: Optional[Path] = None,
    mtls_key_path: Optional[Path] = None,
) -> ssl.SSLContext:
    """Construct an :class:`ssl.SSLContext` for outbound HTTPS to APDP.

    Default is TLS 1.3 minimum; operators with legacy
    APDP infrastructure can downgrade to ``ssl.TLSVersion.TLSv1_2``.
    A custom CA bundle pins trust to a customer-managed CA (private
    PKI, internal corporate CA, etc.); ``None`` falls through to the
    system default trust store.

    When both ``mtls_cert_path`` and ``mtls_key_path`` are supplied,
    the loaded cert chain is attached so the server can authenticate
    the plugin via client-cert. Watchlight does not ship or sign
    certs — the customer / operator is the sole CA. Caller is
    responsible for ensuring both paths are set together; passing
    only one is a programmer error caught at
    :class:`ApdpClient.__init__`.
    """
    ctx = ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None)
    ctx.minimum_version = tls_min_version
    if mtls_cert_path is not None and mtls_key_path is not None:
        # ``load_cert_chain`` raises FileNotFoundError on missing
        # files and ssl.SSLError on a bad PEM — both surface as
        # InsecureChannelError in the constructor's pre-check below,
        # so by this point the files are known-good.
        ctx.load_cert_chain(
            certfile=str(mtls_cert_path),
            keyfile=str(mtls_key_path),
        )
    return ctx


#: RFC 8693 token type for an OpenID Connect ID token, the ``subject_token``
#: type wl-apdp accepts at session creation.
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"


#: Agent trust states wl-apdp treats as cleared to run. Anything else —
#: `unverified`, `quarantined`, `compromised` — is refused.
TRUSTED_AGENT_STATES = ("trusted", "approved")


def trust_from_resolved(resolved: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The trust verdict carried by a resolver payload, or ``None``.

    ``POST /agents/resolve`` already returns the agent's ``trust_state``,
    so a caller that has just resolved a slug needs no second request —
    and must not make one: ``GET /agents/:id`` is a control-plane read
    that a plugin's data-plane bearer is not authorized for (401), which
    turned a passing trust check into a refused run.

    ``None`` means this transport does not carry a trust state (the
    in-process engine, which has no trust service); the caller falls back
    to :meth:`ApdpClient.check_agent_trust`. It never means "trusted".
    """
    state = resolved.get("trust_state")
    if not isinstance(state, str) or not state.strip():
        return None
    state = state.strip()
    return {
        "trusted": state in TRUSTED_AGENT_STATES,
        "trust_state": state,
        "reason": f"Trust state: {state}",
    }


def _describe_http_error(exc: BaseException) -> str:
    """Value-free description of a client error for logs: the error class
    and, for an HTTP status error, the status code. Never the error text,
    the URL or the response body (they can carry internal hostnames,
    tokens echoed by a proxy, or request data)."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


#: Ended runs whose credentials are kept for their late lineage (an
#: ``execution_completed`` / ``execution_failed`` event published after the
#: session close, and its queued retries). Oldest first out; a run past this
#: bound is unknown, and its later publishes are refused.
MAX_ENDED_RUNS = 1024

_RUN_REF_PREFIX = "run_"

#: Lifetime assumed for a run whose credential names no expiry and whose
#: opener gave no TTL (a grant without an ``exp`` claim). A live run is
#: dropped from the table, credentials and all, once it expires.
DEFAULT_RUN_TTL_SECONDS = 3600
#: The expiry heap is rebuilt from the run table once it holds more than
#: twice the table's size plus this many entries, so entries for runs that
#: already left the table (ended and evicted, or wiped) do not pile up.
EXPIRY_HEAP_SLACK = 64
#: After a run ends, its run credential stays in the client only while the
#: run's lineage drains (its terminal event is published after the session
#: close) plus this many seconds; MAX_ENDED_RUNS and the credential's own
#: expiry remain the backstops.
ENDED_RUN_GRACE_SECONDS = 60.0


def _sst_expiry(token: Optional[str]) -> Optional[float]:
    """The ``exp`` claim (epoch seconds) of an ``sst_`` credential, read
    WITHOUT verification to bound how long the client keeps it; ``None``
    when absent or malformed."""
    if not isinstance(token, str) or not token.startswith("sst_"):
        return None
    body, sep, _sig = token[4:].partition(".")
    if not sep or not body:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (ValueError, TypeError, binascii.Error):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        return float(exp)
    return None


def decode_proxy_token_exec_id(token: Optional[str]) -> Optional[str]:
    """Best-effort read of the ``exec_id`` claim from a wl-apdp proxy
    token: the client reading its OWN credential to learn the root
    ``execution_id`` wl-apdp bound into it, so the in-process emit stream
    and the wl-proxy egress lineage share one id.

    Decodes the JWT payload only, WITHOUT signature verification; this is
    not a trust decision. Returns ``None`` on any malformed or absent input.
    """
    if not token or not isinstance(token, str):
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(raw)
    except (ValueError, TypeError, binascii.Error):
        return None
    if not isinstance(claims, dict):
        return None
    exec_id = claims.get("exec_id")
    return exec_id if isinstance(exec_id, str) and exec_id else None


def _parse_proxy_token_fields(
    response: Mapping[str, Any],
    token_key: str = "proxy_token",
    expires_key: str = "proxy_token_expires_at",
) -> Tuple[Optional[str], Optional[datetime]]:
    """``(proxy_token, expires_at)`` from a wl-apdp response. Both ``None``
    when no proxy token was issued; an unparseable expiry is ``None`` and
    logged (the token itself never is)."""
    if not isinstance(response, Mapping):
        return None, None
    token = response.get(token_key)
    if not isinstance(token, str) or not token:
        return None, None
    from .scope import _parse_rfc3339

    expires_raw = response.get(expires_key)
    expires_at: Optional[datetime] = None
    if isinstance(expires_raw, datetime):
        expires_at = expires_raw
    elif isinstance(expires_raw, str) and expires_raw:
        expires_at = _parse_rfc3339(expires_raw)
        if expires_at is None:
            # Fail-soft: the token stays usable, its issuer-side expiry
            # still applies. The value itself is not logged.
            logger.warning("%s not RFC3339-parseable", expires_key)
    return token, expires_at


@dataclass
class _RunCredentials:
    """One run's credentials, held only inside :class:`ApdpClient`."""

    session_id: str
    agent_id: str
    session_token: Optional[str]
    proxy_token: Optional[str]
    proxy_token_expires_at: Optional[datetime]
    parent: Optional[RunRef] = None
    ended: bool = False
    #: Epoch seconds after which the run is dropped from the table.
    expires_at: float = 0.0
    #: The run credential's own expiry (the hard bound for ``expires_at``).
    credential_expires_at: float = 0.0

    def __repr__(self) -> str:
        return (
            f"_RunCredentials(session_id={self.session_id!r}, "
            f"agent_id={self.agent_id!r}, session_token=<redacted>, "
            f"proxy_token=<redacted>, ended={self.ended!r})"
        )

    __str__ = __repr__


class ApdpClient:
    """Lightweight async client for WL-APDP.

    See module docstring for the full design. Construct with either:

    - ``credential=Credential.from_env()`` — preferred; the unified
      credential model.
    - ``api_key="wlapdp_ak_..."`` — legacy admin-API-key path, kept
      for backwards compatibility with code that hasn't migrated.
      Emits :class:`DeprecationWarning`.

    Passing both ``credential=`` and ``api_key=`` is a programmer
    error and raises :class:`ValueError`.

    **Run credentials.** Implements
    :class:`~watchlight_core.backend.GovernanceBackend`. Each run the client
    opens (:meth:`create_session`), spawns (:meth:`spawn_subagent`) or
    adopts (:meth:`adopt_run_grant`) gets an opaque
    :data:`~watchlight_core.backend.RunRef`; the run's ``sst_`` session
    token and its wl-proxy token stay in this client's run table and are
    attached to requests here. A run reference the client did not issue is
    refused, and so is one whose run has ended (except for the run's late
    lineage, :meth:`publish_events` and :meth:`drain`).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        api_key: Optional[str] = None,
        credential: Optional[Credential] = None,
        tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
        ca_bundle: Optional[Union[Path, str]] = None,
        mtls_cert_path: Optional[Union[Path, str]] = None,
        mtls_key_path: Optional[Union[Path, str]] = None,
        auto_probe: bool = True,
        lineage_retry: Optional[LineageRetryPolicy] = None,
        proxy_url: Optional[str] = None,
    ):
        _enforce_channel_safety(base_url)

        if api_key is not None and credential is not None:
            raise ValueError(
                "ApdpClient: pass either credential= or api_key=, not both. "
                "credential= (Credential.from_env()) is the supported path; "
                "api_key= is deprecated and exists only for backwards "
                "compatibility."
            )

        if api_key is not None:
            warnings.warn(
                "ApdpClient(api_key=) is deprecated; use "
                "credential=Credential.from_env() instead. "
                "The api_key= parameter will be removed in a future release.",
                DeprecationWarning,
                stacklevel=2,
            )

        self._base_url = base_url
        self._timeout = timeout
        self._api_key = api_key
        self._credential = credential
        self._tls_min_version = tls_min_version
        self._ca_bundle = Path(ca_bundle) if ca_bundle is not None else None
        self._mtls_cert_path = Path(mtls_cert_path) if mtls_cert_path is not None else None
        self._mtls_key_path = Path(mtls_key_path) if mtls_key_path is not None else None
        self._is_https = urlparse(base_url).scheme == "https"
        self._client: Optional[httpx.AsyncClient] = None

        # One-shot latch for the ``terminate_session`` deprecation
        # warning. Warn loudly the first time so the no-op is visible in
        # ops logs, but don't spam once per failed run.
        self._terminate_deprecation_logged = False

        # Manifest-fetch failures are logged at WARNING once
        # per agent (keyed by the agent id the manifest was asked for), then
        # at DEBUG. The manifest is advisory pre-flight guidance, so a real
        # failure must be visible in ops logs — but the plugin opens a run
        # per invocation, and one WARN per run for the same agent is noise
        # that hides the signal.
        self._manifest_failures_logged: set = set()

        # Lineage / run-end reporting retries a transient refusal (429,
        # 502, 503, 504, transport error) within a bounded budget; see
        # ``watchlight_core._lineage_retry``. ``authorize`` never goes
        # through it.
        self._lineage_retry = RetryRunner(
            lineage_retry if lineage_retry is not None else LineageRetryPolicy.from_env()
        )
        # One delivery lane per run, keyed by a digest of the run
        # credential: ordering, background queue, degraded state. Idle
        # healthy lanes are dropped at once; idle degraded ones are kept
        # (LRU, bounded) so the run stays degraded.
        self._lanes: "OrderedDict[str, RunLane]" = OrderedDict()
        self._max_idle_lanes = MAX_IDLE_LANES
        # Delivery counters (process-lifetime, value-free).
        self._lineage_counters: Dict[str, int] = {
            "retries": 0,
            "delivered_after_retry": 0,
            "exhausted": 0,
            "refused": 0,
            "queued": 0,
            "dropped_queue_full": 0,
            "cancelled": 0,
        }
        self._cancel_logged = False

        # Run table: RunRef -> the run's credentials. The only place in
        # the SDK that holds a run's ``sst_`` and wl-proxy tokens. Ended
        # runs stay (for their late lineage) up to MAX_ENDED_RUNS, oldest
        # first out.
        self._runs: Dict[RunRef, _RunCredentials] = {}
        self._ended_runs: "OrderedDict[RunRef, None]" = OrderedDict()
        # (expiry, run) min-heap: a live run is dropped at its credential
        # or TTL expiry, so runs nobody closes do not pile up.
        self._run_expiry: List[Tuple[float, RunRef]] = []
        self._clock = time.time
        self._kill_subs = KillSubscriptions()
        # The egress proxy reported on a run's EgressBinding (informational:
        # plugins install egress from their own configuration).
        self._proxy_url = proxy_url or os.getenv("WATCHLIGHT_PROXY_URL") or None

        # Startup probe state. The probe runs once on
        # the first authenticated method call when ``auto_probe`` is
        # True. The lock prevents a thundering herd of first calls
        # from each issuing their own GET /health.
        self._auto_probe = auto_probe
        self._probed = False
        self._probe_result: Optional[Dict[str, Any]] = None
        self._probe_lock: Optional[asyncio.Lock] = None  # lazy — bound to caller's loop

        _validate_mtls_config(
            is_https=self._is_https,
            cert_path=self._mtls_cert_path,
            key_path=self._mtls_key_path,
        )

    @property
    def credential(self) -> Optional[Credential]:
        """The credential this client authenticates with (``None`` for the
        legacy ``api_key=`` path or an unauthenticated client). Read-only;
        its ``repr`` is redacted."""
        return self._credential

    @property
    def lineage_delivery_counters(self) -> Dict[str, int]:
        """Process-lifetime counts for lineage and run-end reporting:
        ``retries`` (transient results retried), ``delivered_after_retry``,
        ``exhausted`` (gave up while the server was still transient),
        ``refused`` (a definitive non-2xx), ``queued`` (batches handed to
        background delivery), ``dropped_queue_full`` (events refused
        because the run's queue was full) and ``cancelled`` (publishes
        cancelled before delivery). A copy; value-free."""
        return dict(self._lineage_counters)

    @staticmethod
    def _lane_key(session_token: str) -> str:
        return hashlib.sha256(session_token.encode("utf-8")).hexdigest()

    def _lane(self, key: str) -> RunLane:
        lane = self._lanes.get(key)
        if lane is None:
            lane = RunLane()
            self._lanes[key] = lane
        else:
            self._lanes.move_to_end(key)
        return lane

    def _release_lane(self, key: str) -> None:
        lane = self._lanes.get(key)
        if lane is not None and lane.idle() and not lane.degraded:
            del self._lanes[key]
        if len(self._lanes) > self._max_idle_lanes:
            # Oldest first (the dict is kept in least-recently-used order).
            for k in [k for k, ln in self._lanes.items() if ln.idle()]:
                if len(self._lanes) <= self._max_idle_lanes:
                    break
                del self._lanes[k]

    # ─── Run table ────────────────────────────────────────────────

    def _register_run(
        self,
        *,
        session_id: str,
        agent_id: str,
        session_token: Optional[str],
        proxy_token: Optional[str] = None,
        proxy_token_expires_at: Optional[datetime] = None,
        parent: Optional[RunRef] = None,
        ttl_seconds: Optional[float] = None,
    ) -> RunRef:
        """Record a run's credentials and return its new opaque reference.

        The run is kept until its ``sst_`` credential's ``exp`` (else the
        opener's ``ttl_seconds``, else its parent's expiry, else
        DEFAULT_RUN_TTL_SECONDS); past that it is dropped.

        A run without a run credential is never registered: every call for
        a run carries the run's own credential, never the plugin bearer
        alone. Raises :class:`RunUncredentialed`."""
        if not isinstance(session_token, str) or not session_token:
            logger.warning(
                "run refused: wl-apdp opened session %s without a run "
                "credential (reason=run_uncredentialed)",
                session_id,
            )
            raise RunUncredentialed(
                "the governance backend opened a run without a run credential; "
                "refusing the run (no call for it may go out on the plugin "
                "credential alone)"
            )
        now = self._clock()
        self._sweep_expired(now)
        run = RunRef(_RUN_REF_PREFIX + secrets.token_urlsafe(18))
        expires_at = _sst_expiry(session_token)
        if expires_at is None and ttl_seconds is not None:
            expires_at = now + float(ttl_seconds)
        if expires_at is None and parent is not None and parent in self._runs:
            expires_at = self._runs[parent].expires_at
        if expires_at is None:
            expires_at = now + DEFAULT_RUN_TTL_SECONDS
        self._runs[run] = _RunCredentials(
            session_id=session_id,
            agent_id=agent_id,
            session_token=session_token,
            proxy_token=proxy_token if isinstance(proxy_token, str) and proxy_token else None,
            proxy_token_expires_at=proxy_token_expires_at,
            parent=parent,
            expires_at=expires_at,
            credential_expires_at=expires_at,
        )
        heapq.heappush(self._run_expiry, (expires_at, run))
        return run

    def _sweep_expired(self, now: float) -> None:
        """Drop every run (live or ended) whose expiry has passed from the
        client's state; a live one's kill subscribers are told. An ended
        run whose lineage is still being delivered is kept one more grace
        period, never past its credential's expiry."""
        while self._run_expiry and self._run_expiry[0][0] <= now:
            expires_at, run = heapq.heappop(self._run_expiry)
            entry = self._runs.get(run)
            if entry is None or entry.expires_at != expires_at:
                continue  # an entry for a run that already left the table
            if (
                entry.ended
                and now < entry.credential_expires_at
                and self._lineage_in_flight(entry)
            ):
                entry.expires_at = min(
                    now + ENDED_RUN_GRACE_SECONDS, entry.credential_expires_at
                )
                heapq.heappush(self._run_expiry, (entry.expires_at, run))
                self._schedule_sweep(ENDED_RUN_GRACE_SECONDS)
                continue
            if not entry.ended:
                self._kill_subs.notify(
                    KillNotice(run=run, reason="run_expired", source="backend")
                )
            self._forget_run(run)

    def _lineage_in_flight(self, entry: _RunCredentials) -> bool:
        if not entry.session_token:
            return False
        lane = self._lanes.get(self._lane_key(entry.session_token))
        return lane is not None and lane.busy()

    def _schedule_sweep(self, delay: float) -> None:
        """Sweep again after ``delay`` seconds on the running loop, so an
        ended run leaves the client on time even when no other call comes.
        Best effort: without a loop the next call's sweep does it."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.call_later(max(delay, 0.0) + 0.01, lambda: self._sweep_expired(self._clock()))

    def _forget_run(self, run: RunRef) -> None:
        """Drop the run and its credentials from the client's state: the
        entry's token fields are set to ``None`` and an idle delivery lane
        for the run is dropped with whatever it held (the string objects
        themselves stay in memory until garbage-collected). A lane still
        delivering queued lineage keeps its own reference until its queue is
        sent, then drops it (``_lane_worker``)."""
        entry = self._runs.pop(run, None)
        self._ended_runs.pop(run, None)
        self._kill_subs.discard(run)
        if entry is None:
            return
        token = entry.session_token
        entry.session_token = None
        entry.proxy_token = None
        entry.proxy_token_expires_at = None
        if token:
            key = self._lane_key(token)
            lane = self._lanes.get(key)
            if lane is not None and lane.idle():
                lane.token = None
                del self._lanes[key]
        self._compact_expiry_heap()

    def _compact_expiry_heap(self) -> None:
        """Rebuild the expiry heap from the run table when stale entries
        (for runs no longer in it) make up most of it: bounded memory
        across many start/end cycles, amortised O(1) per run."""
        if len(self._run_expiry) <= 2 * len(self._runs) + EXPIRY_HEAP_SLACK:
            return
        self._run_expiry = [(e.expires_at, r) for r, e in self._runs.items()]
        heapq.heapify(self._run_expiry)

    def _release_dropped_run(self, run: RunRef) -> None:
        """A run handle was garbage-collected without closing its run: end
        the run here (client-side, no request). Its egress token is dropped
        at once; its run credential is kept only for late lineage (see
        :meth:`_end_run`). Never raises."""
        try:
            self._end_run(run, "handle_dropped")
        except Exception:  # noqa: BLE001 - a finalizer never raises
            pass

    def _run_credential(
        self, run: Optional[RunRef], operation: str, *, allow_ended: bool = False
    ) -> Optional[str]:
        """The run's own credential, or ``None`` (logged, value-free) when
        the run is unknown, ended (unless ``allow_ended``) or holds no
        credential. Callers re-check after any ``await`` before sending, so
        a run that left the client meanwhile is never sent for."""
        entry = self._lookup_run(run, operation, allow_ended=allow_ended)
        if entry is None:
            return None
        if not entry.session_token:
            logger.warning(
                "%s refused: the run holds no run credential "
                "(reason=run_uncredentialed, session=%s)",
                operation,
                entry.session_id,
            )
            return None
        return entry.session_token

    def _lookup_run(
        self, run: Optional[RunRef], operation: str, *, allow_ended: bool = False
    ) -> Optional[_RunCredentials]:
        """The run's credentials, or ``None`` (logged, value-free) when the
        reference is unknown, or names an ended run and ``allow_ended`` is
        false. Callers turn ``None`` into their own fail-closed answer."""
        self._sweep_expired(self._clock())
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None:
            logger.warning(
                "%s refused: the run reference is unknown to this client "
                "(reason=unknown_run)",
                operation,
            )
            return None
        if entry.ended and not allow_ended:
            logger.warning(
                "%s refused: the run has ended (reason=run_ended, session=%s)",
                operation,
                entry.session_id,
            )
            return None
        return entry

    def _end_run(self, run: RunRef, reason: str) -> None:
        """Mark the run ended: control calls on it are refused from now on,
        its kill subscribers are told, and its egress token is dropped
        (egress is refused for an ended run). Its run credential is kept
        only for its late lineage: until that lineage has drained plus
        ENDED_RUN_GRACE_SECONDS, within MAX_ENDED_RUNS (oldest dropped
        first) and the credential's own expiry.

        So a terminal lineage event published more than the grace (60 s)
        after the run's close is refused (``publish_events`` returns
        ``False``), and a run whose lane never drains keeps its credential
        until the credential expires, unless MAX_ENDED_RUNS evicts it
        first."""
        entry = self._runs.get(run)
        if entry is None or entry.ended:
            return
        entry.ended = True
        entry.proxy_token = None
        entry.proxy_token_expires_at = None
        grace_until = self._clock() + ENDED_RUN_GRACE_SECONDS
        if grace_until < entry.expires_at:
            entry.expires_at = grace_until
            heapq.heappush(self._run_expiry, (grace_until, run))
            self._schedule_sweep(ENDED_RUN_GRACE_SECONDS)
        self._kill_subs.notify(KillNotice(run=run, reason=reason, source="backend"))
        self._ended_runs[run] = None
        while len(self._ended_runs) > MAX_ENDED_RUNS:
            old = next(iter(self._ended_runs))
            self._forget_run(old)

    def _session_info(
        self, run: RunRef, response: Mapping[str, Any], execution_id: Optional[str]
    ) -> SessionInfo:
        entry = self._runs[run]
        # Only documented, non-secret session fields reach the caller.
        public = public_session_record(response.get("session"))
        root = response.get("root_run_handle_id")
        return SessionInfo(
            run=run,
            session_id=entry.session_id,
            agent_id=entry.agent_id,
            execution_id=execution_id,
            root_run_handle_id=root if isinstance(root, str) and root else None,
            session=public,
        )

    def adopt_run_grant(self, grant: Any) -> SessionInfo:
        """Register a launcher-issued :class:`~watchlight_core.RunGrant`
        as a run of this client and return its
        :class:`~watchlight_core.backend.SessionInfo`. The grant's
        credentials move into the run table; callers keep only the
        reference."""
        from .run_grant import RunGrant

        if not isinstance(grant, RunGrant):
            raise TypeError("adopt_run_grant needs a RunGrant")
        run = self._register_run(
            session_id=grant.session_id,
            agent_id=grant.agent_id,
            session_token=grant.session_token,
            proxy_token=grant.proxy_token,
            proxy_token_expires_at=grant.proxy_token_expires_at,
        )
        execution_id = grant.execution_id or decode_proxy_token_exec_id(grant.proxy_token)
        return SessionInfo(
            run=run,
            session_id=grant.session_id,
            agent_id=grant.agent_id,
            execution_id=execution_id,
            root_run_handle_id=grant.root_run_handle_id,
            session=public_session_record(
                {"id": grant.session_id, "agent_id": grant.agent_id}
            ),
        )

    def run_authorization(self, run: RunRef) -> str:
        """``Bearer <run credential>`` for presenting the run to a Watchlight
        enforcement point outside this client (an MCP PEP that checks
        ``X-Wl-Run-Authorization``). Not part of
        :class:`~watchlight_core.backend.GovernanceBackend`. Raises
        :class:`GovernanceUnavailable` for an unknown or ended run, or a
        run that holds no credential."""
        entry = self._lookup_run(run, "run_authorization")
        if entry is None or not entry.session_token:
            raise GovernanceUnavailable(
                "run_authorization: no run credential for this run reference"
            )
        return f"Bearer {entry.session_token}"

    def egress_for(self, run: RunRef) -> Optional[EgressBinding]:
        """The run's wl-proxy egress binding, or ``None`` when wl-apdp issued
        no proxy token for it (or the reference is unknown or ended). The
        token is resolved from the run table each time it is asked for."""
        entry = self._lookup_run(run, "egress_for")
        if entry is None or not entry.proxy_token:
            return None

        def _token() -> Optional[str]:
            self._sweep_expired(self._clock())
            current = self._runs.get(run)
            if current is None or current.ended:
                return None
            return current.proxy_token

        return EgressBinding(
            proxy_url=self._proxy_url,
            expires_at=entry.proxy_token_expires_at,
            token_source=_token,
        )

    def subscribe_kill(self, run: RunRef, callback: KillCallback) -> Unsubscribe:
        """Register ``callback`` for the run's end. This client has no push
        channel from wl-apdp yet: the callback fires when the run ends in
        this client (:meth:`complete_session`, :meth:`terminate_session`).
        An unknown or already-ended run fires it at once (fail closed)."""
        self._sweep_expired(self._clock())
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None or entry.ended:
            fire_kill_callback(
                callback,
                KillNotice(
                    run=run,
                    reason="unknown_run" if entry is None else "run_ended",
                    source="backend",
                ),
            )
            return lambda: None
        return self._kill_subs.subscribe(run, callback)

    async def drain(self, run: RunRef, timeout_s: Optional[float] = None) -> None:
        """Wait for the run's background lineage deliveries, at most
        ``timeout_s`` seconds (default: one retry budget). The run handle
        calls this when the run ends, so its queued lineage is not left
        behind; a delivery still running when the wait ends carries on."""
        self._sweep_expired(self._clock())
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None or not entry.session_token:
            return
        await self._drain_lane(entry.session_token, timeout_s)

    async def _drain_lane(
        self, session_token: Optional[str], timeout: Optional[float] = None
    ) -> None:
        if not session_token:
            return
        lane = self._lanes.get(self._lane_key(session_token))
        if lane is None or not lane.worker_active():
            return
        if timeout is None:
            timeout = self._lineage_retry.policy.max_wait_seconds
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while lane.worker is not None and not lane.worker.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                return
            await asyncio.wait({lane.worker}, timeout=remaining)

    def _count_retry(self) -> None:
        self._lineage_counters["retries"] += 1

    def _build_auth_headers(self) -> Dict[str, str]:
        """Build the auth headers attached to every outbound request.

        - ``credential=``: emits ``Authorization: Bearer <token>`` and
          ``X-Wl-Credential-Kind`` (so the server's prefix-routing
          middleware can short-circuit before the DB lookup). No
          tenant header: wl-apdp takes the tenant only from the
          verified credential, never from a header the client sets
         .
        - ``api_key=``: emits only ``Authorization: Bearer <key>``;
          the existing bcrypt-API-key path on the server doesn't need
          the discriminator headers.
        - Neither set: no auth headers (used by tests / health-check
          probes that hit unauthenticated endpoints).
        """
        headers: Dict[str, str] = {}
        if self._credential is not None:
            headers["Authorization"] = f"Bearer {self._credential.bearer_token}"
            headers["X-Wl-Credential-Kind"] = self._credential.kind
        elif self._api_key is not None:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    # ─── Startup probe ────────────────────────────────────────────

    async def probe(self) -> Dict[str, Any]:
        """Validate the credential against the server before any
        meaningful traffic flows.

        Calls ``GET /health`` with the credential headers attached.
        On success returns the parsed JSON body — typically
        ``{"auth": "ok", "kind": "plugin", "credential_label": ...,
        "expires_at": ...}``. On any failure raises
        :class:`CredentialProbeFailed` carrying the HTTP status code:

        - ``401`` — credential invalid / missing / expired / revoked
        - ``403`` — credential doesn't satisfy required claims
        - ``404`` — APDP isn't running at this URL
        - ``status_code=None`` — transport failure (connect refused,
          DNS, TLS handshake)

        Idempotent: the result is cached on ``self._probe_result`` so
        subsequent ``probe()`` calls return the cached dict without
        hitting the network. Operators who want to force a re-probe
        construct a new ApdpClient.

        ## Why probe at first-call instead of in __init__

        Python ``__init__`` is synchronous; making it async would
        force every customer to use a special async-construction
        idiom. Probing before the first authenticated request is
        functionally equivalent — no real traffic flows until the
        credential is validated — at the cost of one extra HTTP
        round-trip on the cold path.
        """
        try:
            resp = await self.client.get("/health")
        except httpx.RequestError as e:
            raise CredentialProbeFailed(
                f"ApdpClient: probe to {self._base_url}/health failed "
                f"(transport error: {e.__class__.__name__})",
                status_code=None,
            ) from e

        if resp.status_code == 200:
            try:
                payload = resp.json()
            except ValueError:
                # /health returned 200 but a non-JSON body — older
                # APDP versions returned plain text. Accept the
                # success signal but emit an empty payload so callers
                # can branch on truthy fields without exploding.
                payload = {}
            self._probe_result = payload
            self._probed = True
            return payload

        # Non-200: map status codes to actionable error messages so
        # operator triage doesn't require reading the server source.
        status = resp.status_code
        if status == 401:
            reason = (
                "credential invalid / missing / expired / revoked. "
                "Re-issue or rotate the credential."
            )
        elif status == 403:
            reason = (
                "credential does not satisfy required claims. "
                "Check tenant_id / kind / scope on the issued token."
            )
        elif status == 404:
            reason = (
                "APDP service not found at this URL. "
                "Verify base_url and that the server is running."
            )
        else:
            reason = f"unexpected status {status}"
        raise CredentialProbeFailed(
            f"ApdpClient: probe to {self._base_url}/health returned "
            f"{status}: {reason}",
            status_code=status,
        )

    async def _ensure_probed(self) -> None:
        """Run the startup probe at most once per ApdpClient instance.

        Called from every authenticated request method when
        ``auto_probe=True`` (the default) and a credential is
        configured. Skips when:

        - ``auto_probe=False`` — operator manages probe explicitly
        - No credential — the legacy ``api_key=`` path doesn't
          enforce probe (backwards compat for existing customer code)
        - Already probed — fast-path returns immediately

        Concurrent first calls serialize on ``self._probe_lock`` so
        only ONE probe fires; subsequent waiters see ``_probed=True``
        and short-circuit.
        """
        if self._probed:
            return
        if not self._auto_probe:
            return
        if self._credential is None:
            return

        if self._probe_lock is None:
            # Bind the lock to the running loop the first time we
            # need it. Constructing the lock in __init__ would tie
            # it to the caller's loop, which breaks the lazy-loop
            # pattern that the rest of this client relies on.
            self._probe_lock = asyncio.Lock()

        async with self._probe_lock:
            if self._probed:
                return  # another caller probed while we were waiting
            await self.probe()

    @property
    def client(self) -> httpx.AsyncClient:
        """Lazily-constructed httpx client, recreated if previously closed.

        This pattern matters in three deployment shapes:

        1. **Notebooks / Streamlit** — the constructor often runs in a
           different event loop than the first call.
        2. **Lambda warm starts** — the previous invocation may have
           closed the client; we transparently rebuild.
        3. **Test fixtures** — pytest-asyncio creates a fresh loop per
           test; lazy init avoids cross-loop client reuse warnings.
        """
        if self._client is None or self._client.is_closed:
            headers = self._build_auth_headers()
            kwargs: Dict[str, Any] = {
                "base_url": self._base_url,
                "timeout": self._timeout,
                "headers": headers,
                # Never take HTTP(S)_PROXY / ALL_PROXY / NO_PROXY from the
                # environment: once the CONNECT sidecar is installed those
                # point at wl-proxy, and backend calls carry the plugin
                # bearer and the run's ``sst_`` credential, which must go
                # straight to wl-apdp and never traverse the egress proxy.
                "trust_env": False,
            }
            if self._is_https:
                # Build the SSL context per-client so the lazy-rebuild
                # path picks up any post-construction config changes
                # (rare; mostly a defense for test fixtures that mutate
                # ca_bundle between requests).
                kwargs["verify"] = _build_ssl_context(
                    self._tls_min_version,
                    self._ca_bundle,
                    self._mtls_cert_path,
                    self._mtls_key_path,
                )
            self._client = httpx.AsyncClient(**kwargs)
        return self._client

    # ─── Identity ─────────────────────────────────────────────────

    async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
        """Resolve a slug to canonical agent UUID.

        Returns the resolver payload (``{id, slug, name, trust_state, ...}``)
        on hit, ``None`` on 404, 403 or an answer that names no agent.
        Plugins translate ``None`` to
        :class:`watchlight_core.AgentNotRegistered`, so every non-hit is
        logged with what it actually was — a 403 is a credential that
        carries no tenant, not a missing agent.

        When the server could not answer the question, it is not reported
        as a missing agent: a refused credential (401) raises
        :class:`GovernanceRefused`; a licence refusal (402), a server error
        or no answer at all raises :class:`GovernanceUnavailable`. Either
        way the caller refuses the run.
        """
        await self._ensure_probed()
        try:
            resp = await self.client.post("/agents/resolve", json={"slug": slug})
            if resp.status_code == 404:
                logger.warning("agent slug '%s' not registered with Watchlight", slug)
                return None
            if resp.status_code == 403:
                # Not "the agent is missing" — the CREDENTIAL is wrong.
                # An agent slug is unique per tenant, so wl-apdp resolves
                # one only for a caller whose credential carries a verified
                # tenant. A service (``wlsa_``) credential is cross-tenant
                # by design and carries none, so it is refused for every
                # slug. Returning ``None`` here is still correct — the
                # caller must fail closed — but the plugins above translate
                # ``None`` to ``AgentNotRegistered``, and without this line
                # an operator reads "agent not registered" for an agent
                # that is registered and a token that is not tenant-bound.
                logger.error(
                    "agent resolve refused (403) for slug '%s'. This is a "
                    "CREDENTIAL problem, not a missing agent — use a "
                    "tenant-bound plugin ('wlpa_') credential",
                    slug,
                )
                return None
            if resp.status_code == 401:
                raise GovernanceRefused(
                    "wl-apdp refused the plugin credential (401) while resolving the "
                    "agent; configure a valid plugin credential",
                    status_code=401,
                )
            if resp.status_code == 402:
                raise GovernanceUnavailable(
                    "wl-apdp refused the request for its licence (402) while resolving "
                    "the agent; the agent was not looked up"
                )
            resp.raise_for_status()
            resolved = resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            # The server did not answer (refused, timed out, reset, 5xx):
            # not "no agent". The caller refuses the run on the raise.
            logger.warning("agent resolve failed: %s", _describe_http_error(e))
            raise GovernanceUnavailable(
                f"wl-apdp could not resolve the agent ({_describe_http_error(e)})"
            ) from None
        except ValueError:
            logger.warning("agent resolve answered with a non-JSON body; refusing")
            return None
        if not isinstance(resolved, dict) or not isinstance(resolved.get("id"), str) or not resolved["id"]:
            logger.warning("agent resolve answered without an agent id; refusing")
            return None
        return resolved

    # ─── Authorization ────────────────────────────────────────────

    async def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
        session_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        run: Optional[RunRef] = None,
    ) -> Dict[str, Any]:
        """Authoritative authorization decision via APDP ``/authorize``.

        Always returns a dict with at least ``decision``. On transport
        failure or HTTP error, returns ``{"decision": "Deny", "reason": ...}``
        — the fail-closed shape callers can rely on without inventing
        their own sentinel.

        ``run`` — the run this decision belongs to. Its ``sst_`` credential
        (from this client's run table) is attached as a
        SIGNED run credential on the ``X-Wl-Run-Authorization`` header so
        wl-apdp can bind THIS authorization decision's lineage to the run
        from the token's VERIFIED ``eid`` / ``rid`` claims — never from the
        spoofable request body / context. The ``Authorization`` header still
        carries the caller's plugin/service credential: authentication (who is
        calling) and lineage-binding (which run this decision belongs to) are
        separate concerns, so the run credential rides its own header rather
        than displacing the caller's. When ``run`` is ``None`` no run
        credential is sent; an unknown or ended ``run`` is a Deny without a
        request (fail closed).
        """
        session_token: Optional[str] = None
        if run is not None:
            if self._run_credential(run, "authorize") is None:
                return {"decision": "Deny", "reason": "unknown, ended or uncredentialed run"}
        # ``principal`` / ``action`` / ``resource`` go on the wire EXACTLY as
        # given. This is a published public method: silently rewriting a
        # caller's terms here would change what wl-apdp evaluates for anyone
        # calling it directly (wl-apdp infers a BARE term's entity type from
        # the selected policy's metadata, but takes a TYPED one at face
        # value, so a rewrite can flip a decision). Cedar-wrapping for callers
        # who pass bare terms is ``BaseRunHandle``'s job — see
        # ``watchlight_core._cedar_entities``.
        request: Dict[str, Any] = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": context or {},
        }
        if execution_id:
            request["execution_id"] = execution_id
        if session_id:
            request["session_id"] = session_id
        if intent:
            request["intent"] = intent
        await self._ensure_probed()
        if run is not None:
            # Re-checked after the await: the run may have left the client.
            session_token = self._run_credential(run, "authorize")
            if session_token is None:
                return {"decision": "Deny", "reason": "unknown, ended or uncredentialed run"}
        # Per-request header merge: httpx layers these over the client's
        # default auth headers, so the plugin Authorization stays and the
        # run credential is added for THIS request only.
        req_headers: Optional[Dict[str, str]] = None
        if session_token:
            req_headers = {"X-Wl-Run-Authorization": f"Bearer {session_token}"}
        try:
            resp = await self.client.post("/authorize", json=request, headers=req_headers)
            resp.raise_for_status()
            body = resp.json()
        except httpx.HTTPStatusError as e:
            logger.warning("APDP authorization failed: HTTP %s", e.response.status_code)
            return {"decision": "Deny", "reason": f"APDP error: {e.response.status_code}"}
        except httpx.ConnectError:
            logger.error("Cannot reach WL-APDP (ConnectError); failing closed to Deny")
            return {"decision": "Deny", "reason": "APDP unreachable"}
        except httpx.RequestError as e:
            # Timeout, protocol error, read/write error: the decision is
            # unknown, so it is a Deny (fail closed), never an exception a
            # caller might swallow and carry on from.
            logger.error(
                "WL-APDP authorize transport failure (%s); failing closed to Deny",
                type(e).__name__,
            )
            return {"decision": "Deny", "reason": "APDP transport failure"}
        except ValueError:
            # A 200 whose body is not JSON (an intercepting proxy page, a
            # truncated answer) carries no decision: fail closed.
            logger.error("WL-APDP authorize returned a non-JSON body; failing closed to Deny")
            return {"decision": "Deny", "reason": "APDP returned a non-JSON response"}
        except Exception as e:  # noqa: BLE001 - any failure is an unknown decision
            # A failure nobody planned for (a broken transport, an HTTP
            # library bug) leaves the decision unknown: a Deny, never an
            # exception a caller might swallow and carry on from.
            logger.error(
                "WL-APDP authorize failed unexpectedly (%s); failing closed to Deny",
                type(e).__name__,
            )
            return {"decision": "Deny", "reason": "APDP client failure"}
        problem = authorize_response_problem(body)
        if problem is not None:
            # Not a decision wl-apdp sends: truncated, tampered with or from
            # a broken server. Never read as the decision it appears to name.
            logger.error(
                "WL-APDP authorize returned an unrecognised response (%s); "
                "failing closed to Deny",
                problem,
            )
            return {"decision": "Deny", "reason": "APDP returned an unrecognised response"}
        return body

    # ─── Plan governance ──────────────────────────────────────────

    async def get_manifest(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        ttl_seconds: int = 3600,
        run: Optional[RunRef] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Fetch the pre-flight ``ConstraintManifest`` for ``agent_id``.

        **The run's grant.** With ``run``, the run's ``sst_``
        credential is sent on ``X-Wl-Run-Authorization`` (the plugin
        credential stays on ``Authorization``). wl-apdp then bounds the
        manifest by the run's verified grant (its application ceiling within
        the agent's tools) instead of re-deriving it. Without a token,
        ``application_id`` names the AI application to bound it by.

        Returns the inner manifest dict, or ``None`` when the fetch failed.
        Plugins pass the result to :func:`watchlight_core.require_manifest`,
        which refuses the run on ``None`` unless the operator explicitly
        set ``WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade``.

        **Unknown goal.** A run opened under a ``goal_id`` wl-apdp
        has no record of is *not* a failure: wl-apdp answers 200 with the
        agent's constraints, an empty ``active_goal`` and
        ``unresolved_goal_id`` naming the goal it could not resolve. That
        manifest is returned as-is and logged at DEBUG only — no warning.

        **A refusal raises.** A ``401`` / ``403`` (the agent's trust is
        revoked, the run credential is refused) raises
        :class:`watchlight_core.errors.GovernanceRefused` carrying the
        server's typed code (``code``, e.g. ``agent_trust_revoked``). It is
        never ``None``: degraded mode must not let a refused agent run.

        **Real failures** (unknown agent → 404, connect / timeout) are
        logged at WARNING the first time they occur for a given ``agent_id``
        and at DEBUG afterwards, so an ops log shows the problem once rather
        than once per run. A subsequent successful fetch re-arms the WARNING
        for that agent, so a later outage is reported again.
        """
        session_token: Optional[str] = None
        if run is not None and self._run_credential(run, "get_manifest") is None:
            # Unknown, ended or uncredentialed run: no manifest (the plugin
            # refuses the run unless the operator opted into degraded mode).
            return None
        body: Dict[str, Any] = {"agent_id": agent_id, "ttl_seconds": ttl_seconds}
        if goal_id:
            body["goal_id"] = goal_id
        if application_id:
            body["application_id"] = application_id
        await self._ensure_probed()
        if run is not None:
            session_token = self._run_credential(run, "get_manifest")
            if session_token is None:
                return None
        req_headers: Optional[Dict[str, str]] = None
        if session_token:
            req_headers = {"X-Wl-Run-Authorization": f"Bearer {session_token}"}
        try:
            resp = await self.client.post(
                "/constraints/manifest", json=body, headers=req_headers
            )
            if resp.status_code in (401, 403):
                # The server refused this agent (revoked trust, a refused
                # run credential): not an outage, so never "no manifest"
                # (which degrade mode would let through). The typed code
                # tells the caller why.
                raise self._manifest_refused(agent_id, resp)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError, ValueError) as e:
            # Any uncertain answer (status, transport, non-JSON) is "no
            # manifest"; plan governance then refuses the run unless the
            # operator explicitly opted into degraded mode.
            self._log_manifest_failure(agent_id, e)
            return None
        # A successful fetch re-arms the once-per-agent WARNING so a LATER
        # outage for this agent is visible again rather than buried at DEBUG.
        self._manifest_failures_logged.discard(agent_id)
        # The endpoint wraps the manifest in an envelope:
        #   {"manifest": {...}, "message": "..."}
        # Return the inner ConstraintManifest so callers read its
        # fields (identity, tool_allowlist, governed_proxy_hosts, ...)
        # directly — matching MockApdpClient.get_manifest. Fall back to
        # the raw body if a server ever returns an unwrapped manifest.
        manifest = data["manifest"] if isinstance(data, dict) and "manifest" in data else data
        if not isinstance(manifest, dict):
            self._log_manifest_failure(
                agent_id, ValueError(f"manifest is a {type(manifest).__name__}, not an object")
            )
            return None
        if isinstance(manifest, dict) and manifest.get("unresolved_goal_id"):
            # Documented empty-goal manifest — the agent is known, the
            # goal is not seeded server-side. Quiet by design.
            logger.debug(
                "manifest for agent %s carries no goal section: goal %s is not "
                "known to wl-apdp (unresolved_goal_id)",
                agent_id,
                manifest["unresolved_goal_id"],
                extra={"agent_id": agent_id},
            )
        return manifest

    def _manifest_refused(self, agent_id: str, resp: httpx.Response) -> GovernanceRefused:
        """The :class:`GovernanceRefused` for a refused manifest fetch."""
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {}
        error, reason = typed_refusal(body)
        code = reason or error
        logger.warning(
            "constraint manifest refused for agent %s (status=%s, code=%s); "
            "refusing the run",
            agent_id,
            resp.status_code,
            code or "-",
            extra={"agent_id": agent_id},
        )
        return GovernanceRefused(
            f"wl-apdp refused the constraint manifest for agent {agent_id} "
            f"(status={resp.status_code}, code={code or '-'}); refusing the run",
            status_code=resp.status_code,
            error=error,
            reason=reason,
        )

    def _log_manifest_failure(self, agent_id: str, exc: Exception) -> None:
        """WARNING once per agent, DEBUG thereafter (see :meth:`get_manifest`)."""
        if isinstance(exc, httpx.HTTPStatusError):
            detail = f"APDP returned {exc.response.status_code}"
        else:
            detail = type(exc).__name__
        if agent_id in self._manifest_failures_logged:
            logger.debug(
                "manifest fetch failed (again) for agent %s: %s",
                agent_id,
                detail,
                extra={"agent_id": agent_id},
            )
            return
        self._manifest_failures_logged.add(agent_id)
        logger.warning(
            "manifest fetch failed for agent %s: %s — the run is refused unless "
            "WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade; further failures for this "
            "agent are logged at DEBUG",
            agent_id,
            detail,
            extra={"agent_id": agent_id},
        )

    async def create_session(
        self,
        agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
    ) -> Optional[SessionInfo]:
        """Open a run (``POST /sessions``) and return its
        :class:`~watchlight_core.backend.SessionInfo`. The run's ``sst_``
        credential and wl-proxy token stay in this client's run table;
        the caller gets only the run reference. ``None`` when wl-apdp did
        not accept the session (or answered without a session id). Raises
        :class:`~watchlight_core.errors.RunUncredentialed` when wl-apdp
        opened the session without a run credential (no run is
        registered), and :class:`~watchlight_core.errors.GovernanceRefused`
        when wl-apdp refused it for the agent's trust state.

        ``agent_id=None`` (the default) names no agent: wl-apdp opens the
        run as the agent the client's verified credential is bound to, and
        ``SessionInfo.agent_id`` is that agent. A credential bound to no
        single agent raises
        :class:`~watchlight_core.errors.CredentialBindsNoAgent`. A named
        agent is an optional override that wl-apdp confirms against an
        agent-bound credential (a mismatch is refused, opaquely: ``None``)."""
        response = await self._post_session(
            agent_id=agent_id,
            goal_id=goal_id,
            max_actions=max_actions,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
            subject_token=subject_token,
            application_id=application_id,
        )
        if response is None:
            return None
        session = response.get("session") if isinstance(response, Mapping) else None
        session_id = session.get("id") if isinstance(session, Mapping) else None
        if not isinstance(session_id, str) or not session_id:
            logger.warning("session create answered without a session id; refusing the run")
            return None
        # The agent the run belongs to is the one wl-apdp names. Without a
        # requested agent it is the credential's agent; with one it must be
        # that agent. Anything else is refused: the run is never registered.
        served = session.get("agent_id") if isinstance(session, Mapping) else None
        served = served if isinstance(served, str) and served else None
        if served is None and agent_id is None:
            logger.warning(
                "session create named no agent and wl-apdp's answer names none; "
                "refusing the run"
            )
            return None
        if served is not None and agent_id is not None and served != agent_id:
            logger.warning(
                "session create: wl-apdp opened the run for another agent than the "
                "one named; refusing the run"
            )
            return None
        run_agent = served or agent_id
        assert run_agent is not None  # checked above
        proxy_token, proxy_expires_at = _parse_proxy_token_fields(response)
        run = self._register_run(
            session_id=session_id,
            agent_id=run_agent,
            session_token=response.get("session_token"),
            proxy_token=proxy_token,
            proxy_token_expires_at=proxy_expires_at,
            ttl_seconds=ttl_seconds,
        )
        # Execution-lineage integrity: the canonical root execution id
        # wl-apdp minted (bound into the session token's ``eid`` claim and
        # the proxy token); an older server that names none in the body
        # still binds it into the proxy token.
        execution_id = response.get("execution_id")
        if not isinstance(execution_id, str):
            execution_id = decode_proxy_token_exec_id(proxy_token)
        return self._session_info(run, response, execution_id)

    async def create_run_grant(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        application_id: Optional[str] = None,
        workload_ref: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """Open a run for ANOTHER process and return its
        :class:`~watchlight_core.RunGrant` (redacted ``repr``, not
        picklable): the launcher path, where the credential is
        handed to the agent process on its stdin. The run is not entered in
        this client's run table. ``None`` when wl-apdp refused."""
        from .run_grant import RunGrant

        response = await self._post_session(
            agent_id=agent_id,
            goal_id=goal_id,
            max_actions=max_actions,
            ttl_seconds=ttl_seconds,
            metadata=metadata,
            application_id=application_id,
            workload_ref=workload_ref,
        )
        if response is None:
            return None
        return RunGrant.from_session_response(response)

    async def _post_session(
        self,
        agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
        workload_ref: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """``POST /sessions``; the raw response (it carries credentials and
        never leaves this client except as a RunGrant)."""
        body: Dict[str, Any] = {}
        if agent_id is not None:
            # Naming the agent is an optional override: without it wl-apdp
            # opens the run as the agent the credential is bound to, and
            # with it wl-apdp refuses a name the credential does not match.
            # First, so a named agent's body is byte-for-byte what it was
            # (wl-sidecar's golden capture compares the bytes).
            body["agent_id"] = agent_id
        body["ttl_seconds"] = ttl_seconds
        if goal_id:
            body["goal_id"] = goal_id
        if max_actions is not None:
            body["max_actions"] = max_actions
        if metadata is not None:
            body["metadata"] = metadata
        if subject_token is not None:
            # RFC 8693: the run acts on behalf of the user this token names.
            # wl-apdp verifies it against a trusted identity provider and
            # binds the verified subject to the session and run credential.
            # The token is never logged: failures below log only the status.
            body["subject_token"] = subject_token
            body["subject_token_type"] = ID_TOKEN_TYPE
        if application_id is not None:
            # The AI application this run belongs to; wl-apdp checks
            # the agent is a member of it.
            body["application_id"] = application_id
        if workload_ref is not None:
            # The workload this run will execute in. Only a launcher
            # credential holding ``workload:bind`` may send it; wl-apdp
            # refuses the session for any other caller. See
            # :mod:`watchlight_core.launcher`.
            body["workload_ref"] = dict(workload_ref)
        await self._ensure_probed()
        try:
            resp = await self.client.post("/sessions", json=body)
            if resp.status_code in (401, 403):
                refusal = self._trust_refused_session(agent_id, resp)
                if refusal is not None:
                    raise refusal
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            # Any transport failure (refused, timed out, reset) opens no run.
            logger.warning("session create failed: %s", _describe_http_error(e))
            return None
        except ValueError:
            logger.warning("session create answered with a non-JSON body; refusing the run")
            return None

    def _trust_refused_session(
        self, agent_id: Optional[str], resp: httpx.Response
    ) -> Optional[GovernanceRefused]:
        """The :class:`GovernanceRefused` for a session refused for
        the agent's trust state (``agent_trust_revoked``,
        ``agent_quarantined``, ``agent_unverified``), or ``None`` for any
        other refusal (which stays opaque and reads as ``None``)."""
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            return None
        error, reason = typed_refusal(body)
        code = reason or error
        if code == CREDENTIAL_BINDS_NO_AGENT and agent_id is None:
            # The run named no agent and the credential binds none: a typed
            # refusal, so the caller learns to name the agent or use an
            # agent-bound credential. Never retried with a guessed agent.
            logger.warning(
                "session refused: the credential is not bound to one agent and the "
                "run named none (status=%s, code=%s); refusing the run",
                resp.status_code,
                code,
            )
            return CredentialBindsNoAgent(
                "wl-apdp refused to open the run: no agent was named and the "
                "credential is not bound to one agent. Name the agent, or use a "
                "credential bound to an agent.",
                status_code=resp.status_code,
            )
        if code not in _TRUST_REFUSAL_CODES:
            return None
        logger.warning(
            "session refused for agent %s (status=%s, code=%s); refusing the run",
            agent_id,
            resp.status_code,
            code,
            extra={"agent_id": agent_id},
        )
        return GovernanceRefused(
            f"wl-apdp refused to open a run for agent {agent_id} "
            f"(status={resp.status_code}, code={code}); refusing the run",
            status_code=resp.status_code,
            error=error,
            reason=reason,
        )

    async def submit_plan(
        self, run: RunRef, plan: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Submit the run's plan. ``None`` on failure, or for an unknown or
        ended run (no request)."""
        entry = self._lookup_run(run, "submit_plan")
        if entry is None:
            return None
        session_id = entry.session_id
        await self._ensure_probed()
        try:
            resp = await self.client.post(
                f"/sessions/{session_id}/plan", json={"plan": plan}
            )
            resp.raise_for_status()
            answer = resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            # Any transport failure (refused, timed out, reset) is "no
            # answer": the caller fails closed on None.
            logger.warning("plan submit failed: %s", _describe_http_error(e))
            return None
        except ValueError:
            logger.warning("plan submit answered with a non-JSON body; failing closed")
            return None
        if not isinstance(answer, dict):
            logger.warning("plan submit answered with a non-object body; failing closed")
            return None
        return answer

    async def preflight_step(
        self,
        run: RunRef,
        action: str,
        resource: str,
        resource_type: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Read-only check that this action+resource would be permitted.

        Optional ``resource_type`` lets the caller declare the Cedar
        resource type (e.g. ``Tool``, ``Document``) when the resource
        identifier alone is ambiguous. ADK uses this when the same
        identifier maps to multiple Cedar resource types; LangGraph
        and Bedrock typically rely on the resource string alone.

        ``None`` on failure, or for an unknown or ended run (no request).
        """
        entry = self._lookup_run(run, "preflight_step")
        if entry is None:
            return None
        session_id = entry.session_id
        body: Dict[str, Any] = {"action": action, "resource": resource}
        if resource_type:
            body["resource_type"] = resource_type
        if intent:
            body["intent"] = intent
        if context:
            body["context"] = context
        await self._ensure_probed()
        try:
            resp = await self.client.post(
                f"/sessions/{session_id}/preflight", json=body
            )
            resp.raise_for_status()
            answer = resp.json()
        except (httpx.HTTPStatusError, httpx.RequestError) as e:
            # Any transport failure (refused, timed out, reset) is "no
            # answer": the caller fails closed on None.
            logger.warning("preflight failed: %s", _describe_http_error(e))
            return None
        except ValueError:
            logger.warning("preflight answered with a non-JSON body; failing closed")
            return None
        if not isinstance(answer, dict):
            logger.warning("preflight answered with a non-object body; failing closed")
            return None
        return answer

    # ─── Trust + lineage ──────────────────────────────────────────

    async def check_agent_trust(self, agent_id: str) -> Dict[str, Any]:
        """Check whether an agent is registered and currently trusted.

        Returns ``{"trusted": bool, "trust_state": str, "reason": str}``.
        Always returns a dict — on 404 / transport failure the dict has
        ``trusted=False`` so callers can rely on the shape without
        inventing a fail-closed sentinel.
        """
        await self._ensure_probed()
        try:
            resp = await self.client.get(f"/agents/{agent_id}")
            if resp.status_code == 404:
                return {"trusted": False, "reason": f"Agent '{agent_id}' not registered"}
            resp.raise_for_status()
            agent = resp.json().get("agent", {})
            trust_state = agent.get("trust_state", "unverified")
            trusted = trust_state in TRUSTED_AGENT_STATES
            return {
                "trusted": trusted,
                "trust_state": trust_state,
                "reason": f"Trust state: {trust_state}",
            }
        except Exception as e:  # noqa: BLE001 — fail-closed wrapper
            # Fail closed; the log names the error class (and status) only:
            # the raw client error carries the internal URL.
            logger.warning(
                "agent trust check failed for %s: %s", agent_id, _describe_http_error(e)
            )
            return {
                "trusted": False,
                "trust_state": "unknown",
                "reason": "trust state could not be verified",
            }

    async def publish_events(
        self,
        run: Optional[RunRef],
        events: List[Dict[str, Any]],
    ) -> bool:
        """Publish a batch of execution-lineage events through APDP.

        APDP is the event gateway — plugins do NOT talk to NATS
        directly. ``events`` is a list of canonical ``ExecutionEvent``
        dicts. An empty list returns ``True`` without making a network
        call.

        Execution-lineage integrity. ``run`` names the emitting run; its
        PER-RUN ``sst_`` credential (from this client's run table) is
        REQUIRED: emission is run-credential-only. The token is attached as the
        ``Authorization: Bearer`` header for THIS request ONLY (never
        mutating the shared client's default headers), and wl-apdp binds
        every event's identity to the session it was issued for.

        There is NO shared-bearer fallback: the shared tenant
        plugin/service bearer is refused on the emission path, so if
        the run is unknown (or past the ended-run bound) or holds no run
        credential this returns ``False`` WITHOUT sending
        the request (fail-closed — we never emit under the tenant bearer).
        A missing token means the caller didn't thread the run credential;
        that's a wiring bug to fix, not a reason to fall back.

        Delivery is retried on a transient result — ``429``, ``502``,
        ``503`` (wl-apdp cannot yet know the run's state), ``504`` and
        transport errors — with exponential backoff and jitter, honouring
        ``Retry-After``, within a bounded budget
        (``WATCHLIGHT_LINEAGE_RETRY_MAX_ATTEMPTS``, default 6;
        ``WATCHLIGHT_LINEAGE_RETRY_MAX_WAIT_SECONDS``, default 30, a hard
        wall-clock bound). Any other non-2xx is the server's answer and is
        never retried. Awaited publishes for the same run go out in call
        order; a retried batch keeps its place.

        Two cases never wait (see ``watchlight_core._lineage_retry``):

        * On the governance decision path (``lineage_decision_path``), the
          batch gets one attempt when the run's lane is free; if the lane
          is busy, or the answer is transient, it is queued for background
          delivery and this returns ``True``. It can then land after a
          batch that was being retried when it was emitted.
        * A *degraded* run (an earlier batch exhausted its budget) gets the
          same treatment until a delivery succeeds, so a sustained outage
          costs one attempt per publish, not the whole budget.

        Returns ``True`` when delivered or queued for background delivery;
        ``False`` on a missing run credential, a definitive non-2xx, a
        transient failure that outlasted the budget (logged once at WARNING
        with ``reason=lineage_retry_exhausted``, value-free, and counted in
        :attr:`lineage_delivery_counters`), or a full run queue. It never
        raises, except :class:`asyncio.CancelledError` (counted, logged
        once).
        """
        if not events:
            return True
        # An ended run's late lineage (its terminal event, published after
        # the session close) is still delivered under its own credential.
        session_token = (
            self._run_credential(run, "publish_events", allow_ended=True)
            if run is not None
            else None
        )
        if session_token is not None:
            await self._ensure_probed()
            # Re-checked after the await: a run that left the client during
            # the probe must not put its credential back into a lane.
            session_token = self._run_credential(run, "publish_events", allow_ended=True)
        if not session_token:
            # Fail-closed: never emit under the shared tenant bearer.
            logger.warning(
                "publish_events called without a per-run credential; "
                "refusing to emit %d event(s) under the shared bearer "
                "(run-credential-only emission)",
                len(events),
            )
            return False
        await self._ensure_probed()
        event_types = sorted(
            {str(e.get("event_type", "?")) for e in events if isinstance(e, dict)}
        )
        key = self._lane_key(session_token)
        lane = self._lane(key)
        try:
            if direct_attempt_in_context():
                # One direct attempt, outside the lane: never behind a
                # retry. A transient answer also queues the batch (dedup
                # on event_id makes a double delivery harmless), but the
                # caller still sees False and fails closed.
                outcome = await self._send_events(
                    events, session_token, single_attempt=True
                )
                if outcome.exhausted:
                    self._enqueue(
                        lane, key, session_token, events, delay=outcome.retry_delay
                    )
                    return False
                return self._publish_result(outcome, events, event_types, lane)
            if on_decision_path() or lane.degraded:
                # Never wait. The decision path (and a degraded run) gets
                # one attempt when the lane is free; a busy lane or a
                # transient answer hands the batch to background delivery.
                if lane.busy():
                    return self._enqueue(lane, key, session_token, events, delay=0.0)
                lane.users += 1
                try:
                    async with lane.lock:  # free: acquired without waiting
                        outcome = await self._send_events(
                            events, session_token, single_attempt=True
                        )
                finally:
                    lane.users -= 1
                if outcome.exhausted:
                    return self._enqueue(
                        lane, key, session_token, events, delay=outcome.retry_delay
                    )
                return self._publish_result(outcome, events, event_types, lane)
            # Awaited publish: in call order behind the run's queued and
            # in-flight work; a retried batch keeps its place.
            lane.users += 1
            try:
                while lane.worker is not None and not lane.worker.done():
                    await asyncio.wait({lane.worker})
                async with lane.lock:
                    outcome = await self._send_events(events, session_token)
            finally:
                lane.users -= 1
            return self._publish_result(outcome, events, event_types, lane)
        except asyncio.CancelledError:
            self._note_cancelled(len(events), event_types)
            raise
        except Exception as e:  # noqa: BLE001 - lineage never raises
            # Visible in ops logs: these events are not delivered and the
            # run's lineage is incomplete (value-free: type only).
            logger.warning(
                "APDP event publish error: %s; %d event(s) not delivered",
                type(e).__name__,
                len(events),
            )
            return False
        finally:
            self._release_lane(key)

    async def _send_events(
        self,
        events: List[Dict[str, Any]],
        session_token: str,
        *,
        single_attempt: bool = False,
    ) -> SendOutcome:
        # Per-run credential override. Attach the run-scoped ``sst_``
        # token for this request only; never mutate the shared client's
        # default headers.
        request_headers = {"Authorization": f"Bearer {session_token}"}
        return await self._lineage_retry.send(
            "publish_events",
            lambda timeout: self.client.post(
                "/v1/events", json=events, headers=request_headers, timeout=timeout
            ),
            client_timeout=self._timeout,
            single_attempt=single_attempt,
            on_retry=self._count_retry,
        )

    def _note_cancelled(self, count: int, event_types: List[str]) -> None:
        self._lineage_counters["cancelled"] += 1
        level = logging.DEBUG if self._cancel_logged else logging.WARNING
        self._cancel_logged = True
        logger.log(
            level,
            "lineage report cancelled before delivery "
            "(reason=lineage_publish_cancelled): %d event(s) (types: %s); "
            "further cancellations are only counted",
            count,
            ", ".join(event_types) or "unknown",
        )

    def _enqueue(
        self,
        lane: RunLane,
        key: str,
        session_token: str,
        events: List[Dict[str, Any]],
        *,
        delay: float,
    ) -> bool:
        """Queue a batch for background delivery behind the run's work.
        Returns ``True`` (accepted for delivery), or ``False`` when the
        run's queue is full."""
        if lane.pending_count + len(events) > MAX_PENDING_EVENTS_PER_RUN:
            self._lineage_counters["dropped_queue_full"] += len(events)
            if not lane.overflow_logged:
                lane.overflow_logged = True
                logger.error(
                    "lineage queue full for a run (reason=lineage_queue_full): "
                    "%d event(s) refused, %d already queued (limit %d). The "
                    "run's lineage is incomplete.",
                    len(events),
                    lane.pending_count,
                    MAX_PENDING_EVENTS_PER_RUN,
                )
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return False
        lane.token = session_token
        lane.pending.append(list(events))
        lane.pending_count += len(events)
        self._lineage_counters["queued"] += 1
        if not lane.worker_active():
            lane.worker = loop.create_task(self._lane_worker(lane, key, delay))
        return True

    async def _lane_worker(self, lane: RunLane, key: str, delay: float) -> None:
        """Deliver the run's queued batches in order, each pass with the
        full retry budget; batches queued meanwhile go in the next pass."""
        batch: List[Dict[str, Any]] = []
        try:
            if delay > 0:
                await self._lineage_retry.sleep(delay)
            while lane.pending and lane.token:
                async with lane.lock:
                    # Take the batch once the lane is ours, so events still
                    # waiting count against the run's queue cap.
                    batch = []
                    while lane.pending:
                        batch.extend(lane.pending.popleft())
                    lane.pending_count = 0
                    outcome = await self._send_events(batch, lane.token)
                types = sorted({str(e.get("event_type", "?")) for e in batch})
                self._publish_result(outcome, batch, types, lane)
                batch = []
        except asyncio.CancelledError:
            lost = len(batch) + lane.pending_count
            lane.pending.clear()
            lane.pending_count = 0
            self._note_cancelled(lost, ["queued"])
            raise
        except Exception as e:  # noqa: BLE001 - background delivery never raises
            logger.debug("lineage background delivery error: %s", type(e).__name__)
        finally:
            lane.worker = None
            if not lane.pending:
                # Nothing left to send under the run's credential: the lane
                # does not keep a copy (the run table is its one holder).
                lane.token = None
            self._release_lane(key)

    def _publish_result(
        self,
        outcome: SendOutcome,
        events: List[Dict[str, Any]],
        event_types: List[str],
        lane: Optional[RunLane] = None,
    ) -> bool:
        resp = outcome.response
        if resp is not None and 200 <= resp.status_code < 300:
            # APDP `/v1/events` returns 202 Accepted under the thin
            # pass-through (the events are emitted to NATS asynchronously);
            # older builds returned 200. Accept any 2xx so a correct,
            # accepted publish is never misread as a rejection. The
            # TypeScript lane already uses the same 2xx semantics.
            try:
                accepted = resp.json().get("accepted", len(events))
            except Exception:  # noqa: BLE001 - 2xx body is optional
                accepted = len(events)
            if outcome.attempts > 1:
                self._lineage_counters["delivered_after_retry"] += 1
            if lane is not None:
                lane.degraded = False
            logger.debug(
                "Published %d events via APDP (attempts=%d)",
                accepted,
                outcome.attempts,
            )
            return True
        if outcome.exhausted:
            # The server was still answering "not yet" (503 / 429) or
            # unreachable when the bounded budget ran out. One line per
            # batch, value-free: counts, types and the last status only,
            # never an event payload.
            self._lineage_counters["exhausted"] += 1
            if lane is not None:
                # Degraded: the run's later publishes get one attempt and
                # are then queued, instead of each spending the budget.
                lane.degraded = True
            # WARNING, not ERROR: ERROR here means "fix your emitter"
            # (a schema rejection); this is the transport giving up.
            logger.warning(
                "lineage delivery gave up (reason=lineage_retry_exhausted): "
                "%d event(s) not delivered after %d attempt(s), last result "
                "%s (types: %s). The run's lineage is incomplete; its later "
                "events get one attempt and are queued until one is accepted.",
                len(events),
                outcome.attempts,
                outcome.last_result,
                ", ".join(event_types) or "unknown",
            )
            return False
        self._lineage_counters["refused"] += 1
        if resp is not None and resp.status_code in (400, 422):
            # A schema rejection is a BUG IN THIS EMITTER, not a
            # transient transport failure, and the two must not read
            # the same in the log. wl-apdp decodes the batch against
            # the canonical `ExecutionEvent` struct and fails closed
            # on a mismatch, rejecting EVERY event in the batch — so
            # the whole run silently disappears from the
            # execution-lineage view. Publishing stays FAIL-OPEN
            # (lineage must never block a run), so this log line is
            # the only operator-visible trace: it is ERROR, it names
            # the event types that went out, and it says the run
            # will not appear in lineage. Never retried: the same
            # batch would be rejected again.
            #
            # `watchlight_core_testing.assert_payload_matches_schema`
            # (conformance invariant 16) is the gate that should have
            # caught this in the plugin's own test run.
            logger.error(
                "APDP REJECTED the lineage event batch as malformed: "
                "%d — this is an emitter schema bug, not a transport "
                "failure. All %d event(s) in the batch were dropped "
                "(types: %s) and this run will NOT appear in execution "
                "lineage. The payload does not match the canonical "
                "struct its event_type selects; validate the built "
                "event against watchlight_core.events_schema "
                "(conformance invariant 16) to find the offending "
                "field.",
                resp.status_code,
                len(events),
                ", ".join(event_types) or "unknown",
            )
            return False
        if resp is not None:
            # A definitive refusal (403, 409, 500, ...): never retried.
            logger.warning("APDP event publish failed: %d", resp.status_code)
        return False

    # ─── Sub-agent scope attenuation ──────────────────────────────

    async def spawn_subagent(
        self,
        parent: RunRef,
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Call ``POST /v1/spawn_subagent`` for the ``parent`` run and
        return the canonical response with the child's run reference.

        The child's ``sst_`` credential and wl-proxy token (minted by
        wl-apdp at spawn) go into this client's run table under a new
        :data:`~watchlight_core.backend.RunRef`, returned as
        ``child_run``; the returned dict carries no credential. An unknown
        or ended ``parent``, or an approval without a child credential,
        raises :class:`GovernanceUnavailable` (fail closed).
        """
        entry = self._lookup_run(parent, "spawn_subagent")
        if entry is None:
            raise GovernanceUnavailable(
                "spawn_subagent: the parent run is unknown or has ended; "
                "refusing the spawn"
            )
        if not entry.session_token:
            # The spawn is authenticated with the parent run's own
            # credential, never the shared tenant bearer. Without one the
            # child never runs: refused here, nothing is sent.
            logger.warning(
                "spawn_subagent refused: the parent run holds no run "
                "credential (reason=parent_uncredentialed, session=%s)",
                entry.session_id,
            )
            raise ParentRunUncredentialed(
                "spawn_subagent: the parent run holds no run credential (it "
                "was never issued one, or it was cleared); refusing to run "
                "the sub-agent."
            )
        await self._ensure_probed()
        # Re-checked after the await: the parent may have left the client.
        parent_token = self._run_credential(parent, "spawn_subagent")
        if parent_token is None:
            raise ParentRunUncredentialed(
                "spawn_subagent: the parent run ended or lost its run credential "
                "before the spawn was sent; refusing to run the sub-agent."
            )
        response = await self._post_spawn_subagent(request, parent_token)
        child_token = response.pop("child_session_token", None)
        child_proxy, child_proxy_expires = _parse_proxy_token_fields(
            response, "child_proxy_token", "child_proxy_token_expires_at"
        )
        response.pop("child_proxy_token", None)
        response.pop("child_proxy_token_expires_at", None)
        if not isinstance(child_token, str) or not child_token:
            # Without the child's own credential its lineage would be
            # dropped (run-credential-only emission). Refuse rather than
            # run the child unattributed.
            raise GovernanceUnavailable(
                "spawn_subagent: wl-apdp approved the spawn but returned no "
                "child session credential; refusing to run the sub-agent "
                "without attributable lineage."
            )
        child_handle = response.get("child_run_handle_id")
        if not isinstance(child_handle, str) or not child_handle:
            # Not the canonical shape: no run is registered, and the
            # caller's response parser refuses it.
            return response
        child_session_id = response.get("child_session_id")
        if not isinstance(child_session_id, str) or not child_session_id:
            child_session_id = f"ses_{child_handle}"
        # Swept first: a parent whose credential expired mid-spawn is gone.
        current_parent = self._lookup_run(parent, "spawn_subagent")
        if current_parent is None or not current_parent.session_token:
            # The parent ended while the spawn was in flight: its authority to
            # delegate is gone, so the child is never registered or run. Its
            # session is closed at wl-apdp under its own credential (best
            # effort; it also ends at its TTL).
            logger.warning(
                "spawn_subagent refused: the parent run ended while the spawn "
                "was in flight (reason=parent_ended_during_spawn)"
            )
            try:
                await self._complete_session_request(child_session_id, child_token)
            except Exception as exc:  # noqa: BLE001 - the refusal is what counts
                logger.debug("closing the refused child session failed: %s", type(exc).__name__)
            raise GovernanceUnavailable(
                "spawn_subagent: the parent run ended while the spawn was in "
                "flight; the sub-agent was not started."
            )
        # The agent the child runs as is the one wl-apdp names (a labelled
        # child's mapped agent, or its parent's for an anonymous child); an
        # older server that names none ran the requested agent.
        child_agent = response.get("child_agent_id") or (
            request.get("child_agent_id") if isinstance(request, Mapping) else None
        )
        child_run = self._register_run(
            session_id=child_session_id,
            agent_id=str(child_agent) if child_agent is not None else "",
            session_token=child_token,
            proxy_token=child_proxy,
            proxy_token_expires_at=child_proxy_expires,
            parent=parent,
        )
        if not response.get("child_execution_id"):
            adopted = decode_proxy_token_exec_id(child_proxy)
            if adopted:
                response["child_execution_id"] = adopted
        response["child_run"] = child_run
        return response

    async def _post_spawn_subagent(
        self,
        request_body: Dict[str, Any],
        session_token: Optional[str],
    ) -> Dict[str, Any]:
        """``POST /v1/spawn_subagent`` with the canonical
        request envelope; the parsed response dict (with credentials).

        ``request_body`` is the already-serialised
        :class:`SpawnSubagentRequest` (see
        :func:`watchlight_core.scope.spawn_subagent_request_to_dict`).
        The client is intentionally schema-thin at this boundary —
        :class:`watchlight_core.BaseRunHandle.spawn_subagent` owns the
        SDK-facing kwargs and marshalling.

        Execution-lineage integrity.
        ``session_token`` is the PARENT run's ``sst_`` credential
        (from the run table). wl-apdp's ``/v1/spawn_subagent``
        authenticates with it (NOT the shared tenant bearer) and derives
        the child's root / parent-exec / tenant from the parent's VERIFIED
        claims + server-mints the child ``execution_id`` — so a caller
        cannot graft a child subtree onto another run's tree. When
        provided it overrides the client's default bearer for THIS request
        only.

        Handles the structured error envelope server-side:

        - **200 OK**: returns the parsed JSON dict the caller can feed
          to :func:`spawn_subagent_response_from_dict`.
        - **403 Forbidden** with body
          ``{"reason": "scope_attenuation_violation", "violations": [...]}``:
          raises :class:`ScopeAttenuationDenied` carrying the typed
          dimension list. The strict-subset validator returns this
          when ``requested_scope`` exceeds ``parent_effective_scope``.
        - **404 Not Found** with body
          ``{"reason": "run_handle_invalidated", ...}``: raises
          :class:`RunHandleInvalidated`. This surfaces when the
          parent's handle has expired between issuance and spawn.
        - Other non-2xx, a transport failure, or a 200 that is not a JSON
          object: surfaces as
          :class:`watchlight_core.errors.GovernanceUnavailable` (a
          ``WatchlightError``) with the HTTP status code or the failure
          class in the message, so plugin authors can distinguish
          transport failures from policy denials. The child never runs.

        The server-side validator enforces the strict-subset
        semantics; this method ships the wire-level call.
        """
        await self._ensure_probed()
        # Per-run credential override: attach the parent's
        # run-scoped `sst_` token for this request only; never mutate the
        # shared client's default headers.
        request_headers: Optional[Dict[str, str]] = None
        if session_token:
            request_headers = {"Authorization": f"Bearer {session_token}"}
        try:
            resp = await self.client.post(
                "/v1/spawn_subagent", json=request_body, headers=request_headers
            )
        except httpx.ConnectError as exc:
            # Error class only: the transport text carries the internal URL.
            logger.error("Cannot reach WL-APDP for spawn_subagent (ConnectError)")

            raise GovernanceUnavailable(
                "spawn_subagent: APDP unreachable (reason=apdp_unreachable)"
            ) from exc
        except httpx.RequestError as exc:
            raise GovernanceUnavailable(
                "spawn_subagent: transport error talking to APDP "
                f"({type(exc).__name__}; reason=apdp_transport_error)"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - the child never runs
            logger.error("spawn_subagent failed unexpectedly (%s)", type(exc).__name__)
            raise GovernanceUnavailable(
                "spawn_subagent: the request to APDP failed "
                f"({type(exc).__name__}; reason=apdp_client_failure); "
                "refusing to run the sub-agent"
            ) from exc

        if resp.status_code == 200:
            try:
                parsed = resp.json()
            except ValueError as exc:
                raise GovernanceUnavailable(
                    "spawn_subagent: APDP returned 200 with non-JSON body"
                ) from exc
            if not isinstance(parsed, dict):
                raise GovernanceUnavailable(
                    "spawn_subagent: APDP returned 200 with a non-object body"
                )
            return parsed

        # Non-200 — try to decode the structured error envelope so we
        # can raise the most specific typed exception. APDP returns
        # ``{"reason": "...", "violations": [...]}`` for the canonical
        # cases; transient infrastructure errors (502/503/504) come
        # through as raw bodies and are surfaced as a generic
        # WatchlightError.
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {}
        reason = body.get("reason") if isinstance(body, dict) else None
        if not isinstance(reason, str):
            reason = ""
        # Both codes the server may send: ``{"error": "<code>"}`` (e.g.
        # ``delegation_chain_not_trusted``) and ``{"reason": "<code>"}``.
        refusal_error, refusal_reason = typed_refusal(body)

        if resp.status_code == 403 and reason == "scope_attenuation_violation":
            raw_violations = (
                body.get("violations") if isinstance(body, dict) else []
            )
            violations: List[ScopeViolationDimension] = []
            if isinstance(raw_violations, list):
                for v in raw_violations:
                    try:
                        violations.append(ScopeViolationDimension.from_wire(v))
                    except ValueError:
                        # An unknown dimension from a newer APDP — log
                        # for ops triage but do not block the typed
                        # exception. Operators reading the audit log
                        # see the raw wire string via the SDK warning;
                        # the SDK still raises the typed exception with
                        # the dimensions it CAN decode so the agent's
                        # framework can react.
                        logger.warning(
                            "spawn_subagent: APDP returned unknown "
                            "violation dimension %r; SDK is older than "
                            "the server",
                            v,
                        )
            def _int(v: Any) -> Optional[int]:
                return v if isinstance(v, int) and not isinstance(v, bool) else None

            code = body.get("reason_code") if isinstance(body, dict) else None
            raise ScopeAttenuationDenied(
                reason=reason,
                violations=violations,
                reason_code=code if isinstance(code, str) else None,
                observed_depth=_int(body.get("observed_depth")) if isinstance(body, dict) else None,
                max_delegation_depth=(
                    _int(body.get("max_delegation_depth")) if isinstance(body, dict) else None
                ),
            )

        if resp.status_code == 404 and reason == "run_handle_invalidated":
            raise RunHandleInvalidated(reason=reason)

        # Fallback — surface the status code and every typed code the
        # server sent (``error`` and ``reason``), never the raw body.
        codes = [
            f"{name}={value}"
            for name, value in (("error", refusal_error), ("reason", refusal_reason))
            if value
        ]
        detail = f": {', '.join(codes)}" if codes else ""
        message = f"spawn_subagent: APDP returned {resp.status_code}{detail}"
        if resp.status_code in (401, 403):
            # A definitive refusal: the child never runs.
            raise GovernanceRefused(
                message,
                status_code=resp.status_code,
                error=refusal_error,
                reason=refusal_reason,
            )

        raise GovernanceUnavailable(message)

    async def complete_session(self, run: RunRef) -> bool:
        """Close the run's session.

        Only the run itself may close it: the run's own ``sst_`` credential
        (from this client's run table) is sent on
        ``X-Wl-Run-Authorization`` while the client bearer stays on
        ``Authorization``. Without it wl-apdp refuses the close. An unknown
        or already-ended run returns ``False`` without a request. Once the
        close has been attempted the run is ended in this client: later
        control calls on it are refused, its late lineage still goes out.

        A transient answer (``503`` while the run end cannot yet be
        recorded or replicated, ``429`` when the run-end budget is spent,
        ``502`` / ``504``, a transport error) is retried within the same
        bounded budget as :meth:`publish_events`; any other non-2xx is
        final and never retried. The close does not queue behind the
        run's lineage (a degraded event plane must not hold it back); the
        run's terminal lineage event keeps its order through the run's
        lane. Returns only once the server accepted the close or the
        budget ran out (``False``, logged once with
        ``reason=session_complete_retry_exhausted``). Never raises, except
        :class:`asyncio.CancelledError`.
        """
        entry = self._lookup_run(run, "complete_session")
        if entry is None:
            return False
        session_id = entry.session_id
        session_token = entry.session_token
        if not session_token:
            # Never on the plugin credential alone: end it here, no request.
            logger.warning(
                "complete_session refused: the run holds no run credential "
                "(reason=run_uncredentialed, session=%s)",
                session_id,
            )
            self._end_run(run, "run_completed")
            return False
        try:
            return await self._complete_session_request(session_id, session_token)
        finally:
            self._end_run(run, "run_completed")

    async def _complete_session_request(
        self, session_id: str, session_token: Optional[str]
    ) -> bool:
        await self._ensure_probed()
        headers = (
            {"X-Wl-Run-Authorization": f"Bearer {session_token}"}
            if session_token
            else None
        )
        try:
            # Not queued behind the run's lineage lane: a degraded event
            # plane must not hold the close back. Terminal events keep
            # their order through the lane itself.
            outcome = await self._lineage_retry.send(
                "complete_session",
                lambda timeout: self.client.post(
                    f"/sessions/{session_id}/complete",
                    headers=headers,
                    timeout=timeout,
                ),
                client_timeout=self._timeout,
                on_retry=self._count_retry,
            )
        except asyncio.CancelledError:
            self._note_cancelled(0, ["session_complete"])
            raise
        except Exception as e:  # noqa: BLE001 — close-best-effort
            logger.warning(
                "session complete failed for %s: %s", session_id, type(e).__name__
            )
            return False
        resp = outcome.response
        if resp is not None and resp.status_code == 200:
            if outcome.attempts > 1:
                self._lineage_counters["delivered_after_retry"] += 1
            return True
        if outcome.exhausted:
            self._lineage_counters["exhausted"] += 1
            logger.warning(
                "session complete gave up (reason=session_complete_retry_exhausted) "
                "for %s after %d attempt(s), last result %s; the run stays "
                "open server-side until its TTL.",
                session_id,
                outcome.attempts,
                outcome.last_result,
            )
            return False
        self._lineage_counters["refused"] += 1
        # A non-200 here means the session did NOT reach its terminal
        # state server-side (or, after an earlier attempt that failed in
        # transport, that attempt may already have closed it: wl-apdp
        # answers a second close of an ended run with a refusal). Close
        # is best-effort — we never raise into the caller's ``finally``
        # — but the failure MUST be visible or it rots unnoticed.
        logger.warning(
            "session complete failed: APDP returned %s for %s%s",
            outcome.last_result,
            session_id,
            (
                " (an earlier attempt failed in transport and may have "
                "closed the session already)"
                if outcome.ambiguous_earlier
                else ""
            ),
        )
        return False

    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool:
        """Client-side release only. Agent credentials cannot terminate a
        session.

        **This never performs a round-trip and always returns False.** The
        run is ended in this client (later control calls on it are refused;
        its late lineage still goes out).

        History: this method used to ``POST /sessions/{id}/terminate``
        with a free-form ``reason`` string (``"manual"``, or
        ``"run_failed: <ExceptionType>"`` from the run handle's
        ``__aexit__``). Server-side that field is the closed
        ``TerminationReason`` enum (``completed``, ``agent_requested``,
        ``admin_terminated``, ``policy_violation``, …), so serde
        rejected every request this SDK ever sent with a 422 and the
        ``except`` below swallowed it at debug level. The call has
        never once succeeded.

        It is not being resurrected, because nothing needs it:

        * **Session termination is an operator-plane verb.** It lives at
          ``POST /v1/admin/sessions/{id}/terminate`` behind
          ``require_role(Operator)`` and is restricted to user
          principals. Letting the agent under governance stop its own
          governance session is the authorization inversion that gate
          exists to prevent.
        * **Abnormal end is already recorded, correctly.** The run
          handle emits an ``execution_failed`` lineage event carrying
          the descriptive reason string. That event is the audit signal
          for a failed run, and unlike this call it works.
        * **The session already ends without us.** ``ExecutionSession``
          carries ``expires_at``; ``is_active()`` is time-gated on it,
          so an abandoned session lapses on its own TTL with no server
          call required.

        Retained only because it is part of the published ``ApdpClient``
        surface (see
        :class:`watchlight_core.in_process_client.GovernanceBackend`).
        The in-process client still implements it as real local
        bookkeeping; this HTTP client cannot.
        """
        del reason  # no round-trip is possible; see docstring
        if isinstance(run, str) and run in self._runs:
            self._end_run(run, "run_terminated")
        if not self._terminate_deprecation_logged:
            self._terminate_deprecation_logged = True
            logger.warning(
                "ApdpClient.terminate_session is a deprecated no-op: "
                "agent credentials cannot terminate a session. The run's "
                "abnormal end is recorded by the execution_failed lineage "
                "event; the session lapses at its own expires_at. Operators "
                "terminate via POST /v1/admin/sessions/{id}/terminate."
            )
        return False

    async def health_check(self) -> bool:
        try:
            resp = await self.client.get("/health")
            return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    async def close(self) -> None:
        # Let queued lineage finish first, bounded by one retry budget.
        workers = [ln.worker for ln in self._lanes.values() if ln.worker_active()]
        if workers:
            await asyncio.wait(
                workers, timeout=self._lineage_retry.policy.max_wait_seconds
            )
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
