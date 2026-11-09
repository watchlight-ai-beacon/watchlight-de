"""Authentication credentials for plugin → Watchlight Beacon channels.

This module ships the **client-side** half of the unified credential
model. The server side is implemented in Rust.

## What this module provides

- :class:`Credential` — frozen dataclass wrapping a bearer token
  with kind + identity claims; redacted ``__repr__`` so accidental
  logging cannot leak the cleartext.
- :class:`PluginCredential` — convenience factory that constructs a
  :class:`Credential` with ``kind="plugin"`` and validates plugin-
  specific claims (``tenant_id`` required).
- :class:`ServiceCredential` — convenience factory for ``kind="service"``
  with ``service_name`` required. Used by Beacon-side Python services
  (none today; reserved for future Python services).
- Loaders: :meth:`Credential.from_env`,
  :meth:`Credential.from_file`. Vault and KMS loaders are stubbed
  with ``NotImplementedError`` until a later release wires the optional
  deps; the public API surface is committed here so customers don't
  have to refactor when those land.

## What this module does NOT do

- Modify :class:`ApdpClient` to accept the credential — that lands
  in a later release alongside TLS enforcement and the startup probe.
- Issue tokens — that's a server-side admin operation surfaced via
  the dashboard or the future ``wl admin tokens`` CLI.
- Validate tokens against the server — verification is server-side
  in Rust; the client just presents the bearer.

## Critical: cleartext is never serialized

The ``bearer_token`` field is the credential's secret material. The
class enforces several disciplines so the cleartext cannot leak:

1. ``__repr__`` returns a redacted form showing only the 8-char
   prefix.
2. ``__str__`` is aliased to ``__repr__``.
3. ``__format__`` defers to ``__repr__`` so ``f"{cred}"`` redacts.
4. ``__reduce__`` redacts on pickle (so a leaked pickle file
   doesn't contain cleartext).
5. JSON serialization is intentionally NOT supported — any caller
   that wants to serialize a credential is doing something wrong;
   forcing them to extract ``bearer_token`` explicitly makes the
   leak vector visible at the call site.

The :func:`Credential.bearer_token` accessor is the **only** way to
get the cleartext, and it's documented as "use only for outbound
``Authorization: Bearer`` header construction."
"""

from __future__ import annotations

import json
import os
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Mapping, Optional

# `Literal` lives in `typing` from Python 3.8; we list 3.10+ as the
# minimum Python supported by watchlight-core, so this import is safe.
from typing import Literal

if sys.version_info >= (3, 11):
    from typing import Self
else:
    # 3.10 fallback — typing_extensions is already a watchlight-core dep
    # under that Python version (per pyproject.toml).
    from typing_extensions import Self

from .log import get_logger


__all__ = [
    "Credential",
    "PluginCredential",
    "ServiceCredential",
    "CredentialKind",
    "CredentialNotFound",
    "InvalidCredential",
    "load_default_credential",
]


CredentialKind = Literal["plugin", "service", "run"]
"""Discriminator type alias matching the Rust ``CredentialKind`` enum, plus
``"run"``: a run's own ``sst_`` credential used as the caller credential by
a plugin inside a launcher-bound workload (see
:class:`watchlight_core.run_grant.RunGrant`). Never loaded from the plugin
token variables and never built from a ``wlpa_``/``wlsa_`` token."""


logger = get_logger("watchlight_core.credentials")
"""Module logger. Used only for deprecation notices about legacy
credential env var names — it NEVER receives the token value (only the
variable *name* is logged, which is non-secret)."""


# ─── Canonical credential env var resolution ────────────────────────
#
# The canonical bearer-token env var is ``{prefix}PLUGIN_TOKEN``
# (e.g. ``WATCHLIGHT_PLUGIN_TOKEN``). For backward compatibility we
# still read a short, ordered list of deprecated aliases, emitting a
# ``DeprecationWarning`` (and a logger warning) the first time a
# fallback supplies the token. The deprecation message names the
# offending variable and points at the canonical name; it never logs
# the token value itself.

# Deprecated aliases, in resolution order, expressed as a function of
# the prefix. ``WATCHLIGHT_APDP_TOKEN`` is prefix-derived; the other two
# are fixed legacy names that predate the prefix scheme.
_DEPRECATED_TOKEN_ALIASES: tuple[tuple[str, bool], ...] = (
    # (name_or_suffix, is_prefix_relative)
    ("APDP_TOKEN", True),
    ("WL_APDP_BEARER", False),
    ("WL_STAGING_APDP_TOKEN", False),
)


def _resolve_bearer_token(prefix: str) -> Optional[str]:
    """Resolve the bearer token from the environment, canonical-first.

    Resolution order:

    1. ``{prefix}PLUGIN_TOKEN`` — the canonical plugin-lane name (no
       warning).
    2. ``{prefix}SERVICE_TOKEN`` — the canonical service-lane name (no
       warning). Honored alongside the plugin var so Beacon-side Python
       services can use the lane-appropriate name; the actual kind is
       still derived from the token prefix.
    3. ``{prefix}APDP_TOKEN`` — deprecated alias.
    4. ``WL_APDP_BEARER`` — deprecated legacy alias (fixed name).
    5. ``WL_STAGING_APDP_TOKEN`` — deprecated legacy alias (fixed name).

    When a deprecated alias supplies the value (and no canonical var is
    set), a :class:`DeprecationWarning` is emitted naming the variable
    and pointing at ``{prefix}PLUGIN_TOKEN``. The token value is never
    logged. Returns ``None`` if no source is set.
    """
    canonical = f"{prefix}PLUGIN_TOKEN"

    # Canonical names — no deprecation. Plugin lane wins if both set
    # (the prefix on the token still determines the actual kind).
    token = os.environ.get(canonical)
    if token:
        return token
    token = os.environ.get(f"{prefix}SERVICE_TOKEN")
    if token:
        return token

    for name_or_suffix, is_prefix_relative in _DEPRECATED_TOKEN_ALIASES:
        var = f"{prefix}{name_or_suffix}" if is_prefix_relative else name_or_suffix
        token = os.environ.get(var)
        if token:
            _warn_deprecated_token_var(var, canonical)
            return token

    return None


def _warn_deprecated_token_var(used: str, canonical: str) -> None:
    """Emit the deprecation notice for a legacy bearer-token env var.

    Never logs the token value — only the variable names, which are
    non-secret configuration identifiers."""
    message = (
        f"environment variable {used} is deprecated for the Watchlight "
        f"plugin bearer token; set {canonical} instead. The legacy name "
        "will be removed in a future release."
    )
    warnings.warn(message, DeprecationWarning, stacklevel=3)
    logger.warning("%s", message)


# ─── Errors ─────────────────────────────────────────────────────────


class CredentialNotFound(Exception):
    """No credential could be loaded from any configured source.

    Raised by :meth:`Credential.from_default` when neither the
    environment nor the config file yields a credential.
    """


class InvalidCredential(ValueError):
    """A credential was loaded but its claims are malformed or
    incomplete (e.g. plugin credential missing ``tenant_id``)."""


# ─── Credential ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Credential:
    """Authentication credential for any Watchlight Beacon channel.

    Frozen because mutability would defeat the audit-chain assumption
    that the credential's identity is stable for the lifetime of the
    plugin/service instance. Slots-based for memory efficiency and
    to prevent accidental attribute injection.

    **Construct via factory methods**, not directly:

    - :meth:`PluginCredential.new` — the customer-facing path
    - :meth:`ServiceCredential.new` — for future Python Beacon services
    - :meth:`Credential.from_env` — load from environment variables
    - :meth:`Credential.from_file` — load from a credential file

    Direct construction (``Credential(...)``) works but skips claims
    validation; callers should prefer the factories.
    """

    bearer_token: str
    """The cleartext bearer token. Secret material — never log, never
    serialize, never compare in variable time. Use the
    :meth:`Credential.bearer_token` *accessor* (not direct attribute
    access in code that might log the result) when constructing the
    outbound ``Authorization: Bearer`` header."""

    kind: CredentialKind
    """Discriminator: ``"plugin"`` or ``"service"``. Must match the
    bearer token's prefix (``wlpa_`` for plugin, ``wlsa_`` for service)
    — Beacon services validate this at the auth middleware
    (kind-mismatch refusal at the network edge)."""

    identity_claims: Mapping[str, Any] = field(default_factory=dict)
    """Identity claims attached to the credential. Different shapes per
    kind:

    - **Plugin**: ``{"tenant_id": str, "plugin_kind": str | None,
      "plugin_version": str | None}``
    - **Service**: ``{"service_name": str, "service_instance_id":
      str | None}``

    Use :class:`PluginCredential` / :class:`ServiceCredential`
    factories which validate the shape.
    """

    label: Optional[str] = None
    """Operator-supplied human label, e.g. ``"prod-langgraph"``. Read-
    only after construction. Never used in authorization decisions."""

    # ─── redaction discipline ────────────────────────────────────

    _REDACTED_PREFIX_LEN: ClassVar[int] = 8

    def __repr__(self) -> str:
        prefix = (
            self.bearer_token[: self._REDACTED_PREFIX_LEN]
            if self.bearer_token
            else "?"
        )
        return (
            f"Credential(kind={self.kind!r}, "
            f"prefix={prefix}<redacted>, "
            f"claims={dict(self.identity_claims)!r}, "
            f"label={self.label!r})"
        )

    def __str__(self) -> str:
        # Same as __repr__. Aliasing is required because dataclass(slots=True)
        # disables __dict__-based attribute assignment; can't write
        # ``__str__ = __repr__`` at class scope.
        return self.__repr__()

    def __format__(self, format_spec: str) -> str:
        # f"{cred}" routes here. Always returns redacted form regardless
        # of format_spec, so f-string templates can't accidentally leak.
        return self.__repr__()

    def __reduce__(self):
        # Pickle protocol — return constructor + redacted args. A
        # pickled credential file MUST NOT contain the cleartext
        # token. This is "fail safe" — the unpickled credential is
        # functionally inert (its bearer_token is a placeholder),
        # which is the correct behaviour: pickling secret material
        # is itself a misuse.
        return (
            _redacted_unpickler,
            (self.kind, dict(self.identity_claims), self.label),
        )

    # ─── accessors ───────────────────────────────────────────────

    def tenant_id(self) -> Optional[str]:
        """Bound tenant for plugin credentials; ``None`` for service
        (which are cross-tenant by design)."""
        return self.identity_claims.get("tenant_id")

    def service_name(self) -> Optional[str]:
        """Bound service name for service credentials; ``None`` for
        plugin."""
        return self.identity_claims.get("service_name")

    # ─── loaders ─────────────────────────────────────────────────

    @classmethod
    def from_env(cls, prefix: str = "WATCHLIGHT_") -> Self:
        """Load a credential from environment variables.

        Reads the canonical bearer-token variable
        ``{prefix}PLUGIN_TOKEN`` (the bearer token) and uses the
        token's prefix (``wlpa_`` / ``wlsa_``) to determine kind.

        For backward compatibility, if ``{prefix}PLUGIN_TOKEN`` is
        unset the following **deprecated** aliases are read, in order,
        each emitting a :class:`DeprecationWarning`:
        ``{prefix}APDP_TOKEN``, ``WL_APDP_BEARER``,
        ``WL_STAGING_APDP_TOKEN``. Migrate to ``{prefix}PLUGIN_TOKEN``.

        For plugin tokens, also reads:

        - ``{prefix}TENANT_ID`` (required)
        - ``{prefix}PLUGIN_KIND`` (optional; auto-detected from
          ``__package__`` of the calling plugin if absent)
        - ``{prefix}PLUGIN_VERSION`` (optional; auto-detected from the
          plugin package's ``__version__`` if absent)

        For service tokens, the canonical bearer var is
        ``{prefix}SERVICE_TOKEN``; the same deprecated aliases above are
        honored as fallbacks. Service tokens also read:

        - ``{prefix}SERVICE_NAME`` (required)
        - ``{prefix}SERVICE_INSTANCE_ID`` (optional)

        Raises :class:`CredentialNotFound` if neither
        ``{prefix}PLUGIN_TOKEN`` / ``{prefix}SERVICE_TOKEN`` nor any
        deprecated alias is set; :class:`InvalidCredential` if the
        token format is malformed or required claims are missing.
        """
        token = _resolve_bearer_token(prefix)
        if not token:
            raise CredentialNotFound(
                f"no Watchlight plugin token found. Set "
                f"{prefix}PLUGIN_TOKEN (the canonical bearer-token "
                f"variable). The deprecated aliases {prefix}APDP_TOKEN, "
                "WL_APDP_BEARER, and WL_STAGING_APDP_TOKEN are also "
                "honored but should be migrated."
            )

        return cls._from_token(token, prefix)

    @classmethod
    def _from_token(cls, token: str, prefix: str) -> Self:
        """Build a credential from a bearer, reading the identity claims
        (tenant / plugin kind, or service name) from the environment."""
        kind = _kind_from_token_prefix(token)

        if kind == "plugin":
            tenant_id = os.environ.get(f"{prefix}TENANT_ID")
            if not tenant_id:
                raise InvalidCredential(
                    f"plugin credential requires {prefix}TENANT_ID"
                )
            return PluginCredential.new(
                bearer_token=token,
                tenant_id=tenant_id,
                plugin_kind=os.environ.get(f"{prefix}PLUGIN_KIND"),
                plugin_version=os.environ.get(f"{prefix}PLUGIN_VERSION"),
            )

        # service
        service_name = os.environ.get(f"{prefix}SERVICE_NAME")
        if not service_name:
            raise InvalidCredential(
                f"service credential requires {prefix}SERVICE_NAME"
            )
        return ServiceCredential.new(
            bearer_token=token,
            service_name=service_name,
            service_instance_id=os.environ.get(
                f"{prefix}SERVICE_INSTANCE_ID"
            ),
        )

    @classmethod
    def from_aws_secret(
        cls, secret_id: str, prefix: str = "WATCHLIGHT_"
    ) -> Self:
        """Load the bearer in-process from AWS Secrets Manager.

        The secret holds the bearer as a plain string, or as a JSON
        object with a ``token`` field. Identity claims come from the
        environment, as in :meth:`from_env`. AWS credentials and region
        come from the SDK default chain (IRSA on EKS). Requires the
        ``aws`` extra (``pip install 'watchlight-agent-sdk[aws]'``).
        The bearer is never logged or put in an exception.
        """
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise CredentialNotFound(
                f"{prefix}CREDENTIAL_AWS_SECRET_ID is set but boto3 is not "
                "installed: pip install 'watchlight-agent-sdk[aws]'"
            ) from exc
        try:
            response = boto3.client("secretsmanager").get_secret_value(
                SecretId=secret_id
            )
        except Exception as exc:  # noqa: BLE001 — surface the AWS error code only
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            raise CredentialNotFound(
                f"could not read the credential secret {secret_id!r} ({code})"
            ) from None
        raw = (response.get("SecretString") or "").strip()
        token = raw
        if raw.startswith("{"):
            try:
                token = str(json.loads(raw).get("token", "")).strip()
            except (ValueError, AttributeError):
                token = ""
        if not token:
            raise InvalidCredential(
                f"the credential secret {secret_id!r} has no token"
            )
        return cls._from_token(token, prefix)

    @classmethod
    def from_file(cls, path: os.PathLike[str] | str) -> Self:
        """Load a credential from a file at *path*.

        The file format is intentionally minimal — one line per
        key-value pair, ``KEY=VALUE`` (no quotes, no escaping). Mirrors
        the way K8s mounts secrets into pods (``/var/run/secrets/...``).

        Required keys: ``APDP_TOKEN``. Plugin/service-specific
        required keys per :meth:`from_env`. Lines starting with ``#``
        and blank lines are ignored.

        Raises :class:`CredentialNotFound` if *path* doesn't exist;
        :class:`InvalidCredential` on shape problems.
        """
        p = Path(path)
        if not p.is_file():
            raise CredentialNotFound(f"credential file not found: {path}")
        # Compute file mode and warn if world-readable (operational
        # safety net — secret files should be 0o600 / 0o400).
        try:
            st_mode = p.stat().st_mode & 0o777
            if st_mode & 0o077:
                # Not strict-fail: customers may have their own
                # filesystem-level access controls (e.g. immutable
                # ConfigMap-mounted files where the OS mode is wider
                # than the actual access). Warn loudly.
                import warnings

                warnings.warn(
                    f"credential file {path} is world-readable (mode {st_mode:o}); "
                    "production deployments should use mode 0o600 or stricter",
                    UserWarning,
                    stacklevel=2,
                )
        except OSError:
            # Permission to stat() but not to chmod()? Skip the warning.
            pass

        kv: dict[str, str] = {}
        for line_no, raw_line in enumerate(
            p.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise InvalidCredential(
                    f"credential file line {line_no} lacks '='"
                )
            key, _, value = line.partition("=")
            kv[key.strip()] = value.strip()

        token = kv.get("APDP_TOKEN")
        if not token:
            raise InvalidCredential("credential file missing APDP_TOKEN")
        kind = _kind_from_token_prefix(token)

        if kind == "plugin":
            tenant_id = kv.get("TENANT_ID")
            if not tenant_id:
                raise InvalidCredential(
                    "plugin credential file missing TENANT_ID"
                )
            return PluginCredential.new(
                bearer_token=token,
                tenant_id=tenant_id,
                plugin_kind=kv.get("PLUGIN_KIND"),
                plugin_version=kv.get("PLUGIN_VERSION"),
            )

        service_name = kv.get("SERVICE_NAME")
        if not service_name:
            raise InvalidCredential(
                "service credential file missing SERVICE_NAME"
            )
        return ServiceCredential.new(
            bearer_token=token,
            service_name=service_name,
            service_instance_id=kv.get("SERVICE_INSTANCE_ID"),
        )

    @classmethod
    def from_vault(
        cls,
        addr: str,
        path: str,
        auth: str = "kubernetes",
    ) -> Self:
        """Load a credential from HashiCorp Vault / OpenBao.

        Lands in a later release alongside the ApdpClient channel work.
        Documented here so the public API surface is committed early
        and customers don't have to refactor when the implementation
        ships.
        """
        raise NotImplementedError(
            "Vault loader lands in sub-PR 1.6. Until then, mount your "
            "Vault secret as a file and use Credential.from_file()."
        )

    @classmethod
    def from_kms(cls, kms_arn: str, secret_id: str) -> Self:
        """Load a credential from AWS Secrets Manager (KMS-encrypted).

        Lands in a later release alongside the ApdpClient channel work.
        """
        raise NotImplementedError(
            "KMS loader lands in sub-PR 1.6. Until then, use the AWS "
            "ECS / Lambda secret-injection mechanism to mount as env or "
            "file, then use Credential.from_env() or .from_file()."
        )

    @classmethod
    def from_default(cls, prefix: str = "WATCHLIGHT_") -> Self:
        """Default loader: tries AWS Secrets Manager (when
        ``$WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID`` is set) → env → file → raises.

        File path resolution: ``$WATCHLIGHT_CREDENTIAL_FILE`` if set,
        else ``/etc/watchlight/plugin.cred`` (Linux/macOS) or
        ``%PROGRAMDATA%\\Watchlight\\plugin.cred`` (Windows).
        """
        # 1. AWS Secrets Manager, when the secret id is configured: the
        #    bearer stays in memory, never in the environment or a file.
        aws_secret_id = os.environ.get(f"{prefix}CREDENTIAL_AWS_SECRET_ID", "").strip()
        if aws_secret_id:
            return cls.from_aws_secret(aws_secret_id, prefix=prefix)

        # 2. Environment variables.
        try:
            return cls.from_env(prefix=prefix)
        except CredentialNotFound:
            pass

        # 3. Config file.
        explicit = os.environ.get(f"{prefix}CREDENTIAL_FILE")
        if explicit:
            return cls.from_file(explicit)
        for default_path in _default_file_paths():
            if Path(default_path).is_file():
                return cls.from_file(default_path)

        raise CredentialNotFound(
            f"no credential found. Set {prefix}PLUGIN_TOKEN (env; the "
            f"deprecated aliases {prefix}APDP_TOKEN / WL_APDP_BEARER / "
            "WL_STAGING_APDP_TOKEN are still honored), or write a "
            f"credential file to {_default_file_paths()[0]}, or pass "
            "credential= explicitly to ApdpClient."
        )


def load_default_credential(owner: str, prefix: str = "WATCHLIGHT_") -> Optional[Credential]:
    """The credential a plugin uses when the caller passed neither a key nor
    a backend: :meth:`Credential.from_default`.

    Returns ``None`` only when no credential source exists at all: no token
    in the environment, no credential file (configured or at the default
    path) and no AWS secret id. The client then runs unauthenticated and
    the server refuses it (fail closed). A credential that is present but
    cannot be loaded (a malformed token, a corrupt file at the default
    path, an unreadable configured file or secret) raises
    :class:`CredentialNotFound` before any request goes out; it never
    degrades to an unauthenticated client. The message names the
    error class only. ``owner`` names the plugin in the messages. Mirrors
    ``resolveClientAuth`` in the TypeScript SDK.
    """
    explicitly_configured = bool(
        os.environ.get(f"{prefix}CREDENTIAL_AWS_SECRET_ID", "").strip()
        or os.environ.get(f"{prefix}CREDENTIAL_FILE", "").strip()
    )
    try:
        return Credential.from_default(prefix=prefix)
    except CredentialNotFound:
        if explicitly_configured:
            raise CredentialNotFound(
                f"{owner}: the configured credential could not be loaded "
                "(CredentialNotFound)"
            ) from None
        return None
    except Exception as exc:  # noqa: BLE001 — any other failure: a credential is present
        raise CredentialNotFound(
            f"{owner}: the configured credential could not be loaded "
            f"({type(exc).__name__})"
        ) from None


# ─── Plugin / Service factories ─────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PluginCredential:
    """Convenience factory for plugin credentials.

    Use :meth:`PluginCredential.new` to construct; this class is a
    thin facade that returns a :class:`Credential` with
    ``kind="plugin"`` and validated identity claims.
    """

    @staticmethod
    def new(
        bearer_token: str,
        tenant_id: str,
        plugin_kind: Optional[str] = None,
        plugin_version: Optional[str] = None,
        label: Optional[str] = None,
    ) -> Credential:
        """Construct a plugin credential.

        Validates token-prefix-vs-kind consistency: the bearer must
        start with ``wlpa_`` (kind/prefix mismatch is rejected at
        construction so misconfigured clients fail at startup, not at
        every authentication probe).
        """
        if not bearer_token:
            raise InvalidCredential("bearer_token must be non-empty")
        if not bearer_token.startswith("wlpa_"):
            raise InvalidCredential(
                "plugin credential bearer must start with 'wlpa_'"
            )
        if not tenant_id:
            raise InvalidCredential(
                "plugin credential tenant_id must be non-empty"
            )
        return Credential(
            bearer_token=bearer_token,
            kind="plugin",
            identity_claims={
                "tenant_id": tenant_id,
                "plugin_kind": plugin_kind,
                "plugin_version": plugin_version,
            },
            label=label,
        )


@dataclass(frozen=True, slots=True)
class ServiceCredential:
    """Convenience factory for service credentials. See
    :class:`PluginCredential` for the pattern."""

    @staticmethod
    def new(
        bearer_token: str,
        service_name: str,
        service_instance_id: Optional[str] = None,
        label: Optional[str] = None,
    ) -> Credential:
        if not bearer_token:
            raise InvalidCredential("bearer_token must be non-empty")
        if not bearer_token.startswith("wlsa_"):
            raise InvalidCredential(
                "service credential bearer must start with 'wlsa_'"
            )
        if not service_name:
            raise InvalidCredential(
                "service credential service_name must be non-empty"
            )
        return Credential(
            bearer_token=bearer_token,
            kind="service",
            identity_claims={
                "service_name": service_name,
                "service_instance_id": service_instance_id,
            },
            label=label,
        )


# ─── Internal helpers ───────────────────────────────────────────────


def _kind_from_token_prefix(token: str) -> CredentialKind:
    """Determine the credential kind from the token's prefix.

    Mirrors the equivalent Rust token-parsing logic.
    Both sides MUST agree on the prefix → kind mapping.
    """
    if token.startswith("wlpa_"):
        return "plugin"
    if token.startswith("wlsa_"):
        return "service"
    if token.startswith("wlapdp_ak_"):
        # Existing admin-API-key prefix. This client doesn't speak
        # that protocol — admin API keys go through the existing
        # bearer path the dashboard already uses (bcrypt).
        # Refuse loudly so misconfigured deployments fail fast
        # rather than silently producing 401s on every request.
        raise InvalidCredential(
            "token prefix 'wlapdp_ak_' is the admin-API-key system; "
            "this client expects 'wlpa_' or 'wlsa_'. Misconfigured?"
        )
    raise InvalidCredential(
        "token has an unknown prefix; "
        "expected 'wlpa_' (plugin) or 'wlsa_' (service)"
    )


def _redacted_unpickler(
    kind: CredentialKind,
    identity_claims: dict,
    label: Optional[str],
) -> Credential:
    """Pickle-protocol unpickler. Returns a Credential with a redacted
    placeholder for ``bearer_token``. Functional inertness is
    intentional: pickling a credential is itself a misuse, so the
    unpickled value should not be usable for outbound auth."""
    return Credential(
        bearer_token="<redacted-via-pickle>",
        kind=kind,
        identity_claims=identity_claims,
        label=label,
    )


def _default_file_paths() -> list[str]:
    """Default paths searched by :meth:`Credential.from_default` when
    no explicit file is configured."""
    if os.name == "nt":
        return [
            os.path.join(
                os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
                "Watchlight",
                "plugin.cred",
            )
        ]
    return ["/etc/watchlight/plugin.cred"]
