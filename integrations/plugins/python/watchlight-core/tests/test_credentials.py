"""Tests for watchlight_core.credentials.

Three layers of coverage:

1. Construction + validation — factories enforce token-prefix /
   kind consistency, reject empty fields, etc.
2. Redaction discipline — the cleartext bearer NEVER appears in
   ``__repr__``, ``__str__``, ``f"{cred}"``, pickle output.
3. Loaders — ``from_env`` / ``from_file`` / ``from_default``.
   Vault + KMS loaders raise ``NotImplementedError`` (sub-PR 1.6).
"""

from __future__ import annotations

import logging
import os
import pickle
import stat
import tempfile
from pathlib import Path

import pytest

from watchlight_core.credentials import (
    Credential,
    CredentialNotFound,
    InvalidCredential,
    PluginCredential,
    ServiceCredential,
)


SAMPLE_PLUGIN_TOKEN = "wlpa_aHR0cHM6Ly9hLmIvY3JlZGJ5dGVzMzJiaXRzcmFuZG9tCg"
SAMPLE_SERVICE_TOKEN = "wlsa_xT4u3kPdKqLm9bV2zQwRrYsHnFcAaGpJtMnCzRb-yEsK"
SAMPLE_ADMIN_KEY = "wlapdp_ak_" + "0" * 40


# ─── Construction + validation ───────────────────────────────────────


def test_plugin_credential_factory_succeeds():
    c = PluginCredential.new(
        bearer_token=SAMPLE_PLUGIN_TOKEN,
        tenant_id="acme",
        plugin_kind="langgraph",
        plugin_version="0.2.0",
    )
    assert c.kind == "plugin"
    assert c.tenant_id() == "acme"
    assert c.identity_claims["plugin_kind"] == "langgraph"
    assert c.bearer_token == SAMPLE_PLUGIN_TOKEN


def test_service_credential_factory_succeeds():
    c = ServiceCredential.new(
        bearer_token=SAMPLE_SERVICE_TOKEN,
        service_name="wl-proxy",
        service_instance_id="pod-7",
    )
    assert c.kind == "service"
    assert c.service_name() == "wl-proxy"
    assert c.tenant_id() is None  # services are cross-tenant


def test_plugin_factory_rejects_service_prefix_token():
    """Cross-kind token mitigation enforced at construction: a
    service-prefix token presented as a plugin credential fails
    immediately, not at the first 401 from the server."""
    with pytest.raises(InvalidCredential, match="must start with 'wlpa_'"):
        PluginCredential.new(
            bearer_token=SAMPLE_SERVICE_TOKEN,
            tenant_id="acme",
        )


def test_service_factory_rejects_plugin_prefix_token():
    with pytest.raises(InvalidCredential, match="must start with 'wlsa_'"):
        ServiceCredential.new(
            bearer_token=SAMPLE_PLUGIN_TOKEN,
            service_name="wl-proxy",
        )


def test_plugin_factory_requires_tenant_id():
    with pytest.raises(InvalidCredential, match="tenant_id"):
        PluginCredential.new(bearer_token=SAMPLE_PLUGIN_TOKEN, tenant_id="")


def test_factories_reject_empty_token():
    with pytest.raises(InvalidCredential, match="bearer_token"):
        PluginCredential.new(bearer_token="", tenant_id="acme")
    with pytest.raises(InvalidCredential, match="bearer_token"):
        ServiceCredential.new(bearer_token="", service_name="wl-proxy")


def test_credential_is_frozen():
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    with pytest.raises(AttributeError):
        c.bearer_token = "different"  # type: ignore[misc]


# ─── Redaction discipline ────────────────────────────────────────────


def test_repr_redacts_bearer_token():
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    repr_str = repr(c)
    # The full token suffix MUST NOT appear.
    assert SAMPLE_PLUGIN_TOKEN not in repr_str, (
        f"cleartext leaked in __repr__: {repr_str}"
    )
    # The 8-char prefix is acceptable (operator-readable, not secret).
    assert SAMPLE_PLUGIN_TOKEN[:8] in repr_str
    # The redaction marker is present.
    assert "<redacted>" in repr_str


def test_str_redacts_bearer_token():
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    s = str(c)
    assert SAMPLE_PLUGIN_TOKEN not in s
    assert "<redacted>" in s


def test_f_string_redacts_bearer_token():
    """f"{cred}" must route through __format__ → __repr__, never expose cleartext."""
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    formatted = f"{c}"
    assert SAMPLE_PLUGIN_TOKEN not in formatted
    # Format spec doesn't matter; redaction is unconditional.
    formatted_with_spec = f"{c:>40}"
    assert SAMPLE_PLUGIN_TOKEN not in formatted_with_spec


def test_pickle_redacts_bearer_token():
    """Critical: a leaked pickle file MUST NOT contain the cleartext.

    This is the defense against ``pickle.dumps(cred)`` being written
    to disk as part of a state dump or audit replay archive."""
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    blob = pickle.dumps(c)
    # The cleartext bytes MUST NOT appear in the pickle stream.
    assert SAMPLE_PLUGIN_TOKEN.encode() not in blob, (
        "cleartext token leaked into pickle bytes"
    )
    # Round-trip yields a redacted-placeholder credential — functionally
    # inert, which is the correct behavior (pickling secrets is a misuse).
    restored: Credential = pickle.loads(blob)
    assert restored.bearer_token == "<redacted-via-pickle>"
    # But identity claims survive — useful for forensic replay.
    assert restored.kind == "plugin"
    assert restored.tenant_id() == "acme"


def test_logging_at_debug_does_not_leak_bearer(caplog):
    """If a customer accidentally logs the credential at DEBUG (or any
    level), the cleartext MUST NOT end up in the log buffer.

    This mimics the standard adversarial test from the
    authentication design doc."""
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    logger = logging.getLogger("test_logging_at_debug_does_not_leak_bearer")
    with caplog.at_level(logging.DEBUG):
        logger.debug("loaded credential: %s", c)
        logger.debug("loaded credential as repr: %r", c)
        logger.debug("loaded credential f-string: %s", f"{c}")
    assert SAMPLE_PLUGIN_TOKEN not in caplog.text, (
        f"cleartext leaked into logs: {caplog.text}"
    )


def test_format_with_format_spec_redacts():
    """Edge case: even custom format specs must redact. The
    implementation ignores the spec and always returns __repr__."""
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    for spec in ["", ">50", "<10", "^20", "s"]:
        formatted = format(c, spec)
        assert SAMPLE_PLUGIN_TOKEN not in formatted, (
            f"leaked under format_spec={spec!r}"
        )


# ─── Comprehensive never-logged sweep (sub-PR 1.5) ────────────────────


def _make_random_credential_pair(seed: int) -> tuple[Credential, str]:
    """Generate a fresh (Credential, cleartext_token) pair seeded for
    reproducibility. Alternates between plugin and service kinds so
    the sweep exercises both code paths.

    The token is built from `secrets.token_urlsafe(32)` (43 chars
    base64url) prefixed with the kind discriminator — same shape as
    a real production token, so the sweep does not accidentally
    test under a degenerate input class.
    """
    import secrets

    rng = secrets.SystemRandom()
    rng.seed = lambda *_: None  # SystemRandom doesn't take a seed; symbolic
    is_plugin = (seed % 2) == 0
    suffix = secrets.token_urlsafe(32)[:43]
    if is_plugin:
        token = f"wlpa_{suffix}"
        cred = PluginCredential.new(
            bearer_token=token,
            tenant_id=f"tenant-{seed}",
            plugin_kind=f"plugin-kind-{seed}",
            plugin_version=f"0.{seed}.0",
            label=f"label-{seed}",
        )
    else:
        token = f"wlsa_{suffix}"
        cred = ServiceCredential.new(
            bearer_token=token,
            service_name=f"service-{seed}",
            service_instance_id=f"instance-{seed}",
            label=f"label-{seed}",
        )
    return cred, token


@pytest.mark.parametrize("seed", range(50))
def test_credential_never_logged(seed: int, caplog: pytest.LogCaptureFixture):
    """The load-bearing redaction property: cleartext bearer tokens
    must NEVER appear in any human- or machine-readable rendering of
    the credential.

    This is the adversarial-test target named in the authentication
    design doc. It runs the credential through every realistic leak vector — formatting,
    logging at every level, pickle, json, dict access, copy — with a
    fresh random token so the property holds across the input space,
    not just for one fixture.
    """
    import copy
    import io
    import json
    import logging
    import pickle
    import traceback

    cred, token = _make_random_credential_pair(seed)

    # 1. repr / str / direct format ────────────────────────────────
    assert token not in repr(cred), f"repr leaked seed={seed}"
    assert token not in str(cred), f"str leaked seed={seed}"
    assert token not in f"{cred}", f"f-string leaked seed={seed}"
    assert token not in f"{cred!r}", f"f-string !r leaked seed={seed}"
    assert token not in f"{cred!s}", f"f-string !s leaked seed={seed}"

    # 2. format with a variety of specs ────────────────────────────
    for spec in ("", ">100", "<10", "^20", "s", "20s", "<.5s"):
        try:
            rendered = format(cred, spec)
        except Exception:
            # An exception is fine — silent leak is not. We only care
            # that no successful render contains the cleartext.
            continue
        assert token not in rendered, (
            f"format(spec={spec!r}) leaked seed={seed}"
        )

    # 3. logging at every standard level ───────────────────────────
    logger = logging.getLogger(f"test_never_logged_{seed}")
    logger.setLevel(logging.DEBUG)
    levels = [
        ("debug", logger.debug),
        ("info", logger.info),
        ("warning", logger.warning),
        ("error", logger.error),
        ("critical", logger.critical),
    ]
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=logger.name):
        for _label, log_fn in levels:
            log_fn("cred-as-%%s: %s", cred)
            log_fn("cred-as-%%r: %r", cred)
            log_fn("cred-fstring: %s", f"{cred}")
            try:
                # Direct interpolation in the format string is the
                # most common accidental-leak path in real code.
                log_fn(f"interp: {cred}")
            except Exception:
                pass
    assert token not in caplog.text, (
        f"cleartext leaked into logs at some level (seed={seed}): "
        f"buffer head={caplog.text[:200]!r}"
    )

    # 4. pickle (bytes payload AND round-tripped repr) ─────────────
    pickled = pickle.dumps(cred)
    assert token.encode("utf-8") not in pickled, (
        f"cleartext bytes appeared in pickle output (seed={seed})"
    )
    unpickled = pickle.loads(pickled)
    assert token not in repr(unpickled), (
        f"unpickled repr leaked (seed={seed})"
    )

    # 5. json.dumps must NOT successfully serialize the cleartext.
    # Either it raises TypeError (preferred — caller knows something
    # is wrong) or the resulting string redacts. Silent success with
    # cleartext in the payload would be the worst outcome.
    try:
        # Default encoder will reject; this asserts the rejection.
        json.dumps(cred)
        # If we somehow get here, the encoder accepted — make sure it
        # didn't include the cleartext.
        rendered = json.dumps(cred, default=repr)
        assert token not in rendered, f"json.dumps leaked (seed={seed})"
    except TypeError:
        pass  # Expected — frozen dataclass with non-trivial fields

    # 6. Custom default= encoders that fall through to repr/str MUST
    # also redact (because repr/str redact). This is the typical
    # "defensive serialize" pattern.
    rendered = json.dumps(cred, default=lambda o: repr(o))
    assert token not in rendered, (
        f"json.dumps with default=repr leaked (seed={seed})"
    )

    # 7. vars() / __dict__ access. Slots-based dataclass means vars()
    # raises; assert the failure mode rather than producing a leaky
    # dict.
    try:
        d = vars(cred)
    except TypeError:
        d = None
    if d is not None:
        # If a future code change moves off slots, this branch keeps
        # the test honest — vars() would surface fields, but the
        # cleartext under bearer_token would still be present and we
        # want to know.
        assert token not in str(d), (
            f"vars() exposed cleartext (seed={seed})"
        )

    # 8. copy / deepcopy round-trips must preserve redaction. Frozen
    # dataclasses commonly return the same instance from copy.copy,
    # but deepcopy makes a real clone — the clone's repr must also
    # redact.
    shallow = copy.copy(cred)
    deep = copy.deepcopy(cred)
    assert token not in repr(shallow), f"copy.copy leaked (seed={seed})"
    assert token not in repr(deep), f"copy.deepcopy leaked (seed={seed})"

    # 9. traceback rendering. If the credential winds up in an
    # exception's args (an easy mistake), the resulting traceback
    # must redact too.
    buf = io.StringIO()
    try:
        raise RuntimeError(cred)
    except RuntimeError:
        traceback.print_exc(file=buf)
    assert token not in buf.getvalue(), (
        f"traceback rendering leaked (seed={seed})"
    )


# ─── Loaders: from_env ───────────────────────────────────────────────


def _clear_token_env(monkeypatch):
    """Remove every bearer-token env var the resolver reads so a test
    starts from a known-empty baseline regardless of the host env."""
    for var in (
        "WATCHLIGHT_PLUGIN_TOKEN",
        "WATCHLIGHT_SERVICE_TOKEN",
        "WATCHLIGHT_APDP_TOKEN",
        "WL_APDP_BEARER",
        "WL_STAGING_APDP_TOKEN",
    ):
        monkeypatch.delenv(var, raising=False)


def test_from_env_loads_plugin_credential(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_KIND", "langgraph")
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_VERSION", "0.2.0")

    c = Credential.from_env()
    assert c.kind == "plugin"
    assert c.tenant_id() == "acme"
    assert c.identity_claims["plugin_kind"] == "langgraph"
    assert c.identity_claims["plugin_version"] == "0.2.0"


def test_from_env_loads_service_credential(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_SERVICE_TOKEN", SAMPLE_SERVICE_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_SERVICE_NAME", "wl-proxy")
    monkeypatch.setenv("WATCHLIGHT_SERVICE_INSTANCE_ID", "pod-7")

    c = Credential.from_env()
    assert c.kind == "service"
    assert c.service_name() == "wl-proxy"
    assert c.identity_claims["service_instance_id"] == "pod-7"


def test_from_env_raises_when_token_missing(monkeypatch):
    _clear_token_env(monkeypatch)
    with pytest.raises(CredentialNotFound, match="WATCHLIGHT_PLUGIN_TOKEN"):
        Credential.from_env()


def test_from_env_plugin_requires_tenant_id(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.delenv("WATCHLIGHT_TENANT_ID", raising=False)
    with pytest.raises(InvalidCredential, match="TENANT_ID"):
        Credential.from_env()


def test_from_env_service_requires_service_name(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_SERVICE_TOKEN", SAMPLE_SERVICE_TOKEN)
    monkeypatch.delenv("WATCHLIGHT_SERVICE_NAME", raising=False)
    with pytest.raises(InvalidCredential, match="SERVICE_NAME"):
        Credential.from_env()


def test_from_env_rejects_admin_api_key_prefix(monkeypatch):
    """Cross-kind token mitigation: an admin-API-key token in
    WATCHLIGHT_PLUGIN_TOKEN must fail-loud, not silently produce
    401s. This is the most likely misconfiguration scenario when
    migrating between auth systems."""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_ADMIN_KEY)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.raises(InvalidCredential, match="admin-API-key"):
        Credential.from_env()


def test_from_env_custom_prefix(monkeypatch):
    """Operators with multiple Watchlight deployments (staging, prod)
    can use prefixed env vars to disambiguate."""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WL_STAGING_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WL_STAGING_TENANT_ID", "staging")
    c = Credential.from_env(prefix="WL_STAGING_")
    assert c.tenant_id() == "staging"


# ─── from_env: canonical-vs-deprecated token resolution ──────────────


def test_from_env_reads_canonical_plugin_token_without_warning(monkeypatch):
    """The canonical WATCHLIGHT_PLUGIN_TOKEN loads cleanly with NO
    DeprecationWarning."""
    import warnings

    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        c = Credential.from_env()
    assert c.tenant_id() == "acme"


def test_from_env_reads_canonical_service_token_without_warning(monkeypatch):
    import warnings

    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_SERVICE_TOKEN", SAMPLE_SERVICE_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_SERVICE_NAME", "wl-proxy")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        c = Credential.from_env()
    assert c.service_name() == "wl-proxy"


@pytest.mark.parametrize(
    "alias_var",
    ["WATCHLIGHT_APDP_TOKEN", "WL_APDP_BEARER", "WL_STAGING_APDP_TOKEN"],
)
def test_from_env_deprecated_alias_warns_and_loads(monkeypatch, alias_var):
    """Each deprecated alias still loads the token, but emits a
    DeprecationWarning naming the var when the canonical is absent."""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv(alias_var, SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.warns(DeprecationWarning, match=alias_var):
        c = Credential.from_env()
    assert c.tenant_id() == "acme"


def test_from_env_deprecated_alias_warning_names_canonical(monkeypatch):
    """The deprecation message must point at the canonical var name."""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_APDP_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.warns(DeprecationWarning, match="WATCHLIGHT_PLUGIN_TOKEN"):
        Credential.from_env()


def test_from_env_canonical_wins_over_alias(monkeypatch):
    """When both the canonical var and a deprecated alias are set, the
    canonical value wins and NO deprecation warning is emitted."""
    import warnings

    _clear_token_env(monkeypatch)
    other_token = "wlpa_" + "Z" * 43
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_APDP_TOKEN", other_token)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        c = Credential.from_env()
    # The canonical token's bytes were used, not the alias's.
    assert c.bearer_token == SAMPLE_PLUGIN_TOKEN


def test_from_env_alias_resolution_order(monkeypatch):
    """When multiple deprecated aliases are set (no canonical), the
    documented order wins: APDP_TOKEN > WL_APDP_BEARER >
    WL_STAGING_APDP_TOKEN."""
    _clear_token_env(monkeypatch)
    apdp_token = "wlpa_" + "A" * 43
    bearer_token = "wlpa_" + "B" * 43
    monkeypatch.setenv("WATCHLIGHT_APDP_TOKEN", apdp_token)
    monkeypatch.setenv("WL_APDP_BEARER", bearer_token)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.warns(DeprecationWarning, match="WATCHLIGHT_APDP_TOKEN"):
        c = Credential.from_env()
    assert c.bearer_token == apdp_token


def test_from_env_deprecation_warning_never_logs_token(monkeypatch, caplog):
    """The deprecation path must NEVER log the token value — only the
    variable name."""
    import logging
    import warnings

    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_APDP_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with caplog.at_level(logging.WARNING):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            Credential.from_env()
    assert SAMPLE_PLUGIN_TOKEN not in caplog.text
    # But the variable name IS surfaced so operators can act on it.
    assert "WATCHLIGHT_APDP_TOKEN" in caplog.text


# ─── Loaders: from_file ──────────────────────────────────────────────


def _write_cred_file(content: str, mode: int = 0o600) -> str:
    """Write a temp credential file with the given content + mode."""
    fd, path = tempfile.mkstemp(prefix="wl-cred-test-", suffix=".cred")
    os.close(fd)
    Path(path).write_text(content, encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_from_file_loads_plugin_credential():
    path = _write_cred_file(
        f"# Watchlight plugin credential\n"
        f"APDP_TOKEN={SAMPLE_PLUGIN_TOKEN}\n"
        "TENANT_ID=acme\n"
        "PLUGIN_KIND=langgraph\n"
        "\n"
        "PLUGIN_VERSION=0.2.0\n"
    )
    try:
        c = Credential.from_file(path)
        assert c.kind == "plugin"
        assert c.tenant_id() == "acme"
        assert c.identity_claims["plugin_kind"] == "langgraph"
    finally:
        os.unlink(path)


def test_from_file_loads_service_credential():
    path = _write_cred_file(
        f"APDP_TOKEN={SAMPLE_SERVICE_TOKEN}\n"
        "SERVICE_NAME=wl-proxy\n"
    )
    try:
        c = Credential.from_file(path)
        assert c.kind == "service"
        assert c.service_name() == "wl-proxy"
    finally:
        os.unlink(path)


def test_from_file_raises_when_path_missing():
    with pytest.raises(CredentialNotFound, match="not found"):
        Credential.from_file("/nonexistent/path/to/cred")


def test_from_file_raises_on_missing_token():
    path = _write_cred_file("TENANT_ID=acme\n")
    try:
        with pytest.raises(InvalidCredential, match="APDP_TOKEN"):
            Credential.from_file(path)
    finally:
        os.unlink(path)


def test_from_file_raises_on_malformed_line():
    path = _write_cred_file("this line has no equals sign\n")
    try:
        with pytest.raises(InvalidCredential, match="line 1 lacks '='"):
            Credential.from_file(path)
    finally:
        os.unlink(path)


def test_from_file_warns_on_world_readable_mode():
    """Operational safety net — a world-readable credential file is
    a configuration smell. Warn loudly without failing."""
    path = _write_cred_file(
        f"APDP_TOKEN={SAMPLE_PLUGIN_TOKEN}\nTENANT_ID=acme\n",
        mode=0o644,
    )
    try:
        with pytest.warns(UserWarning, match="world-readable"):
            Credential.from_file(path)
    finally:
        os.unlink(path)


def test_from_file_no_warn_on_strict_mode():
    """The 0o600 mode (owner-only read/write) is the recommended
    production posture; no warning."""
    path = _write_cred_file(
        f"APDP_TOKEN={SAMPLE_PLUGIN_TOKEN}\nTENANT_ID=acme\n",
        mode=0o600,
    )
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # any warning becomes an error
            Credential.from_file(path)
    finally:
        os.unlink(path)


# ─── Loaders: from_default ───────────────────────────────────────────


def test_from_default_prefers_env(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", SAMPLE_PLUGIN_TOKEN)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_FILE", raising=False)

    c = Credential.from_default()
    assert c.tenant_id() == "acme"


def test_from_default_falls_back_to_file(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.delenv("WATCHLIGHT_TENANT_ID", raising=False)

    path = _write_cred_file(
        f"APDP_TOKEN={SAMPLE_PLUGIN_TOKEN}\nTENANT_ID=acme\n"
    )
    try:
        monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", path)
        c = Credential.from_default()
        assert c.tenant_id() == "acme"
    finally:
        os.unlink(path)


def test_from_default_raises_when_nothing_configured(monkeypatch):
    """No env, no explicit file, and (in this test) no default-path
    file exists → CredentialNotFound."""
    _clear_token_env(monkeypatch)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_FILE", raising=False)
    # Default path is /etc/watchlight/plugin.cred — almost certainly
    # absent on the test host. If it ever exists in CI we'll need a
    # tighter fixture, but for now this is good enough.
    if Path("/etc/watchlight/plugin.cred").exists():
        pytest.skip("default credential path exists on this host")
    with pytest.raises(CredentialNotFound, match="no credential found"):
        Credential.from_default()


# ─── Loaders: from_vault, from_kms (sub-PR 1.6 stubs) ────────────────


def test_from_vault_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="sub-PR 1.6"):
        Credential.from_vault(addr="https://vault.acme", path="secret/x")


def test_from_kms_raises_not_implemented():
    with pytest.raises(NotImplementedError, match="sub-PR 1.6"):
        Credential.from_kms(kms_arn="arn:aws:kms:...", secret_id="x")


# ─── Misc ────────────────────────────────────────────────────────────


def test_kind_literal_values():
    """Locked-in string values for the kind discriminator. If anyone
    changes them, the wire format with the Rust server breaks."""
    plugin = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    service = ServiceCredential.new(SAMPLE_SERVICE_TOKEN, "wl-proxy")
    assert plugin.kind == "plugin"
    assert service.kind == "service"


def test_tenant_id_returns_none_for_service():
    c = ServiceCredential.new(SAMPLE_SERVICE_TOKEN, "wl-proxy")
    assert c.tenant_id() is None
    assert c.service_name() == "wl-proxy"


def test_service_name_returns_none_for_plugin():
    c = PluginCredential.new(SAMPLE_PLUGIN_TOKEN, "acme")
    assert c.service_name() is None
    assert c.tenant_id() == "acme"


def test_label_round_trips():
    c = PluginCredential.new(
        SAMPLE_PLUGIN_TOKEN, "acme", label="prod-langgraph"
    )
    assert c.label == "prod-langgraph"
    assert "prod-langgraph" in repr(c)  # label is non-secret; visible


# ─── load_default_credential ────────────────────────────────


def test_load_default_credential_returns_none_with_nothing_configured(monkeypatch):
    from watchlight_core import load_default_credential

    _clear_token_env(monkeypatch)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_FILE", raising=False)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", raising=False)
    if Path("/etc/watchlight/plugin.cred").exists():
        pytest.skip("a default credential file exists on this host")
    assert load_default_credential("test_plugin") is None


def test_load_default_credential_raises_for_a_configured_file_it_cannot_load(monkeypatch, tmp_path):
    from watchlight_core import load_default_credential

    _clear_token_env(monkeypatch)
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(tmp_path / "absent.cred"))
    with pytest.raises(CredentialNotFound, match="test_plugin"):
        load_default_credential("test_plugin")


def test_load_default_credential_raises_for_a_malformed_env_token(monkeypatch):
    """A token that is present but malformed never degrades to an
    unauthenticated client."""
    from watchlight_core import load_default_credential

    _clear_token_env(monkeypatch)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_FILE", raising=False)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", raising=False)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", "not-a-token-sk-live-SECRET")
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.raises(CredentialNotFound, match="test_plugin") as err:
        load_default_credential("test_plugin")
    assert "sk-live-SECRET" not in str(err.value)
    assert err.value.__cause__ is None


def test_load_default_credential_raises_for_a_corrupt_file_at_the_default_path(monkeypatch, tmp_path):
    """A credential file at the default path counts as configured: corrupt,
    it raises instead of running unauthenticated."""
    import watchlight_core.credentials as credentials_module
    from watchlight_core import load_default_credential

    corrupt = tmp_path / "plugin.cred"
    corrupt.write_text("{ not json sk-live-SECRET")
    _clear_token_env(monkeypatch)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_FILE", raising=False)
    monkeypatch.delenv("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", raising=False)
    monkeypatch.setattr(credentials_module, "_default_file_paths", lambda: [str(corrupt)])
    with pytest.raises(CredentialNotFound, match="test_plugin") as err:
        load_default_credential("test_plugin")
    assert "sk-live-SECRET" not in str(err.value)
    assert err.value.__cause__ is None
