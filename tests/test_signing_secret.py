"""``signing_secret`` — the name, the deprecated alias, and rotation.

The value signs scope tokens, and approval tokens when no separate approval
secret is configured, so it is named for what it signs rather than for one kind
of token. ``token_secret`` is the former name: it still works, at lower
precedence, warns once, and is refused when it contradicts the new name.

It also accepts an ORDERED LIST. The first entry signs; every entry verifies, so
rotating is two ordinary deploys instead of a cutover: add the new secret at the
front, wait out the longest token lifetime, drop the old one.
"""
import pytest

pytest.importorskip("watchlight_engine")

from watchlight import SIGNING_SECRET_CONFLICT_MESSAGE, ScopeTokenError, Watchlight

OLD = "an-old-signing-secret-32-bytes-x"
NEW = "a-new-signing-secret-32-bytes-yy"
WARNING = "former name of"
ANY = '@enforcement_effect("require_approval")\npermit(principal, action, resource);'


@pytest.fixture(autouse=True)
def _no_ambient_secret(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_SIGNING_SECRET", raising=False)
    monkeypatch.delenv("WATCHLIGHT_TOKEN_SECRET", raising=False)
    monkeypatch.delenv("WATCHLIGHT_APPROVAL_SECRET", raising=False)


@pytest.fixture(autouse=True)
def _reset_warning():
    """The deprecation notice is once per PROCESS; reset it so each test sees it."""
    import watchlight

    watchlight._warned_token_secret_name = False
    yield
    watchlight._warned_token_secret_name = False


def _gov(tmp_path, name="a", **kw):
    g = Watchlight(agent="sig-agent", audit_dir=str(tmp_path / name / ".watchlight"), **kw)
    g.allow(ANY, "any")
    return g


async def _scope_token(g):
    root = g.scope(tools=["read"])
    return root.to_token()


# ── the name ────────────────────────────────────────────────────────────────


def test_the_new_name_works(tmp_path):
    a = _gov(tmp_path, "a", signing_secret=NEW)
    b = _gov(tmp_path, "b", signing_secret=NEW)
    token = a.scope(tools=["read"]).to_token()
    assert b.scope_from_token(token).allowed_tools == ["read"]


def test_the_old_name_still_works_and_warns_once(tmp_path, capsys):
    a = _gov(tmp_path, "a", token_secret=NEW)
    b = _gov(tmp_path, "b", signing_secret=NEW)
    token = a.scope(tools=["read"]).to_token()
    assert b.scope_from_token(token).allowed_tools == ["read"]
    err = capsys.readouterr().err
    assert WARNING in err and err.count(WARNING) == 1
    # …and only once per process, however many governors use the old name.
    _gov(tmp_path, "c", token_secret=NEW)
    assert WARNING not in capsys.readouterr().err


def test_the_new_name_alone_does_not_warn(tmp_path, capsys):
    _gov(tmp_path, "a", signing_secret=NEW)
    assert WARNING not in capsys.readouterr().err


def test_both_names_with_different_values_are_refused(tmp_path):
    with pytest.raises(ScopeTokenError) as exc:
        _gov(tmp_path, "a", signing_secret=NEW, token_secret=OLD)
    assert exc.value.code == "mismatch"
    assert str(exc.value).endswith(SIGNING_SECRET_CONFLICT_MESSAGE)
    # …and never echoes either secret.
    assert NEW not in str(exc.value) and OLD not in str(exc.value)


def test_both_names_with_the_same_value_are_accepted(tmp_path):
    g = _gov(tmp_path, "a", signing_secret=NEW, token_secret=NEW)
    assert g.scope(tools=["read"]).to_token()


def test_the_environment_variables_follow_the_same_precedence(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WATCHLIGHT_SIGNING_SECRET", NEW)
    a = _gov(tmp_path, "a")
    b = _gov(tmp_path, "b", signing_secret=NEW)
    assert b.scope_from_token(a.scope(tools=["read"]).to_token()).allowed_tools == ["read"]
    assert WARNING not in capsys.readouterr().err


def test_the_old_environment_variable_still_works_and_warns(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WATCHLIGHT_TOKEN_SECRET", NEW)
    a = _gov(tmp_path, "a")
    b = _gov(tmp_path, "b", signing_secret=NEW)
    assert b.scope_from_token(a.scope(tools=["read"]).to_token()).allowed_tools == ["read"]
    assert WARNING in capsys.readouterr().err


def test_an_option_outranks_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_SIGNING_SECRET", OLD)
    a = _gov(tmp_path, "a", signing_secret=NEW)
    b = _gov(tmp_path, "b", signing_secret=NEW)
    assert b.scope_from_token(a.scope(tools=["read"]).to_token()).allowed_tools == ["read"]


def test_the_new_environment_variable_outranks_the_old(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_SIGNING_SECRET", NEW)
    monkeypatch.setenv("WATCHLIGHT_TOKEN_SECRET", OLD)
    with pytest.raises(ScopeTokenError) as exc:
        _gov(tmp_path, "a")
    assert exc.value.code == "mismatch"  # they DISAGREE, so neither is picked silently
    monkeypatch.setenv("WATCHLIGHT_TOKEN_SECRET", NEW)
    assert _gov(tmp_path, "b").scope(tools=["read"]).to_token()


# ── rotation: an ordered list ───────────────────────────────────────────────


def test_a_single_value_behaves_as_a_one_entry_list(tmp_path):
    a = _gov(tmp_path, "a", signing_secret=NEW)
    b = _gov(tmp_path, "b", signing_secret=[NEW])
    assert b.scope_from_token(a.scope(tools=["read"]).to_token()).allowed_tools == ["read"]


def test_a_token_minted_under_the_previous_secret_verifies_while_listed(tmp_path):
    """Deploy one of a rotation: the new secret goes to the FRONT, the old stays."""
    before = _gov(tmp_path, "a", signing_secret=OLD)
    token = before.scope(tools=["read"]).to_token()
    during = _gov(tmp_path, "b", signing_secret=[NEW, OLD])
    assert during.scope_from_token(token).allowed_tools == ["read"]


def test_a_token_minted_under_the_previous_secret_is_refused_once_dropped(tmp_path):
    """Deploy two: the old secret is gone, and so are the tokens it signed."""
    before = _gov(tmp_path, "a", signing_secret=OLD)
    token = before.scope(tools=["read"]).to_token()
    after = _gov(tmp_path, "b", signing_secret=[NEW])
    with pytest.raises(ScopeTokenError) as exc:
        after.scope_from_token(token)
    assert exc.value.code == "signature"


def test_a_token_minted_under_the_new_entry_verifies_from_the_moment_it_is_added(tmp_path):
    during = _gov(tmp_path, "a", signing_secret=[NEW, OLD])
    token = during.scope(tools=["read"]).to_token()   # signed with the FIRST entry
    after = _gov(tmp_path, "b", signing_secret=[NEW])
    assert after.scope_from_token(token).allowed_tools == ["read"]


def test_the_error_never_says_which_entry_was_tried(tmp_path):
    g = _gov(tmp_path, "a", signing_secret=[NEW, OLD])
    other = _gov(tmp_path, "b", signing_secret="a-third-signing-secret-32-bytes-")
    token = other.scope(tools=["read"]).to_token()
    with pytest.raises(ScopeTokenError) as exc:
        g.scope_from_token(token)
    message = str(exc.value)
    assert exc.value.code == "signature"
    assert NEW not in message and OLD not in message
    assert "1" not in message and "2" not in message  # no entry index, no count


def test_a_non_signature_failure_is_not_retried_across_entries(tmp_path):
    """A malformed token is refused for its own reason, not as a signature miss."""
    g = _gov(tmp_path, "a", signing_secret=[NEW, OLD])
    with pytest.raises(ScopeTokenError) as exc:
        g.scope_from_token("not-a-token")
    assert exc.value.code == "malformed"


def test_every_entry_must_meet_the_minimum_length(tmp_path):
    with pytest.raises(ScopeTokenError) as exc:
        _gov(tmp_path, "a", signing_secret=[NEW, "short"])
    assert exc.value.code == "weak_secret"
    assert "short" not in str(exc.value)


def test_an_empty_list_fails_closed(tmp_path):
    with pytest.raises(ScopeTokenError) as exc:
        _gov(tmp_path, "a", signing_secret=[])
    assert exc.value.code == "no_secret"
    with pytest.raises(ScopeTokenError):
        _gov(tmp_path, "b", signing_secret=["", "   "])


def test_the_environment_variable_takes_a_comma_separated_list(tmp_path, monkeypatch):
    before = _gov(tmp_path, "a", signing_secret=OLD)
    token = before.scope(tools=["read"]).to_token()
    monkeypatch.setenv("WATCHLIGHT_SIGNING_SECRET", f"{NEW}, {OLD}")
    during = _gov(tmp_path, "b")
    assert during.scope_from_token(token).allowed_tools == ["read"]


# ── the same list drives approvals ──────────────────────────────────────────


def _held(g, approval=None):
    return g.authorize(principal="U", action="a", resource="r", approval=approval)


def test_an_approval_minted_under_the_previous_secret_verifies_while_listed(tmp_path):
    before = _gov(tmp_path, "a", signing_secret=OLD)
    token = before.mint_approval(principal="U", action="a", resource="r")
    during = _gov(tmp_path, "b", signing_secret=[NEW, OLD])
    assert _held(during, token)["decision"] == "Allow"


def test_an_approval_minted_under_the_previous_secret_is_refused_once_dropped(tmp_path):
    before = _gov(tmp_path, "a", signing_secret=OLD)
    token = before.mint_approval(principal="U", action="a", resource="r")
    after = _gov(tmp_path, "b", signing_secret=[NEW])
    assert _held(after, token)["decision"] == "NeedsApproval"


def test_an_approval_minted_under_the_new_entry_verifies_immediately(tmp_path):
    during = _gov(tmp_path, "a", signing_secret=[NEW, OLD])
    token = during.mint_approval(principal="U", action="a", resource="r")
    after = _gov(tmp_path, "b", signing_secret=[NEW])
    assert _held(after, token)["decision"] == "Allow"


def test_an_approval_secret_list_rotates_independently(tmp_path):
    before = _gov(tmp_path, "a", approval_secret=OLD)
    token = before.mint_approval(principal="U", action="a", resource="r")
    during = _gov(tmp_path, "b", approval_secret=[NEW, OLD])
    assert _held(during, token)["decision"] == "Allow"
    after = _gov(tmp_path, "c", approval_secret=[NEW])
    assert _held(after, token)["decision"] == "NeedsApproval"


def test_an_approval_secret_overrides_the_signing_secret(tmp_path):
    minter = _gov(tmp_path, "a", signing_secret=NEW, approval_secret=OLD)
    token = minter.mint_approval(principal="U", action="a", resource="r")
    # A governor holding only the signing secret cannot verify it…
    assert _held(_gov(tmp_path, "b", signing_secret=NEW), token)["decision"] == "NeedsApproval"
    # …and one holding the approval secret can.
    assert _held(_gov(tmp_path, "c", approval_secret=OLD), token)["decision"] == "Allow"
