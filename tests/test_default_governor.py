"""Configuring the default governor — `configure_default`, `can_configure_default`,
and the environment layer.

The default `govern` is a module-level singleton, so every scenario runs in its
own process: what is being tested is precisely the once-per-process state that a
second `import watchlight` cannot reset.

Two things are proven here that the issue this file answers turned on:

* asking whether the default governor can still be configured is a QUESTION
  (`can_configure_default()`), and re-applying the configuration already in
  force is a no-op rather than an exception path; and
* a process can send the default governor's trail somewhere else — or turn the
  local file off entirely — with an environment variable, so a test run stops
  depositing its verdicts into the `audit.jsonl` an application is writing in the
  same working directory. No code change, no try/except, no import-order puzzle.

What is deliberately NOT changed: the default governor still writes
`.watchlight/audit.jsonl` on its first governed call with no opt-in. That file
IS the quickstart — `watchlight dev` reads it and nothing else — so a default
that wrote nothing until configured would break the first five minutes.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

from watchlight import AUDIT_DIR_ENV, AUDIT_FILE_ENV


def _run(script: str, *args, cwd: pathlib.Path, env: dict | None = None, check: bool = True):
    environ = dict(os.environ)
    # Never let the developer's own environment decide a test's answer.
    environ.pop(AUDIT_DIR_ENV, None)
    environ.pop(AUDIT_FILE_ENV, None)
    environ.update(env or {})
    return subprocess.run(
        [sys.executable, "-c", script, *[str(a) for a in args]],
        capture_output=True,
        text=True,
        check=check,
        cwd=str(cwd),
        env=environ,
    )


# ── the environment variable names are part of the contract ─────────


def test_the_environment_variable_names_follow_the_existing_scheme():
    # WATCHLIGHT_<OPTION>, exactly as WATCHLIGHT_AGENT / WATCHLIGHT_SIGNING_SECRET.
    assert AUDIT_DIR_ENV == "WATCHLIGHT_AUDIT_DIR"
    assert AUDIT_FILE_ENV == "WATCHLIGHT_AUDIT_FILE"


# ── can_configure_default: the question, not the exception ──────────


_ASK_SCRIPT = """
from watchlight import govern, configure_default, can_configure_default

assert can_configure_default() is True
# Asking mutates nothing: it is still true, and configuring still works.
assert can_configure_default() is True
configure_default(agent="asked")
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
assert can_configure_default() is False
print("OK")
"""


def test_can_configure_default_answers_before_and_after_the_first_record(tmp_path):
    out = _run(_ASK_SCRIPT, cwd=tmp_path)
    assert "OK" in out.stdout


# ── configure_default is idempotent-safe ────────────────────────────


_IDEMPOTENT_SCRIPT = """
from watchlight import govern, configure_default, can_configure_default

sink = lambda record: None
configure_default(agent="billing-agent", audit_sink=sink, audit_dir="trail")
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
assert can_configure_default() is False

# The SAME options, applied again — the common defensive call. A no-op, and the
# governor it returns is still the one governor.
assert configure_default(agent="billing-agent", audit_sink=sink, audit_dir="trail") is govern
# Naming nothing at all is trivially a no-op too.
configure_default()
# A subset is fine; so is an equivalent spelling of the same directory.
configure_default(audit_dir="./trail")
assert govern.agent == "billing-agent"
print("OK")
"""

_CONFLICT_SCRIPT = """
from watchlight import govern, configure_default

sink = lambda record: None
configure_default(agent="billing-agent", audit_sink=sink, audit_dir="trail")
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')

def conflict(**options):
    try:
        configure_default(**options)
    except RuntimeError as exc:
        return str(exc)
    raise AssertionError(f"expected a conflict for {options!r}")

# Each message names WHICH option conflicts, and with what.
assert "agent would change from 'billing-agent' to 'other'" in conflict(agent="other")
assert "audit_dir would change from 'trail' to 'elsewhere'" in conflict(audit_dir="elsewhere")
assert "audit_file would change from True to False" in conflict(audit_file=False)
# A sink BUILT a second time is a different sink: silently keeping the first
# would discard the records the caller believed it had just redirected.
assert "audit_sink would change" in conflict(audit_sink=lambda record: None)
assert "strict_principal would change from True to False" in conflict(strict_principal=False)
# A secret conflict never reports either value.
message = conflict(signing_secret="a-different-signing-secret-32-by")
assert "signing_secret would change" in message
assert "a-different-signing-secret" not in message
# The advice is the question, not a try/except.
assert "can_configure_default()" in message
print("OK")
"""


def test_reapplying_the_same_configuration_is_a_no_op(tmp_path):
    assert "OK" in _run(_IDEMPOTENT_SCRIPT, cwd=tmp_path).stdout


_BOUND_SINK_SCRIPT = """
from watchlight import govern, configure_default

class Store:
    def __init__(self):
        self.rows = []
    def insert(self, record):
        self.rows.append(record)
    def count(self, query):
        return len(self.rows)

# A BOUND METHOD is a new object on every attribute access, so identity alone
# could never match it — and `records.append` is the shape the docs show.
records = []
assert records.append is not records.append
assert records.append == records.append

store = Store()
configure_default(
    agent="rpt", audit_sink=records.append, audit_dir="trail", counter_source=store.count
)
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
assert len(records) == 1, records

# Re-applying byte-identical configuration — the defensive second call — with
# every callable read a SECOND time from the same object.
configure_default(
    agent="rpt", audit_sink=records.append, audit_dir="trail", counter_source=store.count
)
assert len(records) == 1, "the trail must not have been rebuilt"

# One more governed call still reaches the original sink.
govern.authorize(action="read", principal='User::"u"')
assert len(records) == 2, records

# But a DIFFERENT callable is still a conflict, in every position.
def refuse(**options):
    try:
        configure_default(**options)
    except RuntimeError as exc:
        return str(exc)
    raise AssertionError(f"expected a conflict for {options!r}")

assert "audit_sink would change" in refuse(audit_sink=lambda record: None)
assert "audit_sink would change" in refuse(audit_sink=[].append)        # another instance
assert "counter_source would change" in refuse(counter_source=Store().count)

# A pathological __eq__ can neither raise out of the check nor be believed.
class Hostile:
    def __eq__(self, other):
        raise RuntimeError("boom")
    def __call__(self, record):
        pass

class Vague:
    def __eq__(self, other):
        return "yes"                      # truthy, but not True
    def __call__(self, record):
        pass

assert "audit_sink would change" in refuse(audit_sink=Hostile())
assert "audit_sink would change" in refuse(audit_sink=Vague())
print("OK")
"""


def test_a_bound_method_sink_re_read_is_the_same_sink(tmp_path):
    # A bound method is a NEW object every time it is read, so an identity-only
    # comparison would make the idempotence path unreachable for most real sinks.
    assert "OK" in _run(_BOUND_SINK_SCRIPT, cwd=tmp_path).stdout


def test_a_genuine_conflict_names_the_option_and_never_a_secret(tmp_path):
    assert "OK" in _run(_CONFLICT_SCRIPT, cwd=tmp_path).stdout


# ── the environment layer ───────────────────────────────────────────


_WRITE_SCRIPT = """
import pathlib
from watchlight import govern

govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
print("here:", pathlib.Path(".watchlight/audit.jsonl").exists())
print("there:", pathlib.Path("elsewhere/audit.jsonl").exists())
"""


def _wrote(out) -> tuple[bool, bool]:
    lines = dict(
        line.split(": ", 1) for line in out.stdout.splitlines() if line.startswith(("here", "there"))
    )
    return lines["here"] == "True", lines["there"] == "True"


def test_zero_configuration_still_writes_the_quickstart_file(tmp_path):
    # The decision the issue floated and this change deliberately did NOT take:
    # `watchlight dev` reads `.watchlight/audit.jsonl` and nothing else, so a
    # default that wrote nothing until configured would break the quickstart.
    here, there = _wrote(_run(_WRITE_SCRIPT, cwd=tmp_path))
    assert here and not there
    assert (tmp_path / ".watchlight" / "audit.jsonl").read_text().strip()


def test_the_audit_file_switch_writes_nothing_into_the_working_directory(tmp_path):
    here, there = _wrote(_run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: "0"}))
    assert not here and not there
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("off", ["0", "false", "FALSE", "no", "off", " Off "])
def test_every_accepted_spelling_of_off_turns_the_file_off(tmp_path, off):
    here, _ = _wrote(_run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: off}))
    assert not here


@pytest.mark.parametrize("on", ["1", "true", "yes", "on"])
def test_every_accepted_spelling_of_on_keeps_the_file(tmp_path, on):
    here, _ = _wrote(_run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: on}))
    assert here


def test_an_unrecognized_switch_is_ignored_reported_once_and_keeps_the_trail(tmp_path):
    # The conservative reading of an audit switch: a typo must never quietly turn
    # a trail off, and must never take an application down either.
    out = _run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: "of"})
    here, _ = _wrote(out)
    assert here
    assert out.stderr.count("does not recognize") == 1
    assert AUDIT_FILE_ENV in out.stderr


def test_the_audit_directory_redirects_the_trail(tmp_path):
    here, there = _wrote(_run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_DIR_ENV: "elsewhere"}))
    assert there and not here


_LATE_ENV_SCRIPT = """
import os, pathlib, sys
import watchlight                      # imported BEFORE the variable is set

os.environ["WATCHLIGHT_AUDIT_DIR"] = "elsewhere"
watchlight.govern.allow('permit(principal, action, resource);')
watchlight.govern.authorize(action="read", principal='User::"u"')
print("here:", pathlib.Path(".watchlight/audit.jsonl").exists())
print("there:", pathlib.Path("elsewhere/audit.jsonl").exists())
"""


def test_the_environment_is_read_lazily_at_first_use(tmp_path):
    # Read at import time, the variable's effect would depend on whether the
    # application imported `watchlight` before or after setting it.
    here, there = _wrote(_run(_LATE_ENV_SCRIPT, cwd=tmp_path))
    assert there and not here


_CONSTRUCTED_SCRIPT = """
import pathlib
from watchlight import Watchlight

g = Watchlight(agent="mine", audit_dir="mine")
g.allow('permit(principal, action, resource);')
g.authorize(action="read", principal='User::"u"')
print("here:", pathlib.Path("mine/audit.jsonl").exists())
print("there:", pathlib.Path("elsewhere/audit.jsonl").exists())
"""


def test_a_governor_you_construct_names_its_own_options_and_ignores_the_environment(tmp_path):
    # The environment layer exists for the ONE governor an application never
    # constructs. Letting it override an explicit constructor argument would
    # invert the precedence every other option in this SDK resolves in.
    out = _run(
        _CONSTRUCTED_SCRIPT,
        cwd=tmp_path,
        env={AUDIT_DIR_ENV: "elsewhere", AUDIT_FILE_ENV: "0"},
    )
    here, there = _wrote(out)
    assert here and not there


# ── precedence: option > environment > default ──────────────────────


_PRECEDENCE_SCRIPT = """
import pathlib
from watchlight import govern, configure_default

configure_default(audit_dir="chosen")     # explicit, against WATCHLIGHT_AUDIT_DIR=elsewhere
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
assert pathlib.Path("chosen/audit.jsonl").exists()
assert not pathlib.Path("elsewhere/audit.jsonl").exists()
assert not pathlib.Path(".watchlight/audit.jsonl").exists()
print("OK")
"""

_PRECEDENCE_OVER_OFF_SCRIPT = """
import pathlib
from watchlight import govern, configure_default

configure_default(audit_file=True, audit_dir="chosen")   # explicit, against WATCHLIGHT_AUDIT_FILE=0
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
assert pathlib.Path("chosen/audit.jsonl").exists()
print("OK")
"""


def test_an_explicit_option_beats_the_environment(tmp_path):
    out = _run(_PRECEDENCE_SCRIPT, cwd=tmp_path, env={AUDIT_DIR_ENV: "elsewhere"})
    assert "OK" in out.stdout


def test_an_explicit_option_beats_the_environment_switch_too(tmp_path):
    out = _run(_PRECEDENCE_OVER_OFF_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: "0"})
    assert "OK" in out.stdout


def test_the_environment_becomes_the_configuration_a_later_call_is_compared_against(tmp_path):
    # After the first record, the environment's directory is what is "in force":
    # naming the same one again is a no-op, naming another one is a conflict.
    script = """
import pathlib
from watchlight import govern, configure_default

govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u"')
configure_default(audit_dir="elsewhere")          # matches the environment: a no-op
try:
    configure_default(audit_dir="third")
except RuntimeError as exc:
    assert "audit_dir would change from 'elsewhere' to 'third'" in str(exc), exc
else:
    raise AssertionError("a different directory must conflict")
print("OK")
"""
    out = _run(script, cwd=tmp_path, env={AUDIT_DIR_ENV: "elsewhere"})
    assert "OK" in out.stdout


# ── the contamination case the issue reported ───────────────────────


_APP_SCRIPT = """
from watchlight import govern, configure_default

configure_default(agent="statements-api")
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"u1"')
print("OK")
"""

# A test process that authorizes directly — a perfectly reasonable thing to write
# in a test, and the case `govern.test()` never covered because policy tests
# write nothing at all.
_TEST_PROCESS_SCRIPT = """
from watchlight import govern

govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"fixture"')
govern.authorize(action="write", principal='User::"fixture"')
print("OK")
"""


def test_a_test_process_can_opt_out_of_the_working_directory_an_application_uses(tmp_path):
    assert "OK" in _run(_APP_SCRIPT, cwd=tmp_path).stdout
    trail = tmp_path / ".watchlight" / "audit.jsonl"
    before = trail.read_text()

    # Without the variable, the test process would append its verdicts — under
    # the DEFAULT agent name — to the application's file.
    assert "OK" in _run(_TEST_PROCESS_SCRIPT, cwd=tmp_path).stdout
    assert trail.read_text() != before
    contaminated = trail.read_text()

    # With it, the same test process writes nothing at all.
    assert "OK" in _run(_TEST_PROCESS_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: "0"}).stdout
    assert trail.read_text() == contaminated

    # Or sends its own trail somewhere of its own, still touching nothing here.
    assert "OK" in _run(_TEST_PROCESS_SCRIPT, cwd=tmp_path, env={AUDIT_DIR_ENV: "test-run"}).stdout
    assert trail.read_text() == contaminated
    assert (tmp_path / "test-run" / "audit.jsonl").exists()


def test_policy_tests_already_wrote_nothing(tmp_path):
    # `govern.test()` uses the engine's decision core directly; it has never
    # written a record. Pinned so it stays that way.
    script = """
import pathlib
from watchlight import govern

govern.allow('permit(principal, action == Action::"read", resource);')
report = govern.test([{"name": "read", "action": "read", "expect": "Allow"}])
assert report["failed"] == 0, report
print("here:", pathlib.Path(".watchlight/audit.jsonl").exists())
print("there:", False)
"""
    here, _ = _wrote(_run(script, cwd=tmp_path))
    assert not here


# ── the file-off notice is the trail's own, not the default's ───────


def test_with_the_file_off_and_no_sink_only_the_no_destination_notice_is_printed(tmp_path):
    out = _run(_WRITE_SCRIPT, cwd=tmp_path, env={AUDIT_FILE_ENV: "0"})
    assert out.stderr.count("audit records are discarded") == 1
    # "writes only to the local audit file" would be untrue with the file off.
    assert "writes only to the local audit file" not in out.stderr


# ── `watchlight dev` follows the trail ──────────────────────────────


def test_the_dashboard_default_follows_the_audit_directory(monkeypatch):
    from watchlight import cli

    monkeypatch.delenv(AUDIT_DIR_ENV, raising=False)
    assert cli._default_audit_path() == os.path.join(".watchlight", "audit.jsonl")
    monkeypatch.setenv(AUDIT_DIR_ENV, "elsewhere")
    assert cli._default_audit_path() == os.path.join("elsewhere", "audit.jsonl")
    monkeypatch.setenv(AUDIT_DIR_ENV, "   ")
    assert cli._default_audit_path() == os.path.join(".watchlight", "audit.jsonl")
