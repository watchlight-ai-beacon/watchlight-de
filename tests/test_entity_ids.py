"""The request helpers build only references the engine accepts, in the one
spelling it accepts, and refuse every id it would refuse.

The engine (``watchlight-engine`` 0.2.3) reads a request reference with a
strict parser: a quote, an apostrophe and a backslash must be escaped as
``\\"``, ``\\'`` and ``\\\\``, and a character that is not printable must be
written as ``\\u{…}``. The helpers escape the first group and refuse the
second. The shared fixture ``tests/fixtures/entity-ids.json`` holds the cases
both lanes must agree on; the TypeScript twin is ``ts/test/entity-ids.test.mjs``.
"""

from __future__ import annotations

import json
import pathlib
import unicodedata

import pytest

watchlight_engine = pytest.importorskip("watchlight_engine")

from watchlight import Watchlight, principals  # noqa: E402
from watchlight.principals import UNPRINTABLE_ID_MESSAGE, for_policy  # noqa: E402

FIXTURE = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "entity-ids.json").read_text("utf-8")
)["cases"]


def _engine():
    return watchlight_engine.PolicyEngine()


def _engine_accepts(engine, principal):
    """Whether the engine accepts ``principal`` as a request principal."""
    request = {"principal": principal, "action": "t", "resource": "r", "context": {}}
    try:
        engine.authorize(json.dumps(request))
    except Exception:  # noqa: BLE001 — any refusal counts
        return False
    return True


def _raw(entity_id):
    """The id with only a quote, an apostrophe and a backslash escaped: what a
    caller would write without the helper's refusal."""
    return 'User::"' + entity_id.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'") + '"'


@pytest.mark.parametrize("case", FIXTURE, ids=[c["label"] for c in FIXTURE])
def test_the_helper_builds_the_reference_the_engine_accepts_or_refuses(case):
    engine = _engine()
    if case["user"] is None:
        with pytest.raises(TypeError) as refused:
            principals.user(case["id"])
        # The message is fixed and never echoes the id.
        assert case["id"] not in str(refused.value)
        # The engine would refuse the id too: the refusal loses nothing.
        assert _engine_accepts(engine, _raw(case["id"])) is False
        return
    reference = principals.user(case["id"])
    assert reference == case["user"]
    assert reference == for_policy("User", case["id"])
    assert _engine_accepts(engine, reference) is True
    # The engine reads it back as exactly this id: it matches a policy written
    # for this id, and not one written for a neighbouring id.
    g = Watchlight(agent="ids", audit_file=False, audit_sink=lambda _r: None)
    g.allow(f'permit(principal == {for_policy("User", case["id"])}, action == Action::"t", resource);')
    assert g.authorize(action="t", principal=reference)["allowed"] is True
    assert g.authorize(action="t", principal=principals.user(case["id"] + "x"))["allowed"] is False


@pytest.mark.parametrize("entity_id", ["a\ud800b", "\udc00"])
def test_a_lone_surrogate_is_refused(entity_id):
    # A Cs code point: no request can carry it, and the helper says so.
    with pytest.raises(TypeError):
        principals.user(entity_id)


def test_an_apostrophe_is_escaped_in_the_spelling_the_engine_accepts():
    engine = _engine()
    assert principals.user("o'brien@example.com") == "User::\"o\\'brien@example.com\""
    assert _engine_accepts(engine, "User::\"o'brien@example.com\"") is False
    assert _engine_accepts(engine, principals.user("o'brien@example.com")) is True


def test_nul_is_escaped_for_policy_text_as_the_engine_spells_it():
    # The request helpers refuse a control character; for_policy escapes it,
    # and `\\0` is the spelling the strict parser accepts.
    assert for_policy("User", "a\x00b") == 'User::"a\\0b"'
    assert _engine_accepts(_engine(), 'User::"a\\0b"') is True
    assert _engine_accepts(_engine(), 'User::"a\\u{0}b"') is False


def test_an_unprintable_agent_name_is_refused_at_the_name():
    for name in ("a b", "a​b", "́a"):
        with pytest.raises(TypeError, match="must not contain a character the engine requires"):
            Watchlight(agent=name, audit_file=False)
    assert UNPRINTABLE_ID_MESSAGE.startswith("entity reference: id must not contain")


def _code_points():
    # Planes 0 and 1 in full, the CJK planes 2 and 3 (uniform ideographs and
    # unassigned blocks) sampled, and the tag and variation-selector block of
    # plane 14 in full. Surrogates are covered by the fixture.
    every = list(range(0, 0x20000)) + list(range(0x20000, 0x40000, 61)) + list(range(0xE0000, 0xE1000))
    for cp in every:
        if not 0xD800 <= cp <= 0xDFFF:
            yield cp


def test_every_id_the_helper_accepts_is_one_the_engine_accepts():
    """Code point by code point, in the middle and at the start of an id: the
    helper never builds a reference the engine refuses. The other direction
    is checked only where both Unicode tables agree: Python's Unicode data
    can be older than the engine's, and then the helper refuses a newly
    assigned character the engine accepts, which fails closed."""
    engine = _engine()
    accepted_but_refused = []
    refused_but_accepted = []
    for cp in _code_points():
        ch = chr(cp)
        for entity_id in ("a" + ch + "b", ch + "b"):
            try:
                reference = principals.user(entity_id)
            except TypeError:
                if (
                    unicodedata.category(ch) != "Cn"
                    and ch not in "\x00\t\n\r\x7f"
                    and _engine_accepts(engine, _raw(entity_id))
                ):
                    refused_but_accepted.append(hex(cp))
                continue
            if not _engine_accepts(engine, reference):
                accepted_but_refused.append(hex(cp))
    assert accepted_but_refused == []
    assert refused_but_accepted == []
