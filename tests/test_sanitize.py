"""sanitize (Python) — de-rules-2 detector set, mirroring ts/test/sanitize.test.mjs:
PASSPORT / DOB structured detectors, the application-supplied KNOWN dictionary,
the opt-in PERSON / ADDRESS heuristics, value-free reports, and regex safety."""
import inspect
import json
import pathlib
import random
import re
import sys
import time
import unicodedata

import pytest

import watchlight
from watchlight import (
    DEFAULT_PII_TYPES,
    DETECTOR_VERSION,
    HEURISTIC_PII_TYPES,
    SanitizeError,
    Watchlight,
    sanitize,
)

SAMPLE = (
    "Contact alice@acme.com or bob@acme.com. Card 4111 1111 1111 1111, SSN 123-45-6789, "
    "phone (415) 555-0132, IP 10.0.0.5, IBAN GB82 WEST 1234 5698 7654 32, key sk-ABCDEFGHIJKLMNOP1234."
)


def counts(text, **kw):
    return sanitize(text, **kw)["report"]["counts"]


def test_detector_set_and_defaults():
    r = sanitize(SAMPLE)
    assert DETECTOR_VERSION == "de-rules-2" == r["report"]["detector_version"]
    assert all(t not in DEFAULT_PII_TYPES for t in HEURISTIC_PII_TYPES)
    assert "PASSPORT" in DEFAULT_PII_TYPES and "DOB" in DEFAULT_PII_TYPES
    # existing callers see no new types on the legacy sample
    assert not {"KNOWN", "PERSON", "ADDRESS"} & set(r["report"]["counts"])
    assert r["report"]["counts"]["EMAIL"] == 2 and r["report"]["counts"]["CREDIT_CARD"] == 1


def test_passport_labelled_and_mrz():
    r = sanitize("Passport No: X1234567, passport #: AB123456, PASSPORT NUMBER 987654321.")
    assert r["report"]["counts"]["PASSPORT"] == 3
    assert r["text"].startswith("Passport No: <PASSPORT_1>")
    assert "X1234567" not in r["text"] and "AB123456" not in r["text"]
    # negatives: label without a digit-bearing token; bare numbers
    assert counts("passport renewal office 123456").get("PASSPORT", 0) == 0
    assert counts("ref AB123456 / 987654321").get("PASSPORT", 0) == 0
    mrz1 = "P<UTOERIKSSON<<ANNA<MARIA".ljust(44, "<")
    mrz2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    r = sanitize(f"scan:\n{mrz1}\n{mrz2}\n")
    assert r["report"]["counts"]["PASSPORT"] == 2
    assert "ERIKSSON" not in r["text"] and "L898902C3" not in r["text"]
    assert counts("A" * 44).get("PASSPORT", 0) == 0


def test_dob_labelled_only():
    r = sanitize(
        "DOB: 03/15/1985. Date of birth 1985-03-15; born on 15 March 1985; "
        "birthday March 15th, 1985; D.O.B. 15.03.85"
    )
    assert r["report"]["counts"]["DOB"] == 5
    assert "DOB: <DOB_1>" in r["text"] and "1985" not in r["text"] and "15.03.85" not in r["text"]
    assert counts("Statement date 03/15/2024, due 04/01/2024").get("DOB", 0) == 0
    assert counts("DOB: 13/45/1985 dob 99/99/99 DOB: 01/01/1850").get("DOB", 0) == 0
    assert counts("the project was born in 2019").get("DOB", 0) == 0


def test_ssn_is_redacted_not_validated():
    # The excluded ranges are not issuable SSNs, but a mistyped one on a form is
    # still a disclosure. Redaction removes the shape; it does not check it.
    for text in ("987-65-4321", "666-12-3456", "000-11-2222", "123-00-4567", "123-45-0000"):
        out = sanitize(f"SSN {text}")
        assert out["text"] == "SSN <SSN_1>", f"{text} was not redacted"
        assert out["report"]["counts"]["SSN"] == 1
    # and a value is never echoed into the report
    assert "987" not in json.dumps(sanitize("SSN 987-65-4321")["report"])


def test_known_dictionary():
    r = sanitize(
        "Ada Lovelace lives at 12 Oak Lane; contact ada lovelace or ADA LOVELACE.",
        known=["Ada Lovelace", "Oak Lane"],
    )
    assert r["report"]["counts"]["KNOWN"] == 4
    assert not re.search(r"ada lovelace|oak lane", r["text"], re.I)
    assert r["text"].count("<KNOWN_1>") == 3 and "<KNOWN_2>" in r["text"]
    dumped = json.dumps(r["report"])
    assert "Lovelace" not in dumped and "Oak" not in dumped
    # overlapping / nested spans merge — no fragment survives
    ov = sanitize("Ann Lee Smith and ANN LEE", known=["Ann Lee", "Lee Smith"])
    assert not re.search(r"smith|lee|ann", ov["text"], re.I) and ov["report"]["counts"]["KNOWN"] == 2
    # A known value matches as a WHOLE WORD: "aa" is not an occurrence inside
    # "aaaa", and a name is not an occurrence inside a longer name.
    assert sanitize("aaaa", known=["aa"])["text"] == "aaaa"
    assert sanitize("aa aaaa", known=["aa"])["text"] == "<KNOWN_1> aaaa"
    assert sanitize("Smithfield Road", known=["Smith"])["text"] == "Smithfield Road"
    # …and punctuation at either edge is still a boundary, so a possessive,
    # a comma or a value whose own edge is punctuation all still match.
    assert sanitize("Smith's file", known=["Smith"])["text"] == "<KNOWN_1>'s file"
    # a span extending past a structured span is clipped, not dropped
    clip = sanitize("a@b.com Ltd", known=["com Ltd"])
    assert clip["text"] == "<EMAIL_1><KNOWN_1>" and clip["report"]["counts"]["EMAIL"] == 1
    # union: a structured span that STARTS inside a KNOWN span keeps its tail
    assert sanitize("ACC 4111 1111 1111 1111", known=["ACC 4111"])["text"] == "<KNOWN_1><CREDIT_CARD_1>"
    assert sanitize("SSN 123-45-6789", known=["SSN 123"])["text"] == "<KNOWN_1><SSN_1>"
    assert sanitize("Ann Lee@example.com", known=["Ann Lee"])["text"] == "<KNOWN_1><EMAIL_1>"
    both = sanitize("ACC 4111 1111 1111 1111 / SSN 123-45-6789", known=["ACC 4111", "SSN 123"])["text"]
    assert not re.search(r"\d", re.sub(r"<[A-Z_]+_\d+>", "", both))  # only tag numerals remain
    # regex metacharacters are literal
    meta = sanitize("see (a.b)*c$ and (a.b)*c$", known=["(a.b)*c$"])
    assert meta["report"]["counts"]["KNOWN"] == 2 and "(a.b)" not in meta["text"]
    # blanks ignored; honoured under a restrictive types filter; absent otherwise
    assert sanitize("nothing here", known=["", "   "])["text"] == "nothing here"
    assert sanitize("SSN 123-45-6789 alice", known=["alice"], types=["EMAIL"])["text"] == "SSN 123-45-6789 <KNOWN_1>"
    assert "KNOWN" not in counts("alice")
    h1 = sanitize("Ada", known=["ada"], mode="hash")["text"]
    assert h1 == sanitize("Ada", known=["ada"], mode="hash")["text"] and re.fullmatch(r"<KNOWN_[0-9a-f]{8}>", h1)
    hk = sanitize("Ada ADA ada", known=["ada"], mode="hash")["text"].split(" ")
    assert len(hk) == 3 and len(set(hk)) == 1  # hash mode is case-unified
    with pytest.raises(SanitizeError) as ei:
        sanitize("x", known=["ok", 42])
    assert "42" not in str(ei.value)
    # a bare str is a Sequence[str] of characters — rejected, never echoed
    for bad in ("Ann Lee", b"Ann Lee"):
        with pytest.raises(SanitizeError) as ei:
            sanitize("Ann Lee", known=bad)
        assert str(ei.value).endswith("known must be a sequence of strings")


def test_known_large_dictionary_stays_fast():
    dictionary = [f"name{i} street{i}" for i in range(10000)]
    text = ("lorem ipsum " * 16000)[:200000]
    t0 = time.monotonic()
    sanitize(text, known=dictionary)
    assert time.monotonic() - t0 < 3.0


def test_person_and_address_opt_in():
    people = (
        "Dr. Ada Lovelace met Patient: Grace Hopper and ATTN: Alan M. Turing. "
        "Alan Turing wrote it. The Cedar is neat."
    )
    assert "PERSON" not in counts(people) and "Ada Lovelace" in sanitize(people)["text"]
    per = sanitize(people, types=["PERSON"])
    assert per["report"]["counts"]["PERSON"] == 4, per
    for leak in ("Lovelace", "Hopper", "Turing"):
        assert leak not in per["text"]
    assert "The Cedar is neat" in per["text"]  # stop word + single word is not a name
    trimmed = sanitize("Dear Ada Lovelace, Thanks Grace Hopper. From Alan Turing", types=["PERSON"])
    assert trimmed["text"] == "Dear <PERSON_1>, Thanks <PERSON_2>. From <PERSON_3>"
    irish = sanitize("Dr. Sam O'Neil met Kim McDonald-Lee and Jean-Luc D'Angelo", types=["PERSON"])
    assert irish["text"] == "Dr. <PERSON_1> met <PERSON_2> and <PERSON_3>"
    assert counts("alice met bob at the cafe", types=["PERSON"]).get("PERSON", 0) == 0

    where = "Ship to 123 Main Street, Apt 4B, Springfield, IL 62704 or P.O. Box 987. Meet at 10 Downing St."
    assert "ADDRESS" not in counts(where)
    addr = sanitize(where, types=["ADDRESS"])
    assert addr["report"]["counts"]["ADDRESS"] == 3, addr
    for leak in ("Main Street", "Box 987", "Downing"):
        assert leak not in addr["text"]
    assert counts("Meet on Main at noon; 5 apples", types=["ADDRESS"]).get("ADDRESS", 0) == 0
    assert sanitize("123 Main Street", types=["PERSON", "ADDRESS"])["text"] == "<ADDRESS_1>"


def test_person_exclusions_are_exact_and_scoped_to_person(tmp_path):
    text = (
        "Placing agency: Larkspur Hollow Services; contact Ada Lovelace at "
        "ada@example.com, SSN 123-45-6789"
    )
    default = sanitize(text, types=["PERSON", "EMAIL", "SSN"])
    assert "Larkspur Hollow Services" not in default["text"]

    excluded = sanitize(
        text,
        types=["PERSON", "EMAIL", "SSN"],
        person_exclusions=["larkspur hollow services"],
    )
    assert "Larkspur Hollow Services" in excluded["text"]
    assert "Ada Lovelace" not in excluded["text"]
    assert "ada@example.com" not in excluded["text"]
    assert "123-45-6789" not in excluded["text"]
    assert excluded["report"]["counts"] == {"PERSON": 1, "EMAIL": 1, "SSN": 1}
    assert "Larkspur" not in json.dumps(excluded["report"])

    # Exclusions name a complete PERSON candidate; partial strings do not make
    # a larger candidate survive.
    partial = sanitize(
        "Larkspur Hollow Services", types=["PERSON"], person_exclusions=["Larkspur Hollow"]
    )
    assert partial["text"] == "<PERSON_1>"

    g = Watchlight(agent="doc-agent", audit_dir=tmp_path)
    governed = g.sanitize(
        text,
        types=["PERSON", "EMAIL", "SSN"],
        person_exclusions=["Larkspur Hollow Services"],
        agent="reviewer",
    )
    assert "Larkspur Hollow Services" in governed["text"]
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"agent": "reviewer"' in raw
    assert "Larkspur" not in raw and "Hollow" not in raw and "Services" not in raw


def test_person_exclusions_reject_invalid_shapes_without_echoing_values():
    for bad in ("Larkspur Hollow Services", b"Larkspur Hollow Services", 42):
        with pytest.raises(SanitizeError) as ei:
            sanitize("Larkspur Hollow Services", types=["PERSON"], person_exclusions=bad)
        assert str(ei.value).endswith("person_exclusions must be a sequence of strings")
    with pytest.raises(SanitizeError) as ei:
        sanitize("Larkspur Hollow Services", types=["PERSON"], person_exclusions=["ok", 42])
    assert "42" not in str(ei.value)


def test_adversarial_inputs_stay_fast():
    adversarial = [
        "passport" + " " * 50000 + "x", "DOB:" + " " * 50000, "Aa " * 20000,
        "1 " * 30000 + "Main St", "born on " + "1/" * 30000, "<" * 50000, "x" * 200000,
    ]
    t0 = time.monotonic()
    for a in adversarial:
        sanitize(a, types=["PASSPORT", "DOB", "PERSON", "ADDRESS", "PHONE", "CREDIT_CARD"], known=["zzz"])
    assert time.monotonic() - t0 < 5.0
    # The EMAIL rule must be LINEAR in the length of a local-part run that never
    # reaches a domain — the classic catastrophic-backtracking shape. A fixed
    # millisecond budget measures the machine as much as the regex and fails on
    # a slow shared runner, so assert the property itself: ten times the input
    # takes roughly ten times as long, not a hundred or more. Best-of-three,
    # because the small measurement is the noisy one.
    def scan_seconds(n: int) -> float:
        text = "a." * n + "@"
        best = float("inf")
        for _ in range(3):
            t = time.monotonic()
            sanitize(text)
            best = min(best, time.monotonic() - t)
        return best

    small, large = scan_seconds(20_000), scan_seconds(200_000)
    assert large < 5.0, f"a 200k-char local-part run took {large:.2f}s — not linear"
    # Linear is ~10x for 10x the input. Quadratic would be ~100x and catastrophic
    # backtracking would not finish; 25x leaves room for timer noise and a cold
    # cache without admitting either.
    assert large < small * 25, f"scan time grew {large / small:.0f}x for 10x the input"
    for a in ("a@" * 50000, "x@" + "a." * 100000):
        sanitize(a)
    assert counts(".alice@acme.com x-bob@acme.com plus+tag@acme.co.uk")["EMAIL"] == 3


def test_governed_known_never_reaches_audit(tmp_path):
    g = Watchlight(agent="doc-agent", audit_dir=tmp_path)
    g.sanitize("Ada Lovelace, DOB: 03/15/1985", resource="intake.txt", known=["Ada Lovelace"])
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"KNOWN": 1' in raw and '"DOB": 1' in raw and '"detector": "de-rules-2"' in raw
    assert "Lovelace" not in raw and "1985" not in raw


# ── register_detector ───────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _no_registered_detectors():
    """The registry is process-wide, so every case starts and ends empty."""
    watchlight._clear_custom_detectors()
    yield
    watchlight._clear_custom_detectors()


def test_a_registered_detector_redacts_and_counts():
    watchlight.register_detector("ALIEN_NUMBER", r"\bA[- ]?\d{8,9}\b")
    out = sanitize("Applicant A-12345678 filed the form.")
    assert out["text"] == "Applicant <ALIEN_NUMBER_1> filed the form."
    assert out["report"]["counts"] == {"ALIEN_NUMBER": 1}
    assert "12345678" not in json.dumps(out["report"])


def test_a_registered_detector_is_on_by_default_and_selectable():
    watchlight.register_detector("CASE_NO", r"\bCASE-\d{4}-\d{5}\b")
    assert sanitize("ref CASE-2026-00123")["text"] == "ref <CASE_NO_1>"
    # selectable by label
    assert sanitize("ref CASE-2026-00123", types=["CASE_NO"])["text"] == "ref <CASE_NO_1>"
    # and excluded when the caller names a different set
    assert sanitize("ref CASE-2026-00123", types=["SSN"])["text"] == "ref CASE-2026-00123"


def test_a_validator_can_reject_a_match():
    watchlight.register_detector(
        "EVEN_ID", r"\bID\d{4}\b", validate=lambda v: int(v[2:]) % 2 == 0
    )
    assert sanitize("ID1234 and ID1235")["text"] == "<EVEN_ID_1> and ID1235"


def test_the_detector_version_names_the_registered_set():
    plain = sanitize("nothing here")["report"]["detector_version"]
    assert plain == watchlight.DETECTOR_VERSION
    watchlight.register_detector("CASE_NO", r"\bCASE-\d{4}\b")
    with_custom = sanitize("nothing here")["report"]["detector_version"]
    assert with_custom.startswith(watchlight.DETECTOR_VERSION + "+custom.")
    # the digest tracks the set, and never leaks the pattern itself
    assert "CASE" not in with_custom.split("+custom.")[1]
    watchlight.register_detector("OTHER", r"\bX\d{4}\b")
    assert sanitize("x")["report"]["detector_version"] != with_custom


@pytest.mark.parametrize(
    "pattern",
    [r"(a+)+$", r"(a|aa)+$", r"(a|a?)+$", r"([a-z]+)*$", r"(x+x+)+y$", r"(\s*\w+)+$"],
)
def test_a_catastrophic_pattern_is_refused_rather_than_run(pattern):
    # It must REFUSE, not hang: a detector runs over every document, so the
    # cost of finding out belongs at registration.
    with pytest.raises(SanitizeError):
        watchlight.register_detector("EVIL", pattern)
    assert watchlight.registered_detectors() == ()


@pytest.mark.parametrize(
    "pattern",
    [r"\bA[- ]?\d{8,9}\b", r"\bCASE-\d{4}-\d{5}\b", r"\b\d{9}\b", r"\b[A-Z]{1,2}\d{6,8}\b",
     r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,20}\b", r"(?:VISA|PASSPORT)[ -]?[A-Z0-9]{6,9}",
     r"\b\d{3}-\d{3}-\d{4}\b", r"[\w.+-]+@[\w-]+\.[a-z]{2,}"],
)
def test_a_real_detector_pattern_is_accepted(pattern):
    # The guard is worthless if it refuses the patterns people actually write.
    watchlight.register_detector("CUSTOM", pattern)
    assert watchlight.registered_detectors() == ("CUSTOM",)


def test_a_builtin_label_cannot_be_replaced():
    for label in ("SSN", "EMAIL", "KNOWN"):
        with pytest.raises(SanitizeError):
            watchlight.register_detector(label, r"\d{3}")
    # …and the built-in still works
    assert sanitize("SSN 123-45-6789")["text"] == "SSN <SSN_1>"


@pytest.mark.parametrize("label", ["lower", "With Space", "TRAILING_", "9LEADING", ""])
def test_a_label_must_be_upper_snake_case(label):
    with pytest.raises(SanitizeError):
        watchlight.register_detector(label, r"\d{3}")


def test_an_invalid_pattern_is_refused():
    with pytest.raises(SanitizeError):
        watchlight.register_detector("BAD", r"([a-z")


def test_re_registering_is_a_no_op_but_a_conflict_raises():
    watchlight.register_detector("CASE_NO", r"\bCASE-\d{4}\b")
    watchlight.register_detector("CASE_NO", r"\bCASE-\d{4}\b")  # an import that ran twice
    assert watchlight.registered_detectors() == ("CASE_NO",)
    with pytest.raises(SanitizeError):
        watchlight.register_detector("CASE_NO", r"\bCASE-\d{5}\b")


def test_a_builtin_span_wins_over_a_custom_one():
    # Built-ins are scanned first, so a custom rule cannot take a span from one.
    watchlight.register_detector("NINE_DIGITS", r"\b[\d-]{11}\b")
    out = sanitize("SSN 123-45-6789")
    assert out["report"]["counts"] == {"SSN": 1}


# ── PHONE: E.164 and grouped international forms ────────────────────

E164_AND_GROUPED = [
    "+15550142889",       # E.164 US — the format systems normalise to
    "+442071838750",      # E.164 UK
    "+493012345678",      # E.164 DE
    "+1 555 014 2889",
    "+1-555-014-2889",
    "+1-555-0142-8899",
    "(555) 014-2889",
    "555-014-2889",
    "555.014.2889",
    "555 014 2889",
    "5550142889",
    "020 7183 8750",      # UK national grouping
    "555-014-2889 x22",
]


@pytest.mark.parametrize("number", E164_AND_GROUPED)
def test_phone_detects_every_common_format(number):
    # PHONE is default-on, so a format it misses is one every caller is
    # silently exposed to. The unseparated E.164 forms were missed in every
    # country: the North-American rule consumes at most ten digits.
    assert sanitize(number, types=["PHONE"])["report"]["counts"].get("PHONE") == 1, number


@pytest.mark.parametrize(
    "text,expected",
    [
        ("2026-09-07", None),                       # an ISO date is not a phone number
        ("2026-09-07 to 2026-09-30", None),
        ("ORD-2026-0001", None),
        ("1.10.0", None),
        ("1,234.56", None),
        ("12 34 56", None),
        ("4111 1111 1111 1111", "CREDIT_CARD"),     # still the card rule
        ("123-45-6789", "SSN"),                     # still the SSN rule
        ("192.168.1.1", "IPV4"),                    # still the IPv4 rule
    ],
)
def test_phone_does_not_swallow_other_shapes(text, expected):
    counts = sanitize(text)["report"]["counts"]
    assert "PHONE" not in counts, f"{text} became a phone number: {counts}"
    if expected:
        assert expected in counts, f"{text} lost its own detector: {counts}"


# ── KNOWN: case variants collapse to one value; the dictionary is bounded ──
# tests/fixtures/sanitize_known_parity.json is shared with ts/test/sanitize.test.mjs,
# so both lanes give the same text and accept or refuse the same dictionaries.
KNOWN_PARITY = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "sanitize_known_parity.json").read_text(encoding="utf-8")
)


def _fixture_known(entries):
    # Entry k of a group: value*repeat, then grow*k, then k zero-padded to
    # index_width digits when index_width is given (see the fixture's comment).
    return [
        e["value"] * e["repeat"]
        + e.get("grow", "") * k
        + (str(k).zfill(e["index_width"]) if "index_width" in e else "")
        for e in entries
        for k in range(e["count"])
    ]


def _fixture_parts(parts):
    return "".join(p["value"] * p["repeat"] for p in parts)


def test_known_limits_are_exported_and_match_the_shared_fixture():
    assert {
        "KNOWN_MAX_VALUES": watchlight.KNOWN_MAX_VALUES,
        "KNOWN_VALUE_MAX_LENGTH": watchlight.KNOWN_VALUE_MAX_LENGTH,
        "KNOWN_MAX_TOTAL_LENGTH": watchlight.KNOWN_MAX_TOTAL_LENGTH,
    } == KNOWN_PARITY["limits"] == {
        "KNOWN_MAX_VALUES": 50_000,
        "KNOWN_VALUE_MAX_LENGTH": 512,
        "KNOWN_MAX_TOTAL_LENGTH": 500_000,
    }


@pytest.mark.parametrize("case", KNOWN_PARITY["cases"], ids=lambda c: c["name"])
def test_known_parity_cases(case):
    assert sanitize(case["text"], known=case["known"], mode=case["mode"])["text"] == case["expect"]


@pytest.mark.parametrize("case", KNOWN_PARITY["generated_cases"], ids=lambda c: c["name"])
def test_known_parity_generated_cases(case):
    # The adversarial shapes: an entry at the length limit, a 512-deep chain of
    # nested prefixes, and dictionaries at the full count and total-length limits.
    text = _fixture_parts(case["text"])
    got = sanitize(text, known=_fixture_known(case["known"]), mode=case["mode"])["text"]
    assert got == _fixture_parts(case["expect"])


@pytest.mark.parametrize("case", KNOWN_PARITY["limit_cases"], ids=lambda c: c["name"])
def test_known_parity_limits(case):
    known = _fixture_known(case["entries"])
    if case["error"] is None:
        assert sanitize("x", known=known)["text"] == "x"
    else:
        with pytest.raises(SanitizeError) as exc:
            sanitize("x", known=known)
        assert case["error"] in str(exc.value)


def test_known_case_variants_match_the_single_word():
    word = "lovelacelovela"
    variants = [
        "".join(ch.upper() if mask & (1 << i) else ch for i, ch in enumerate(word))
        for mask in range(1 << len(word))
    ]
    doc = "Ada LOVELACElovela met lovelaceLOVELA; lovelacelovela-x, and Lovelacelovelas. " * 500
    single = sanitize(doc, known=[word], mode="mask")
    many = sanitize(doc, known=variants, mode="mask")
    assert many["text"] == single["text"] and single["report"]["total"] == many["report"]["total"] == 1500
    assert sanitize("ADA ada", known=["Ada", "ADA", "ada"])["text"] == "<KNOWN_1> <KNOWN_1>"
    # Generous bound: a slow CI runner must not fail it.
    t = time.perf_counter()
    sanitize(doc, known=variants, mode="mask")
    assert time.perf_counter() - t < 10


def test_known_fold_keeps_values_the_regex_does_not_merge():
    # U+0130 lowercases to two characters, so it is never merged with "i".
    assert sanitize("İ i", known=["İ", "i"], mode="mask")["text"] == "[KNOWN] [KNOWN]"


def test_known_any_dictionary_within_the_limits_works_on_a_shallow_stack():
    # Nothing recursive is built from the dictionary: the deepest shapes the
    # limits allow still work with only a few frames left before the
    # interpreter's recursion limit.
    chain = ["a" * k for k in range(1, watchlight.KNOWN_VALUE_MAX_LENGTH + 1)]
    comb = ["a" * k + "b" for k in range(watchlight.KNOWN_VALUE_MAX_LENGTH)]
    text = "x " + "A" * 512 + " " + "a" * 511 + "b y"

    def at_depth(depth):
        if depth > 0:
            return at_depth(depth - 1)
        return sanitize(text, known=chain, mode="mask")["text"], sanitize(text, known=comb, mode="mask")["text"]

    used = len(inspect.stack())
    assert at_depth(sys.getrecursionlimit() - used - 60) == ("x [KNOWN] " + "a" * 511 + "b y", "x " + "A" * 512 + " [KNOWN] y")


def test_known_longest_entry_wins_whatever_the_case():
    # At each position the longest entry that matches as a whole word wins,
    # whichever way the entries are spelled, so no part of a longer entry is
    # left in the text because a shorter entry also matched there.
    assert sanitize("John Smith x", known=["JOHN", "john smith"], mode="mask")["text"] == "[KNOWN] x"
    assert sanitize("a-b-c", known=["A", "a-b-c"], mode="mask")["text"] == "[KNOWN]"


_EXOTIC = ["a", "A", "b", " ", "-", "_", "1", "ı", "İ", "i", "I", "ſ", "s", "S", "K", "\u212a", "k", "σ", "ς",
           "Σ", "ß", "ẞ", "ΐ", "\u1fd3", "\ufb05", "\ufb06", "é", "É", "\u0345", "ι", "Ι", "\U0001f600", "ǅ", "ǆ", "Ǆ"]


def _reference_known(text, known):
    # One regex per entry, tried at every position: the longest whole-word
    # match at each start, overlapping matches merged. Slow, and obviously
    # what the dictionary matcher promises: ASCII word characters as the
    # boundary, and each value in its given, NFC and NFD forms.
    word = re.compile(r"[A-Za-z0-9_]")
    values = [f for v in known if v.strip() for f in {v, unicodedata.normalize("NFC", v), unicodedata.normalize("NFD", v)}]
    covered, out = [], []
    for i in range(len(text)):
        if i and word.match(text, i - 1):
            continue
        ends = [
            i + len(v) for v in values
            if re.fullmatch(re.escape(v), text[i:i + len(v)], re.IGNORECASE)
            and (i + len(v) == len(text) or not word.match(text, i + len(v)))
        ]
        if ends:
            if covered and i < covered[-1][1]:
                covered[-1][1] = max(covered[-1][1], max(ends))
            else:
                covered.append([i, max(ends)])
    cursor = 0
    for s, e in covered:
        out.append(text[cursor:s] + "[KNOWN]")
        cursor = e
    return "".join(out) + text[cursor:]


def test_known_matches_a_regex_per_entry_reference():
    rnd = random.Random(222)
    for _ in range(1500):
        alphabet = rnd.sample(_EXOTIC, rnd.randint(2, 8))

        def word():
            return "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 6)))

        base = [word() for _ in range(rnd.randint(1, 6))]
        known = base + [b.swapcase() for b in base if rnd.random() < 0.5] + [b + rnd.choice(alphabet) + b for b in base if rnd.random() < 0.3]
        text = rnd.choice([" ", "", "-"]).join(rnd.choice(base + [word(), rnd.choice(base).swapcase()]) for _ in range(rnd.randint(1, 10)))
        assert sanitize(text, known=known, mode="mask", types=[])["text"] == _reference_known(text, known), (text, known)


def test_known_character_folding_agrees_with_the_regex_engine():
    # The matcher folds each character to one representative; two characters
    # share it exactly when a case-insensitive regex literal of one matches the
    # other on this interpreter. Every cased character, and its case images.
    from watchlight import _match_char

    def cased(c):
        return c != c.lower()[0] or c != c.upper()[0]

    chars = {
        x
        for i in range(0x110000)
        if not 0xD800 <= i < 0xE000 and cased(chr(i))
        for x in (chr(i), chr(i).lower()[0], chr(i).upper()[0])
    }
    blob = "".join(sorted(chars))
    by_rep: dict = {}
    for c in chars:
        by_rep.setdefault(_match_char(c), set()).add(c)
    for p in chars:
        matched = {m.group() for m in re.compile(re.escape(p), re.IGNORECASE).finditer(blob)}
        assert matched == by_rep[_match_char(p)], hex(ord(p))
    assert all(_match_char(c) == c for c in map(chr, range(0x3000, 0x4000)) if not cased(c))


def test_known_pathological_dictionary_stays_bounded():
    # A dictionary of nested word prefixes over text made of the same word: the
    # walk from every word start runs to the longest entry, the most work any
    # position can cost. Generous bound: a slow CI runner must not fail it.
    chain = [" ".join(["a"] * k) for k in range(1, 257)]
    t = time.perf_counter()
    out = sanitize("x " + "a " * 10_000 + "y", known=chain, mode="mask")
    assert out["text"] == "x [KNOWN] y"
    assert time.perf_counter() - t < 10


def test_known_boundaries_are_ascii_word_characters():
    # A letter of another script is a boundary, as in the TypeScript lane: a
    # value written next to CJK text is still redacted.
    assert sanitize("我是张伟。", known=["张伟"], mode="mask", types=[])["text"] == "我是[KNOWN]。"
    assert sanitize("联系Ann获取", known=["Ann"], mode="mask", types=[])["text"] == "联系[KNOWN]获取"
    assert sanitize("Smithfield", known=["Smith"], mode="mask", types=[])["text"] == "Smithfield"
    assert sanitize("Renée's", known=["René"], mode="mask", types=[])["text"] == "Renée's"


def test_known_matches_composed_and_decomposed_text_under_one_tag():
    composed, decomposed = "Jos\u00e9", "Jose\u0301"
    text = f"{composed} and {decomposed} and {composed.upper()}"
    for entry in (composed, decomposed):
        assert sanitize(text, known=[entry], types=[])["text"] == "<KNOWN_1> and <KNOWN_1> and <KNOWN_1>"
        hashed = sanitize(text, known=[entry], mode="hash", types=[])["text"].split(" and ")
        assert len(set(hashed)) == 1


def test_known_tag_key_folds_like_matching():
    # ſ matches s, so both spellings of one value share a tag and a hash.
    assert sanitize("Ross and Ro\u017fs and Kim and kim", known=["ross", "kim"], types=[])["text"] == (
        "<KNOWN_1> and <KNOWN_1> and <KNOWN_2> and <KNOWN_2>"
    )
    hashed = sanitize("Ross Ro\u017fs", known=["ross"], mode="hash", types=[])["text"].split(" ")
    assert hashed[0] == hashed[1] == sanitize("ross", known=["ross"], mode="hash")["text"]
    # Letters with no precomposed capital: the capital is the base letter plus
    # combining marks, and still shares the tag.
    for small, capital in (("\u01f0", "J\u030c"), ("\u0390", "\u0399\u0308\u0301"), ("\u03b0", "\u03a5\u0308\u0301")):
        text = f"{small} and {capital} and {small}"
        assert sanitize(text, known=[small], types=[])["text"] == "<KNOWN_1> and <KNOWN_1> and <KNOWN_1>", ascii(small)


@pytest.mark.parametrize("bad", [5, 1.5, object(), True])
def test_known_that_is_not_iterable_is_a_sanitize_error(bad):
    with pytest.raises(SanitizeError, match="known must be a sequence of strings"):
        sanitize("x", known=bad)


def test_known_limit_errors_are_value_free():
    secretish = "z" * watchlight.KNOWN_VALUE_MAX_LENGTH + "SECRETVALUE"
    with pytest.raises(SanitizeError) as exc:
        sanitize("x", known=[secretish])
    assert "SECRETVALUE" not in str(exc.value)


def test_known_oversized_iterable_is_refused_without_reading_it_all():
    def endless():
        while True:
            yield "a"

    with pytest.raises(SanitizeError, match="more than 50000 entries"):
        sanitize("x", known=endless())
