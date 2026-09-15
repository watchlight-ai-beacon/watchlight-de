"""sanitize (Python) — de-rules-2 detector set, mirroring ts/test/sanitize.test.mjs:
PASSPORT / DOB structured detectors, the application-supplied KNOWN dictionary,
the opt-in PERSON / ADDRESS heuristics, value-free reports, and regex safety."""
import json
import re
import time

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
        "Placing agency: Bethany Christian Services; contact Ada Lovelace at "
        "ada@example.com, SSN 123-45-6789"
    )
    default = sanitize(text, types=["PERSON", "EMAIL", "SSN"])
    assert "Bethany Christian Services" not in default["text"]

    excluded = sanitize(
        text,
        types=["PERSON", "EMAIL", "SSN"],
        person_exclusions=["bethany christian services"],
    )
    assert "Bethany Christian Services" in excluded["text"]
    assert "Ada Lovelace" not in excluded["text"]
    assert "ada@example.com" not in excluded["text"]
    assert "123-45-6789" not in excluded["text"]
    assert excluded["report"]["counts"] == {"PERSON": 1, "EMAIL": 1, "SSN": 1}
    assert "Bethany" not in json.dumps(excluded["report"])

    # Exclusions name a complete PERSON candidate; partial strings do not make
    # a larger candidate survive.
    partial = sanitize(
        "Bethany Christian Services", types=["PERSON"], person_exclusions=["Bethany Christian"]
    )
    assert partial["text"] == "<PERSON_1>"

    g = Watchlight(agent="doc-agent", audit_dir=tmp_path)
    governed = g.sanitize(
        text,
        types=["PERSON", "EMAIL", "SSN"],
        person_exclusions=["Bethany Christian Services"],
        agent="reviewer",
    )
    assert "Bethany Christian Services" in governed["text"]
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"agent": "reviewer"' in raw
    assert "Bethany" not in raw and "Christian" not in raw and "Services" not in raw


def test_person_exclusions_reject_invalid_shapes_without_echoing_values():
    for bad in ("Bethany Christian Services", b"Bethany Christian Services", 42):
        with pytest.raises(SanitizeError) as ei:
            sanitize("Bethany Christian Services", types=["PERSON"], person_exclusions=bad)
        assert str(ei.value).endswith("person_exclusions must be a sequence of strings")
    with pytest.raises(SanitizeError) as ei:
        sanitize("Bethany Christian Services", types=["PERSON"], person_exclusions=["ok", 42])
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
