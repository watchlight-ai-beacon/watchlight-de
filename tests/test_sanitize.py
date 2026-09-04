"""sanitize (Python) — de-rules-2 detector set, mirroring ts/test/sanitize.test.mjs:
PASSPORT / DOB structured detectors, the application-supplied KNOWN dictionary,
the opt-in PERSON / ADDRESS heuristics, value-free reports, and regex safety."""
import json
import re
import time

import pytest

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
    assert sanitize("aaaa", known=["aa"])["text"] == "<KNOWN_1>"
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


def test_adversarial_inputs_stay_fast():
    adversarial = [
        "passport" + " " * 50000 + "x", "DOB:" + " " * 50000, "Aa " * 20000,
        "1 " * 30000 + "Main St", "born on " + "1/" * 30000, "<" * 50000, "x" * 200000,
    ]
    t0 = time.monotonic()
    for a in adversarial:
        sanitize(a, types=["PASSPORT", "DOB", "PERSON", "ADDRESS", "PHONE", "CREDIT_CARD"], known=["zzz"])
    assert time.monotonic() - t0 < 5.0
    t1 = time.monotonic()
    for a in ("a." * 100000 + "@", "a@" * 50000, "x@" + "a." * 100000):
        sanitize(a)
    assert time.monotonic() - t1 < 0.1  # EMAIL local-part run without a domain is linear
    assert counts(".alice@acme.com x-bob@acme.com plus+tag@acme.co.uk")["EMAIL"] == 3


def test_governed_known_never_reaches_audit(tmp_path):
    g = Watchlight(agent="doc-agent", audit_dir=tmp_path)
    g.sanitize("Ada Lovelace, DOB: 03/15/1985", resource="intake.txt", known=["Ada Lovelace"])
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"KNOWN": 1' in raw and '"DOB": 1' in raw and '"detector": "de-rules-2"' in raw
    assert "Lovelace" not in raw and "1985" not in raw
