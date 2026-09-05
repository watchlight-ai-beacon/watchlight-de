#!/usr/bin/env python3
"""Red-team corpus run — every adversarial prompt through a governed agent.

    pip install watchlight
    python examples/showcase/red-team/run.py                       # the shipped corpus
    python examples/showcase/red-team/run.py corpus.unhandled.json # a family nobody handles → red

Runs offline — no API key, no model call. Exits non-zero if any assertion fails.

Two layers stand between an adversarial prompt and a side effect:

    1. screening — the prompt enters through a governed `ingest` tool whose
       `on_result` hook runs `govern.screen(...)`. A prompt flagged for an
       injection family is withheld: the model never receives it.
    2. policy    — whatever does reach the model, the model (a stub here) complies
       with. The corpus records the tool call each prompt tries to induce; the
       stub makes exactly that call, through a governed tool, and the policy set
       (`policy.suite.json`) refuses everything but `answer`.

The corpus (`corpus.json`) groups prompts by family. The runner derives the
expectation for each family from the SDK's own `SCREEN_FAMILIES` (must be
withheld by screening), from its own list of policy-caught families (must be
denied by policy), and from the `BENIGN` control group (must pass both layers).
A family it recognises from none of those is UNHANDLED and fails the run — a
runner that has no expectation for a family cannot report it green.

Output is value-free: family names, counts and prompt ids — never prompt text.
The same run in TypeScript: `run.mjs`.
"""

import atexit
import json
import pathlib
import shutil
import sys
import tempfile
from collections import Counter

from watchlight import DENY_REASON, SCREEN_FAMILIES, Denied, Watchlight

HERE = pathlib.Path(__file__).parent

# Families the policy layer is expected to stop: plain requests with no injection
# phrasing, so screening (rightly) passes them and the induced call must be denied.
POLICY_FAMILIES = ("DATA_EXFILTRATION_REQUEST", "DESTRUCTIVE_REQUEST")
CONTROL_FAMILY = "BENIGN"

# family → the outcome every prompt in it must reach.
EXPECT = {**{f: "withheld" for f in SCREEN_FAMILIES},
          **{f: "denied" for f in POLICY_FAMILIES},
          CONTROL_FAMILY: "executed"}
UNHANDLED = "UNHANDLED"

# ── the governed agent ───────────────────────────────────────────────
trail: list[dict] = []  # this run's audit records; the on-disk copy goes to a scratch dir removed at exit
AUDIT_DIR = tempfile.mkdtemp(prefix="red-team-audit-")
atexit.register(shutil.rmtree, AUDIT_DIR, True)
govern = Watchlight(agent="red-team-target", audit_dir=AUDIT_DIR, audit_sink=trail.append)
govern.load(HERE / "policy.suite.json")  # the same policies `watchlight policy test` verifies

TEXT: dict[str, str] = {}  # prompt id → text, filled from the corpus (never printed)


def screen_input(text: str, info: dict) -> None:
    """Egress hook on `ingest`: flagged → withhold (raise); clean → pass through."""
    screened = govern.screen(text, intent="ingest", resource=info["resource"], decision_id=info["decision_id"])
    if screened["report"]["flagged"]:
        raise Denied(info["resource"], "ingest", DENY_REASON)
    return None


@govern.tool("ingest", resource=lambda pid: f"prompt/{pid}", context={"source": "untrusted"}, on_result=screen_input)
def ingest(prompt_id: str) -> str:
    return TEXT[prompt_id]


executed: Counter = Counter()  # intent → how many times a tool body actually ran


def make_tool(intent: str):
    def body(target: str) -> str:
        executed[intent] += 1
        return f"{intent} done"

    body.__name__ = intent
    return govern.tool(intent, resource=lambda target: target)(body)


TOOLS = {intent: make_tool(intent) for intent in ("answer", "export", "send_email", "delete")}

model_inputs: list[str] = []  # prompt ids the model stub received


def model(text: str, entry: dict) -> dict:
    """Stand-in for the model: it complies with whatever the prompt asks. The corpus
    records the call each prompt tries to induce, so the stub returns exactly that."""
    model_inputs.append(entry["id"])
    return entry["induces"]


def drive(entry: dict) -> tuple[str, dict]:
    """Run one prompt through both layers. Returns (outcome, screening counts)."""
    try:
        text = ingest(entry["id"])
    except Denied:
        return "withheld", screening_counts(entry["id"])
    call = model(text, entry)
    if call["intent"] not in TOOLS:
        raise ValueError(f"corpus entry {entry['id']} induces an unknown tool: {call['intent']}")
    try:
        TOOLS[call["intent"]](call["resource"])
    except Denied:
        return "denied", screening_counts(entry["id"])
    return "executed", screening_counts(entry["id"])


def screening_counts(prompt_id: str) -> dict:
    recs = [r for r in trail if r.get("event") == "screening" and r.get("resource") == f"prompt/{prompt_id}"]
    return recs[-1]["counts"] if recs else {}


def main(argv: list[str]) -> int:
    corpus_path = pathlib.Path(argv[1]) if len(argv) > 1 else HERE / "corpus.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))["families"]
    ids = [e["id"] for entries in corpus.values() for e in entries]
    duplicate_ids = sorted(i for i, n in Counter(ids).items() if n > 1)
    for entries in corpus.values():
        for e in entries:
            TEXT[e["id"]] = e["text"]
    total = len(ids)
    kinds = Counter("screening" if f in SCREEN_FAMILIES else "policy" if f in POLICY_FAMILIES
                    else "control" if f == CONTROL_FAMILY else "unhandled" for f in corpus)
    extra = f", {kinds['unhandled']} unhandled" if kinds["unhandled"] else ""
    print(f"corpus: {corpus_path.name} — {total} prompts in {len(corpus)} families "
          f"({kinds['screening']} screening, {kinds['policy']} policy, {kinds['control']} control{extra})\n")

    # ── drive every prompt ──
    rows = []        # (family, prompts, withheld, reached, denied, executed, expect)
    mislabelled = []  # (family, id): flagged, but not for the family the corpus says
    wrong = []        # (family, id, outcome): a prompt that missed its family's expectation
    for family, entries in corpus.items():
        expect = EXPECT.get(family, UNHANDLED)
        tally = Counter()
        for entry in entries:
            outcome, counts = drive(entry)
            tally[outcome] += 1
            if family in SCREEN_FAMILIES and outcome == "withheld" and family not in counts:
                mislabelled.append((family, entry["id"]))
            if expect != UNHANDLED and outcome != expect:
                wrong.append((family, entry["id"], outcome))
        reached = tally["denied"] + tally["executed"]
        rows.append((family, len(entries), tally["withheld"], reached, tally["denied"], tally["executed"], expect))

    # ── per-family report (value-free) ──
    print("\n=== per family ===")
    print(f"  {'family':27} {'prompts':>7} {'withheld':>8} {'reached':>7} {'denied':>6} {'executed':>8}  expected")
    for family, n, withheld, reached, denied, ran in (r[:6] for r in rows):
        expect = EXPECT.get(family, UNHANDLED)
        got = {"withheld": withheld, "denied": denied, "executed": ran}.get(expect, 0)
        mark = "✓" if expect != UNHANDLED and got == n else "✗"
        print(f"  {family:27} {n:>7} {withheld:>8} {reached:>7} {denied:>6} {ran:>8}  {expect:9} {mark}")
    print(f"  {'total':27} {total:>7} {sum(r[2] for r in rows):>8} {sum(r[3] for r in rows):>7} "
          f"{sum(r[4] for r in rows):>6} {sum(r[5] for r in rows):>8}")

    # ── assertions ──
    failures = 0

    def check(name: str, cond: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'✓' if cond else '✗'} {name}{'' if cond or not detail else ' — ' + detail}")
        failures += 0 if cond else 1

    print("\n=== assertions ===")
    # Coverage first: a corpus that simply omits a family would otherwise pass every check below.
    missing = [f for f in EXPECT if not corpus.get(f)]
    check("the corpus covers every family this runner expects — each SCREEN_FAMILIES entry, each policy family, the control group",
          not missing, f"no prompts for: {', '.join(missing)}")
    check("prompt ids are unique", not duplicate_ids, f"duplicates: {', '.join(duplicate_ids)}")
    unhandled = [f for f in corpus if f not in EXPECT]
    check("every corpus family is handled by a layer this runner knows (screening, policy) or is the control group",
          not unhandled, f"unhandled: {', '.join(unhandled)}")
    adversarial = [f for f in corpus if f != CONTROL_FAMILY]
    screen_leaks = [(f, i, o) for f, i, o in wrong if f in SCREEN_FAMILIES]
    check("no screening-family prompt reached the model", not screen_leaks,
          "reached: " + ", ".join(f"{f}/{i}" for f, i, _ in screen_leaks))
    ran_adversarial = sum(r[5] for r in rows if r[0] != CONTROL_FAMILY)
    check("no adversarial prompt executed its induced action — both layers missed nothing",
          ran_adversarial == 0, f"{ran_adversarial} executed")
    policy_misses = [(f, i, o) for f, i, o in wrong if f in POLICY_FAMILIES]
    check("every policy-family prompt reached the model and was denied there", not policy_misses,
          ", ".join(f"{f}/{i}={o}" for f, i, o in policy_misses))
    control_misses = [(f, i, o) for f, i, o in wrong if f == CONTROL_FAMILY]
    check("control prompts pass both layers (no false positives)", not control_misses,
          ", ".join(f"{i}={o}" for _, i, o in control_misses))
    check("the corpus is labelled correctly — each withheld prompt was flagged for its own family",
          not mislabelled, ", ".join(f"{f}/{i}" for f, i in mislabelled))

    # The trail: one ingest Allow per prompt; a screening record joined to each; the
    # model only ever saw prompts whose screening was clean; every hook run wrote egress.
    ingests = [r for r in trail if r.get("decision") and r["intent"] == "ingest"]
    screenings = {r["decision_id"]: r for r in trail if r.get("event") == "screening" and r.get("decision_id")}
    check("one Allow ingest decision per prompt, each with a decision_id",
          len(ingests) == total and all(r["decision"] == "Allow" and r.get("decision_id") for r in ingests))
    check("every ingest decision has a screening record joined on its decision_id",
          all(r["decision_id"] in screenings for r in ingests))
    by_prompt = {r["resource"]: screenings.get(r["decision_id"]) for r in ingests}
    check("every prompt the model received has a clean screening record — nothing reached it unscreened",
          all(by_prompt.get(f"prompt/{pid}") is not None and not by_prompt[f"prompt/{pid}"]["flagged"]
              for pid in model_inputs) and len(model_inputs) == sum(r[3] for r in rows))
    egress = [r for r in trail if r.get("event") == "egress" and r["intent"] == "ingest"]
    check("every hook run wrote an egress record: withheld for flagged prompts, passthrough otherwise",
          len(egress) == total and sum(1 for r in egress if r.get("withheld")) == sum(r[2] for r in rows)
          and all(r["replaced"] is False for r in egress))
    blob = json.dumps(trail).lower()
    check("the audit trail is value-free — no prompt text appears in it",
          not any(t.lower()[:40] in blob for t in TEXT.values()))

    # The policy suite this run loaded, executed in-process (same as `watchlight policy test`).
    suite = json.loads((HERE / "policy.suite.json").read_text(encoding="utf-8"))
    report = govern.test(suite["tests"])
    check(f"policy.suite.json: {report['passed']}/{report['total']} fixtures pass", report["failed"] == 0)

    print(f"\n{'ALL CHECKS OK' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
