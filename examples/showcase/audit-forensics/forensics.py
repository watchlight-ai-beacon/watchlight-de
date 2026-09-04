#!/usr/bin/env python3
"""Reconstruct who did what from a Watchlight audit trail — stdlib only.

    python forensics.py [PATH] [--json] [--principal PRINCIPAL]

PATH defaults to ./trail/audit.jsonl (what generate_trail.py writes); pass
.watchlight/audit.jsonl to analyze the trail any other example leaves behind.

Sections:
  records by kind      — decision / sanitization / egress / attenuation / screening
  per principal        — allowed / approved / held (NeedsApproval) / denied
  decisions → follow-up— sanitizations and egress dispositions joined on decision_id
  attenuation chains   — parent → child scopes with the tools each child dropped, and refusals
  screenings           — flagged resources, matches per rule family
  integrity            — records that do not join (orphans), decisions without an id

The output is value-free by construction: it prints identifiers (principals,
resources, decision and node ids), counts, and field names — never argument
values or content, which the trail does not contain in the first place.

Exit codes: 0 report produced; 1 nothing to analyze (missing or empty file);
2 unreadable file or unusable arguments.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections import Counter, OrderedDict, defaultdict
from typing import Any

KINDS = ("decision", "sanitization", "egress", "attenuation", "screening")


def kind_of(record: dict) -> str:
    return record.get("event") or "decision"


def outcome_of(decision: dict) -> str:
    verdict = decision.get("decision")
    if verdict == "Allow":
        return "approved" if decision.get("approved") else "allowed"
    if verdict == "NeedsApproval":
        return "held"
    return "denied"


def egress_disposition(record: dict) -> str:
    if record.get("withheld"):
        return "withheld"
    return "replaced" if record.get("replaced") else "passthrough"


def load(path: pathlib.Path) -> tuple[list[dict], int]:
    """Parse the JSONL. Malformed lines are counted, never echoed."""
    records: list[dict] = []
    skipped = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                skipped += 1
                continue
            if isinstance(obj, dict):
                records.append(obj)
            else:
                skipped += 1
    return records, skipped


def analyze(records: list[dict], principal: str | None = None) -> dict[str, Any]:
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_kind[kind_of(r)].append(r)

    decisions = by_kind["decision"]
    if principal:
        decisions = [d for d in decisions if d.get("principal") == principal]
    by_id: dict[str, dict] = {d["decision_id"]: d for d in decisions if d.get("decision_id")}

    # Per principal roll-up.
    per_principal: dict[str, Counter] = defaultdict(Counter)
    for d in decisions:
        per_principal[str(d.get("principal"))][outcome_of(d)] += 1

    # Join sanitization / egress onto decisions by decision_id.
    follow_ups: dict[str, dict[str, Any]] = OrderedDict()
    orphans: list[dict[str, Any]] = []
    unjoined = Counter()
    for kind in ("sanitization", "egress"):
        for r in by_kind[kind]:
            did = r.get("decision_id")
            if not did:
                unjoined[kind] += 1
                continue
            if did not in by_id:
                if principal is None:  # with a principal filter, others' records are simply out of scope
                    orphans.append({"kind": kind, "decision_id": did, "resource": r.get("resource")})
                continue
            entry = follow_ups.setdefault(did, {"sanitizations": [], "egress": []})
            if kind == "sanitization":
                entry["sanitizations"].append({"total": r.get("total", 0), "counts": r.get("counts", {}), "mode": r.get("mode")})
            else:
                entry["egress"].append(egress_disposition(r))

    joined = []
    for did, d in by_id.items():
        f = follow_ups.get(did)
        joined.append({
            "decision_id": did,
            "principal": d.get("principal"),
            "intent": d.get("intent"),
            "resource": d.get("resource"),
            "outcome": outcome_of(d),
            "sanitizations": f["sanitizations"] if f else [],
            "egress": f["egress"] if f else [],
        })

    # Attenuation chains: node_id / parent_id tree; a refusal is a Deny record
    # whose node_id was never granted (it has no children and no scope).
    attn = by_kind["attenuation"]
    nodes = {r["node_id"]: r for r in attn if r.get("node_id")}
    children: dict[str | None, list[dict]] = defaultdict(list)
    for r in attn:
        children[r.get("parent_id")].append(r)
    chains = []
    for r in attn:
        pid = r.get("parent_id")
        parent_tools = set(nodes[pid].get("tools", [])) if pid in nodes else None
        child_tools = set(r.get("tools", []))
        chains.append({
            "node_id": r.get("node_id"),
            "parent_id": pid,
            "depth": r.get("depth"),
            "decision": r.get("decision"),
            "tools": sorted(child_tools),
            "dropped": sorted(parent_tools - child_tools) if parent_tools is not None else [],
            "reason": r.get("reason"),
        })

    screenings = [{
        "resource": r.get("resource"),
        "intent": r.get("intent"),
        "mode": r.get("mode"),
        "flagged": bool(r.get("flagged")),
        "total": r.get("total", 0),
        "counts": r.get("counts", {}),
    } for r in by_kind["screening"]]

    return {
        "records": {k: len(by_kind[k]) for k in KINDS} | {"other": sum(len(v) for k, v in by_kind.items() if k not in KINDS)},
        "per_principal": {p: dict(c) for p, c in sorted(per_principal.items())},
        "decisions": joined,
        "attenuation": chains,
        "screenings": screenings,
        "integrity": {
            "decisions_without_id": sum(1 for d in decisions if not d.get("decision_id")),
            "unjoined": dict(unjoined),
            "orphans": orphans,
        },
    }


def render(report: dict[str, Any], skipped: int, path: pathlib.Path) -> str:
    out: list[str] = [f"audit forensics — {path}", ""]
    out.append("== records by kind ==")
    for k, n in report["records"].items():
        if n or k != "other":
            out.append(f"  {k:<13} {n}")
    if skipped:
        out.append(f"  (malformed lines skipped: {skipped})")

    out += ["", "== per principal ==", f"  {'principal':<18} {'allowed':>8} {'approved':>9} {'held':>6} {'denied':>7}"]
    for p, c in report["per_principal"].items():
        out.append(f"  {p:<18} {c.get('allowed', 0):>8} {c.get('approved', 0):>9} {c.get('held', 0):>6} {c.get('denied', 0):>7}")

    out += ["", "== decisions and what followed (joined on decision_id) =="]
    for d in report["decisions"]:
        tail = []
        for s in d["sanitizations"]:
            fams = ",".join(f"{k}={v}" for k, v in sorted(s["counts"].items())) or "none"
            tail.append(f"sanitization redacted={s['total']} [{fams}] mode={s['mode']}")
        for e in d["egress"]:
            tail.append(f"egress {e}")
        out.append(f"  {d['decision_id'][:8]}  {d['outcome']:<8} {d['intent']:<8} {str(d['resource']):<18} {str(d['principal'])}")
        for t in tail:
            out.append(f"           → {t}")
    reads = [d for d in report["decisions"] if d["outcome"] in ("allowed", "approved")]
    followed = [d for d in reads if d["sanitizations"] or d["egress"]]
    out.append(f"  allowed actions: {len(reads)}; followed by a sanitization or egress record: {len(followed)}")

    out += ["", "== attenuation chains (parent → child, tools dropped) =="]
    for c in report["attenuation"]:
        parent = c["parent_id"] or "(root)"
        line = f"  {parent:<10} → {str(c['node_id']):<10} depth={c['depth']} {c['decision']:<5} tools={c['tools']}"
        if c["parent_id"]:
            line += f" dropped={c['dropped']}"
        out.append(line)
        if c["reason"]:
            out.append(f"             reason: {c['reason']}")

    out += ["", "== screenings =="]
    for s in report["screenings"]:
        fams = ",".join(f"{k}={v}" for k, v in sorted(s["counts"].items())) or "none"
        out.append(f"  {str(s['resource']):<18} {s['intent']:<8} {'FLAGGED' if s['flagged'] else 'clean':<8} total={s['total']} [{fams}]")

    integ = report["integrity"]
    out += ["", "== integrity =="]
    out.append(f"  decisions without decision_id: {integ['decisions_without_id']}")
    out.append(f"  sanitization/egress without decision_id: {integ['unjoined'] or 0}")
    out.append(f"  orphans (decision_id with no decision record): {len(integ['orphans'])}")
    for o in integ["orphans"]:
        out.append(f"    {o['kind']} {o['decision_id'][:8]} {o['resource']}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default="trail/audit.jsonl", help="audit JSONL (default: trail/audit.jsonl)")
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--principal", help='restrict decisions to one principal, e.g. \'User::"alice"\'')
    args = ap.parse_args()

    path = pathlib.Path(args.path)
    if not path.exists():
        print(f"forensics: no such file: {path}", file=sys.stderr)
        return 1
    try:
        records, skipped = load(path)
    except OSError as exc:
        print(f"forensics: cannot read {path}: {exc.__class__.__name__}", file=sys.stderr)
        return 2
    if not records:
        print(f"forensics: no records in {path}", file=sys.stderr)
        return 1

    report = analyze(records, principal=args.principal)
    if args.json:
        report["skipped_lines"] = skipped
        print(json.dumps(report, indent=2))
    else:
        print(render(report, skipped, path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
