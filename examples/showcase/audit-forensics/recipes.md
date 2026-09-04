# jq recipes for the audit trail

Every recipe reads the value-free `audit.jsonl` the SDK writes (one JSON object
per line) and prints identifiers and counts only. Set `TRAIL` to the file you
want to look at:

```bash
TRAIL=trail/audit.jsonl              # what generate_trail.py / generate-trail.mjs wrote
TRAIL=.watchlight/audit.jsonl        # what any other example leaves behind
```

A **decision** record has no `event` field; every other kind names itself in
`event`. The join key across kinds is `decision_id`. Field names are listed in
[README.md](./README.md#record-kinds).

## Records by kind

```bash
jq -r '.event // "decision"' "$TRAIL" | sort | uniq -c
```

## Per principal: allowed / approved / held / denied

`approved` is an `Allow` that carries `approved: true` (a human confirmed a
`NeedsApproval`); `held` is a `NeedsApproval` that was not (yet) confirmed.

```bash
jq -r 'select(.event == null)
  | (if .decision == "Allow" then (if .approved then "approved" else "allowed" end)
     elif .decision == "NeedsApproval" then "held" else "denied" end) as $outcome
  | "\(.principal) \($outcome)"' "$TRAIL" | sort | uniq -c
```

## Join sanitization and egress records to their decision

Index the decisions by `decision_id`, then look each follow-up record up. The
result says which principal's decision, on which resource, led to how many
redactions and to which egress disposition.

```bash
jq -s '
  (map(select(.event == null and .decision_id)) | INDEX(.decision_id)) as $d
  | map(select((.event == "sanitization" or .event == "egress") and .decision_id))
  | map({
      decision_id, event,
      principal: $d[.decision_id].principal,
      intent:    $d[.decision_id].intent,
      resource,
      outcome: (if .event == "egress"
                then (if .withheld then "withheld" elif .replaced then "replaced" else "passthrough" end)
                else "redacted \(.total)" end)
    })' "$TRAIL"
```

## Which allowed reads were followed by a sanitization or an egress record

Group by `decision_id`; an allowed decision with nothing after it is a body that
ran with no egress hook (or a hook that never reported).

```bash
jq -s '
  group_by(.decision_id) | map(select(.[0].decision_id != null))
  | map({
      decision_id: .[0].decision_id,
      decision: (map(select(.event == null)) | .[0] | {principal, intent, resource, decision}),
      sanitizations: map(select(.event == "sanitization")) | length,
      egress: map(select(.event == "egress")
                  | if .withheld then "withheld" elif .replaced then "replaced" else "passthrough" end)
    })
  | map(select(.decision.decision == "Allow"))' "$TRAIL"
```

## Attenuation chains: parent → child and what was dropped

`tools` on an `attenuation` record is the set the child was **granted** (the
engine's clamped grant, not the request). Subtracting it from the parent's set
gives what the child gave up. A `Deny` record is a refused attenuation — its
`node_id` was never granted, so it heads no chain.

```bash
jq -s '
  map(select(.event == "attenuation")) | INDEX(.node_id) as $n
  | map(select(.parent_id)
        | {parent: .parent_id, child: .node_id, depth, decision,
           tools, dropped: (($n[.parent_id].tools // []) - .tools), reason})' "$TRAIL"
```

The root of each tree is the record with no `parent_id`:

```bash
jq -c 'select(.event == "attenuation" and (.parent_id | not)) | {node_id, depth, tools}' "$TRAIL"
```

## Screenings that flagged something, per rule family

```bash
jq -c 'select(.event == "screening" and .flagged) | {resource, intent, total, counts}' "$TRAIL"
```

## Every approved action (a human confirmed it)

```bash
jq -c 'select(.event == null and .approved == true) | {principal, intent, resource, decision_id}' "$TRAIL"
```

## Denials, by intent and resource

```bash
jq -r 'select(.event == null and .decision == "Deny") | "\(.principal) \(.intent) \(.resource)"' "$TRAIL" | sort | uniq -c
```

## Integrity: follow-up records that join nothing

A `sanitization` or `egress` record whose `decision_id` has no decision record
in this file (the decision went to another trail, or the file was truncated).

```bash
jq -s '
  (map(select(.event == null and .decision_id) | .decision_id)) as $ids
  | map(select((.event == "sanitization" or .event == "egress") and .decision_id
               and (.decision_id as $x | $ids | index($x) | not))
        | {event, decision_id, resource})' "$TRAIL"
```

And records that never carried a join key at all — a `sanitize()` called
without `decision_id`, or an egress hook on a framework adapter that had no
`tool_use_id` to bind to:

```bash
jq -r 'select((.event == "sanitization" or .event == "egress") and (.decision_id | not)) | .event' "$TRAIL" | sort | uniq -c
```

## One principal's full timeline

```bash
P='User::"alice"'
jq -s --arg p "$P" '
  (map(select(.event == null and .principal == $p and .decision_id) | .decision_id)) as $ids
  | map(select((.event == null and .principal == $p)
               or (.decision_id as $x | $ids | index($x))))
  | map({ts, kind: (.event // "decision"), intent, resource, decision, approved, replaced, withheld, total})' "$TRAIL"
```
