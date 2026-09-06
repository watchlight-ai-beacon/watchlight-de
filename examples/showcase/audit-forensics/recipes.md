# jq recipes for the audit trail

The same questions `forensics.py` answers, for a host where only `jq` is
installed. Point `TRAIL` at any `audit.jsonl`:

```bash
TRAIL=trail/audit.jsonl              # what generate_trail.py / generate-trail.mjs wrote
TRAIL=.watchlight/audit.jsonl        # what any other example leaves behind
```

A **decision** record has no `event` field; every other kind names itself in
`event`. `decision_id` joins them. Field names are in
[README.md](./README.md#record-kinds).

## Records by kind

```bash
jq -r '.event // "decision"' "$TRAIL" | sort | uniq -c
```

## Per principal: allowed / approved / held / denied

`approved` is an `Allow` carrying `approved: true`; `held` is a
`NeedsApproval` nobody has confirmed yet.

```bash
jq -r 'select(.event == null)
  | (if .decision == "Allow" then (if .approved then "approved" else "allowed" end)
     elif .decision == "NeedsApproval" then "held" else "denied" end) as $outcome
  | "\(.principal) \($outcome)"' "$TRAIL" | sort | uniq -c
```

## Join sanitization and egress records to their decision

Index the decisions by `decision_id`, then look each follow-up record up.

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

An allowed decision with nothing after it is a body that ran with no egress
hook.

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

`tools` is the set the child was **granted**, so subtracting it from the
parent's gives what the child gave up. A `Deny` was never granted and heads no
chain.

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

A follow-up record whose `decision_id` has no decision in this file: the
decision went to another trail, or the file was truncated.

```bash
jq -s '
  (map(select(.event == null and .decision_id) | .decision_id)) as $ids
  | map(select((.event == "sanitization" or .event == "egress") and .decision_id
               and (.decision_id as $x | $ids | index($x) | not))
        | {event, decision_id, resource})' "$TRAIL"
```

And records that never carried a join key — a `sanitize()` called without
`decision_id`, or an egress hook on an adapter with no `tool_use_id`:

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
