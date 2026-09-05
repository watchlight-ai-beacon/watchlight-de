# Showcase: audit forensics

The SDK writes one JSON line per governance event to `.watchlight/audit.jsonl`.
The trail is **value-free** — no tool arguments, no document text, no model
output — but it carries enough identifiers to answer the question an incident
review asks: *which principal, under which intent, did what to which resource,
and what happened to the data afterwards?* This folder turns that file into
that answer.

```
audit-forensics/
├── generate_trail.py       drive the real SDK (Python) → trail/audit.jsonl, then verify its shape
├── generate-trail.mjs      the same scenario in the TypeScript lane
├── forensics.py            stdlib-only analyzer: joins, roll-ups, chains, integrity
├── recipes.md              the same questions as one-line jq recipes
└── README.md               this file, including the record-kind field reference
```

## Run it

```bash
pip install watchlight                 # Python lane (also needed for forensics.py)
cd examples/showcase/audit-forensics

python generate_trail.py               # writes ./trail/audit.jsonl and checks it
python forensics.py                    # analyzes ./trail/audit.jsonl
python forensics.py --json             # same report, machine-readable
python forensics.py --principal 'User::"alice"'

# or generate the trail from the TypeScript lane instead — same records, same fields.
# The script resolves @watchlight/sdk from NODE_PATH (a global install) or from
# the in-repo build at ts/dist; pick one:
npm i -g @watchlight/sdk && NODE_PATH="$(npm root -g)" node generate-trail.mjs   # global install
(cd ../../../ts && npm install && npm run build) && node generate-trail.mjs       # in-repo build
python forensics.py

# any other example's trail works too:
python forensics.py ../../../.watchlight/audit.jsonl
```

The generators exit non-zero if the trail is missing a record kind, if a
`sanitization` or `egress` record does not join a decision, if the single
approved action is missing, or if **any record carries a field name this README
does not list** — the field table below is checked against the real trail on
every run, in both lanes.

## The scenario

A support-ticket agent, governed with `govern.tool`, acting for two users:

| step | what the SDK writes |
|---|---|
| `alice` reads ticket T-1 (public); the egress hook sanitizes the body | `decision` Allow → `sanitization` (3 redactions) → `egress` replaced |
| `bob` reads ticket T-2 (internal); nothing to redact | `decision` Allow → `sanitization` (0) → `egress` replaced |
| `alice` reads ticket T-9 (restricted) | `decision` Deny — the body never ran, so no egress |
| `alice` fetches a clean page; the hook screens it and passes it through | `decision` Allow → `screening` clean → `egress` passthrough |
| `alice` fetches a page carrying an injection; the hook withholds it | `decision` Allow → `screening` flagged → `egress` withheld |
| `alice` refunds 40 | `decision` Allow |
| `alice` refunds 250; a human confirms | `decision` NeedsApproval, then `decision` Allow with `approved: true` |
| `bob` refunds 250; left pending | `decision` NeedsApproval |
| `alice` deletes a ticket (no policy) | `decision` Deny |
| root scope → triage → reader; triage asks for `refund` | `attenuation` ×3 Allow, ×1 Deny |
| a draft reply is screened before it leaves | `screening` flagged |

Twenty-three records: 10 decisions, 2 sanitizations, 4 egress, 4 attenuations,
3 screenings. Every fixture is synthetic; the trail contains none of them.

## What the analyzer reports

```
== records by kind ==
  decision      10
  sanitization  2
  egress        4
  attenuation   4
  screening     3

== per principal ==
  principal           allowed  approved   held  denied
  User::"alice"             4         1      1       2
  User::"bob"               1         0      1       0

== decisions and what followed (joined on decision_id) ==
  98230d9d  allowed  read     ticket/T-1         User::"alice"
           → sanitization redacted=3 [CREDIT_CARD=1,KNOWN=1,SSN=1] mode=tag
           → egress replaced
  df8780c9  allowed  read     ticket/T-2         User::"bob"
           → sanitization redacted=0 [none] mode=tag
           → egress replaced
  afff37ef  denied   read     ticket/T-9         User::"alice"
  73dd1d6a  allowed  fetch    page/faq           User::"alice"
           → egress passthrough
  e8e3882f  allowed  fetch    page/vendor-notice User::"alice"
           → egress withheld
  ecda5fd9  allowed  refund   ticket/T-1         User::"alice"
  81e2c655  held     refund   ticket/T-1         User::"alice"
  52c8ebc5  approved refund   ticket/T-1         User::"alice"
  b179b77a  held     refund   ticket/T-3         User::"bob"
  60ff8368  denied   delete   ticket/T-1         User::"alice"
  allowed actions: 6; followed by a sanitization or egress record: 4

== attenuation chains (parent → child, tools dropped) ==
  (root)     → 38466c7d   depth=0 Allow tools=['delete_ticket', 'fetch_page', 'read_ticket', 'refund']
  38466c7d   → 4c39f75e   depth=1 Allow tools=['fetch_page', 'read_ticket'] dropped=['delete_ticket', 'refund']
  4c39f75e   → 5a3ccb54   depth=2 Allow tools=['read_ticket'] dropped=['fetch_page']
  4c39f75e   → bf3045db   depth=2 Deny  tools=['refund'] dropped=['fetch_page', 'read_ticket']
             reason: 1 tool(s) not in parent.allowed_tools (e.g. ["refund"])

== screenings ==
  page/faq           fetch    clean    total=0 [none]
  page/vendor-notice fetch    FLAGGED  total=2 [INSTRUCTION_OVERRIDE=1,PROMPT_EXFILTRATION=1]
  draft/reply-1      respond  FLAGGED  total=1 [PROMPT_LEAK=1]

== integrity ==
  decisions without decision_id: 0
  sanitization/egress without decision_id: 0
  orphans (decision_id with no decision record): 0
```

Everything printed is an identifier, a count, or a field name. `allowed` is an
`Allow` without `approved`; `approved` is an `Allow` that carries
`approved: true`; `held` is a `NeedsApproval` with no confirmation yet.

## Record kinds

The exact field names the SDK writes, taken from the writers in
`ts/src/index.ts`, `ts/src/attenuation.ts`, `src/watchlight/__init__.py` and
`src/watchlight/attenuation.py`, and asserted against the generated trail by
both generators. A **decision** record has no `event` field; every other kind
names itself in `event`. Both lanes write the same names.

This table is also a **type**. TypeScript exports the five kinds as a
discriminated union on `event` — `AuditRecord = DecisionRecord |
SanitizationRecord | ScreeningRecord | EgressRecord | AttenuationRecord`, with
the common fields on `AuditRecordBase` — and Python exports the same five as
`TypedDict`s under the same names. A sink annotated with them reads a kind's
fields by name, and a field renamed or removed breaks that sink where its author
wants to hear about it. To opt out, annotate `UnknownAuditRecord` (TypeScript)
or `dict` (Python) and take the record as the untyped bag it has always been.

Two fields ride along on every kind but `attenuation` and are easy to miss:

| field | type | notes |
|---|---|---|
| `actor_chain` | string[], optional | the ordered delegation chain, root first. Written ONLY through a `delegate()`d governor, whose chain is longer than one name; a call outside any delegation carries none |
| `principal` | string | the subject. Required on `decision` and `egress`; carried by `sanitization` and `screening` too — a governor resolves one for every call, so in practice both name their subject even with no decision to join to |

### `decision` — written by `authorize()` (and so by every governed tool call)

| field | type | notes |
|---|---|---|
| `ts` | string | ISO-8601 UTC timestamp |
| `agent` | string | the governor's agent identity |
| `principal` | string | the acting principal, e.g. `User::"alice"`; defaults to `agent` |
| `intent` | string | the action authorized |
| `resource` | string | the resource; `tool/<name>` for a governed tool with no `resource` binding |
| `decision` | string | `Allow`, `Deny`, or `NeedsApproval` |
| `actor_chain` | string[], optional | the delegation chain — see above |
| `decision_id` | string, optional | the engine's per-decision correlation id — the join key; present on every record the in-process engine produces |
| `approved` | `true`, optional | present only when a valid approval token downgraded a `NeedsApproval` to `Allow` |

An approved action is **two** records: the `NeedsApproval` hold, then a second
`Allow` with `approved: true` under a new `decision_id`. The `reason` is never
written — callers see a uniform, non-revealing reason and the trail carries the
verdict only.

### `sanitization` — written by `sanitize()`

| field | type | notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `intent` | string | label passed to `sanitize` (default `read`) |
| `event` | `"sanitization"` | |
| `resource` | string | label passed to `sanitize` (default `document`) |
| `mode` | string | `tag`, `mask`, or `hash` |
| `detector` | string | detector version, e.g. `de-rules-2` |
| `counts` | object | redactions per PII type, e.g. `{"SSN": 1, "KNOWN": 1}` |
| `total` | number | total redactions |
| `actor_chain` | string[], optional | the delegation chain — see above |
| `decision_id` | string, optional | present only when the caller passed the read's `decision_id` / `decisionId` to `sanitize` — that is what joins it to the decision |
| `principal` | string, optional | whom the text was redacted for. A governor resolves one for every call — the caller's, or the typed `Agent::"<name>"` — so a `sanitize()` through a governor always carries it; the field is optional because the writer emits it only when the report carries one |

### `egress` — written after a governed tool's `on_result` / `onResult` hook

| field | type | notes |
|---|---|---|
| `ts`, `agent`, `principal`, `intent`, `resource` | | those of the call whose result was inspected |
| `event` | `"egress"` | |
| `replaced` | boolean | `true` when the hook returned a value that replaced the payload |
| `actor_chain` | string[], optional | the delegation chain — see above |
| `decision_id` | string, optional | the id of the decision that let the body run — present for `govern.tool`; on a framework adapter without a `tool_use_id` there is none |
| `withheld` | `true`, optional | the hook threw, or outran its deadline — the payload was never released; `replaced` is `false` |

Three dispositions: `withheld` (present) → **withheld**; else `replaced: true`
→ **replaced**; else **passthrough**. A denied call has no `egress` record, since
the body never ran.

### `attenuation` — written by `scope()` (the root) and every `attenuate()`

| field | type | notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `intent` | `"attenuate"` | fixed |
| `event` | `"attenuation"` | |
| `node_id` | string | this scope's id (a refused request gets a fresh id that heads no chain) |
| `resource` | string | `root scope`, or `sub-agent depth <n>` |
| `decision` | string | `Allow` (granted) or `Deny` (refused) |
| `depth` | number | 0 for the root |
| `tools` | string[] | the **granted** tool set (the engine's clamped grant) — for a `Deny`, the requested set |
| `parent_id` | string, optional | absent on the root |
| `reason` | string, optional | present on a `Deny`: the violated dimension, or the depth-ceiling notice |

The one kind with no `principal` and no `actor_chain`: a scope names capabilities,
not a subject.

Chains are `parent_id → node_id`; what a child dropped is
`parent.tools − child.tools`. Only tool names appear; resources and intents
granted to a scope are not written.

### `screening` — written by `screen()`

| field | type | notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `intent` | string | label passed to `screen` (default `read`) |
| `event` | `"screening"` | |
| `resource` | string | label passed to `screen` (default `content`) |
| `mode` | string | `report` or `redact` |
| `detector` | string | detector version, e.g. `de-screen-1` |
| `counts` | object | matches per rule family, e.g. `{"PROMPT_LEAK": 1}` |
| `total` | number | total matches |
| `flagged` | boolean | `total > 0` |
| `actor_chain` | string[], optional | the delegation chain — see above |
| `decision_id` | string, optional | present only when the caller passed a `decision_id` / `decisionId` to `screen` |
| `principal` | string, optional | whom the text was screened for — resolved exactly as on `sanitization` above |

A screening the caller gives no `decision_id` is joined to a call only by being
written inside its egress hook — order it by `ts` next to the `egress` record on
the same `resource`, or give the screen the call's `resource` label, as the
generators do.

## Reading the joins

- **`decision_id` is the only cross-kind key.** `sanitization` and `screening`
  carry it only when the caller passed the read's id into `sanitize` / `screen`;
  `egress` carries it automatically from `govern.tool`. Calls through a framework
  adapter can lack it — `forensics.py` counts those under *integrity* rather than
  guessing.
- **`principal` is not a join key.** `sanitization` and `screening` name their
  own subject, so a query that filters the trail on principal alone matches them
  as well as decisions. Count decisions by testing that `event` is absent — see
  the quotas note in `examples/patterns/audit-sink.md`.
- **An `Allow` with nothing after it** is a body that ran with no egress hook.
  If every read in your application should be minimized, that count should be
  zero — the analyzer prints it.
- **Orphans** are follow-up records whose decision is not in this file: another
  process's trail, or a truncated file. They are reported, never dropped.
- **Malformed lines** are counted and skipped, never echoed.

## jq

Every section above is also a one-liner in [`recipes.md`](./recipes.md) —
handy on a host where only `jq` is available.
