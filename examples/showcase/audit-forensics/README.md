# Audit forensics

Generate an audit trail with every record kind, then read it back. It answers
one question: which principal did what to which resource, and what happened to
the data afterwards. No argument value is ever in it.

```bash
cd examples/showcase/audit-forensics

python generate_trail.py        # writes ./trail/audit.jsonl and checks it
python forensics.py             # reads it — joins, roll-ups, chains, integrity
```

`forensics.py` is stdlib-only and takes any trail: `python forensics.py
../../../.watchlight/audit.jsonl`. Add `--json` for the machine-readable report,
`--principal 'User::"alice"'` for one subject. `node generate-trail.mjs` writes
the same records from the TypeScript lane.

## The scenario

A support-ticket agent, governed with `govern.tool`, acting for two users:

| Step | What the SDK writes |
|---|---|
| `alice` reads ticket T-1 (public); the egress hook sanitizes the body | `decision` Allow → `sanitization` (3 redactions) → `egress` replaced |
| `bob` reads ticket T-2 (internal); nothing to redact | `decision` Allow → `sanitization` (0) → `egress` replaced |
| `alice` reads ticket T-9 (restricted) | `decision` Deny — the body never ran, so no egress |
| `alice` fetches a clean page; the hook screens and passes it | `decision` Allow → `screening` clean → `egress` passthrough |
| `alice` fetches a page carrying an injection | `decision` Allow → `screening` flagged → `egress` withheld |
| `alice` refunds 40 | `decision` Allow |
| `alice` refunds 250; a human confirms | `decision` NeedsApproval, then `decision` Allow with `approved: true` |
| `bob` refunds 250; left pending | `decision` NeedsApproval |
| `alice` deletes a ticket (no policy) | `decision` Deny |
| root scope → triage → reader; triage asks for `refund` | `attenuation` ×3 Allow, ×1 Deny |
| a draft reply is screened before it leaves | `screening` flagged |

Twenty-three records: 10 decisions, 2 sanitizations, 4 egress, 4 attenuations,
3 screenings. Every fixture is synthetic.

## What the analyzer reports

```text
== per principal ==
  principal           allowed  approved   held  denied
  User::"alice"             4         1      1       2
  User::"bob"               1         0      1       0

== decisions and what followed (joined on decision_id) ==
  50a7faca  allowed  read     ticket/T-1         User::"alice"
           → sanitization redacted=3 [CREDIT_CARD=1,KNOWN=1,SSN=1] mode=tag
           → egress replaced
  c5b70142  denied   read     ticket/T-9         User::"alice"
  7b50ab23  allowed  fetch    page/vendor-notice User::"alice"
           → egress withheld
  efe6b6ac  held     refund   ticket/T-1         User::"alice"
  9fadb0fe  approved refund   ticket/T-1         User::"alice"
  allowed actions: 6; followed by a sanitization or egress record: 4

== attenuation chains (parent → child, tools dropped) ==
  (root)     → 1c67b608   depth=0 Allow tools=['delete_ticket', 'fetch_page', 'read_ticket', 'refund']
  1c67b608   → 0b7ca400   depth=1 Allow tools=['fetch_page', 'read_ticket'] dropped=['delete_ticket', 'refund']
  0b7ca400   → 9f093402   depth=2 Deny  tools=['refund'] dropped=['fetch_page', 'read_ticket']
             reason: 1 tool(s) not in parent.allowed_tools (e.g. ["refund"])

== integrity ==
  decisions without decision_id: 0
  sanitization/egress without decision_id: 0
  orphans (decision_id with no decision record): 0
```

`allowed` is an `Allow` without `approved`; `approved` is an `Allow` carrying
`approved: true`; `held` is a `NeedsApproval` nobody has confirmed yet.
Everything printed is an identifier, a count or a field name.

## Record kinds

Five kinds, told apart by `event`. A decision has no `event` field; every other
kind names itself there. One allowed read and the two records that followed it,
abridged:

```json
{"ts": "…", "agent": "ticket-agent", "principal": "User::\"alice\"", "intent": "read", "resource": "ticket/T-1", "decision": "Allow", "decision_id": "5b096b77-…"}
{"ts": "…", "agent": "ticket-agent", "intent": "read", "event": "sanitization", "resource": "ticket/T-1", "total": 3, "decision_id": "5b096b77-…"}
{"ts": "…", "agent": "ticket-agent", "principal": "User::\"alice\"", "intent": "read", "event": "egress", "resource": "ticket/T-1", "replaced": true, "decision_id": "5b096b77-…"}
```

So `.event // "decision"` names any record's kind, and `select(.event == null)`
picks out the decisions. `decision_id` is what joins the three.

Both SDKs also ship types for these five records. They are described in
[the audit trail](../../../docs/audit-trail.md#send-records-to-your-own-store).

Both generators assert every record against the tables below, on every run and
in both lanes. The tables cannot drift from the code.

Two fields ride along on every kind but `attenuation`:

| Field | Type | Notes |
|---|---|---|
| `actor_chain` | string[], optional | the ordered delegation chain, root first. Written only through a `delegate()`d governor |
| `principal` | string | the subject. Required on `decision` and `egress`, and carried by `sanitization` and `screening` when the report names one |

### `decision` — written by `authorize()`, and so by every governed tool call

| Field | Type | Notes |
|---|---|---|
| `ts` | string | ISO-8601 UTC |
| `agent` | string | the governor's agent identity |
| `principal` | string | the acting principal, e.g. `User::"alice"`; `Agent::"<name>"` when the call names no subject |
| `intent` | string | the action authorized |
| `resource` | string | `tool/<name>` for a governed tool with no `resource` binding |
| `decision` | string | `Allow`, `Deny` or `NeedsApproval` |
| `actor_chain` | string[], optional | see above |
| `decision_id` | string, optional | the join key, on every record the in-process engine produces |
| `approved` | `true`, optional | only when an approval token downgraded a `NeedsApproval` |

An approved action is **two** records: the hold, then a second `Allow` with
`approved: true` under a new `decision_id`. The deny reason is never written —
callers get a uniform one, and the trail carries the verdict.

### `sanitization` — written by `sanitize()`

| Field | Type | Notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `event` | `"sanitization"` | |
| `intent` | string | label passed to `sanitize` (default `read`) |
| `resource` | string | label passed to `sanitize` (default `document`) |
| `mode` | string | `tag`, `mask` or `hash` |
| `detector` | string | detector version, e.g. `de-rules-2` |
| `counts` | object | redactions per PII type |
| `total` | number | total redactions |
| `actor_chain` | string[], optional | see above |
| `decision_id` | string, optional | only when you pass the read's `decision_id` / `decisionId` into `sanitize` |
| `principal` | string, optional | whom the text was redacted for |

### `egress` — written after a governed tool's `on_result` / `onResult` hook

| Field | Type | Notes |
|---|---|---|
| `ts`, `agent`, `principal`, `intent`, `resource` | | those of the call whose result was inspected |
| `event` | `"egress"` | |
| `replaced` | boolean | `true` when the hook returned a replacement payload |
| `actor_chain` | string[], optional | see above |
| `decision_id` | string, optional | present for `govern.tool`; a framework adapter without a `tool_use_id` has none |
| `withheld` | `true`, optional | the hook threw or outran its deadline; the payload never left. `replaced` is `false` |

Three dispositions: `withheld` → **withheld**; else `replaced: true` →
**replaced**; else **passthrough**. A denied call has no `egress` record.

`withheld` says the payload never left. It does not say why: a hook that threw
and a hook that outran its 8-second deadline look identical here. The caller
gets the error. The deadline itself is in
[governing what a tool returns](../../../docs/typescript.md#govern-what-a-tool-returns).

### `attenuation` — written by `scope()` and every `attenuate()`

| Field | Type | Notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `event` | `"attenuation"` | |
| `intent` | `"attenuate"` | fixed |
| `node_id` | string | this scope's id; a refused request gets a fresh id that heads no chain |
| `resource` | string | `root scope`, or `sub-agent depth <n>` |
| `decision` | string | `Allow` (granted) or `Deny` (refused) |
| `depth` | number | 0 for the root |
| `tools` | string[] | the granted set; for a `Deny`, the requested one |
| `parent_id` | string, optional | absent on the root |
| `reason` | string, optional | on a `Deny`: the violated dimension, or the depth ceiling |

The one kind with no `principal` and no `actor_chain` — a scope names
capabilities, not a subject. Chains are `parent_id → node_id`, and what a child
dropped is `parent.tools − child.tools`.

### `screening` — written by `screen()`

| Field | Type | Notes |
|---|---|---|
| `ts`, `agent` | | as above |
| `event` | `"screening"` | |
| `intent` | string | label passed to `screen` (default `read`) |
| `resource` | string | label passed to `screen` (default `content`) |
| `mode` | string | `report` or `redact` |
| `detector` | string | detector version, e.g. `de-screen-1` |
| `counts` | object | matches per rule family |
| `total` | number | total matches |
| `flagged` | boolean | `total > 0` |
| `actor_chain` | string[], optional | see above |
| `decision_id` | string, optional | only when you pass one into `screen` |
| `principal` | string, optional | whom the text was screened for |

## Reading the joins

- **`decision_id` is the only cross-kind key.** `egress` carries it
  automatically from `govern.tool`; `sanitization` and `screening` carry it only
  when you pass the read's id in.
- **`principal` is not a join key.** `sanitization` and `screening` name a
  subject too, so filtering on principal alone over-counts decisions. Count
  decisions by testing that `event` is absent.
- **An `Allow` with nothing after it** is a body that ran with no egress hook.
  If every read in your application should be minimized, that count is zero.
- **Orphans** — follow-up records whose decision is not in this file — are
  reported, never dropped. Malformed lines are counted and skipped.
- A screening with no `decision_id` joins only by `ts` and `resource` next to
  its `egress` record. Give the screen the call's `resource` label, as the
  generators do.

The same questions as `jq` one-liners are in [`recipes.md`](./recipes.md).

Verified by [`check.sh`](./check.sh). Order is the point here: `forensics.py`
reads what `generate_trail.py` writes, so it exits 1 on its own and 0 after —
and the check asserts both, from an empty `trail/`.
