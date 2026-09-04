# Showcase: poisoned-document RAG

A retrieval pipeline where one retrieved document hides a prompt injection and
personal data. `screen()` flags it, the policy's `@obligate_redact` obligation
strips personal data from what passes, and an egress hook makes sure **the model
only ever receives cleaned text** — with every step joined to the tool call's
decision in the audit trail. Python and TypeScript, identical behaviour.

| File | What it is |
|---|---|
| [`rag.py`](./rag.py) | The pipeline in Python — corpus, governed `retrieve` tool, `on_result` hook, assertions |
| [`rag.mjs`](./rag.mjs) | The same pipeline in TypeScript / Node |
| [`policy.suite.json`](./policy.suite.json) | The policy the run loads **and** the fixtures `watchlight policy test` checks, including the obligations |

## Run it

```bash
# Python
pip install watchlight
python examples/showcase/poisoned-rag/rag.py

# TypeScript / Node
npm i -g @watchlight/sdk            # or, in this repo: cd ts && npm install && npm run build
node examples/showcase/poisoned-rag/rag.mjs

# The policy suite, in either CLI (they agree)
watchlight policy test examples/showcase/poisoned-rag/policy.suite.json
```

Both scripts run offline (no API key, no model call), print a value-free view of
what the model would receive, assert the outcome, and **exit non-zero if any
assertion fails**. Run `watchlight dev` in a second terminal to watch the
decisions live.

## The corpus

Four in-memory documents, all synthetic. Three are ordinary handbook / ticket
text; **`vendor-faq`** is poisoned — an invisible `<div style="display:none">`
block carries an instruction override, an e-mail address, an SSN-shaped number
and a customer name. **`ticket-4471`** is clean but carries the same customer's
name and e-mail, so the redact obligation has something to do on a document that
*passes* screening. The retriever is a keyword scorer (real systems use
embeddings); what matters is that every hit goes through the governed tool.

## The policy

```cedar
@obligate_redact("email, name, ssn")
permit(principal, action == Action::"retrieve", resource)
when { context.collection == "kb" };
```

Retrieval is *allowed* for the whole knowledge base — including the poisoned
document. The policy is not where an injection is caught (the text is unknown
until it comes back); it is where the "yes, but redact these" rule lives, as an
obligation the hook must honour. The suite asserts the obligation like a verdict:

```json
{ "action": "retrieve", "resource": "doc/ticket-4471", "context": { "collection": "kb" },
  "expect": "Allow", "obligations": { "redact": ["email", "name", "ssn"] } }
```

## The hook

`retrieve(doc_id)` is governed with `resource = doc/<id>` and an egress hook that
runs **after the body returns and before the caller sees the result**. The hook
receives the `decision_id` *and the obligations* of the decision that let the
body run, and threads the id through every step:

```python
def release(text, info):
    resource, decision_id = info["resource"], info["decision_id"]
    # 1. screen — flagged for an injection family → withhold (raise)
    screened = govern.screen(text, intent="retrieve", resource=resource, decision_id=decision_id)
    if screened["report"]["flagged"]:
        raise Denied(resource, "retrieve", DENY_REASON)
    # 2. honour the redact obligation: email/ssn → detectors, name → the `known` dictionary
    fields = (info["obligations"] or {}).get("redact", [])
    ...
    cleaned = govern.sanitize(screened["text"], intent="retrieve", resource=resource,
                              decision_id=decision_id, types=types, known=known)
    # 3. the cleaned text replaces the raw payload
    return cleaned["text"]

@govern.tool("retrieve", resource=lambda d: f"doc/{d}", context={"collection": "kb"}, on_result=release)
def retrieve(doc_id): ...
```

```ts
function release(text, { resource, decisionId, obligations }) {
  const screened = govern.screen(text, { intent: "retrieve", resource, decisionId });
  if (screened.report.flagged) throw new Denied(resource, "retrieve", DENY_REASON);
  const fields = obligations?.redact ?? [];
  ...
  return govern.sanitize(screened.text, { intent: "retrieve", resource, decisionId, types, known }).text;
}
const retrieve = govern.tool(function retrieve(id) { ... }, {
  intent: "retrieve", resource: (id) => `doc/${id}`, context: { collection: "kb" }, onResult: release,
});
```

Three fail-closed choices worth copying: a flagged document is **withheld**, not
redacted (the pipeline puts a fixed opaque line in its slot); an obligation field
the hook has no detector for **withholds** the document rather than silently
dropping the constraint; and the `name` field is honoured through `known` — the
value the application already holds — rather than the lower-precision `PERSON`
heuristic.

## Sample output

```
corpus: 4 documents; question → 3 hits: vendor-faq, handbook-expenses, ticket-4471

watchlight: governing 'rag-agent' (dev mode, in-process engine)
watchlight: ALLOW  retrieve  doc/vendor-faq
watchlight: SCREEN retrieve  doc/vendor-faq     flagged 2 (report)
watchlight: EGRESS retrieve  doc/vendor-faq     withheld
watchlight: ALLOW  retrieve  doc/handbook-expenses
watchlight: SCREEN retrieve  doc/handbook-expenses     flagged 0 (report)
watchlight: SANIT  retrieve  doc/handbook-expenses     redacted 0 (tag)
watchlight: EGRESS retrieve  doc/handbook-expenses     replaced
watchlight: ALLOW  retrieve  doc/ticket-4471
watchlight: SCREEN retrieve  doc/ticket-4471     flagged 0 (report)
watchlight: SANIT  retrieve  doc/ticket-4471     redacted 2 (tag)
watchlight: EGRESS retrieve  doc/ticket-4471     replaced

=== model input (value-free view) ===
  doc/vendor-faq           withheld   screening flagged: HTML_INJECTION, INSTRUCTION_OVERRIDE
  doc/handbook-expenses    released   screening clean; redacted 0 (nothing to redact)
  doc/ticket-4471          released   screening clean; redacted 2 (EMAIL 1, KNOWN 1)
  2 of 3 retrieved documents released to the model; 1 withheld.

=== audit trail (this run, joined on decision_id) ===
  …f869b1  decision=Allow  screening=1  sanitization=0  egress=withheld
  …686860  decision=Allow  screening=1  sanitization=1  egress=replaced
  …f262c5  decision=Allow  screening=1  sanitization=1  egress=replaced

=== assertions ===
  ✓ the poisoned document never reaches the model — no injection text, no personal data in the model input
  ✓ the withheld slot carries the fixed opaque line, once
  ✓ clean documents pass through — the expense policy arrives verbatim
  ✓ the clean document with personal data is released redacted (<EMAIL_1>, <KNOWN_1>)
  ✓ every hook run honoured the redact obligation [email, name, ssn] from the decision
  ✓ the model input is bounded to the retrieved hits
  ✓ one Allow decision per retrieved document, each with a decision_id
  ✓ doc/vendor-faq: screening flagged INSTRUCTION_OVERRIDE + HTML_INJECTION, no sanitization, egress withheld — one decision_id
  ✓ doc/handbook-expenses: screening clean, one sanitization, egress replaced — one decision_id
  ✓ doc/ticket-4471: screening clean, one sanitization, egress replaced — one decision_id
  ✓ the ticket's sanitization record carries counts only — EMAIL 1, KNOWN 1
  ✓ no screening / sanitization / egress record is left unjoined
  ✓ the audit trail is value-free — none of the personal data or injection text appears in it
  ✓ policy.suite.json: 5/5 fixtures pass, obligations asserted

ALL CHECKS OK
```

Nothing above is matched text — the view is counts, family names and
dispositions. The model input itself is built in memory and only asserted on.

## The audit trail

The scripts collect this run's records through `audit_sink` / `auditSink` (the
same records land in `.watchlight/audit.jsonl`). For the poisoned document the
trail reads, on **one** `decision_id`:

```json
{"agent":"rag-agent","principal":"rag-agent","intent":"retrieve","resource":"doc/vendor-faq","decision":"Allow","decision_id":"…74f44b"}
{"agent":"rag-agent","intent":"retrieve","event":"screening","resource":"doc/vendor-faq","mode":"report","detector":"de-screen-1","counts":{"HTML_INJECTION":1,"INSTRUCTION_OVERRIDE":1},"total":2,"flagged":true,"decision_id":"…74f44b"}
{"agent":"rag-agent","principal":"rag-agent","intent":"retrieve","event":"egress","resource":"doc/vendor-faq","replaced":false,"decision_id":"…74f44b","withheld":true}
```

and for the clean ticket a `sanitization` line (`"counts":{"EMAIL":1,"KNOWN":1}`)
sits between a clean `screening` line and an `egress` line with `"replaced":true`.
The scripts assert exactly that shape per document: one Allow decision; one
`screening` record; a `sanitization` record for every released document and none
for the withheld one; one `egress` record with the right disposition; every
non-decision record carrying a `decision_id`; and no personal data or injection
text anywhere in the trail.

## Notes

- **Screening is rules, not a classifier.** It catches the literal, well-known
  shapes (here an instruction override inside a hiding `style=` attribute). A
  document that *quotes* an attack is flagged too. Treat `flagged` as a signal to
  withhold, route or log — this pipeline withholds.
- **Withhold vs redact.** `govern.screen(..., mode: "redact")` would return the
  text with `[FAMILY]` markers in place of the triggers; this pipeline refuses
  instead, because a document that tried to instruct the model has nothing the
  model should read. The withheld slot is a fixed string — never the reason.
- **Redaction recall is bounded by the enabled detectors** and the `known`
  dictionary. Names not in `known` are not caught unless the opt-in `PERSON`
  heuristic is enabled.
- Related patterns: [screen before model](../../patterns/screen-before-model.md),
  [allow, but redact](../../patterns/allow-but-redact.md),
  [egress after read](../../patterns/egress-after-read.md),
  [PII before read](../../patterns/pii-before-read.md).
