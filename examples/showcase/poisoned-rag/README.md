# Poisoned RAG

One retrieved document hides a prompt injection and personal data. It is
screened and withheld before the model sees it, and the clean documents are
redacted on the way out.

```bash
python rag.py            # or: node rag.mjs
```

No API key, no model call. The scripts print a value-free view of what the model
would have received, assert it, and exit non-zero on any failure. Run
`watchlight dev` in a second terminal to watch the decisions land.

## The corpus

The corpus holds four synthetic documents. `vendor-faq` is poisoned: an
invisible `<div style="display:none">` block carries an instruction override, an
e-mail address, an SSN-shaped number and a customer name. `ticket-4471` is clean
but names the same customer, so the redact obligation has work to do on a
document that *passes* screening. The retriever is a keyword scorer; what matters
is that every hit goes through the governed tool.

## The policy

```cedar
@obligate_redact("email, name, ssn")
permit(principal, action == Action::"retrieve", resource)
when { context.collection == "kb" };
```

Retrieval is allowed for the whole knowledge base, poisoned document included.
The policy is not where an injection is caught — the text is unknown until it
comes back. It is where the "yes, but redact these" rule lives, and the suite
asserts the obligation like a verdict:

```json
{ "action": "retrieve", "resource": "doc/ticket-4471", "context": { "collection": "kb" },
  "expect": "Allow", "obligations": { "redact": ["email", "name", "ssn"] } }
```

## The hook

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

The hook runs after the body returns and before the caller sees the result. It
is handed the decision's `decision_id` **and its obligations**, and threads the
id through every step. `rag.mjs` is the same shape with `onResult` and
`decisionId`.

Three fail-closed choices worth copying:

- A flagged document is **withheld, not redacted**. The pipeline puts a fixed
  opaque line in its slot.
- An Allow carrying **no `redact` obligation withholds** the document. A missing
  obligation is no permission, not no limit, so a permit that forgot the
  annotation cannot release personal data in full.
- An obligation field the hook has **no detector for withholds** the document,
  rather than dropping the constraint silently.

The scripts exercise all three branches directly with synthetic `info` objects,
independent of the corpus.

## What you see

```text
watchlight: ALLOW  retrieve  doc/vendor-faq
watchlight: SCREEN retrieve  doc/vendor-faq     flagged 2 (report)
watchlight: EGRESS retrieve  doc/vendor-faq     withheld
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
  …57c74c  decision=Allow  screening=1  sanitization=0  egress=withheld
  …217879  decision=Allow  screening=1  sanitization=1  egress=replaced
  …4137aa  decision=Allow  screening=1  sanitization=1  egress=replaced

=== assertions ===
  ✓ the poisoned document never reaches the model — no injection text, no personal data in the model input
  ✓ the clean document with personal data is released redacted (<EMAIL_1>, <KNOWN_1>)
  ✓ the audit trail is value-free — none of the personal data or injection text appears in it
  ✓ an Allow that carries no redact obligation withholds the document (fail-closed)
  … 17 assertions in all

ALL CHECKS OK
```

Nothing there is matched text: the view is counts, family names and
dispositions.

## The trail, for the poisoned document

Three records on one `decision_id`:

```json
{"agent":"rag-agent","principal":"Agent::\"rag-agent\"","intent":"retrieve","resource":"doc/vendor-faq","decision":"Allow","decision_id":"…57c74c"}
{"agent":"rag-agent","intent":"retrieve","event":"screening","resource":"doc/vendor-faq","mode":"report","detector":"de-screen-1","counts":{"HTML_INJECTION":1,"INSTRUCTION_OVERRIDE":1},"total":2,"flagged":true,"decision_id":"…57c74c","principal":"Agent::\"rag-agent\""}
{"agent":"rag-agent","principal":"Agent::\"rag-agent\"","intent":"retrieve","event":"egress","resource":"doc/vendor-faq","replaced":false,"decision_id":"…57c74c","withheld":true}
```

A released document has a `sanitization` line between the screening and an
`egress` with `"replaced":true`. The scripts assert that shape per document, and
that no follow-up record is left unjoined.
→ [Every record's fields](../audit-forensics/README.md#record-kinds)

## Worth knowing

- **Screening is rules, not a classifier.** It catches literal, well-known
  shapes. A document that merely *quotes* an attack is flagged too. Treat
  `flagged` as a signal to withhold, route or log.
- **Withhold or redact.** `screen(..., mode: "redact")` returns the text with
  `[FAMILY]` markers instead. This pipeline refuses, because a document that
  tried to instruct the model has nothing the model should read.
- **Recall is bounded by the enabled detectors and the `known` dictionary.**
  `KNOWN_PEOPLE` holds what the application already knows, never anything
  derived from the retrieved text. Its values never enter the trail, and names
  outside it need the opt-in `PERSON` heuristic.

Verified by [`check.sh`](./check.sh). Related patterns:
[screen before model](../../patterns/screen-before-model.md) ·
[allow, but redact](../../patterns/allow-but-redact.md) ·
[egress after read](../../patterns/egress-after-read.md) ·
[PII before read](../../patterns/pii-before-read.md).
