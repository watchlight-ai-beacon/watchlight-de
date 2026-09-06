# Pattern: strip PII before an agent reads a document

The agent needs a document's content, not the personal data in it. Remove the
PII before the model ever sees the text.

This is data minimization, not a policy decision, so it uses `govern.sanitize`.

```ts
import { govern } from "@watchlight/sdk";

const text = await extractPdfText("statement.pdf");          // your extractor
const { text: safe, report } = govern.sanitize(text, { resource: "statement.pdf" });
// safe   → "Card on file: <CREDIT_CARD_1>   SSN: <SSN_1> …"
// report → { counts: { CREDIT_CARD: 1, SSN: 1 }, total: 2 }   (value-free)
await agent.read(safe);
```

```python
from watchlight import govern

text = extract_pdf_text("statement.pdf")
result = govern.sanitize(text, resource="statement.pdf")
agent.read(result["text"])          # redacted
# result["report"] → counts by type + total; never the values
```

Detection is deterministic: email, phone, SSN, credit card (Luhn-checked), IBAN,
IPv4, API keys, labelled passport numbers and MRZ lines, labelled dates of birth.
Matches become stable tags (`<SSN_1>`), masks or hashes —
`mode: "tag" | "mask" | "hash"`. A value-free `sanitization` record goes to the
audit trail, and a sanitization that cannot complete raises rather than returning
raw text.

## Redact values you already hold

The document is *about* someone your system knows. Pass those values in `known`
and every occurrence is redacted, counted under `KNOWN`, and never leaves your
process.

```ts
const { text: safe, report } = govern.sanitize(text, {
  resource: "intake-form.txt",
  known: [applicant.fullName, applicant.street],
});
// safe   → "Applicant <KNOWN_1>, DOB <DOB_1>, of <KNOWN_2> …"
// report → { counts: { KNOWN: 3, DOB: 1 }, total: 4 }
```

```python
result = govern.sanitize(
    text, resource="intake-form.txt", known=[applicant.full_name, applicant.street]
)
# result["report"]["counts"] → {"KNOWN": 3, "DOB": 1}
```

## Make the sanitizing path the only way in

```cedar
// the governed wrapper sets `sanitized: true`; a raw read never matches
permit(principal, action == Action::"read", resource)
when { context.sanitized == true };

// some documents are never read at all
forbid(principal, action == Action::"read", resource)
when { context.classification == "restricted" };
```

```ts
const readDoc = govern.tool(
  async (id: string) => govern.sanitize(await fetchText(id), { resource: `doc/${id}` }).text,
  { intent: "read", resource: (id) => `doc/${id}`,
    context: (id) => ({ sanitized: true, classification: classify(id) }) }
);
```

## Verdicts

Proved by [`suites/pii-before-read.suite.json`](./suites/pii-before-read.suite.json).

| read | `sanitized` | `classification` | verdict |
|---|---|---|---|
| through the sanitizing tool | true | internal | **Allow** |
| of the raw text | false | internal | **Deny** |
| with no context | — | — | **Deny** — fail-closed |
| through the sanitizing tool | true | restricted | **Deny** — the `forbid` |
| a `write` on the same path | true | internal | **Deny** — reads only |

## Worth knowing

- **Extract to text first.** A "redacted" PDF still carries the original in
  hidden layers, annotations and metadata. Sanitize the extracted text.
- Overlapping values merge into one span, so no fragment survives, and `known` is
  honoured even when `types` narrows the detectors.
- `known` matching is simple case-insensitive. Unicode case folding differs
  between the TypeScript and Python lanes.
- `PERSON` and `ADDRESS` are heuristics and off by default. Turn them on with
  `types: [...DEFAULT_PII_TYPES, "PERSON", "ADDRESS"]`.
- `detectorVersion` / `detector_version` (`de-rules-2`) names the detector set
  that produced a report.

## Verified by

The suite above, plus
[`scripts/pii-before-read.mjs`](./scripts/pii-before-read.mjs), which runs
`sanitize` itself. Structured PII and every `known` value are gone from the text.
The report and the audit record carry counts only. `decisionId` joins the
sanitization to its decision, and a malformed correlation id is refused.
