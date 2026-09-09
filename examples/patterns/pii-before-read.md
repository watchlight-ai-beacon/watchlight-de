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

### `known` covers your subjects. `PERSON` covers everyone else.

`known` is exact, so it is the precise half of this — but it can only ever hold
values your application already has. That is a boundary worth seeing before you
rely on it: **the people in a document who are not your users are the ones
`known` structurally cannot reach.** A friend named in a trip request, a child's
school, a doctor in a case note — none of them ever used your product, so none
of them are in your database, and they have the least say in the matter.

Those are what the `PERSON` and `ADDRESS` heuristics are for. They are off by
default because they are heuristics — lower precision, and they redact
organisation names as people — so turning them on is a judgement about which
error you would rather make:

```python
govern.sanitize(text, types=[*DEFAULT_PII_TYPES, "PERSON", "ADDRESS"], known=[user.full_name])
```

Use both. `known` for the subjects you hold, the heuristics for the third
parties you do not.

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

## Register a detector for your own vocabulary

The built-ins cover identifiers everyone has. An alien registration number, a
driver's licence, an internal case number — those are yours, and a workload that
cannot add them runs a second redaction engine beside this one.

```python
from watchlight import register_detector

register_detector("ALIEN_NUMBER", r"\bA[- ]?\d{8,9}\b")
register_detector("CASE_NO", r"\bCASE-\d{4}-\d{5}\b")
```

```ts
import { registerDetector } from "@watchlight/sdk";

registerDetector("ALIEN_NUMBER", /\bA[- ]?\d{8,9}\b/);
```

Registered detectors are on by default, tag like any other
(`<ALIEN_NUMBER_1>`), and are selectable through `types`. Register at start-up:
the registry is process-wide, and one added mid-scan does not apply to it.

Pass `validate` for a check the pattern cannot express — the built-in card rule
uses it for the Luhn check:

```python
register_detector("EVEN_ID", r"\bID\d{4}\b", validate=lambda v: int(v[2:]) % 2 == 0)
```

**A pattern that backtracks catastrophically is refused at registration.** One
`(a+)+` in a detector hangs every call that scans a document, so the cost of
finding out is paid once, at start-up:

```python
register_detector("EVIL", r"(a+)+$")
# SanitizeError: detector 'EVIL': (a+)+ nests one unbounded quantifier inside
# another, which backtracks catastrophically on input that nearly matches.
```

Also refused: a label that is already built in — replacing `SSN` with a weaker
rule is exactly the change nobody would notice — and a label that is not
`UPPER_SNAKE_CASE`.

Once anything is registered, `detector_version` carries a digest of the set
(`de-rules-2+custom.1aaea373`), so an audit record says what was screening at
the time. It is a hash of the labels and patterns, never the patterns
themselves, so the record stays value-free.

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
  `types: [...DEFAULT_PII_TYPES, "PERSON", "ADDRESS"]` — and see
  [`known` covers your subjects](#known-covers-your-subjects-person-covers-everyone-else)
  for which of the two you actually need.
- `detectorVersion` / `detector_version` (`de-rules-2`) names the detector set
  that produced a report, and carries a `+custom.<digest>` suffix once you have
  registered any of your own.

## Verified by

The suite above, plus
[`scripts/pii-before-read.mjs`](./scripts/pii-before-read.mjs), which runs
`sanitize` itself. Structured PII and every `known` value are gone from the text.
The report and the audit record carry counts only. `decisionId` joins the
sanitization to its decision, and a malformed correlation id is refused.
