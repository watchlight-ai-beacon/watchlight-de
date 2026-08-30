# Pattern: strip PII before an agent reads a document

**Problem.** An agent needs the *content* of a document — a statement, a form, a
support thread — but not the personal data in it. You want to remove PII **before**
the model ever sees the text, deterministically, and keep a value-free record of
what was removed.

This one isn't a policy decision — it's **data minimization** at the boundary — so
it uses `govern.sanitize`, not `authorize`.

**Use it:**

```ts
import { govern } from "@watchlight/sdk";

const text = await extractPdfText("statement.pdf");          // your extractor
const { text: safe, report } = govern.sanitize(text, { resource: "statement.pdf" });
// safe   → "Card on file: <CREDIT_CARD_1>   SSN: <SSN_1> …"   (what the agent sees)
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

**What it does.** Deterministic detection of structured PII — email, phone, SSN,
credit card (Luhn-checked), IBAN, IPv4, API keys — replaced by stable tags
(`<SSN_1>`), masks, or hashes (`mode: "tag" | "mask" | "hash"`). It writes a
**value-free** `sanitization` record to the audit trail (counts by type and mode,
never the values), and is **fail-closed**: if sanitization can't complete it
raises rather than handing back raw text.

**Two rules that matter.**

- **Extract to text first — never hand the agent the original PDF.** A "redacted"
  PDF still carries the original in hidden layers, annotations, and metadata.
  Sanitize the extracted *text* and give the agent that.
- **This is minimization, not authorization.** Pair it with a policy (e.g.
  [per-user attribution](./per-user-attribution.md)) when *whether* the agent may
  read the document is also a decision.

Choose the types you care about with `types: ["SSN", "CREDIT_CARD"]` (TS) /
`types=[...]` (Python). See the DE docs for the full detector list.
