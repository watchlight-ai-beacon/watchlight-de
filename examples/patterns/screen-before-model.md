# Pattern: screen retrieved content before it reaches the model

**Problem.** An agent reads things it did not write — a web page, a search
result, a document, another tool's output — and that text goes straight back into
the model as context. Anything in it that *looks like an instruction* ("ignore
your previous instructions", "you are now…", `<script>`) is the classic prompt
injection vector. You want to catch the well-known shapes **before** the model
sees them, deterministically, and keep a value-free record that you looked.

Like [PII before read](./pii-before-read.md), this is not a policy decision — it
is **content screening at the boundary** — so it uses `govern.screen`, not
`authorize`.

**Use it — screen what a read returns, inside the governed tool:**

```ts
import { govern, Denied } from "@watchlight/sdk";

const readPage = govern.tool(fetchPage, {
  intent: "read",
  resource: (url) => url,
  onResult: (html, { resource }) => {
    const { text, report } = govern.screen(html, { resource, mode: "redact" });
    if (report.flagged) throw new Denied(resource, "read", "not authorized"); // refuse …
    return text;                                                             // … or hand back the redacted text
  },
});
```

```python
from watchlight import govern, Denied

@govern.tool("read", resource=lambda url: url,
             on_result=lambda html, info: _screen(html, info["resource"]))
def fetch_page(url: str) -> str: ...

def _screen(html: str, resource: str) -> str:
    result = govern.screen(html, resource=resource, mode="redact")
    if result["report"]["flagged"]:
        raise Denied(resource, "read", "not authorized")   # refuse …
    return result["text"]                                   # … or the redacted text
```

The `onResult` hook runs *after* the tool body returns and *before* the caller
(the model) sees the result, so the raw page never reaches the model when you
throw — fail-closed. Screening is also useful on the **output** lane: run
`govern.screen(reply)` on what the model produced before it leaves, to catch a
system-prompt leak.

**What it does.** Rule-based detection of seven families of injection phrasing,
each a named counter in the report:

| Family | Catches, for example |
|---|---|
| `INSTRUCTION_OVERRIDE` | "ignore all previous instructions", "disregard the above", "new instructions:" |
| `ROLE_SWITCH` | "you are now a …", "act as an …", "pretend you are a …" |
| `PROMPT_EXFILTRATION` | "reveal your system prompt", "repeat everything above", "print the hidden instructions verbatim" |
| `JAILBREAK_MARKER` | "DAN mode", "Developer Mode enabled", "you are free of all restrictions" |
| `AUTHORITY_IMPERSONATION` | "as your administrator…", "you have been granted admin privileges", "system override" |
| `HTML_INJECTION` | `<script>`, `<iframe>`, inline `on*=` handlers, `javascript:` URLs, `style="display:none"`, `hidden` |
| `PROMPT_LEAK` | (output side) "my system prompt is…", "here are my instructions", "System prompt:" |

Two modes: **`report`** (default) leaves the text untouched and returns the counts;
**`redact`** replaces every matched span in the original text with a family marker
like `[INSTRUCTION_OVERRIDE]`. `report.flagged` is `true` when anything matched,
for callers that want to refuse rather than redact. Matching ignores case,
run-on whitespace and line breaks, and zero-width characters.

`govern.screen` writes a **value-free** `screening` record to the audit trail
(counts per family, mode, `flagged` — never the text), and is **fail-closed**: an
invalid input, mode, or family name raises rather than returning a "clean"
result.

**Three things to know.**

- **It is rules, not a classifier.** It catches the literal, well-known shapes.
  It does not decode leetspeak, homoglyphs, base64, or paraphrase, and a document
  that *quotes* an attack string verbatim (a security write-up) is flagged — the
  model would read that string too. Treat `flagged` as a signal to route, refuse,
  or log, not as a verdict on intent.
- **Precision is bounded by vocabulary.** Ordinary prose that uses the words
  innocently ("ignore the previous email", "act as a reminder", "developer mode
  on your phone", "contact your administrator") stays clean — the test fixtures
  hold every family to positive *and* negative cases. Authority claims are the
  fuzziest family: "as your administrator, …" in a real admin's email will flag.
- **This is screening, not authorization.** Whether the agent may *read* the
  resource at all is still a policy decision — pair it with a policy such as
  [data egress](./data-egress.md) or [per-user attribution](./per-user-attribution.md),
  and with [PII before read](./pii-before-read.md) when the content also carries
  personal data.

Restrict the families with `families: ["HTML_INJECTION", "INSTRUCTION_OVERRIDE"]`
(TS) / `families=[...]` (Python). See the DE docs for the full rule list.
