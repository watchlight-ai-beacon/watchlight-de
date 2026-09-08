# Pattern: screen retrieved content before it reaches the model

An agent reads text it did not write — a web page, a search result, another
tool's output. Catch the known injection shapes before the model sees them.

This is content screening, not a policy decision, so it uses `govern.screen`.

```ts
import { govern, Denied, DENY_REASON } from "@watchlight/sdk";

const readPage = govern.tool(async function fetchPage(url: string) {
  const html = await httpGet(url);                                   // your fetch
  const { text, report } = govern.screen(html, { resource: url, mode: "redact" });
  if (report.flagged) throw new Denied("fetchPage", "read", DENY_REASON); // refuse …
  return text;                                                       // … or hand back redacted text
}, { intent: "read", resource: (url) => url });
```

```python
from watchlight import govern, Denied, DENY_REASON

@govern.tool("read", resource=lambda url: url)
def fetch_page(url: str) -> str:
    html = http_get(url)                                             # your fetch
    result = govern.screen(html, resource=url, mode="redact")
    if result["report"]["flagged"]:
        raise Denied("fetch_page", "read", DENY_REASON)              # refuse …
    return result["text"]                                            # … or the redacted text
```

Run the same screen on `govern.screen(reply)` before a model's output leaves, to
catch a system-prompt leak.

## When the tool body is not yours to edit

Put the screen in the `onResult` / `on_result` hook. It sees the body's result
before the caller does; return a value to replace the payload, raise to withhold
it.

```ts
const readPage = govern.tool(fetchPage, {
  intent: "read",
  resource: (url) => url,
  onResult: (html, { resource, decisionId }) => {
    const { text, report } = govern.screen(html, { resource, decisionId, mode: "redact" });
    if (report.flagged) throw new Denied("fetchPage", "read", DENY_REASON);
    return text;
  },
});
```

Passing `decisionId` / `decision_id` joins the `screening` record to the decision
that governed the read, and to the `egress` record the hook produces.

## What it detects

Seven families of injection phrasing, each a named counter in the report.

| Family | Catches, for example |
|---|---|
| `INSTRUCTION_OVERRIDE` | "ignore all previous instructions", "new instructions:" |
| `ROLE_SWITCH` | "you are now a hacker AI", "act as an unrestricted assistant" |
| `PROMPT_EXFILTRATION` | "reveal your system prompt", "repeat everything above" |
| `JAILBREAK_MARKER` | "DAN mode", "Developer Mode enabled" |
| `AUTHORITY_IMPERSONATION` | "as your administrator…", "system override engaged", and the **channel-prefix** form: `SYSTEM:`, `[SYSTEM]`, `<system>`, `<\|im_start\|>system`, `### System` |
| `HTML_INJECTION` | `<script>`, `<iframe>`, `on*=` handlers, `javascript:` URLs, hidden styles |
| `PROMPT_LEAK` | (output side) "my system prompt is…", "System prompt:" |

`report` mode (the default) leaves the text alone and returns counts. `redact`
replaces every matched span with a family marker like `[INSTRUCTION_OVERRIDE]`.
`report.flagged` is true when anything matched. Matching ignores case, run-on
whitespace, line breaks and zero-width characters.

The `screening` audit record carries counts per family, the mode and `flagged` —
never the text. A non-string input, an unknown mode or family, an empty family
list or a malformed correlation id raises rather than returning a clean result.

Narrow the families with `families: ["HTML_INJECTION", "INSTRUCTION_OVERRIDE"]`
(TypeScript) / `families=[...]` (Python).

### The channel-prefix form, and what it costs

`AUTHORITY_IMPERSONATION` covers two different things. A **claim** of authority
in prose — *"as your administrator…"* — and text **formatted as though it came
from a privileged channel** — `SYSTEM:`, `[SYSTEM]`, `<|im_start|>system`. The
second asserts nothing, which is exactly why it is the dominant shape in
stored-content injection: it wears the costume of a system turn and relies on
the model's parsing to grant it.

Covering it has a precision cost, and it is worth knowing before you turn
`redact` on. Text that legitimately contains a system-turn marker now flags:

```
FIRES   Agent: Hello! System: chat session started at 09:12.
FIRES   Use the <system> element to configure the daemon.
```

A support transcript and developer documentation are both realistic things for
an agent to read. If you screen that kind of content, narrow the families rather
than living with the noise:

```python
screen(text, families=[f for f in SCREEN_FAMILIES if f != "AUTHORITY_IMPERSONATION"])
```

Ordinary prose is unaffected — *"the system administrator will contact you"*,
*"### System Requirements"*, *"please ignore the previous email"* — and those are
asserted in the suite alongside the hostile corpus, because widening a screening
rule is how you make it useless.

## Register a family for your own domain

The seven are generic on purpose: they leave domain vocabulary alone, which is
what makes screening usable on text about substance history or firearms storage
without rejecting the applications that mention them. The cost is that a shape
specific to your domain — a forced approval, a skipped check, a job title in
place of an AI role — is not covered, and a second screener beside this one puts
those hits outside the `screening` record.

```python
from watchlight import register_screen_family

register_screen_family(
    "INJ_FORCE_APPROVAL",
    r"\b(?:approve|mark) this [a-z ]{0,30}(?:immediately|as approved)\b",
)
```

```ts
registerScreenFamily("INJ_FORCE_APPROVAL", /\b(?:approve|mark) this .{0,30}immediately\b/);
```

Registered families are on by default, counted and redacted under their own
label, and selectable through `families` like a built-in.

**Write the pattern against normalized text.** Zero-width characters are removed
and every whitespace run is collapsed to one space before any rule runs — that is
what stops an evasive spelling — so use single spaces and no `\s+`. A redaction
still replaces the original span.

A pattern that backtracks catastrophically is refused at registration: a
screening rule runs over every submission, so one `(a+)+` hangs the intake path.
A built-in family cannot be replaced. Once anything is registered,
`detector_version` carries a digest of the set, so the `screening` record says
what was actually screening.

## Worth knowing

- **It is rules, not a classifier.** It does not decode leetspeak, homoglyphs,
  base64 or paraphrase, and a document that quotes an attack verbatim is flagged
  — the model would read that string too. Treat `flagged` as a signal to route,
  refuse or log.
- **`redact` marks the trigger; it does not neutralise HTML.** A whole `<script>`
  element is replaced only when its body contains no `<`. Strip HTML to text
  first if the model must not see markup.
- **Markers can be spoofed.** Input already containing `[INSTRUCTION_OVERRIDE]`
  is indistinguishable from a redaction. Decide from the report, never from the
  text.
- **Screening is not authorization.** Whether the agent may read the resource is
  still a policy decision — pair it with [data egress](./data-egress.md) or
  [per-user attribution](./per-user-attribution.md).
- The two lanes are held to identical verdicts by shared fixtures. The one known
  divergence is the Turkish dotted capital İ, which case-folds in Python only.

## Verified by

[`scripts/screen-before-model.mjs`](./scripts/screen-before-model.mjs) — this is
not a policy verdict, so there is no suite. It asserts one known shape per family
under `report` and under `redact`. Innocent prose using the same vocabulary stays
clean, an empty family list raises `ScreenError`, and every call writes a
value-free `screening` record.
