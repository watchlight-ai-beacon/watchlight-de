# Changelog

Every released version of `watchlight` and `@watchlight/sdk`, newest first. The
two are versioned in lockstep even when only one lane changed, so a version pair
is unambiguous.

This file says **what changed**. [`docs/breaking-changes.md`](docs/breaking-changes.md)
says **what to do about it** — the migration for each change and which direction
it fails in. Read that one before upgrading; read this one to see whether an
upgrade is worth your afternoon.

Each entry links to its release, which carries the reasoning and the measurements.

## Unreleased

**Added**
- Docs: [using Watchlight with an MCP gateway you already run](docs/existing-mcp-gateway.md).

**Fixed**
- Docs and examples: the decision filter in the
  [quota](examples/patterns/quotas.md) and
  [audit-sink](examples/patterns/audit-sink.md) patterns, and the jq recipes in
  [audit forensics](examples/showcase/audit-forensics/recipes.md), matched
  decisions by a missing `event` field. Since 0.13.0 a decision record carries
  `"event": "decision"`, so a quota built from that filter counted zero
  decisions and never tripped. The filter is now
  `coalesce(record->>'event', 'decision') = 'decision'` (jq:
  `(.event // "decision") == "decision"`), which counts decisions written by
  any release and still excludes every other record kind. If you copied the
  old filter, update it. See [breaking changes](docs/breaking-changes.md).
- Docs: [using the governor](docs/using-the-governor.md) said a `load` of a
  missing file raises nothing; since 0.13.0 it raises `FileNotFoundError`
  (TypeScript: an `Error` with `code: "ENOENT"`).

**Changed**
- The `mcp` and `all` extras now require `watchlight-mcp` 0.4.4 or later.
  Version 0.4.4 makes the PEP stricter in these ways:
  - A governed MCP call that has no `Watchlight-Agent-Id` header is now
    refused (HTTP status 400, JSON-RPC error code `-32002`) instead of being
    decided as an unattributed principal.
  - The principal comes from that one header only. A request that carries
    `Watchlight-Principal-Id` is refused.
  - A request of any method is refused when one of the `Watchlight-*` headers
    the PEP reads is repeated or malformed.
  - Headers that only look like Watchlight's, such as `X-Watchlight-Agent-Id`,
    are stripped before the request is forwarded.
  - The PEP's process log no longer contains tool argument values, and a
    resource URI recorded in the audit `tool` field has its path hashed.

  See [breaking changes](docs/breaking-changes.md).

## 0.13.0 — 2026-10-02

Policy loading fails closed: a file that would load nothing, or a policy that
does not compile, now stops the load or refuses decisions instead of being
skipped. Framework integrations no longer accept a backend from the call site,
audit records name decisions and sub-agent scopes, and a scope can be previewed
without recording a grant. Four of these change what a call returns; read
[breaking changes](docs/breaking-changes.md) before upgrading.

**Added**
- `govern.preview_scope()` / `govern.previewScope()` and
  `Scope.preview_attenuate()` / `Scope.previewAttenuate()` return a
  `ScopePreview`: what a scope would be granted, decided by the same engine
  check, with nothing recorded. A preview cannot authorize, delegate or mint a
  token.
- An attenuation record for a named sub-agent (`attenuate(agent=…)`,
  `delegate()`) carries that sub-agent's `actor_chain`, and its `resource` reads
  `scope for <name>` — on grants and refusals alike.
- `sanitize(person_exclusions=…)` / `sanitize({ personExclusions })`: exact,
  case-insensitive values the optional `PERSON` heuristic leaves untouched, for
  the Title Case organization names it would otherwise redact. It suppresses
  only a complete `PERSON` candidate; every other enabled detector still runs,
  and the values never reach the report or the audit trail.

**Fixed**
- Hardening: a policy that fails to compile now fails the load, or denies,
  instead of being skipped. In TypeScript, a Cedar error in one queued policy
  used to drop the rest of its batch, and later decisions ran without them, so
  a skipped `forbid` no longer applied. Now every decision throws
  `PolicyCompileError`, naming the policy and its file, until `reload()`
  replaces the set; `await govern.ready()` compiles the queued policies and
  surfaces the error at start-up. In Python, `load()` compiles the whole file
  into a scratch engine first, so a Cedar error raises `PolicyCompileError` and
  adds nothing from the file, where it used to leave the policies before it
  loaded. `watchlight policy test` exits 2 on it in both lanes. See
  [breaking changes](docs/breaking-changes.md).

**Changed**
- Loading a policy file never loads nothing quietly. `govern.load()`,
  `govern.reload()` and `watchlight policy test` (both lanes) raise or throw,
  naming the file, on a missing path, a directory, a path that cannot be read
  (reported as itself, never as missing), invalid UTF-8 or JSON, an
  unrecognised shape, an entry without a Cedar `code`, a policy marked
  `"active": false`, or a file that holds no policies. No message quotes the
  file's contents; a JSON error gives the line and column. A governor that loaded such a file used to hold
  no policies and deny every call with no sign of why. An empty set loads only
  with `allow_empty=True` / `{ allowEmpty: true }`; `reload` refuses it always.
  `watchlight policy test` exits 2 on a suite that declares no policies. See
  [breaking changes](docs/breaking-changes.md).
- A policy file may hold a single `{"name", "code"}` object, which loads as one
  policy. That is the shape `watchlight-mcp` reads, so one file serves both;
  `examples/mcp.policy.json` used to load zero policies through `govern.load()`
  and now loads its one.
- Decision records carry `"event": "decision"`. See
  [breaking changes](docs/breaking-changes.md).
- Hardening: `governed_plugin` in `watchlight.langgraph`,
  `watchlight.pydantic_ai` and `watchlight.claude_agent` refuses `governance=`
  and `apdp_url=`. The backend is chosen by `WATCHLIGHT_APDP_URL` (networked) or
  its absence (in-process), and a keyword can no longer replace that choice. The
  "install the extra" `ImportError` now covers only a missing plugin package or
  class; any other error raised while the plugin imports surfaces as itself.
  See [breaking changes](docs/breaking-changes.md).
- Framework integrations are built on one internal contract
  (`watchlight.integrations`, for contributors; not a public API): LangGraph,
  Pydantic AI and the Claude Agent SDK. `watchlight.langgraph`,
  `watchlight.pydantic_ai` and `watchlight.claude_agent` keep every name they
  exposed.

Engine unchanged at `0.2`. [Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.13.0)

## 0.12.0 — 2026-09-12

Delegation depth becomes a governance control, and the engine licence no longer
limits governed agents. One of these changes what a call returns.

**Changed**

- Sub-agent delegation depth is a governance control, not an edition limit.
  `max_delegation_depth` (Python) / `maxDelegationDepth` (TypeScript) on the
  governor sets it, default 8; `scope(max_depth=…)` lowers it for one tree. A hop
  past it is a deny — `DelegationDepthExceeded`, reason code
  `DELEGATION_DEPTH_EXCEEDED` — recorded with the observed depth and the limit.
  Strict-subset attenuation still applies at every hop.
- Scope tokens carry up to 64 levels, held to the receiving governor's limit.
  `MAX_ACTOR_CHAIN` is 65.
- `PROMPT_EXFILTRATION` flags the paraphrase form — requests to summarise or
  explain the model's own instructions, not only to repeat them.
- The engine licence no longer limits governed agents: `watchlight-engine` and
  `watchlight-mcp` are free to use, including in production and commercially. A
  commercial license is needed only to re-offer the engine itself as a hosted
  authorization service.

**Removed**

- `DevEditionCeiling` and `DE_MAX_DEPTH`, and the depth-5 cap they enforced.

Engine `0.2.1` (licence only). [Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.12.0)

## 0.11.0 — 2026-09-08

Detector and screening coverage, from a partner harness run against a real
workload. Three of these change what a call returns.

**Added**

- `PERSISTENCE` and `CONDITIONAL_TRIGGER` screening families — an instruction
  meant to outlive its turn, and one that lies dormant until a matching question
  arrives. `SCREEN_FAMILIES` is now nine.

**Changed**

- `PHONE` detects unseparated E.164 (`+15550142889`) and grouped international
  numbers. The same number was caught with separators and missed without, in
  every country.
- `AUTHORITY_IMPERSONATION` flags the channel-prefix form — `SYSTEM:`,
  `[SYSTEM]`, `<system>`, `<|im_start|>system`, `### System`. It modelled a
  claim of authority and not text wearing the costume of a privileged turn.
- `INSTRUCTION_OVERRIDE` matches an imperative shape rather than a phrase list,
  so "Forget the above" flags as "Disregard all prior instructions" did.

Engine unchanged at `0.2`. [Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.11.0)

## 0.10.0 — 2026-09-07

Five capabilities that did not exist, and four changes to what a call returns.

**Added**

- `register_detector` — teach `sanitize` an identifier of your own. A pattern
  that backtracks catastrophically is refused at registration.
- `register_screen_family` — the same for injection screening, for shapes the
  seven generic families deliberately leave alone.
- `reload` — replace the policy set on a running process. `load` and `allow`
  only ever add, so nothing could remove authority without a restart.
- `audit_sink_batch` / `audit_sink_interval` — hand the sink a list from a
  background worker rather than one record on the request path.
- `on_result_timeout_ms` on synchronous tool bodies, which is the shape most
  framework tools have.

**Changed**

- `sanitize` redacts every SSN shape, including the ranges that cannot be issued.
- A `known` value matches as a whole word rather than a substring.
- A policy fixture carrying an unknown key raises; fixtures can name an `actor`.
- `WATCHLIGHT_AUDIT_FILE` / `WATCHLIGHT_AUDIT_DIR` reach a governor you construct.

Engine unchanged at `0.2`. [Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.10.0)

## 0.9.1 — 2026-09-06

**Changed** — the egress hook has a deadline on every path. `govern.tool()` and
the LangChain adapters had none, so a slow `onResult` could release a payload
late; all three paths now share one deadline and withhold on expiry.
[Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.9.1)

## 0.9.0 — 2026-09-05

**Changed** — four tightenings, three of them found by an adversarial harness
that tries to break the engine rather than demonstrate it: an unrecognised
`@enforcement_effect` fails at load rather than being dropped, an empty
principal raises rather than becoming the agent, and an unnamed governor no
longer invents a matchable identity.
[Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.9.0)

## 0.8.2 — 2026-09-05

**Added** — the framework-plugin path can name an acting subject per call, and
its Cedar entity types discriminate. Requires `watchlight-agent-sdk` 0.7.0.
[Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.8.2)

## 0.8.1 — 2026-09-05

**Added** — the framework adapters take the same terms as `tool()`: `principal`,
`agent`, `resource`, `context` and the approval hook, each a value or a function
of the call arguments. Asynchronous context bindings. No breaking changes.
[Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.8.1)

## 0.8.0 — 2026-09-05

**Added** — per-call agent naming with `as()`, a configurable default governor,
an application-supplied approval store and counter source, `auditFile: false`,
and a typed `AuditRecord`.
[Release](https://github.com/watchlight-ai-beacon/watchlight-de/releases/tag/v0.8.0)

---

Versions before 0.8.0 predate this file. Their releases are on the
[releases page](https://github.com/watchlight-ai-beacon/watchlight-de/releases).
