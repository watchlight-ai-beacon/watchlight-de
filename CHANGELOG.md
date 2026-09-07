# Changelog

Every released version of `watchlight` and `@watchlight/sdk`, newest first. The
two are versioned in lockstep even when only one lane changed, so a version pair
is unambiguous.

This file says **what changed**. [`docs/breaking-changes.md`](docs/breaking-changes.md)
says **what to do about it** — the migration for each change and which direction
it fails in. Read that one before upgrading; read this one to see whether an
upgrade is worth your afternoon.

Each entry links to its release, which carries the reasoning and the measurements.

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
