<!-- INTERNAL — decision log. Review before public release. -->

# Watchlight Developer Edition — decision log

Lightweight ADRs. Two decisions are **load-bearing** — they shape everything
downstream and are worth settling before deep implementation. The rest are
tracked so nothing silently defaults.

---

## D1 — How the in-process Cedar engine runs (DECIDED: A — Cedar Python binding)

**Decided 2026-08-12: Option A, validated by spike.** Using `cedarpy` (a PyO3
binding to the real `cedar-policy` crate, currently 4.8.7 — same Cedar 4.x major
as the platform's 4.5.1). Spike confirmed in-process, zero-infra evaluation:
`is_authorized(request, policies, entities)` → `Decision.Allow` with determining-
policy diagnostics on a matching permit, and **`Decision.Deny` by default** on no
match (fail-closed, exactly our semantic). This is the real Cedar engine, not a
reimplementation. Remaining diligence: pin/track the binding version; confirm it
covers the policy features we use (templates, `when`/`unless`, entity attrs).

<details><summary>Original options (for the record)</summary>


The Developer Edition's promise is `pip install watchlight` with **zero
infrastructure**. The authorization *pipeline* (delegation chain → intent → goal
→ policy selection → Cedar evaluation → scope attenuation) runs in Python; the
open question is how **Cedar policy evaluation** happens.

| Option | How | Pro | Con |
|---|---|---|---|
| **A. Cedar Python binding** | evaluate against the real `cedar-policy` crate via a Python binding (PyO3 wheel) | true `pip install`, no server, no binary shipping; developers learn real Cedar | binding is a dependency to trust/track; not literally the prod service |
| **B. Bundled service binary** | ship the real policy-service binary, run it on localhost with SQLite/in-memory | literally the same engine as prod | platform-specific binaries in the wheel; heavier; that binary is internal source |
| **C. Pure-Python reimpl** | reimplement Cedar eval in Python | no external dep | **rejected** — divergence from prod is exactly what the vision forbids |

**Recommendation: A.** Cedar-the-language is the contract a developer actually
learns; a maintained Python binding delivers the zero-infra install while the
evaluation is still the real Cedar engine. Option B *is* the Level-2
`docker compose` path (the real service). Needs a spike to confirm the binding's
feature parity + maintenance story.
</details>

## D2 — Relationship to the production plugin / "same code as prod" (DECIDED: A — depend on the real SDK, staged)

**Decided 2026-08-12: Option A.** `watchlight` depends on the real
`watchlight-agent-sdk` / plugins as an EXTERNAL package and adds only an
in-process backend they target — no API drift. Until the SDK is on PyPI, dev
against it as a **local editable** install pointing at the monorepo checkout (a
developer-machine convenience, NOT committed; this maybe-public repo never
vendors private source). DE thereby becomes the forcing function to publish the
SDK to PyPI.

<details><summary>Original options (for the record)</summary>


The hard constraint (vision §2): dev and prod expose the **same** API
(`create_governed_deep_agent`), so migrating is one env var, never a rewrite.

| Option | How | Pro | Con |
|---|---|---|---|
| **A. Depend on the published SDK** | `watchlight` pulls the real SDK + plugins (from PyPI) and provides an in-process backend the SDK targets | no API divergence; DE forces the PyPI-publish win | SDK/plugins aren't on PyPI yet (that's the #1 sequencing item) |
| **B. Self-contained reimpl in DE** | reimplement the plugin surface in this repo | starts today, no PyPI dependency | risks API drift from the real plugin — the exact failure the vision warns of |

**Recommendation: A, staged.** Build DE against the real SDK as an *external
package* dependency. Until it's on PyPI, dev against it as a **local editable**
install pointing at the monorepo checkout — a developer-machine convenience, NOT
committed. **This public repo must never vendor private plugin source.** DE
becomes the forcing function that also lands the PyPI publish.

---

</details>

## D3 — Package + repo naming (LEANING)

- Distribution: `watchlight` on PyPI (per the vision). Import: `watchlight`.
- This repo: `watchlight-de` (private now; may go public).

## D4 — License (OPEN)

If/when public, likely **Apache-2.0** to match the SDK. No license committed
until the public flip is decided. → tracked, not defaulted.

## D5 — Public-flip checklist (BLOCKING before any public push)

This repo may become public. Before flipping:

- [ ] **Sanitize `docs/original-notes.md`** — strip internal env-var names,
      internal repo/service structure, the specific customer vertical, and the
      "production incident" reference. Keep the vision.
- [ ] **No private source vendored** — confirm no plugin/service source from the
      monorepo is committed here (external pip dependency only).
- [ ] **No secrets, tokens, or `.env`** in history (not just the tree) — audit
      the full git log, not the working tree.
- [ ] **Add a LICENSE** (D4) and any required NOTICE.
- [ ] **README is clean** — no internal architecture detail (already the case).
- [ ] **Confirm the push identity** has org rights and is the intended author
      (plain `git@github.com` resolves to a personal account here — verify).

---

## Working rule (until public)

Treat the repo as **private and possibly-soon-public**: no secrets ever, no
private source, and every commit written as if a stranger will read it. Push
only after an explicit clean-diff review.
