<!-- INTERNAL — decision log. Review before public release. -->

# Watchlight Developer Edition — decision log

Lightweight ADRs. Two decisions are **load-bearing** — they shape everything
downstream and are worth settling before deep implementation. The rest are
tracked so nothing silently defaults.

---

## D1 — What the in-process engine binds (DECIDED: bind wl-apdp itself, via PyO3)

**Decided 2026-08-12 (corrected).** The DE embeds the **real wl-apdp
authorization core** as a Python extension — NOT a generic Cedar binding.

Why the correction: `cedarpy` binds only the Cedar *language* (leaf policy
evaluation). But wl-apdp is the whole **pipeline around** Cedar — delegation-chain
validation, intent, goal, intelligent policy selection, Cedar eval, **M43
strict-subset scope attenuation**, enforcement-effect taxonomy. Binding only Cedar
would force a Python reimplementation of that pipeline = divergence from prod (the
exact thing the vision forbids). Binding wl-apdp runs the *actual production
engine* in-process; Cedar comes along inside it. "Use Watchlight AI tech."

**Feasibility (verified against the monorepo):**
- `wl-apdp` already has a **`lib.rs`** exposing `pub mod authz / policy / models /
  error` → a PyO3 crate can depend on the lib directly (no extraction).
- `PolicyManager` is **fully in-memory** (`Arc<RwLock<HashMap<String,Policy>>>` +
  `Arc<RwLock<PolicySet>>`, populated via `add_policy`) — no DB coupling. Postgres
  is only *loaded into* it at startup.
- `AuthzService`'s sole DB tie is an **optional** `decisions_chain_pool:
  Option<PgPool>` (audit-chain writes), set separately → authz runs pool-less.

**Structure (consequence — spans two repos):**
- A **new PyO3 crate in the MONOREPO** (`wl-apdp-py`, maturin-built) wraps
  `AuthzService` + `PolicyManager`, loads policies from a local `.cedar`/JSON file
  instead of Postgres, exposes `authorize(...)` to Python → publishes a wheel
  (e.g. `watchlight-apdp`). Lives where the source lives (private, maintainable).
- `watchlight-de` depends on that **published wheel** (external) — never vendors
  wl-apdp source (consistent with the maybe-public rule + D2).

**Open implementation details (not feasibility blockers):** `AuthzService`
authorize is async (Tokio) → bridge via an internal `block_on` or `pyo3-asyncio`;
the exact authorize entrypoint to expose; policy-file load format; maturin
per-platform wheel build. `cedarpy` is discarded (one layer too low).

<details><summary>Original options — note A was refined from "Cedar binding" to "wl-apdp binding"</summary>


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
