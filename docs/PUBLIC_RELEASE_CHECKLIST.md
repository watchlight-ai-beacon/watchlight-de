<!-- INTERNAL — gating checklist for the public flip. Sanitize/remove before public. -->

# Public-release checklist (watchlight-de)

This repo may go public. **Flipping it public is a one-way door for git history**
— everything ever committed is visible forever. Nothing here is public until
every BLOCKING item below is checked. Expands decision **D5** in
[`DECISIONS.md`](DECISIONS.md).

Legend: ☐ = not done · ✅ = done · N/A = not applicable yet.

## A. Blocking — installability (a public `pip install` MUST work)

A public `watchlight-de` whose dependencies don't resolve from PyPI is a broken
quickstart — the worst first impression for a "5-minute DENY line" product.

- ✅ **`wl-apdp` light core on `main`** — merged in #1393; the wheel builds from it.
- ☐ **Reserve the PyPI names** `watchlight` and `watchlight-engine` (and on
  TestPyPI) **under the `watchlight-ai` PyPI org**, not a personal account, to
  prevent squatting + keep ownership with the company. Do this now, independent
  of everything else. PyPI package names are GLOBAL (no per-org namespacing), so
  reserving the exact strings matters. Cleanest path: add a **pending trusted
  publisher** for each name (scoped so the project is created under the
  `watchlight-ai` org on first publish) — that reserves the name AND wires OIDC
  in one step, no placeholder upload, no token.
  - ⚠️ Two different namespaces, don't conflate them: the **PyPI org** is
    `watchlight-ai`; the trusted-publisher config references the **GitHub** org
    `watchlight-ai-beacon` / repo `watchlight-beacon` / workflow
    `publish-watchlight-engine.yml` / environment `pypi` (or `testpypi`).
  - ✅ Pending trusted publisher registered on **pypi.org** (2026-08-17) — added
    from the **personal account's** Publishing settings, so:
  - ☐ **Transfer `watchlight-engine` to the `watchlight-ai` org after the FIRST
    publish** (Manage project → Settings → transfer to organization). The
    pending publisher was account-level, so the project is created account-owned;
    transfer keeps ownership with the company and avoids a personal-account
    single point of failure. (The trusted-publisher config travels with the
    project on transfer — no reconfig needed.)
- ☐ **Publish `watchlight-engine` to PyPI** — release + STRIPPED wheels via
  `.github/workflows/publish-watchlight-engine.yml` (monorepo). Prereqs are done:
  ✅ SHA-pinned actions (#1397), ✅ PyPI trusted publisher (account-level), ✅ the
  `pypi` GitHub Environment (restricted to `main`). Run `dry_run:true` to
  validate the wheels, then `dry_run:false` `repository:pypi` for the real
  `0.1.0` (immutable — one shot). Aldo is skipping TestPyPI.
  - ⚠️ **No required reviewer on the `pypi` environment.** GitHub returned a 422
    (*"billing plan supports the required reviewers protection rule"*) on this
    PRIVATE repo, even though the org shows as `team` — a GitHub plan/entitlement
    nuance to resolve in org billing if you want the approval-click gate. Standing
    in for it: the workflow is **manual-dispatch + `dry_run:true` default +
    `main`-only branch policy**, so a real publish is already a deliberate,
    two-decision action. Revisit adding a required reviewer once the plan allows.
- ☐ **Publish the Python SDK the DE depends on** — M0 (`watchlight`) is
  standalone; **M1** (`create_governed_deep_agent`) pulls the real
  `watchlight-agent-sdk`. Publish that before M1 ships publicly.
- ☐ **Pin the dependency ranges** in `pyproject.toml` to the published versions
  once they exist (currently `watchlight-engine>=0.1,<0.2`).

> **Not a blocker:** the TypeScript/npm publish (`@watchlight-ai/*`, milestone
> #32) is an INDEPENDENT track. The Python DE does not depend on it.

## B. Blocking — content & git HISTORY sanitization

Audit the **full history**, not just the working tree.

- ☐ **Sanitize `docs/original-notes.md`** — strip internal env-var names,
  internal repo/service structure, the specific customer vertical, and the
  "production incident" reference (keep the vision) **AND scrub the pre-public
  history** (e.g. `git filter-repo` / a fresh squashed root) so the unsanitized
  version isn't recoverable once public.
- ☐ **No secrets/tokens/`.env`/keys in history** — audit the whole `git log`
  (e.g. `gitleaks detect`), not just the tree.
- ☐ **No private monorepo/plugin source vendored** — the repo depends on the
  published `watchlight-engine` wheel + the SDK as external pip packages only.
  Confirm nothing under `src/`/`examples/` imports or copies wl-apdp source.
- ☐ **`.gitignore` covers** `.env*`, `*.pem/*.key`, `secrets/`, `.watchlight/`,
  `*.audit.jsonl`, `*.whl`, `.venv/` (already hardened — reconfirm).

## C. Blocking — legal & meta

- ☐ **Add `LICENSE`** — Apache-2.0 (D4), matching the SDK/plugins. Add `NOTICE`
  if required.
- ✅ **README is clean** — open-core positioning (Developer Edition vs
  Enterprise + CTA); no internal architecture.
- ☐ **Add `SECURITY.md`** (how to report a vuln) and a `CONTRIBUTING.md` /
  `CODE_OF_CONDUCT.md` for external contributors.
- ☐ **Remove/relocate this checklist and `docs/original-notes.md`** (or sanitize)
  from what ships publicly.

## D. Blocking — push identity & remote

- ☐ **Verify the push identity is the `watchlight-ai-beacon` org**, not a
  personal account — plain `git@github.com` resolves to the personal
  `spark-app-studio` identity here. Confirm the remote + the SSH host alias
  (`git remote -v`; use the org's `github-watchlight`-style host) before ANY push.
- ☐ **Decide private-first vs. public** — a push to the private org remote (for
  backup/CI/review) is fine now and is NOT the public flip; keep them separate.

## E. Final verification (on a clean machine, from PyPI)

- ☐ `pip install watchlight` (real PyPI) in a fresh venv resolves + imports.
- ☐ Run `examples/agent.py` → the `ALLOW` / `DENY` lines print with zero infra.
- ☐ `watchlight-engine` wheel contains only the compiled extension + metadata
  (no `.rs`), and is the release-stripped build (`nm` shows ~1 symbol, not ~47k).

---

## Ready-to-publish gate

Public flip is authorized only when **every ☐ in A–D is ✅** and section E passes.
Owner: Aldo. Do not flip on anyone else's say-so.
