<!--
INTERNAL DESIGN NOTE — not for public release as-is.
Before this repository is made public, SANITIZE this file: it names internal
environment variables, internal repository structure, a specific customer
vertical (home studies), and references an internal "production incident."
Keep the vision; strip the internals. See docs/DECISIONS.md → "Public-flip checklist".
-->

# Watchlight AI Developer Edition — original design notes (author)

> Preserved verbatim as the source-of-truth vision. Synthesis, build plan, and
> open decisions live in `docs/DESIGN.md` and `docs/DECISIONS.md`.

**Author's note.** This is written from having just integrated Watchlight into a
greenfield service end to end: the deepagents plugin into a LangChain
`deepagents` app, Cedar policies, sub-agent attenuation, guardrails, and a
Railway deployment of the platform subset. Everything below is a friction point
actually hit, in the order hit — not a hypothetical critique.

The headline: **the plugin is excellent, and almost nothing that cost time was
the plugin.** `create_governed_deep_agent` is a genuinely great API — one import
swap, one required argument, zero tool-code changes. A governed agent was written
in about fifteen minutes. Getting something it could *talk to* took the rest of
the day. That gap is the entire product problem, and it is fixable without
weakening a single guarantee.

## 1. What "developer edition" has to optimize

One number: **time from `git clone` to a first authorized tool call that a
developer can see in a log.** Today that path is ~13 steps of ceremony (private
repo access, building wheels, GHCR PAT, Postgres, shared-DB knowledge, canonical
URL resolver chain, bootstrap flag, async schema bootstrap, Cedar policies, a
registration seeder, the right admin key) *then* a tool call. A developer quits
around step 6. The target: steps 1–13 collapse into `pip install watchlight` and
one decorator or one factory call.

## 2. Recommendation: one dependency, zero infrastructure, same API

`pip install watchlight` → the same `create_governed_deep_agent` factory, with an
**embedded in-process policy engine** as the default backend when no policy-service
URL is configured. It runs, it governs, it logs decisions. The critical
constraint: **this is the same code that runs in production.** Going to production
is setting the policy-service URL — not rewriting anything.

### Component set (Developer Edition)

| Component | Developer Edition | Replaces | Why in the minimum set |
|---|---|---|---|
| Policy engine | in-process Cedar, policies from a local `.cedar` file | the policy service + DB | The gate. Without it nothing is governed. |
| Agent registry | derived from `agent_slug` + `subagent_scopes` in code | the registry service + shared DB | The facts are already in the source. |
| Scope attenuation | engine-side strict-subset validation | the server-side validator | Load-bearing security property; must stay engine-side. |
| Content + PII screening | in-process evaluation of the same YAML policy format | the guardrails service | Same policy files work against the real service later. |
| Audit | JSONL to `.watchlight/audit.jsonl` | the audit service | Local, greppable, value-free. Same event shape as production. |
| Dashboard | `watchlight dev` → `localhost:7000` (policies + execution lineage) | the operator console | Makes governance visible rather than theoretical. |

Deliberately **not** included: the egress proxy (needs a real network path),
secrets broker + KMS (env vars are correct at this scale), the lineage graph +
broker (nobody reads it yet), drift detection (needs production traffic). The
test for inclusion: *does a developer need this to see a DENY line in their own
terminal in five minutes?*

## 3. Progressive disclosure

Four levels, each one env var from the next, **nothing rewritten between levels**:
Level 0 `pip install watchlight` (in-process, in-memory, audit to stdout) →
Level 1 `watchlight dev` (local dashboard) →
Level 2 `docker compose up` (real policy service + DB, policies still local) →
Level 3 Production (registry, guardrails, proxy, secrets, audit).

## 4. Specific friction (each small; together most of a day)

1. **One tool means editing four files** — the `@tool` fn, the scopes, a Cedar
   `permit`, and the registration seeder's `allowed_tools`. Miss one → fail
   closed, identical symptom for all four causes. Fix: derive policy + scope +
   registration from one `@governed_tool` declaration; `watchlight policy export`
   dumps a real `.cedar` file so production stays reviewable.
2. **Tool-name prefix silently picks the Cedar action verb** (`read`/`get`/`list`
   → read, `write`/`edit`/`create` → write, else execute). Renaming a tool
   silently breaks a permit. Fix: startup reconciliation logging `tool → verb →
   resource` and **warning loudly when a tool has no matching policy**.
3. **Two constructors, one of which quietly cannot work** — the root-only
   `plugin.middleware()` refuses every sub-agent spawn (correct, fail-closed) but
   is presented as a peer to the factory. Fix: make the factory the only
   documented path; raise at construction when `subagents=` is non-empty.
4. **The default guardrails policy is domain-hostile** — the shipped default
   blocks ordinary vocabulary for sensitive workloads. Fix: rename to
   `chat-safety.yaml`, ship a minimal `default.yaml` (injection + PII only), add
   a workload header to each policy.
5. **Guardrails policy changes require an image rebuild.** Fix: reload endpoint,
   watched directory, or DB-backed policy storage.
6. **Schema bootstrap is async and unannounced** — a container reports deployed
   before migrations finish. Fix: `/ready` false until migrations complete,
   distinct from `/health`.
7. **The shared-database requirement fails silently** — separate DBs both start
   and migrate cleanly while registry writes stay invisible to authz. Fix: assert
   at bootstrap that shared schemas are on the same cluster; fail loudly.

## 5. What must NOT change (guarantees, not ceremony)

- **Fail-closed everywhere** — unscoped sub-agent → zero privileges; unreachable
  engine → refuse. Keep in dev.
- **Engine-side scope attenuation** — the engine, never the client, validates
  strict subset. A dev mode where the client can widen its own scope teaches the
  wrong model.
- **Explicit scopes** — never infer scopes from tools/free text. That
  `subagent_scopes` is mandatory is a real security property.
- **Value-free audit** — tool argument *values* never enter the audit trail, in
  any mode.

The dev edition removes **ceremony**, not **constraints**.

## 6. Suggested sequencing (developer-hours saved per engineering-hour)

1. Publish SDK + plugins to PyPI (~1d) — the hardest blocker; nothing works until
   `pip install` does.
2. Public images / credential-free compose (~1d) — the second wall.
3. In-process engine when no policy URL (~1–2w) — *this is the developer edition.*
4. Startup tool↔policy reconciliation warning (~2d).
5. Derive policy + registration from `@governed_tool` (~1w).
6. `watchlight dev` local dashboard (~1w).
7. Rename `default.yaml`, workload headers (~1h).
8. Shared-DB assertion at bootstrap (~2d).
9. `/ready` gated on migrations (~1d).

## 7. The pitch this unlocks

Explaining Watchlight stops requiring an architecture diagram and fits in a
code-block diff (`create_deep_agent` → `create_governed_deep_agent`) plus a
terminal showing `ALLOW` / `DENY` lines. A developer who sees that `DENY` line in
their own terminal, in under five minutes, with no signup, understands the
product. The hard part — the plugin, the attenuation model, the fail-closed
semantics — is already built and good. What is missing is the on-ramp.
