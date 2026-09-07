# Documentation

The [repository README](../README.md) gets you to your first `DENY`. These pages
pick up from there.

| Page | Read it when |
|---|---|
| [Using the governor](using-the-governor.md) | You are placing the governor in a real app — a request handler, a worker, a test. |
| [How policy works](policies.md) | You are writing Cedar and want the request shape, default deny, and what the engine resolves. |
| [Role-based access control](rbac.md) | You are carrying a user's role, or several, into a decision. |
| [Attribute-based access control](abac.md) | You are deciding on runtime facts — an amount, a region, a verified session. |
| [Enforcement effects](enforcement-effects.md) | You want a policy to hold an action for a person, run a rule in monitor mode, or you are reading `@enforcement_effect`. |
| [The identity model](identity-model.md) | You need a decision to say *who it was for*: the subject, the acting runtime, the delegation chain. |
| [The TypeScript / Node lane](typescript.md) | You are governing a Node app: approvals, egress hooks, obligations, the framework adapters. |
| [Governing an agent you already have](integrations.md) | You want to govern an agent or an MCP server without changing its code. |
| [The audit trail](audit-trail.md) | You want to watch decisions land, ship them to your own store, or count them for a quota. |
| [Testing your policies](testing-policies.md) | You want to prove a policy behaves before it gates anything real, and fail a CI run when it does not. |
| [The signing secret](signing-secret.md) | You need a scope or an approval to cross a process boundary, or you are rotating the secret. |
| [Changelog](../CHANGELOG.md) | You want to know what a version added before deciding to upgrade. |
| [Breaking changes](breaking-changes.md) | You are bumping the version and need to know what flips a verdict. |
| [Extending Watchlight](extending.md) | You are plugging your own code in — a detector, a screening rule, an audit sink, a counter source. |
| [Glossary](glossary.md) | A word is doing more work than you expected and you want it pinned down. |

Runnable programs are in [`examples/`](../examples/README.md). The full
reference — every option, every record field, every error — is on
[docs.watchlight.ai/de](https://docs.watchlight.ai/de).

**Upgrading?** [The changelog](../CHANGELOG.md) says what each version added; [breaking changes](breaking-changes.md) says what to do about it. Read that one first. Only some of
them announce themselves with an error; the rest surface as a denial that looks
exactly like a policy of yours doing its job.

**Found a mistake?** A documentation error is a bug. Every example here is
written to be pasted and run, so open an issue or a pull request.
