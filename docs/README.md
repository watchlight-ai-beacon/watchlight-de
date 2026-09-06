# Documentation

The [repository README](../README.md) gets you to your first `DENY`. These pages
pick up from there.

| Page | Read it when |
|---|---|
| [Using the governor](using-the-governor.md) | You are placing the governor in a real app — a request handler, a worker, a test. |
| [The identity model](identity-model.md) | A decision has to say *who it was for*: the subject, the acting runtime, the delegation chain. |
| [The TypeScript / Node lane](typescript.md) | You are governing a Node app: approvals, egress hooks, obligations, the framework adapters. |
| [Governing an agent you already have](integrations.md) | The agent or the MCP server is not yours to rewrite. |
| [The audit trail](audit-trail.md) | You want to watch decisions land, ship them to your own store, or count them for a quota. |
| [Testing your policies](testing-policies.md) | Before a policy gates anything real. Golden fixtures, and the CLI that fails a CI run. |
| [The signing secret](signing-secret.md) | A scope or an approval has to cross a process boundary — or the secret needs rotating. |
| [Breaking changes](breaking-changes.md) | You are bumping the version. Every entry that flips a verdict, newest first. |
| [Glossary](glossary.md) | A word is doing more work than you expected. |

Runnable programs are in [`examples/`](../examples/README.md). The full
reference — every option, every record field, every error — is on
[docs.watchlight.ai/de](https://docs.watchlight.ai/de).

**Upgrading?** Read [breaking changes](breaking-changes.md) first. Only some of
them announce themselves with an error; the rest surface as a denial that looks
exactly like a policy of yours doing its job.

**Found a mistake?** A documentation error is a bug. Every example here is
written to be pasted and run, so open an issue or a pull request.
