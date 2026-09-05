# Documentation

Four pages, in the order they are worth reading. The [repository
README](../README.md) is still the place to start if you have not governed a
tool yet; these pick up after that.

| Page | Read it when |
|---|---|
| [Using the governor](using-the-governor.md) | You have seen a `DENY` and now need to place the governor in a real application: where it is constructed, how many you need, and what a request handler, a worker and a test each look like. |
| [The identity model](identity-model.md) | You need a decision to say *who it was for*, not just that it happened. The subject, the acting runtime, the delegation chain, and what a policy can name. |
| [The signing secret](signing-secret.md) | You are moving a scope or an approval between processes, or rotating the secret that signs them. |
| [Glossary](glossary.md) | Any time a word is doing more work than you expected. Also worth a look before you invent a name of your own. |

The reference — every option, every record field, every error — is on the
[documentation site](https://docs.watchlight.ai/de), which also carries the
quickstart and the framework guides. These four pages are the ones worth having
beside the source, so they live here too and are kept identical.

## If you are upgrading

The breaking changes for each release are in [the identity
model](identity-model.md#breaking-in-080), which is where the migration notes
live even for the ones that are not strictly about identity. Read that section
before you bump the version, not after. Only one of the three announces itself
with an error that names the problem; the other two surface as a denial, which
is indistinguishable from a policy of yours doing its job.

## If something here is wrong

A documentation error is a bug. Open an issue with the page and the line, or a
pull request. The examples in these pages are written to be pasted and run, so
if one does not do what it says, that is a defect worth reporting rather than
working around.
