# TypeScript plugins

This directory is an npm workspace. Each subdirectory with a `package.json` is
one package in it, and the workspace root's `package.json` runs the same script
in every package. The packages are listed in [`../README.md`](../README.md).

## What a package directory contains

A package's `package.json` defines the scripts the workspace runs:

- `build`, which compiles the package.
- `typecheck`, which checks the types without writing output.
- `test`, which runs the package's tests.

A package that leaves one of these out is skipped for that step, so define all
three. The package's `files` field lists exactly what it publishes, and each
package carries its own `README.md` and `CHANGELOG.md`.

## Working on the packages

```bash
cd integrations/plugins/ts
npm ci             # installs every package and links them to each other
npm run build
npm run typecheck
npm test
```

The workspace's `package-lock.json` is committed, so CI installs exactly the
versions it pins. Update it with `npm install` in this directory when you change
a package's dependencies, and commit it with the change.

This workspace is separate from `ts/` at the top of the repository, which holds
`@watchlight/sdk` and keeps its own lockfile.
