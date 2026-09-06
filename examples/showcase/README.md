# Showcases

Runnable programs, not snippets. Each one governs a real agent path end to end
and prints what the engine decided.

Every showcase runs in **Python and Node** and asserts its own outcome, so what
a showcase claims and what the engine does can't drift.

## The showcases

| Showcase | What it proves |
|---|---|
| [Denied before it executed](./denied-before-execute/) | The tool body never runs. The side effect never happens. |
| [Human in the loop](./human-in-the-loop/) | `NeedsApproval`, a person approves, the call resumes — across two processes. |
| [The identity model](./identity/) | Three identities through one engine and one policy set. |
| [Audit forensics](./audit-forensics/) | Read the trail. Every decision joined to the record it produced, values never in it. |
| [Poisoned RAG](./poisoned-rag/) | A retrieved document hides an injection. It gets screened and redacted before the model sees it. |
| [Red team](./red-team/) | An adversarial corpus against a governed agent. Nothing gets through. |
| [Governed web backend](./web-backend/) | The authenticated user becomes the principal of the tool call. |
| [Policy tests as a CI gate](./policy-tests-ci/) | Policies get golden fixtures and go red on a pull request. A workflow, not a program. |

## Run one

```bash
pip install watchlight          # Python lane
npm i -g @watchlight/sdk        # Node lane

cd examples/showcase/denied-before-execute
python agent.py                 # or: node agent.mjs
```

Working in a clone instead? `cd ts && npm run build` puts the Node lane where
the showcases look for it.

## Run them all

```bash
examples/showcase/check.sh
```

Every showcase declares its own steps in a `check.sh`, so ordering and cleanup
are handled. A showcase that needs an optional extra is skipped and says so.

`scripts/preflight.sh` runs this along with the test suites, the patterns and
the adversarial harness.

## Next

- [Governance patterns](../patterns/) — copy-paste policies for high-stakes decisions
- [The docs](../../docs/) — the identity model, the audit trail, testing
