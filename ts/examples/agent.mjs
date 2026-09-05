// The Developer-Edition DENY line for Node — govern an agent's tools with zero
// infra. The TS counterpart of watchlight-de's examples/agent.py.
//
// Expected output:
//   watchlight: governing 'research-agent' (dev mode, in-process engine)
//   watchlight: ALLOW research  tool/webSearch
//   [tool ran] results for: cedar policy language
//   watchlight: DENY  transfer  tool/transferFunds     not authorized
//   denied before it executed: watchlight denied intent 'transfer' on tool/transferFunds: ...
//
// Only the `research` intent is permitted by watchlight.policy.json. The
// transferFunds tool is governed but no policy permits it, so the engine denies
// the call BEFORE the body runs — no money moves.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { govern, Denied, configureDefault } = require("@watchlight/sdk");

// Name the agent. It is what the audit trail records and what a policy reads as
// `context.actor`; without it the governor asserts no actor at all.
configureDefault({ agent: "research-agent" });

const here = dirname(fileURLToPath(import.meta.url));
govern.load(join(here, "watchlight.policy.json"));

// Named functions → the audit resource reads tool/webSearch, tool/transferFunds.
const webSearch = govern.tool(async function webSearch(query) {
  return `results for: ${query}`;
}, { intent: "research" });

const transferFunds = govern.tool(async function transferFunds(to, amount) {
  // This body must never run without a policy that permits "transfer".
  return `transferred ${amount} to ${to}`;
}, { intent: "transfer" });

async function main() {
  // Permitted — a policy allows the 'research' intent.
  console.log("[tool ran]", await webSearch("cedar policy language"));

  // Denied — governed, but no policy permits 'transfer'. Fail-closed.
  try {
    await transferFunds("acct-999", 5000);
  } catch (e) {
    if (e instanceof Denied) {
      console.log("denied before it executed:", e.message);
      return;
    }
    throw e;
  }
  throw new Error("SECURITY BUG: transfer should have been denied");
}

main().catch((e) => { console.error(e); process.exit(1); });
