// Govern a LangGraph.js / LangChain tool with the in-process engine.
//
// Real usage (needs `npm i @langchain/core`):
//
//   import { tool } from "@langchain/core/tools";
//   import { z } from "zod";
//   import { govern, governTool } from "@watchlight/sdk";
//
//   govern.load("watchlight.policy.json");
//   const search = governTool(
//     tool(async ({ query }) => webSearch(query),
//          { name: "web_search", description: "...", schema: z.object({ query: z.string() }) }),
//     { intent: "research" }
//   );
//   // pass `search` to your LangGraph ToolNode / createReactAgent as usual.
//
// This script uses a mock StructuredTool (name + invoke) so it runs offline and
// shows the DENY-before-execution decision LangGraph would enforce. Only the
// `research` intent is permitted, so web_search runs and wire_transfer is denied
// before it moves any money.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { govern, governTool, Denied } = require("@watchlight/sdk");

const here = dirname(fileURLToPath(import.meta.url));
govern.load(join(here, "watchlight.policy.json"));

const mockTool = (name, fn) => ({ name, invoke: async (input) => fn(input) });

const search = governTool(
  mockTool("web_search", ({ query }) => `results for: ${query}`),
  { intent: "research" }
);
const wire = governTool(
  mockTool("wire_transfer", ({ amount }) => `moved ${amount}`),
  { intent: "transfer" }
);

async function main() {
  console.log("web_search   →", await search.invoke({ query: "cedar policy" }));
  try {
    await wire.invoke({ to: "acct-999", amount: 5000 });
  } catch (e) {
    if (e instanceof Denied) {
      console.log("wire_transfer → denied before it executed:", e.message);
      return;
    }
    throw e;
  }
  throw new Error("SECURITY BUG: wire_transfer should have been denied");
}

main().catch((e) => { console.error(e); process.exit(1); });
