// Govern a Claude Agent SDK agent's tool calls with the in-process engine.
//
// Real wiring (needs `npm i @anthropic-ai/claude-agent-sdk` + an API key):
//
//   import { query } from "@anthropic-ai/claude-agent-sdk";
//   import { govern, governedHooks } from "@watchlight/sdk";
//
//   govern.load("watchlight.policy.json");
//   const { hooks } = governedHooks({ intentFor: (t) => TOOL_INTENTS[t] ?? t });
//   for await (const msg of query({ prompt, options: { hooks } })) { … }
//
// This script instead invokes the PreToolUse hook directly with synthetic tool
// calls, so it runs offline and shows the DENY-before-execution decision the SDK
// would enforce. Only the `research` intent is permitted, so a WebSearch is
// allowed and a TransferFunds is denied before it ever runs.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { govern, governedHooks } = require("@watchlight/sdk");

const here = dirname(fileURLToPath(import.meta.url));
govern.load(join(here, "watchlight.policy.json"));

// Map the Claude tool names your agent uses to governance intents.
const TOOL_INTENTS = { WebSearch: "research", TransferFunds: "transfer" };
const { hooks } = governedHooks({ intentFor: (t) => TOOL_INTENTS[t] ?? t });

const preToolUse = hooks.PreToolUse[0].hooks[0];
const gate = async (tool_name, tool_input) => {
  const out = await preToolUse({ hook_event_name: "PreToolUse", tool_name, tool_input });
  return out.hookSpecificOutput; // { permissionDecision, permissionDecisionReason? }
};

async function main() {
  const allow = await gate("WebSearch", { query: "cedar policy language" });
  console.log(`WebSearch     → ${allow.permissionDecision}`);

  const deny = await gate("TransferFunds", { to: "acct-999", amount: 5000 });
  console.log(`TransferFunds → ${deny.permissionDecision}  (${deny.permissionDecisionReason})`);

  if (allow.permissionDecision !== "allow" || deny.permissionDecision !== "deny") {
    throw new Error("unexpected governance decision");
  }
  console.log("\nDenied before it executed — the Claude Agent SDK would block the tool call.");
}

main().catch((e) => { console.error(e); process.exit(1); });
