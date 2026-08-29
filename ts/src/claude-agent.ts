// Claude Agent SDK integration — govern an SDK-managed agent's tool calls with
// the in-process engine. The TS counterpart of Python `watchlight.claude_agent`.
//
//   import { query } from "@anthropic-ai/claude-agent-sdk";
//   import { govern, governedHooks } from "@watchlight/sdk";
//
//   govern.load("watchlight.policy.json");
//   const { hooks } = governedHooks({ intentFor: (t) => TOOL_INTENTS[t] ?? t });
//
//   for await (const msg of query({ prompt, options: { hooks } })) { … }
//
// The returned `hooks` install a PreToolUse gate: before the SDK runs any tool,
// the in-process engine authorizes (agent, intent, tool/<name>). ALLOW lets the
// call proceed; anything else returns a `deny` permission decision and the tool
// never executes — denied before it runs. Fail-closed: a governance error also
// denies. Every decision lands in the value-free `.watchlight/audit.jsonl`.

import { Watchlight, govern } from "./index";
import type {
  HooksOption,
  HookCallback,
  HookOutput,
  PreToolUseHookInput,
} from "./claude-agent-types";

export type {
  HookEventName,
  PermissionDecision,
  BaseHookInput,
  PreToolUseHookInput,
  HookOutput,
  HookCallback,
  HookMatcherEntry,
  HooksOption,
} from "./claude-agent-types";

export interface GovernedHooksOptions {
  /** The governor to authorize against. Defaults to the shared `govern`. */
  governor?: Watchlight;
  /** Map a Claude tool name to a governance intent. Defaults to identity
   *  (the intent is the tool name). Provide this to bind semantic intents,
   *  e.g. `(t) => ({ WebSearch: "research", Bash: "execute" }[t] ?? t)`. */
  intentFor?: (toolName: string) => string;
}

export interface GovernedHooksResult {
  /** Pass directly to the Claude Agent SDK: `query({ options: { hooks } })`. */
  hooks: HooksOption;
}

/**
 * Build Claude Agent SDK hooks that gate every tool call through the in-process
 * Watchlight engine. Fail-closed. The hook never throws back to the SDK — a
 * governance error becomes a `deny`.
 */
export function governedHooks(options: GovernedHooksOptions = {}): GovernedHooksResult {
  const governor = options.governor ?? govern;
  const intentFor = options.intentFor ?? ((t: string) => t);

  const preToolUse: HookCallback = async (input): Promise<HookOutput> => {
    const ev = input as PreToolUseHookInput;
    const toolName = ev.tool_name ?? "unknown";
    try {
      const intent = intentFor(toolName);
      const { allowed, reason } = await governor.check(intent, toolName);
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: allowed ? "allow" : "deny",
          ...(allowed ? {} : { permissionDecisionReason: reason || "no matching policy" }),
        },
      };
    } catch (e) {
      // Hooks must never throw back to the SDK; a governance error is
      // fail-closed — deny the tool call rather than let it through.
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `watchlight governance error (fail-closed): ${String(e)}`,
        },
      };
    }
  };

  return { hooks: { PreToolUse: [{ hooks: [preToolUse] }] } };
}
