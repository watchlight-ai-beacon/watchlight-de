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
//
// With `onResult`, a PostToolUse hook is installed as well: after the tool runs
// and before the model sees its output, the hook inspects the result (sanitize,
// screen, re-authorize on its classification) and may replace it. The `egress`
// audit record it writes is joined to the PreToolUse decision by `decision_id`.

import { Watchlight, govern, DENY_REASON, type OnResult, type EgressInfo } from "./index";
import type {
  HooksOption,
  HookCallback,
  HookOutput,
  PreToolUseHookInput,
  PostToolUseHookInput,
} from "./claude-agent-types";

export type {
  HookEventName,
  PermissionDecision,
  BaseHookInput,
  PreToolUseHookInput,
  PostToolUseHookInput,
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
  /** Egress hook (PostToolUse). Awaited over the tool's raw response AFTER the
   *  tool ran and BEFORE the model sees it, with `{ intent, resource, principal,
   *  decisionId }` — the same `decisionId` the PreToolUse gate recorded for this
   *  call. Return a value to replace the output the model receives
   *  (`updatedToolOutput`); `void` passes it through. Fail-closed: if the hook
   *  throws, the model receives the opaque `"not authorized"` string instead of
   *  the raw output. Writes a value-free `egress` audit record. */
  onResult?: OnResult<unknown>;
}

export interface GovernedHooksResult {
  /** Pass directly to the Claude Agent SDK: `query({ options: { hooks } })`. */
  hooks: HooksOption;
}

// Upper bound on PreToolUse decisions awaiting their PostToolUse event — a tool
// call that never reports back (SDK abort) must not grow this without bound.
const PENDING_CAP = 1024;

/**
 * Build Claude Agent SDK hooks that gate every tool call through the in-process
 * Watchlight engine. Fail-closed. The hook never throws back to the SDK — a
 * governance error becomes a `deny`.
 */
export function governedHooks(options: GovernedHooksOptions = {}): GovernedHooksResult {
  const governor = options.governor ?? govern;
  const intentFor = options.intentFor ?? ((t: string) => t);
  const onResult = options.onResult;

  // PreToolUse decision → PostToolUse egress correlation, keyed by the SDK's
  // tool_use_id (falls back to the tool name on SDKs that don't send one).
  const pending = new Map<string, EgressInfo>();
  const pendingKey = (ev: { tool_use_id?: string; tool_name?: string }, toolUseID?: string): string =>
    ev.tool_use_id ?? toolUseID ?? `tool:${ev.tool_name ?? "unknown"}`;

  const preToolUse: HookCallback = async (input, toolUseID): Promise<HookOutput> => {
    const ev = input as PreToolUseHookInput;
    const toolName = ev.tool_name ?? "unknown";
    try {
      const intent = intentFor(toolName);
      const { allowed, reason, decisionId } = await governor.check(intent, toolName);
      if (allowed && onResult) {
        if (pending.size >= PENDING_CAP) {
          const oldest = pending.keys().next().value;
          if (oldest !== undefined) pending.delete(oldest);
        }
        pending.set(pendingKey(ev, toolUseID), {
          intent,
          resource: `tool/${toolName}`,
          principal: governor.agent,
          decisionId,
        });
      }
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: allowed ? "allow" : "deny",
          ...(allowed ? {} : { permissionDecisionReason: reason || DENY_REASON }),
        },
      };
    } catch (e) {
      // Hooks must never throw back to the SDK; a governance error is
      // fail-closed — deny the tool call rather than let it through. The
      // model-facing reason stays OPAQUE (the same uniform string as any other
      // denial), so an internal error can't disclose anything to the caller and
      // can't be told apart from a policy deny. The detail goes to stderr for
      // the developer, never into the decision surfaced to the agent.
      // eslint-disable-next-line no-console
      console.error("watchlight governance error (fail-closed):", e);
      return {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: DENY_REASON,
        },
      };
    }
  };

  if (!onResult) return { hooks: { PreToolUse: [{ hooks: [preToolUse] }] } };

  const postToolUse: HookCallback = async (input, toolUseID): Promise<HookOutput> => {
    const ev = input as PostToolUseHookInput;
    const toolName = ev.tool_name ?? "unknown";
    try {
      const key = pendingKey(ev, toolUseID);
      const info = pending.get(key);
      pending.delete(key);
      const egress: EgressInfo = info ?? {
        // No PreToolUse decision on record for this call (e.g. the SDK sent no
        // tool_use_id and the fallback key was consumed): the hook still runs,
        // and the egress record is written honestly without a decision_id.
        intent: intentFor(toolName),
        resource: `tool/${toolName}`,
        principal: governor.agent,
      };
      const { value, replaced } = await governor._applyOnResult(ev.tool_response, onResult, egress);
      return {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          ...(replaced ? { updatedToolOutput: value } : {}),
        },
      };
    } catch (e) {
      // Fail-closed: the tool already ran, so the only thing left to protect is
      // what the model sees — replace the raw output with the opaque reason.
      // Nothing about the result or the error reaches the model.
      // eslint-disable-next-line no-console
      console.error("watchlight egress error (fail-closed):", e);
      return {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          updatedToolOutput: DENY_REASON,
        },
      };
    }
  };

  return {
    hooks: {
      PreToolUse: [{ hooks: [preToolUse] }],
      PostToolUse: [{ hooks: [postToolUse] }],
    },
  };
}
