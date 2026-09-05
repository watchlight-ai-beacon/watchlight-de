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
// The hook is raced against an internal deadline set BELOW the SDK's own hook
// timeout: SDK hooks run in parallel on the original output, so a hook that
// merely outran the SDK timeout would let the raw output through. Ours withholds.

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

/** Default internal deadline for `onResult` (ms). The SDK-side matcher timeout is
 *  derived from it so the deadline sits at 80% of the SDK's. */
export const DEFAULT_ON_RESULT_TIMEOUT_MS = 8_000;

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
   *  call (joined by the SDK's `tool_use_id`; without one, no join and no
   *  `decision_id` on the egress record). Return a value to replace the output
   *  the model receives (`updatedToolOutput`); `undefined`/`null` passes it
   *  through. Fail-closed: if the hook throws or outruns
   *  {@link onResultTimeoutMs}, the model receives the opaque `"not authorized"`
   *  string instead of the raw output. Writes a value-free `egress` record. */
  onResult?: OnResult<unknown>;
  /** Internal deadline for `onResult`, in ms (default
   *  {@link DEFAULT_ON_RESULT_TIMEOUT_MS}). The PostToolUse matcher's SDK
   *  `timeout` (seconds) is set to `ceil(onResultTimeoutMs / 0.8 / 1000)` so this
   *  deadline always fires first and withholds the output. */
  onResultTimeoutMs?: number;
}

export interface GovernedHooksResult {
  /** Pass directly to the Claude Agent SDK: `query({ options: { hooks } })`. */
  hooks: HooksOption;
}

// Upper bound on PreToolUse decisions awaiting their PostToolUse event — a tool
// call that never reports back (SDK abort) must not grow this without bound.
const PENDING_CAP = 1024;

// Only a standard error NAME ever reaches stderr — never the message or stack,
// which a hook may have built from the payload it was inspecting.
const STD_ERROR_NAMES = new Set([
  "Error",
  "TypeError",
  "RangeError",
  "SyntaxError",
  "ReferenceError",
  "EvalError",
  "URIError",
  "AggregateError",
  "AbortError",
  "TimeoutError",
  "EgressTimeout",
]);
const safeErrorName = (e: unknown): string => {
  const n = (e as { name?: unknown } | null | undefined)?.name;
  return typeof n === "string" && STD_ERROR_NAMES.has(n) ? n : "Error";
};

/**
 * Build Claude Agent SDK hooks that gate every tool call through the in-process
 * Watchlight engine. Fail-closed. The hook never throws back to the SDK — a
 * governance error becomes a `deny`.
 */
export function governedHooks(options: GovernedHooksOptions = {}): GovernedHooksResult {
  const governor = options.governor ?? govern;
  const intentFor = options.intentFor ?? ((t: string) => t);
  const onResult = options.onResult;
  const timeoutMs = options.onResultTimeoutMs ?? DEFAULT_ON_RESULT_TIMEOUT_MS;
  if (!(Number.isFinite(timeoutMs) && timeoutMs > 0)) {
    throw new RangeError("onResultTimeoutMs must be a positive number of milliseconds");
  }

  // PreToolUse decision → PostToolUse egress correlation, keyed by the SDK's
  // tool_use_id. No id → no correlation (a name-based fallback would mis-join
  // concurrent calls of the same tool).
  const pending = new Map<string, EgressInfo>();
  const pendingKey = (ev: { tool_use_id?: string }, toolUseID?: string): string | undefined =>
    ev.tool_use_id ?? toolUseID;

  const preToolUse: HookCallback = async (input, toolUseID): Promise<HookOutput> => {
    const ev = input as PreToolUseHookInput;
    const toolName = ev.tool_name ?? "unknown";
    try {
      const intent = intentFor(toolName);
      const { allowed, reason, decisionId, obligations, principal } = await governor.check(intent, toolName);
      const key = pendingKey(ev, toolUseID);
      if (allowed && onResult && key !== undefined) {
        if (pending.size >= PENDING_CAP) {
          const oldest = pending.keys().next().value;
          if (oldest !== undefined) pending.delete(oldest);
        }
        // The PostToolUse hook receives the decision's id AND its obligations.
        // `principal` is the subject the decision was recorded against, so the
        // egress record joins the decision record on both id and subject.
        const info: EgressInfo = { intent, resource: `tool/${toolName}`, principal, decisionId };
        if (obligations) info.obligations = obligations;
        pending.set(key, info);
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
      // can't be told apart from a policy deny. Only the error's standard NAME
      // goes to stderr for the developer — never its message or stack.
      // eslint-disable-next-line no-console
      console.error(`watchlight governance error (fail-closed): ${safeErrorName(e)}`);
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
      const info = key !== undefined ? pending.get(key) : undefined;
      if (key !== undefined) pending.delete(key);
      const egress: EgressInfo = info ?? {
        // No PreToolUse decision on record for this call: the hook still runs,
        // and the egress record is written honestly without a decision_id.
        intent: intentFor(toolName),
        resource: `tool/${toolName}`,
        principal: governor._principal(),
      };
      const { value, replaced } = await governor._applyOnResult(ev.tool_response, onResult, egress, {
        timeoutMs,
      });
      return {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          ...(replaced ? { updatedToolOutput: value } : {}),
        },
      };
    } catch (e) {
      // Fail-closed: the tool already ran, so the only thing left to protect is
      // what the model sees — replace the raw output with the opaque reason.
      // Nothing about the result or the error reaches the model; only the
      // error's standard name reaches stderr.
      // eslint-disable-next-line no-console
      console.error(`watchlight egress error (fail-closed): ${safeErrorName(e)}`);
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
      // SDK timeout (seconds) sits ABOVE our internal deadline so a slow hook is
      // withheld by us, never released by the SDK's timeout.
      PostToolUse: [{ hooks: [postToolUse], timeout: Math.ceil(timeoutMs / 0.8 / 1000) }],
    },
  };
}
