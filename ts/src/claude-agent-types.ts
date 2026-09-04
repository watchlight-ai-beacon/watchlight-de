// Minimal local type definitions mirroring the Claude Agent SDK's hook contract
// — just the subset the PreToolUse governance gate needs. Kept local so
// @watchlight/sdk does not take a hard dependency on the Claude Agent SDK; it is
// a peer you install alongside. Shapes match the SDK's documented hook I/O.

export type HookEventName =
  | "PreToolUse"
  | "PostToolUse"
  | "UserPromptSubmit"
  | "Stop"
  | "SessionStart"
  | "SessionEnd"
  | "SubagentStart"
  | "SubagentStop";

/** Permission verdict the SDK accepts on a PreToolUse hook. */
export type PermissionDecision = "allow" | "deny" | "ask" | "defer";

export interface BaseHookInput {
  hook_event_name: HookEventName;
  session_id?: string;
  cwd?: string;
  agent_id?: string;
  agent_type?: string;
}

export interface PreToolUseHookInput extends BaseHookInput {
  hook_event_name: "PreToolUse";
  tool_name: string;
  tool_input: Record<string, unknown>;
  /** Correlates this call with its PostToolUse event. */
  tool_use_id?: string;
}

export interface PostToolUseHookInput extends BaseHookInput {
  hook_event_name: "PostToolUse";
  tool_name: string;
  tool_input: Record<string, unknown>;
  /** The tool's raw result, as the SDK would hand it to the model. */
  tool_response: unknown;
  /** Correlates this event with its PreToolUse call. */
  tool_use_id?: string;
}

export interface HookOutput {
  continue?: boolean;
  hookSpecificOutput?: {
    hookEventName: HookEventName;
    permissionDecision?: PermissionDecision;
    permissionDecisionReason?: string;
    /** PostToolUse: replaces the tool output before it is sent to the model. */
    updatedToolOutput?: unknown;
  };
}

/** The SDK passes the `tool_use_id` as a second argument as well; hooks written
 *  against the one-argument form keep working. */
export type HookCallback = (
  input: BaseHookInput,
  toolUseID?: string
) => Promise<HookOutput> | HookOutput;

export interface HookMatcherEntry {
  matcher?: string;
  hooks: HookCallback[];
  /** SDK-side timeout, in SECONDS, for all hooks in this matcher. */
  timeout?: number;
}

export type HooksOption = Partial<Record<HookEventName, HookMatcherEntry[]>>;
