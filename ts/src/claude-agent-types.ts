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
}

export interface HookOutput {
  continue?: boolean;
  hookSpecificOutput?: {
    hookEventName: HookEventName;
    permissionDecision?: PermissionDecision;
    permissionDecisionReason?: string;
  };
}

export type HookCallback = (input: BaseHookInput) => Promise<HookOutput> | HookOutput;

export interface HookMatcherEntry {
  matcher?: string;
  hooks: HookCallback[];
}

export type HooksOption = Partial<Record<HookEventName, HookMatcherEntry[]>>;
