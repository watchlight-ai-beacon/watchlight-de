// LangChain / LangGraph.js integration — govern a tool's execution with the
// in-process engine. The TS counterpart of Python `watchlight.langgraph`.
//
//   import { tool } from "@langchain/core/tools";
//   import { govern, governTool } from "@watchlight/sdk";
//
//   govern.load("watchlight.policy.json");
//   const search = governTool(
//     tool(async ({ query }) => webSearch(query), { name: "web_search", schema }),
//     { intent: "research" }
//   );
//   // pass `search` to your LangGraph agent / ToolNode as usual.
//
// Before the tool runs, the engine authorizes (principal, intent, resource).
// ALLOW runs it; anything else throws `Denied` and the tool body never
// executes — denied before it runs. Fail-closed. Works for any LangChain
// `StructuredTool` (which is what LangGraph.js tools are).
//
// `governTool` is a thin shim over `govern.tool()`: it takes the same
// `principal`, `agent`, `resource`, `context`, `onNeedsApproval` and `onResult`
// as a hand-written governed tool, so a policy that reads Cedar `context.*`
// reaches the same verdict here as it does there. Each of `principal`,
// `resource` and `context` is a fixed value OR a function of the tool's own
// `invoke(input, config)` arguments, because a framework tool's subject is
// usually per-invocation rather than fixed at wrap time.
//
// This is glue: it intercepts the tool's `invoke`; the decision comes from the
// engine (via the shared governor). No LangChain hard dependency — the adapter is
// structurally typed against the tool's public shape, so `@langchain/core` stays
// a peer you already have installed.

import {
  Watchlight,
  govern,
  type Binding,
  type ContextBinding,
  type OnNeedsApproval,
  type OnResult,
} from "./index";

/** The minimal shape of a LangChain `StructuredTool` this adapter needs. */
export interface LangChainToolLike {
  name: string;
  invoke(input: unknown, config?: unknown): Promise<unknown>;
  [k: string]: unknown;
}

/** The arguments a governed tool's `invoke` is called with — what a per-call
 *  binding (`(input, config) => value`) receives. */
export type InvokeArgs = [input: unknown, config?: unknown];

export interface GovernToolOptions {
  /** The governor to authorize against. Defaults to the shared `govern`. */
  governor?: Watchlight;
  /** Governance intent for this tool. Defaults to the tool's `name`. */
  intent?: string;
  /** Acting principal — a value, or `(input, config) => value` so the subject
   *  can come from the call itself. Build it with `principals`
   *  (`principals.user(sub)`). With none, the agent is the subject and is
   *  recorded as `Agent::"<name>"`, exactly as before. */
  principal?: Binding<InvokeArgs>;
  /** Agent name for this tool, overriding the governor's — the same rename
   *  `as()` returns, applied to one tool. */
  agent?: string;
  /** Cedar resource entity — a value, or `(input, config) => value`. Defaults
   *  to `tool/<name>`, the resource this adapter has always used. Change it
   *  only deliberately: a policy is anchored on the resource, so a new value
   *  is a new anchor. */
  resource?: Binding<InvokeArgs>;
  /** Attributes for Cedar `context.*` — an object, or `(input, config) =>
   *  object`. A policy whose verdict depends on `context` needs this; without
   *  it the context is empty and such a policy denies. */
  context?: ContextBinding<InvokeArgs>;
  /** Human-in-the-loop hook. Called when the decision is `NeedsApproval`;
   *  return `true` to proceed (records an approval), `false`/absent to hold
   *  (throws `NeedsApproval`). */
  onNeedsApproval?: OnNeedsApproval;
  /** Egress hook, awaited over the tool's result AFTER `invoke` returns and
   *  BEFORE the agent sees it, with `{ intent, resource, principal, decisionId,
   *  obligations? }` — the id and obligations of the decision that let it run.
   *  Return a value to replace the result; `void` passes it through; a throw
   *  propagates and the raw result is withheld (fail-closed). Writes a
   *  value-free `egress` audit record joined to the decision by `decision_id`. */
  onResult?: OnResult<unknown>;
}

export interface GovernToolsOptions {
  governor?: Watchlight;
  /** Map a tool name to a governance intent. Defaults to identity (intent =
   *  tool name). */
  intentFor?: (toolName: string) => string;
  /** Map a tool name to its Cedar resource — return `undefined` to keep that
   *  tool's default, `tool/<name>`. A per-tool mapping, not a single value: one
   *  resource shared by every tool in the array would collapse them onto one
   *  anchor and silently re-point every policy written against them. The mapped
   *  value may itself be `(input, config) => value`. */
  resourceFor?: (toolName: string) => Binding<InvokeArgs> | undefined;
  /** Acting principal for every tool in the array — a value, or `(input,
   *  config) => value` for a per-call subject. See
   *  {@link GovernToolOptions.principal}. */
  principal?: Binding<InvokeArgs>;
  /** Agent name for every tool in the array, overriding the governor's. */
  agent?: string;
  /** Cedar `context.*` attributes for every tool in the array — an object, or
   *  `(input, config) => object`. See {@link GovernToolOptions.context}. */
  context?: ContextBinding<InvokeArgs>;
  /** Human-in-the-loop hook applied to every governed tool — see
   *  {@link GovernToolOptions.onNeedsApproval}. */
  onNeedsApproval?: OnNeedsApproval;
  /** Egress hook applied to every governed tool — see {@link GovernToolOptions.onResult}. */
  onResult?: OnResult<unknown>;
}

/**
 * Wrap a LangChain / LangGraph.js tool so its `invoke` is authorized by the
 * in-process engine before it runs. Returns a governed copy of the tool (a
 * Proxy) — pass it to your agent / `ToolNode` exactly like the original. The
 * original tool is not mutated. Fail-closed: on anything but ALLOW, `invoke`
 * throws `Denied` and the underlying tool never executes.
 *
 * The decision is `govern.tool()`'s decision: same intent, same resource, same
 * principal, same audit records. Called with none of `principal`, `agent`,
 * `resource`, `context` or `onNeedsApproval`, the subject is the agent and the
 * resource is `tool/<name>` — unchanged. One behaviour differs once a policy
 * asks for a human: a `NeedsApproval` verdict raises `NeedsApproval` — which
 * carries the decision id — rather than a flat `Denied`, and `onNeedsApproval`
 * can confirm and proceed.
 */
export function governTool<T extends LangChainToolLike>(tool: T, opts: GovernToolOptions = {}): T {
  const governor = opts.governor ?? govern;
  const intent = opts.intent ?? tool.name;
  const name = tool.name;

  // The body the governor wraps. `tool()` derives both the default resource
  // (`tool/<name>`) and the name on a `Denied` from the function's own `name`,
  // so stamp the framework tool's name on it — an anonymous arrow would
  // otherwise re-anchor every policy on `tool/anonymous`.
  const body = async (input: unknown, config?: unknown): Promise<unknown> =>
    tool.invoke(input, config);
  Object.defineProperty(body, "name", { value: name, configurable: true });

  const governedInvoke = governor.tool<InvokeArgs, Promise<unknown>>(body, {
    intent,
    principal: opts.principal,
    agent: opts.agent,
    resource: opts.resource,
    context: opts.context,
    onNeedsApproval: opts.onNeedsApproval,
    onResult: opts.onResult,
  });

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") return governedInvoke;
      // Delegate everything else to the real tool, bound to it so `this` stays
      // correct and internal calls hit the real (un-governed) methods.
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as T;
}

/**
 * Govern an array of LangChain / LangGraph.js tools. `intentFor` maps each tool
 * name to an intent (default: the tool name) and `resourceFor` to a resource
 * (default: `tool/<name>`); `principal`, `agent`, `context`, `onNeedsApproval`
 * and `onResult` apply to every tool in the array — pass the `(input, config)
 * => value` form where the subject or the context varies per call.
 */
export function governTools<T extends LangChainToolLike>(
  tools: T[],
  opts: GovernToolsOptions = {}
): T[] {
  const intentFor = opts.intentFor ?? ((n: string) => n);
  return tools.map((t) =>
    governTool(t, {
      governor: opts.governor,
      intent: intentFor(t.name),
      resource: opts.resourceFor?.(t.name),
      principal: opts.principal,
      agent: opts.agent,
      context: opts.context,
      onNeedsApproval: opts.onNeedsApproval,
      onResult: opts.onResult,
    })
  );
}
