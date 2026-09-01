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
// Before the tool runs, the engine authorizes (agent, intent, tool/<name>). ALLOW
// runs it; anything else throws `Denied` and the tool body never executes —
// denied before it runs. Fail-closed. Works for any LangChain `StructuredTool`
// (which is what LangGraph.js tools are).
//
// This is glue: it intercepts the tool's `invoke`; the decision comes from the
// engine (via the shared governor). No LangChain hard dependency — the adapter is
// structurally typed against the tool's public shape, so `@langchain/core` stays
// a peer you already have installed.

import { Watchlight, govern, Denied, DENY_REASON } from "./index";

/** The minimal shape of a LangChain `StructuredTool` this adapter needs. */
export interface LangChainToolLike {
  name: string;
  invoke(input: unknown, config?: unknown): Promise<unknown>;
  [k: string]: unknown;
}

export interface GovernToolOptions {
  /** The governor to authorize against. Defaults to the shared `govern`. */
  governor?: Watchlight;
  /** Governance intent for this tool. Defaults to the tool's `name`. */
  intent?: string;
}

export interface GovernToolsOptions {
  governor?: Watchlight;
  /** Map a tool name to a governance intent. Defaults to identity (intent =
   *  tool name). */
  intentFor?: (toolName: string) => string;
}

/**
 * Wrap a LangChain / LangGraph.js tool so its `invoke` is authorized by the
 * in-process engine before it runs. Returns a governed view of the tool (a
 * Proxy) — pass it to your agent / `ToolNode` exactly like the original. The
 * original tool is not mutated. Fail-closed: on anything but ALLOW, `invoke`
 * throws `Denied` and the underlying tool never executes.
 */
export function governTool<T extends LangChainToolLike>(tool: T, opts: GovernToolOptions = {}): T {
  const governor = opts.governor ?? govern;
  const intent = opts.intent ?? tool.name;
  const name = tool.name;

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") {
        return async (input: unknown, config?: unknown): Promise<unknown> => {
          const { allowed, reason } = await governor.check(intent, name);
          if (!allowed) {
            throw new Denied(name, intent, reason || DENY_REASON);
          }
          return target.invoke(input, config);
        };
      }
      // Delegate everything else to the real tool, bound to it so `this` stays
      // correct and internal calls hit the real (un-governed) methods.
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as T;
}

/**
 * Govern an array of LangChain / LangGraph.js tools. `intentFor` maps each tool
 * name to an intent (default: the tool name).
 */
export function governTools<T extends LangChainToolLike>(
  tools: T[],
  opts: GovernToolsOptions = {}
): T[] {
  const intentFor = opts.intentFor ?? ((n: string) => n);
  return tools.map((t) => governTool(t, { governor: opts.governor, intent: intentFor(t.name) }));
}
