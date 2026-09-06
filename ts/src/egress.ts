// The egress-hook deadline — shared by every path that runs an `onResult`
// hook, so `tool()`, `governTool` / `governTools` and the `governedHooks`
// `PostToolUse` hook all bound the hook the same way and `EgressRecord.withheld`
// means the same thing on all three.
//
// It lives in its own module because both `./index` (which runs the hook) and
// `./claude-agent` (which additionally derives the SDK matcher timeout from it)
// need the constant, and `./claude-agent` already imports `./index`.

/** Default deadline for an egress (`onResult`) hook, in milliseconds.
 *
 *  A hook that has not settled within it withholds the payload: the call
 *  rejects with {@link EgressTimeout} and the `egress` audit record is written
 *  with `withheld: true`. The payload is never released late.
 *
 *  Applies to `tool()`, `governTool` / `governTools` and `governedHooks` alike;
 *  each takes an `onResultTimeoutMs` to override it per call. On
 *  `governedHooks` the Claude Agent SDK's own matcher timeout is derived from
 *  it (`ceil(ms / 0.8 / 1000)` seconds) so this deadline always fires first. */
export const DEFAULT_ON_RESULT_TIMEOUT_MS = 8_000;

/** Thrown when an egress hook outruns its deadline. The payload it was
 *  inspecting is withheld — never returned, never logged. The error carries
 *  nothing derived from the payload: a fixed message and a stable `name`, so it
 *  is safe to log and safe to catch (`e instanceof EgressTimeout`). */
export class EgressTimeout extends Error {
  constructor() {
    super("egress hook deadline exceeded");
    this.name = "EgressTimeout";
  }
}

/** Resolve an `onResultTimeoutMs` option to the deadline to enforce, applying
 *  {@link DEFAULT_ON_RESULT_TIMEOUT_MS} when it is absent.
 *
 *  Validated eagerly — where the tool is wrapped, not where it is called — so a
 *  misconfigured deadline surfaces at wiring time rather than on the first
 *  payload it fails to bound. There is deliberately no "no deadline" value: `0`,
 *  a negative, `NaN` and `Infinity` are all refused. An unbounded hook is the
 *  defect this deadline closes, so disabling it is not a value you can pass by
 *  accident; a hook that genuinely needs longer takes an explicit large number
 *  (`onResultTimeoutMs: 300_000`), which says so in review.
 *  @internal */
export function resolveEgressTimeoutMs(ms: number | undefined): number {
  const timeoutMs = ms ?? DEFAULT_ON_RESULT_TIMEOUT_MS;
  if (!(Number.isFinite(timeoutMs) && timeoutMs > 0)) {
    throw new RangeError("onResultTimeoutMs must be a positive number of milliseconds");
  }
  return timeoutMs;
}
