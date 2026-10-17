// How a policy's `@enforcement_effect` annotation is checked at load.
//
// WHY THE CHECK EXISTS
//
// `@enforcement_effect("<verb>")` changes the VERDICT. On a `permit`,
// `require_approval` turns an Allow into a NeedsApproval that a human has to
// release. An effect value the engine did not implement used to be dropped. On
// a `forbid` that leaves a plain deny, which is the closed direction. On a
// `permit` it leaves a plain allow, which is the open one: a one-character typo
// turned a human-in-the-loop gate into an unconditional permit. A misspelled
// annotation NAME (`@enforcement_efect`) did the same, because Cedar accepts any
// annotation name.
//
// WHO DECIDES
//
// The engine. Since `@watchlight/engine` 0.2.3 the engine refuses such a policy
// when it is added, with a `PolicyAnnotationError` carrying a stable `code`:
// `UNRECOGNISED_ENFORCEMENT_EFFECT` for a value it does not implement, and
// `ENFORCEMENT_EFFECT_NAME_NEAR_MISS` for an annotation name within two edits
// of `enforcement_effect` (case folded) that is not the exact name. The SDK keeps
// no list of its own: it maps the engine's typed refusal to `PolicyError`.

/** The annotation whose value the engine turns into an enforcement effect. */
export const ENFORCEMENT_EFFECT_ANNOTATION = "enforcement_effect";

/** `PolicyError.code` for an `@enforcement_effect` value the engine does not implement. */
export const UNRECOGNISED_ENFORCEMENT_EFFECT = "UNRECOGNISED_ENFORCEMENT_EFFECT";

/** `PolicyError.code` for an annotation name that is a near miss for `@enforcement_effect`. */
export const ENFORCEMENT_EFFECT_NAME_NEAR_MISS = "ENFORCEMENT_EFFECT_NAME_NEAR_MISS";

/** Every `PolicyError.code`, as the engine reports them. */
export const POLICY_ERROR_CODES = [
  ENFORCEMENT_EFFECT_NAME_NEAR_MISS,
  UNRECOGNISED_ENFORCEMENT_EFFECT,
] as const;

export type PolicyErrorCode = (typeof POLICY_ERROR_CODES)[number];

/** Raised when the engine refuses a policy for its `@enforcement_effect`
 *  annotation: a value it does not implement, or an annotation name that is a
 *  near miss for `enforcement_effect`.
 *
 *  The engine compiles asynchronously, so it surfaces at {@link Watchlight.ready}
 *  or the next decision, like a {@link PolicyCompileError}, and from then on
 *  every decision throws it until `reload()` replaces the set: a set holding a
 *  refused policy never decides. `code` names the refusal, `policy` the policy,
 *  and `source` the file it came from. */
export class PolicyError extends Error {
  readonly name = "PolicyError";
  readonly code: PolicyErrorCode;
  /** The name the policy was loaded under. */
  readonly policy: string;
  /** The file it was loaded from, when it came from one. */
  readonly source?: string;
  constructor(message: string, opts: { code: PolicyErrorCode; policy: string; source?: string }) {
    super(message);
    this.code = opts.code;
    this.policy = opts.policy;
    this.source = opts.source;
  }
}

/** Whether `e` is the engine's typed refusal of an enforcement annotation. */
export function isEngineAnnotationError(e: unknown): e is Error & { code: PolicyErrorCode } {
  return (
    e instanceof Error &&
    e.name === "PolicyAnnotationError" &&
    (POLICY_ERROR_CODES as readonly string[]).includes((e as { code?: unknown }).code as string)
  );
}

/** Map the engine's `PolicyAnnotationError` to a {@link PolicyError} naming the
 *  policy as the developer did. The engine's explanation is kept; it is the same
 *  in every language, because it comes from the same engine. */
export function policyErrorFromEngine(
  e: Error & { code: PolicyErrorCode },
  policy: string,
  source?: string
): PolicyError {
  let detail = e.message.replace(/^add_policy failed:\s*/, "");
  const marker = " rejected: ";
  if (detail.startsWith("Policy ") && detail.includes(marker)) {
    detail = detail.slice(detail.indexOf(marker) + marker.length);
  }
  const where = source ? ` from ${source}` : "";
  return new PolicyError(`policy "${policy}"${where}: ${detail}`, {
    code: e.code,
    policy,
    source,
  });
}
