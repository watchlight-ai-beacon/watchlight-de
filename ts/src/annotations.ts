// The Cedar policy ANNOTATIONS the SDK reads at load, and the check that a
// policy cannot silently mean something other than what it says.
//
// WHY THIS CHECK EXISTS
//
// `@enforcement_effect("<verb>")` changes the VERDICT. On a `permit`,
// `require_approval` turns an Allow into a NeedsApproval that a human has to
// release.
//
// The engine maps a value it does not implement to *no effect at all*. That is
// the fail-CLOSED direction for the verbs that escalate a `forbid` —
// `terminate`, `quarantine`, `sever_subtree` and `revoke` all take a deny and
// make it stronger, so dropping one leaves a plain deny. It is the fail-OPEN
// direction for the verb that holds back a `permit`: dropping
// `require_approval` leaves a plain allow. One rule, fail-closed for one family
// and fail-open for the other — and a one-character typo in the value is enough
// to turn a human-in-the-loop gate into an unconditional permit, with no error
// and no warning.
//
// So the SDK refuses a policy whose effect it cannot read, at load, before the
// engine ever sees it. That is deliberately unlike an unknown `@obligate_*`,
// which the engine preserves and hands to the caller as an uninterpreted extra:
// an obligation the engine does not interpret still has a reader (the caller),
// so passing it through is meaningful. An effect verb nothing implements has no
// reader — the engine makes the decision, and it would make it wrongly.
//
// A misspelled annotation NAME cannot be told apart from a legitimate user
// annotation in general, so a near miss for `@enforcement_effect` warns and
// nothing else does. It never throws: an arbitrary annotation is valid Cedar.
//
// VERSION COUPLING — READ THIS BEFORE ADDING A VERB
//
// `ENFORCEMENT_EFFECTS` is the set the PINNED engine implements (the
// `@watchlight/engine` range in `ts/package.json`). The SDK and the engine are
// released together, so shipping the list here is safe, but it makes adding a
// verb a TWO-PLACE change:
//
//   1. `ts/src/annotations.ts`            (this list)
//   2. `src/watchlight/_annotations.py`   (the identical list, Python)
//
// Both lanes must carry the same set, in the same order, or the same policy is
// accepted in one language and refused in the other.

/** The annotation whose value the engine turns into an enforcement effect. */
export const ENFORCEMENT_EFFECT_ANNOTATION = "enforcement_effect";

/** Every `@enforcement_effect` value the pinned engine implements, sorted so the
 *  error message lists them the same way every time. See the header: adding one
 *  here is half a change — `src/watchlight/_annotations.py` holds the other half. */
export const ENFORCEMENT_EFFECTS = [
  "attenuate",
  "escalate",
  "observe",
  "quarantine",
  "require_approval",
  "revoke",
  "sever_subtree",
  "terminate",
] as const;

export type EnforcementEffect = (typeof ENFORCEMENT_EFFECTS)[number];

/** How close a misspelled annotation name has to be to `enforcement_effect`
 *  before it is called a near miss and warned about. Two edits over an
 *  18-character name means a candidate must be 16 to 20 characters long and at
 *  least ~89% identical, which covers every realistic typo — a dropped, doubled,
 *  transposed or substituted character, `-` for `_`, camelCase, a trailing
 *  plural, the wrong case — while no ordinary annotation (`description`,
 *  `owner`, `severity`, `obligate_redact`) comes anywhere near it. */
export const NEAR_MISS_MAX_EDITS = 2;

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*/;

/** Thrown at policy load by {@link Watchlight.allow} and {@link Watchlight.load}
 *  when a policy carries an `@enforcement_effect` value the engine does not
 *  implement.
 *
 *  It is thrown *before* the policy reaches the engine, so a policy set that
 *  would decide differently from what it says never loads at all. Carries the
 *  offending `value`, the `policy` name it came from, and the `accepted` set. */
export class PolicyError extends Error {
  readonly name = "PolicyError";
  /** The `@enforcement_effect` value as written. */
  readonly value: string;
  /** The name the policy was loaded under. */
  readonly policy: string;
  /** Every value the pinned engine implements. */
  readonly accepted: readonly string[] = ENFORCEMENT_EFFECTS;
  constructor(message: string, opts: { value: string; policy: string }) {
    super(message);
    this.value = opts.value;
    this.policy = opts.policy;
  }
}

// ── the parser ──────────────────────────────────────────────────────────────
//
// Annotations are read, never grepped. A policy BODY can contain the literal
// text `@enforcement_effect("terminate")` inside a Cedar string —
//
//     permit(principal, action, resource)
//     when { context.note == "@enforcement_effect(\"terminate\")" };
//
// — and that is a string, not an annotation. So the source is walked with a
// small scanner that knows three things: annotations are only legal at the HEAD
// of a policy (before `permit`/`forbid`), string literals are skipped over with
// their escapes, and `//` runs to end of line. Anything the scanner cannot read
// is handed to the engine unjudged rather than guessed at.

/** One annotation as written: `value` is `undefined` for a valueless `@name`. */
export interface PolicyAnnotation {
  name: string;
  value?: string;
}

/** Advance past whitespace and `//` comments (Cedar has no block comment). */
function skipTrivia(code: string, i: number): number {
  const n = code.length;
  while (i < n) {
    const c = code[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i += 1;
    } else if (code.startsWith("//", i)) {
      const nl = code.indexOf("\n", i);
      i = nl < 0 ? n : nl + 1;
    } else {
      break;
    }
  }
  return i;
}

/** Read the Cedar string literal starting at the opening quote `code[i]`.
 *  Returns the RAW contents (escapes left as written) and the index after the
 *  closing quote, or `undefined` on an unterminated literal — which makes the
 *  whole policy unreadable to us and therefore the engine's business, not ours. */
function readString(code: string, i: number): { raw: string; next: number } | undefined {
  const n = code.length;
  i += 1; // past the opening quote
  const start = i;
  while (i < n) {
    const c = code[i];
    if (c === "\\") {
      i += 2; // an escaped character never ends the literal
      continue;
    }
    if (c === '"') return { raw: code.slice(start, i), next: i + 1 };
    i += 1;
  }
  return undefined;
}

/** Every annotation on every policy in `code`, in source order — one entry per
 *  policy — or `undefined` when the source cannot be read, in which case nothing
 *  is judged and the engine reports whatever is actually wrong with it. */
export function parsePolicyAnnotations(code: string): PolicyAnnotation[][] | undefined {
  const n = code.length;
  const policies: PolicyAnnotation[][] = [];
  let current: PolicyAnnotation[] = [];
  let head = true; // annotations are only legal here, before the policy's effect
  let depth = 0; // brace depth, so a `;` inside `when { … }` is not a terminator
  let seen = false; // anything at all in the policy under construction?
  let i = 0;

  while (i < n) {
    i = skipTrivia(code, i);
    if (i >= n) break;
    const c = code[i];

    if (head && c === "@") {
      i += 1;
      const m = IDENT.exec(code.slice(i));
      if (!m) return undefined;
      const name = m[0];
      i = skipTrivia(code, i + name.length);
      let value: string | undefined;
      if (i < n && code[i] === "(") {
        i = skipTrivia(code, i + 1);
        if (i >= n || code[i] !== '"') return undefined;
        const read = readString(code, i);
        if (!read) return undefined;
        value = read.raw;
        i = skipTrivia(code, read.next);
        if (i >= n || code[i] !== ")") return undefined;
        i += 1;
      }
      current.push(value === undefined ? { name } : { name, value });
      seen = true;
      continue;
    }

    // Past the annotation block: this is the policy itself.
    head = false;
    seen = true;
    if (c === '"') {
      const read = readString(code, i);
      if (!read) return undefined;
      i = read.next;
      continue;
    }
    if (c === "{") depth += 1;
    else if (c === "}") depth -= 1;
    else if (c === ";" && depth <= 0) {
      policies.push(current);
      current = [];
      head = true;
      seen = false;
      i += 1;
      continue;
    }
    i += 1;
  }

  if (current.length > 0 || seen) policies.push(current);
  return policies;
}

// ── the checks ──────────────────────────────────────────────────────────────

/** Levenshtein distance between `a` and `b`, saturating at `limit + 1`. */
function editDistance(a: string, b: string, limit: number): number {
  if (Math.abs(a.length - b.length) > limit) return limit + 1;
  let previous = Array.from({ length: b.length + 1 }, (_, k) => k);
  for (let x = 1; x <= a.length; x += 1) {
    const current = [x];
    for (let y = 1; y <= b.length; y += 1) {
      current.push(
        Math.min(
          previous[y] + 1, // delete
          current[y - 1] + 1, // insert
          previous[y - 1] + (a[x - 1] === b[y - 1] ? 0 : 1) // substitute
        )
      );
    }
    if (Math.min(...current) > limit) return limit + 1;
    previous = current;
  }
  return previous[b.length];
}

/** Whether `name` is a near miss for `enforcement_effect` — close enough to be a
 *  typo of it, and not it. Case is folded first, so a name that differs only in
 *  case is a near miss too. */
export function isNearMiss(name: string): boolean {
  if (name === ENFORCEMENT_EFFECT_ANNOTATION) return false;
  const lowered = name.toLowerCase();
  return editDistance(lowered, ENFORCEMENT_EFFECT_ANNOTATION, NEAR_MISS_MAX_EDITS) <=
    NEAR_MISS_MAX_EDITS;
}

/** The one wording both lanes use, so the same mistake reads the same way in
 *  TypeScript and in Python. */
export function unrecognizedEffectMessage(at: string, value: string): string {
  return (
    `${at}: @${ENFORCEMENT_EFFECT_ANNOTATION}("${value}") is not an effect this engine ` +
    `implements. Accepted: ${ENFORCEMENT_EFFECTS.join(", ")}. An effect the engine does ` +
    "not implement is dropped, and on a `permit` that turns an approval hold into an " +
    "unconditional allow — so the policy is refused here rather than deciding differently " +
    "from what it says."
  );
}

/** The one wording both lanes use for an annotation NAME that looks like a typo
 *  of `@enforcement_effect`. */
export function nearMissMessage(at: string, written: string): string {
  return (
    `watchlight: ${at}: \`@${written}\` is not an annotation Watchlight reads, and it is a ` +
    `near miss for \`@${ENFORCEMENT_EFFECT_ANNOTATION}\`. As written it is inert — the ` +
    "policy decides as if the effect were absent, so an approval gate would be a plain " +
    "allow. Fix the spelling, or ignore this if the annotation is your own."
  );
}

/** Refuse a policy whose `@enforcement_effect` the engine cannot honour, and
 *  warn on an annotation name that looks like a typo of it.
 *
 *  Silent on every correct policy, on every annotation that is not ours, and on
 *  a source this parser cannot read — the engine reports that.
 *
 *  `{ warn: false }` throws the same way and says nothing: it is the pass
 *  {@link Watchlight.load} makes over a whole file BEFORE adding any of it, so a
 *  file with one bad policy loads none of it and the near-miss warnings are
 *  still printed exactly once, by the load itself. */
export function checkPolicyAnnotations(
  code: string,
  policyName: string,
  opts: { warn?: boolean } = {}
): void {
  if (typeof code !== "string" || !code.includes("@")) return;
  const parsed = parsePolicyAnnotations(code);
  if (!parsed) return;
  const where = `policy "${policyName}"`;
  for (const annotations of parsed) {
    for (const annotation of annotations) {
      if (annotation.name === ENFORCEMENT_EFFECT_ANNOTATION) {
        checkEffectValue(annotation.value, where, policyName);
        continue;
      }
      if (opts.warn === false) continue;
      if (isNearMiss(annotation.name)) {
        // eslint-disable-next-line no-console
        console.warn(nearMissMessage(where, annotation.name));
      }
    }
  }
}

function checkEffectValue(value: string | undefined, at: string, policyName: string): void {
  const written = value ?? "";
  // An escape sequence in the value: we read literals raw, so we cannot say what
  // the engine will decode this to. No verb needs an escape, so this is not a
  // shape anyone writes on purpose — judging it would risk refusing a policy the
  // engine accepts, which is worse than staying quiet.
  if (written.includes("\\")) return;
  if ((ENFORCEMENT_EFFECTS as readonly string[]).includes(written)) return;
  throw new PolicyError(unrecognizedEffectMessage(at, written), {
    value: written,
    policy: policyName,
  });
}
