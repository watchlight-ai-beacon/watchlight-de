// Cedar entity references for the acting subject — built here so callers never
// paste an untrusted id into one by hand.
//
// `principal` is a free-form string at every layer, and the id in it is usually
// taken from an identity the application has already verified (the `sub` of a
// token, say), which is an arbitrary string: it may contain a quote, a
// backslash or a space.
//
// The two sides of a Cedar entity reference are NOT written the same way:
//
//   * a REQUEST (what the SDK sends and records) carries the id verbatim —
//     `User::"a"b"` is the id `a"b`;
//   * a POLICY is Cedar source, so the same id must be escaped for the parser —
//     `permit(principal == User::"a\"b", …)`.
//
// So: build the request side with `principals.user` / `principals.agent`, and
// the policy side with `principals.forPolicy` (or `escapeCedarString`). A
// reference built with one matches a reference built with the other.
//
//   principals.user("db:4412")             →  User::"db:4412"
//   principals.agent("research-agent")     →  Agent::"research-agent"
//   principals.forPolicy("User", sub)      →  User::"…" for policy text
//
// The vocabulary the SDK writes and the audit trail carries:
//   * `User::"<subject>"` — the person a call runs on behalf of (RFC 8693 `sub`);
//     a stable, opaque id — a primary key, an account id, a subject claim —
//     never an email address or a username, both of which move and make an old
//     audit row point at someone else. Namespace it (`db:`, `sso:`) when more
//     than one identity source can produce subjects
//   * `Agent::"<name>"`   — the agent acting on its own behalf; what a call that
//     names no subject records
//   * which runtime executed the call is NOT the principal: it is the reserved
//     `context.actor` key (RFC 8693 `act.sub`; see `ACTOR_CONTEXT_KEY`).

const TYPE_NAME = /^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/** Escape a Cedar string literal's contents for POLICY TEXT: the two characters
 *  that would end or re-open the literal, plus the control characters a literal
 *  cannot carry raw. Use it when an id from outside goes into a policy you
 *  generate. */
export function escapeCedarString(value: string): string {
  let out = "";
  for (const ch of String(value)) {
    if (ch === "\\") out += "\\\\";
    else if (ch === '"') out += '\\"';
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (CONTROL_CHARS.test(ch)) out += `\\u{${ch.codePointAt(0)!.toString(16)}}`;
    else out += ch;
  }
  return out;
}

function checkType(type: string): void {
  if (!TYPE_NAME.test(type)) {
    throw new TypeError("entity reference: type must be a Cedar entity type name");
  }
}

/**
 * A Cedar entity reference for a REQUEST — `<Type>::"<id>"`, id verbatim, which
 * is how the engine reads the principal of an authorization. An empty id, or
 * one carrying control characters (which no reference can represent
 * unambiguously), is refused rather than silently mangled.
 */
export function entityRef(type: string, id: string): string {
  checkType(type);
  if (typeof id !== "string" || id === "") {
    throw new TypeError("entity reference: id must be a non-empty string");
  }
  if (CONTROL_CHARS.test(id)) {
    throw new TypeError("entity reference: id must not contain control characters");
  }
  return `${type}::"${id}"`;
}

/** The same reference as Cedar SOURCE, for a policy you generate: the id is
 *  escaped so the parser reads it back exactly. `principals.user(sub)` in a
 *  request matches `principals.forPolicy("User", sub)` in a policy. */
export function policyEntityRef(type: string, id: string): string {
  checkType(type);
  if (typeof id !== "string" || id === "") {
    throw new TypeError("entity reference: id must be a non-empty string");
  }
  return `${type}::"${escapeCedarString(id)}"`;
}

/** The longest name the SDK decides on or records, in bytes of UTF-8: a
 *  principal, an action (intent), a resource, an agent name. Real names are a
 *  few dozen bytes; 4 KiB leaves room for a long URL or path as a resource. The
 *  bound keeps every audit record far below the line limit the counters read
 *  (`MAX_COUNTERS_LINE_BYTES`, 1 MiB), so no record the SDK writes is too long
 *  to be counted. A longer name is refused before anything is decided or
 *  recorded. Measured in UTF-8 bytes so both language packages draw the line at
 *  exactly the same place. */
export const MAX_NAME_BYTES = 4096;

/** The fixed, value-free message a name over {@link MAX_NAME_BYTES} is refused with. */
export const NAME_TOO_LONG_MESSAGE = `is longer than the maximum of ${MAX_NAME_BYTES} bytes`;

/** Refuse a string `value` longer than {@link MAX_NAME_BYTES} (UTF-8 bytes) and
 *  return it unchanged otherwise. A non-string passes through: the type is each
 *  caller's own rule. The message names the field and the bound, never the
 *  value. A lone surrogate counts 3 bytes, as in Python. @internal */
export function assertNameLength<T>(
  value: T,
  field: string,
  makeError: (message: string) => Error = (m) => new TypeError(m)
): T {
  // Cheap first test: at most 3 UTF-8 bytes per UTF-16 code unit, so a string
  // of at most MAX_NAME_BYTES / 3 code units cannot exceed the bound.
  if (
    typeof value === "string" &&
    value.length * 3 > MAX_NAME_BYTES &&
    Buffer.byteLength(value, "utf8") > MAX_NAME_BYTES
  ) {
    throw makeError(`${field} ${NAME_TOO_LONG_MESSAGE}`);
  }
  return value;
}

/** What a caller-supplied `principal` must satisfy at EVERY boundary that takes
 *  one — the same two rules `entityRef` already applies to an id, applied to the
 *  whole reference. The message is fixed and never echoes the value. */
export const PRINCIPAL_EMPTY_MESSAGE = "principal must be a non-empty string";
export const PRINCIPAL_CONTROL_MESSAGE = "principal must not contain control characters";

/**
 * Check a caller-supplied `principal` and return it unchanged.
 *
 * The principal is recorded verbatim and is the subject of every audit row, so
 * a value that cannot be a subject is refused at the boundary rather than
 * written. Three rules:
 *
 *   * it must be a non-empty string — blank (or whitespace-only) is a mistake,
 *     never a request for the default. `user?.id ?? ""` reaching a governed call
 *     used to be recorded as the AGENT, attributing a person's action to the
 *     runtime;
 *   * it must carry no control characters, which no reference can represent
 *     unambiguously;
 *   * it must be at most {@link MAX_NAME_BYTES} bytes of UTF-8, so the record
 *     that carries it stays short enough to be read back and counted.
 *
 * It is deliberately NOT parsed: a bare identifier is a valid, opaque principal
 * (see `docs/identity-model.md`), and only a typed `Type::"id"` reference
 * discriminates by type.
 *
 * `makeError` lets a primitive raise its own typed error; the default is the
 * `TypeError` the identity builders raise. @internal
 */
export function assertPrincipal(
  value: unknown,
  makeError: (message: string) => Error = (m) => new TypeError(m)
): string {
  if (typeof value !== "string" || !value.trim()) throw makeError(PRINCIPAL_EMPTY_MESSAGE);
  if (CONTROL_CHARS.test(value)) throw makeError(PRINCIPAL_CONTROL_MESSAGE);
  assertNameLength(value, "principal", makeError);
  return value;
}

/** Builders for the principal an application asserts. */
export const principals = {
  /** The person a call runs on behalf of — the subject an application takes
   *  from an identity it has already verified. */
  user: (subject: string): string => entityRef("User", subject),
  /** The agent acting on its own behalf. */
  agent: (name: string): string => entityRef("Agent", name),
  /** Any other entity type the policy set uses. */
  entity: entityRef,
  /** The reference to write into POLICY text (escaped). */
  forPolicy: policyEntityRef,
} as const;
