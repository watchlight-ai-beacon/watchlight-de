// Cedar entity references for the acting subject — built here so callers never
// paste an untrusted id into one by hand.
//
// `principal` is a free-form string at every layer, and the id in it is usually
// taken from an identity the application has already verified (the `sub` of a
// token, say), which is an arbitrary string: it may contain a quote, a
// backslash or a space.
//
// A request and a policy write a Cedar entity reference the same way. The
// engine reads every request principal, action and resource with the same
// strict parser it uses for policy text, so the id inside the quotes is a Cedar
// string literal on both sides: a quote or a backslash in it must be escaped.
// The id `a"b` is written `User::"a\"b"` in a request and in a policy alike. An
// unescaped reference such as `User::"a"b"` is not read as some other entity:
// the engine refuses the request as invalid.
//
// So build every reference from an outside id with `principals.user`,
// `principals.agent` or `principals.entity`, which escape the id for you.
// `principals.forPolicy` returns the same string as `principals.entity` for
// every id `entity` accepts, so a reference built for a request matches the
// same reference written into a policy.
//
//   principals.user("db:4412")             →  User::"db:4412"
//   principals.user('a"b')                 →  User::"a\"b"
//   principals.agent("research-agent")     →  Agent::"research-agent"
//   principals.forPolicy("User", 'a"b')    →  User::"a\"b"
//
// A BARE principal, one written without `Type::"…"`, is read by the engine as a
// `User`: `team-42` is the entity `User::"team-42"`. It matches
// `principal is User` and a policy naming `User::"team-42"`, and never a policy
// of another type. Write the type to name anything other than a user. In the
// same way a bare action is read as an `Action` and a bare resource as a
// `Resource`. A bare name that holds a quote, or `::`, is refused as invalid.
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
 * A Cedar entity reference, `<Type>::"<id>"`, for a request.
 *
 * The id is escaped exactly as {@link policyEntityRef} escapes it, because the
 * engine reads a request reference with the same strict parser it uses for
 * policy text: a quote or a backslash in the id must be escaped, or the request
 * is refused as invalid. The engine reads the returned string back as exactly
 * `id`, so a crafted id can never name another entity or another type.
 *
 * These ids are refused rather than silently changed:
 *
 *   * an empty id;
 *   * an id with control characters, which no request principal may carry;
 *   * an id whose escaped reference is longer than {@link MAX_NAME_BYTES}
 *     bytes of UTF-8, because the reference is recorded on every audit row.
 */
export function entityRef(type: string, id: string): string {
  checkType(type);
  if (typeof id !== "string" || id === "") {
    throw new TypeError("entity reference: id must be a non-empty string");
  }
  if (CONTROL_CHARS.test(id)) {
    throw new TypeError("entity reference: id must not contain control characters");
  }
  const reference = `${type}::"${escapeCedarString(id)}"`;
  if (utf8Length(reference) > MAX_NAME_BYTES) throw new TypeError(ENTITY_TOO_LONG_MESSAGE);
  return reference;
}

/** The reference written into the text of a policy you generate.
 *
 *  For every id {@link entityRef} accepts, this returns the same string as
 *  `entityRef`: requests and policies spell a reference the same way, so
 *  `principals.user(sub)` in a request matches `principals.forPolicy("User",
 *  sub)` in a policy. Both names stay public. The one difference is that policy
 *  text is not a request: an id with control characters is escaped here (`\n`,
 *  `\u{…}`) instead of refused, and the length is not bounded. Such a policy can
 *  never match a request, because no request principal may carry a control
 *  character. */
export function policyEntityRef(type: string, id: string): string {
  checkType(type);
  if (typeof id !== "string" || id === "") {
    throw new TypeError("entity reference: id must be a non-empty string");
  }
  return `${type}::"${escapeCedarString(id)}"`;
}

// ── bounds on what the SDK records ──────────────────────────────────────────
//
// Every audit record the SDK writes must stay below the line limit the counters
// read (`MAX_COUNTERS_LINE_BYTES`, 1 MiB): a line over it counts toward every
// quota (fail-closed), so a record that could exceed it would let a caller
// exhaust every quota. These bounds are what guarantee it. The worst case each
// record kind can reach is built and measured by `ts/test/counters.test.mjs`
// (and `tests/test_record_bounds.py` in Python): under 270,000 bytes with
// TypeScript's escaping and under 400,000 with Python's, at most about 38% of
// the limit. All bounds are measured in UTF-8 bytes, so both language packages
// draw every line in exactly the same place.

/** The longest name the SDK decides on or records: a principal, an action
 *  (intent), a resource, and each entry of a scope's tool, resource and intent
 *  lists. Real names are a few dozen bytes; 4 KiB leaves room for a long URL or
 *  path as a resource. A longer name is refused before anything is decided or
 *  recorded. */
export const MAX_NAME_BYTES = 4096;

/** The longest agent name: short enough that the principal derived from it,
 *  `Agent::"<name>"`, is itself within {@link MAX_NAME_BYTES}. The bound applies
 *  to the escaped name too (a quote or a backslash counts two bytes there). */
export const MAX_AGENT_NAME_BYTES = MAX_NAME_BYTES - 'Agent::""'.length;

/** The most entries a scope's `tools`, `resources` or `intents` list may hold. */
export const MAX_SCOPE_ENTRIES = 256;

/** The most UTF-8 bytes the entries of one scope list may hold in total. */
export const MAX_SCOPE_LIST_BYTES = 64 * 1024;

/** The most UTF-8 bytes the agent names of one delegation chain may hold in
 *  total. The chain is written on every record a delegated governor produces. */
export const MAX_ACTOR_CHAIN_BYTES = 64 * 1024;

/** The fixed, value-free message a name over {@link MAX_NAME_BYTES} is refused with. */
export const NAME_TOO_LONG_MESSAGE = `is longer than the maximum of ${MAX_NAME_BYTES} bytes`;

const utf8Length = (value: string): number => Buffer.byteLength(value, "utf8");

/** The fixed, value-free message an entity reference over
 *  {@link MAX_NAME_BYTES} is refused with. @internal */
export const ENTITY_TOO_LONG_MESSAGE =
  `entity reference: the escaped reference is longer than the maximum of ${MAX_NAME_BYTES} bytes`;

/** Refuse a string `value` longer than `limit` (default {@link MAX_NAME_BYTES})
 *  UTF-8 bytes and return it unchanged otherwise. A non-string passes through:
 *  the type is each caller's own rule. The message names the field and the
 *  bound, never the value. A lone surrogate counts 3 bytes, as in Python.
 *  @internal */
export function assertNameLength<T>(
  value: T,
  field: string,
  makeError: (message: string) => Error = (m) => new TypeError(m),
  limit: number = MAX_NAME_BYTES
): T {
  // Cheap first test: at most 3 UTF-8 bytes per UTF-16 code unit, so a string
  // of at most limit / 3 code units cannot exceed the bound.
  if (typeof value === "string" && value.length * 3 > limit && utf8Length(value) > limit) {
    throw makeError(`${field} is longer than the maximum of ${limit} bytes`);
  }
  return value;
}

/** A name the SDK decides on and records — an action, a resource, a scope
 *  entry: a string, with no control characters, of at most
 *  {@link MAX_NAME_BYTES}. Refused value-free otherwise. @internal */
export function assertName(
  value: unknown,
  field: string,
  makeError: (message: string) => Error = (m) => new TypeError(m)
): string {
  if (typeof value !== "string") throw makeError(`${field} must be a string`);
  if (CONTROL_CHARS.test(value)) throw makeError(`${field} must not contain control characters`);
  return assertNameLength(value, field, makeError);
}

/** An agent name: a non-empty string with no control characters, of at most
 *  {@link MAX_AGENT_NAME_BYTES}, whose principal `Agent::"<name>"` (with the
 *  name escaped, see {@link entityRef}) is at most {@link MAX_NAME_BYTES}.
 *  Throws a `TypeError` prefixed with `where`. @internal */
export function assertAgentNameRules(value: unknown, where: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new TypeError(`${where}: agent must be a non-empty string`);
  }
  if (CONTROL_CHARS.test(value)) {
    throw new TypeError(`${where}: agent must not contain control characters`);
  }
  assertNameLength(value, `${where}: agent`, (m) => new TypeError(m), MAX_AGENT_NAME_BYTES);
  // A quote or a backslash takes two bytes once escaped, so a name of at most
  // MAX_AGENT_NAME_BYTES can still make a longer principal. It is refused here,
  // at the name, rather than later when the principal is built.
  if (utf8Length(escapeCedarString(value)) > MAX_AGENT_NAME_BYTES) {
    throw new TypeError(
      `${where}: agent is longer than the maximum of ${MAX_AGENT_NAME_BYTES} bytes once escaped for its entity reference`
    );
  }
  return value;
}

/** Refuse a delegation chain whose agent names hold more than
 *  {@link MAX_ACTOR_CHAIN_BYTES} in total. @internal */
export function assertActorChain(chain: readonly string[], where: string): void {
  let total = 0;
  for (const name of chain) total += utf8Length(name);
  if (total > MAX_ACTOR_CHAIN_BYTES) {
    throw new TypeError(
      `${where}: the delegation chain is longer than the maximum of ${MAX_ACTOR_CHAIN_BYTES} bytes`
    );
  }
}

/** A scope's `tools` / `resources` / `intents`: `undefined` (inherit), or at
 *  most {@link MAX_SCOPE_ENTRIES} names (each checked by {@link assertName}) of
 *  at most {@link MAX_SCOPE_LIST_BYTES} in total.
 *
 *  Returns the array it checked — read from `values` exactly once — and the
 *  caller must use THAT array: iterating `values` again could yield something
 *  else (an iterable that changes between passes), or nothing (a generator
 *  already used up). `null` and `undefined` return `undefined`. @internal */
export function assertNameList(values: unknown, field: string): string[] | undefined {
  if (values === undefined || values === null) return undefined;
  if (typeof values === "string" || typeof (values as Iterable<unknown>)[Symbol.iterator] !== "function") {
    throw new TypeError(`${field} must be a list of strings`);
  }
  const items = [...(values as Iterable<unknown>)];
  if (items.length > MAX_SCOPE_ENTRIES) {
    throw new TypeError(`${field} holds more than the maximum of ${MAX_SCOPE_ENTRIES} entries`);
  }
  let total = 0;
  const checked: string[] = [];
  for (const item of items) {
    checked.push(assertName(item, `${field} entry`));
    total += utf8Length(checked[checked.length - 1]);
  }
  if (total > MAX_SCOPE_LIST_BYTES) {
    throw new TypeError(`${field} is longer than the maximum of ${MAX_SCOPE_LIST_BYTES} bytes in total`);
  }
  return checked;
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
 * It is not parsed here; the engine parses it when it decides. A typed
 * reference must be well formed, with the id escaped as {@link entityRef}
 * escapes it, or the engine refuses the request. A bare identifier is read as a
 * `User` (see `docs/identity-model.md`). What was checked is what is recorded:
 * the record carries the principal exactly as the caller wrote it.
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
   *  from an identity it has already verified. `User::"<subject>"`, with the
   *  subject escaped as {@link entityRef} escapes it. */
  user: (subject: string): string => entityRef("User", subject),
  /** The agent acting on its own behalf. `Agent::"<name>"`, with the name
   *  escaped as {@link entityRef} escapes it. */
  agent: (name: string): string => entityRef("Agent", name),
  /** Any other entity type the policy set uses. */
  entity: entityRef,
  /** The reference to write into policy text. The same string as `entity`
   *  for every id `entity` accepts. */
  forPolicy: policyEntityRef,
} as const;
