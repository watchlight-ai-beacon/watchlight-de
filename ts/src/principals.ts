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
