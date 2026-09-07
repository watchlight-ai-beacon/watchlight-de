// govern.sanitize — governed data minimization at the agent boundary.
//
// Strip PII from text BEFORE an agent reads it. Deterministic, in-process,
// fail-closed. This is the Developer-Edition baseline detector: high-precision
// STRUCTURED PII via rules (email, phone, SSN, credit card w/ Luhn, IBAN, IPv4,
// API keys, labelled passport numbers + MRZ lines, labelled dates of birth),
// plus an application-supplied dictionary of KNOWN values (exact strings the
// caller already holds — names, streets, ids). Free-text names and addresses
// are available as OPT-IN heuristics (PERSON, ADDRESS) — lower precision, off
// by default — so recall is honestly bounded by the enabled detectors and
// surfaced in the report.
//
// Operates on extracted TEXT. Document extraction (PDF/docx → text, across all
// layers) is a separate step: you never hand the agent a "redacted PDF" (its
// hidden layers leak) — you hand it redacted text.
//
// Regex safety: every repetition is either bounded, or anchored on a literal
// prefix / run start so a failed attempt cannot rescan the same run (EMAIL's
// local part is bounded to 64 and may only start where a run of local-part
// characters starts). No nested unbounded repetition; the test suites assert
// adversarial 100k-character inputs complete in well under 100 ms.

import { createHash } from "node:crypto";
import { assertPrincipal } from "./principals";

/** PII categories the deterministic detector recognizes. */
export type PiiType =
  | "EMAIL"
  | "PHONE"
  | "SSN"
  | "CREDIT_CARD"
  | "IBAN"
  | "IPV4"
  | "API_KEY"
  | "PASSPORT"
  | "DOB"
  | "KNOWN"
  | "PERSON"
  | "ADDRESS";

/** A built-in {@link PiiType}, or a label registered with
 *  {@link registerDetector}. The `string & {}` keeps editor autocomplete for the
 *  built-ins while still accepting a custom label. */
export type DetectorLabel = PiiType | (string & {});

/** How a detected value is replaced. */
export type RedactMode = "tag" | "mask" | "hash";

/** Detector-set version, recorded on every report / audit line. Bump whenever
 *  a detector is added, removed or its shape changes. */
export const DETECTOR_VERSION = "de-rules-2";

/** Heuristic detectors: lower precision, OFF unless listed in `types`. */
export const HEURISTIC_PII_TYPES: readonly PiiType[] = ["PERSON", "ADDRESS"];

/** Raised when sanitization cannot complete — fail-closed: the caller must NOT
 *  fall back to raw content. */
export class SanitizeError extends Error {
  constructor(message: string) {
    super(`sanitize failed (fail-closed): ${message}`);
    this.name = "SanitizeError";
  }
}

/** Bounds on a caller-supplied `decisionId`: an opaque correlation token, never
 *  interpreted. Length-capped and free of control characters so it can be
 *  written to the audit line without letting the caller inject or bloat it. */
export const DECISION_ID_MAX_LENGTH = 128;
// eslint-disable-next-line no-control-regex
// Also U+2028/U+2029: JSON.stringify emits them raw, and a line-oriented
// reader would split the audit record in two.
const DECISION_ID_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

export interface SanitizeOptions {
  /** Replacement strategy. Default `"tag"` (consistent `<EMAIL_1>` placeholders). */
  mode?: RedactMode;
  /** Restrict to these PII types. Default: every structured type (all types
   *  except the heuristics `PERSON` / `ADDRESS`, which must be listed here to
   *  run). `KNOWN` is enabled by supplying `known`, independent of this list. */
  types?: DetectorLabel[];
  /** Intent label for the `sanitization` audit record. Default `"read"`.
   *  Used by `Watchlight.sanitize`; the pure `sanitize()` ignores it. */
  intent?: string;
  /** Resource label for the `sanitization` audit record. Default `"document"`.
   *  Used by `Watchlight.sanitize`; the pure `sanitize()` ignores it. */
  resource?: string;
  /** Correlation id of the `authorize` decision that governed this read. Echoed
   *  onto `report.decisionId` and written as `decision_id` on the `sanitization`
   *  audit record, so the two audit lines join on the same key. Opaque: must be
   *  1–{@link DECISION_ID_MAX_LENGTH} characters with no control characters. */
  decisionId?: string;
  /** Who the text is being sanitized FOR — the Cedar principal, exactly as it
   *  is written on the decision record (e.g. `User::"u1"`). Echoed onto
   *  `report.principal` and written as `principal` on the `sanitization` audit
   *  record, so "what was redacted, for whom" is answerable from that record
   *  alone — including when the sanitization happens BEFORE any decision exists
   *  to join to. Opaque and never interpreted; validated exactly like
   *  `decisionId` (1–{@link DECISION_ID_MAX_LENGTH} characters, no control or
   *  line-separator characters). An identifier the caller supplies — never
   *  anything derived from the content. */
  principal?: string;
  /** Application-supplied dictionary: exact strings to redact (names, streets,
   *  ids the caller already holds). Matched as substrings with simple
   *  (ASCII-style) case-insensitivity — Unicode case folding differs between
   *  the TypeScript and Python lanes; every occurrence is covered — overlapping
   *  or nested occurrences merge into one span. Counted under `KNOWN`. The
   *  values never appear in the output, the report, or the audit trail. */
  known?: string[];
}

export interface SanitizeReport {
  mode: RedactMode;
  detectorVersion: string;
  /** Count of redactions per type. Value-free by construction — never the values. */
  counts: Partial<Record<DetectorLabel, number>>;
  /** Total redactions. */
  total: number;
  /** The `decisionId` supplied by the caller, if any (validated, never interpreted). */
  decisionId?: string;
  /** The `principal` supplied by the caller, if any (validated, never interpreted). */
  principal?: string;
}

export interface SanitizeResult {
  /** The redacted text, safe to hand to an agent. */
  text: string;
  /** Value-free summary of what was redacted (for the audit trail). */
  report: SanitizeReport;
}

// ── deterministic detectors ─────────────────────────────────────────
// Each returns [start, end) match spans over the input. High precision first;
// CREDIT_CARD is Luhn-validated to cut false positives.

const luhnOk = (digits: string): boolean => {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
};

interface Detector {
  type: DetectorLabel;
  re: RegExp;
  /** Optional validator on the redacted value; false drops it. */
  valid?: (m: string) => boolean;
  /** Optional front-trim of the redacted value (returns the kept suffix, or
   *  null to drop the match). Runs before `valid`. */
  trim?: (m: string) => string | null;
  /** When true the redacted span is capture group 1, which is always the LAST
   *  component of the match (a label such as `DOB:` precedes it and is kept). */
  group?: boolean;
  /** False for opt-in heuristics (must be listed in `types` to run). */
  defaultOn: boolean;
}

// ── shared shapes (bounded quantifiers only) ──
const MONTH = "(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}\\.?";
const DAY_ORD = "\\d{1,2}(?:st|nd|rd|th)?";
const DATE_SHAPE =
  "(?:\\d{4}[/.-]\\d{1,2}[/.-]\\d{1,2}" + // 1985-03-15
  "|\\d{1,2}[/.-]\\d{1,2}[/.-]\\d{2,4}" + // 03/15/1985, 15.03.85
  `|${DAY_ORD}[ \\t]{1,3}${MONTH}[ \\t]{1,3}\\d{4}` + // 15 March 1985
  `|${MONTH}[ \\t]{1,3}${DAY_ORD},?[ \\t]{1,3}\\d{4})`; // March 15, 1985
const DOB_LABEL =
  "(?:d\\.?o\\.?b\\.?|date[ \\t]{1,3}of[ \\t]{1,3}birth|birth[ \\t]?date|birthday|born(?:[ \\t]{1,3}on)?)";
const CAP_WORD = "[A-Z][a-z]{1,20}";
// "Ada", "O'Neil", "D'Angelo", "McDonald", "Lovelace-Smith", "McDonald-Lee".
const NAME_PART = `${CAP_WORD}(?:${CAP_WORD})?`;
const NAME_WORD = `(?:[A-Z]')?${NAME_PART}(?:[-']${NAME_PART})?`;
const HONORIFIC = "(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Dame|Rev|Hon)\\.?";
// Case-tolerant label (the pattern itself is case-sensitive so name words stay Title Case).
const PERSON_LABEL =
  "(?:[Nn]ame|[Pp]atient|[Cc]ustomer|[Cc]lient|[Ee]mployee|[Cc]ontact|[Aa]ttn|ATTN|[Aa]ttention|[Aa]pplicant|[Bb]eneficiary)";
const STREET_SUFFIX =
  "(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Square|Sq|Trail|Trl|Close|Crescent|Cres)";

/** Plausibility check for numeric date shapes (labelled contexts only). */
const plausibleDate = (m: string): boolean => {
  if (!/^\d/.test(m) || !/^[\d/.-]+$/.test(m)) return true; // textual month: shape already strict
  const parts = m.split(/[/.-]/).map((p) => Number(p));
  if (parts.length !== 3 || parts.some((p) => Number.isNaN(p))) return false;
  const yearIdx = parts.findIndex((p) => p >= 1000);
  const small = parts.filter((_, i) => i !== yearIdx);
  if (yearIdx >= 0 && (parts[yearIdx] < 1900 || parts[yearIdx] > 2099)) return false;
  if (yearIdx < 0) small.pop(); // two-digit year in last position
  return small.every((p) => p >= 1 && p <= 31) && Math.min(...small) <= 12;
};

/** Common capitalized sentence starters / calendar words that are not names.
 *  Leading stop words are trimmed off a candidate; the remaining name is kept. */
const PERSON_STOP = new Set([
  "The", "This", "That", "These", "Those", "There", "Then", "Thanks", "Thank", "Please", "Dear",
  "Hello", "Hi", "Hey", "Our", "Your", "Their", "His", "Her", "New", "Re", "Subject", "From", "To",
  "Date", "Sent", "Cc", "Bcc", "Note", "Notes", "Summary", "Total", "Amount", "Invoice", "Order",
  "Account", "Card", "Page", "Section", "Chapter", "Table", "Figure", "See", "Also", "However",
  "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
  "January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
  "November", "December",
]);

/** Strip leading stop words; drop the candidate if fewer than two words remain. */
const trimPersonStop = (m: string): string | null => {
  let v = m;
  for (;;) {
    const i = v.search(/[ \t]/);
    if (i < 0) return null; // single word left → not a name candidate
    if (!PERSON_STOP.has(v.slice(0, i))) return v;
    v = v.slice(i).replace(/^[ \t]+/, "");
  }
};

const DETECTORS: Detector[] = [
  // Local part bounded (RFC 5321: 64) and only attempted where a run of
  // local-part characters begins, so a long run without "@" is scanned once.
  {
    type: "EMAIL",
    re: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
    defaultOn: true,
  },
  // API keys / tokens with well-known prefixes (before generic patterns).
  {
    type: "API_KEY",
    re: /\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g,
    defaultOn: true,
  },
  // Redaction, not validation: the excluded area/group ranges are not ISSUABLE
  // SSNs, but a mistyped one on a form is still somebody's disclosure. Matching
  // the shape over-redacts at worst; excluding the ranges leaks.
  { type: "SSN", re: /\b\d{3}-\d{2}-\d{4}\b/g, defaultOn: true },
  {
    type: "CREDIT_CARD",
    re: /\b(?:\d[ -]?){13,19}\b/g,
    valid: (m) => {
      const d = m.replace(/[ -]/g, "");
      return d.length >= 13 && d.length <= 19 && luhnOk(d);
    },
    defaultOn: true,
  },
  { type: "IBAN", re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,3})?\b/g, defaultOn: true },
  {
    type: "IPV4",
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    valid: (m) => m.split(".").every((o) => Number(o) <= 255),
    defaultOn: true,
  },
  // PASSPORT (a): a number labelled as a passport — 6–9 alphanumerics with at
  // least one digit. Bare unlabelled numbers are NOT detected (too ambiguous;
  // list held numbers in `known`).
  {
    type: "PASSPORT",
    re: /\bpassport(?:[ \t]{1,3}(?:no|number|num|nr))?\.?[ \t]{0,4}[:#-]{0,2}[ \t]{0,4}([A-Za-z0-9]{6,9})(?![A-Za-z0-9])/gi,
    group: true,
    valid: (m) => /\d/.test(m),
    defaultOn: true,
  },
  // PASSPORT (b): ICAO 9303 TD3 machine-readable-zone lines (44 chars) as
  // produced by OCR of a passport data page — line 1 (P<ISO name<<...) and
  // line 2 (number, check digit, nationality, DOB, sex, expiry, ...).
  {
    type: "PASSPORT",
    re: /(?<![A-Z0-9<])(?:P[A-Z<][A-Z]{3}[A-Z<]{39}|[A-Z0-9<]{9}\d[A-Z<]{3}\d{7}[MF<]\d{7}[A-Z0-9<]{14}\d{2})(?![A-Z0-9<])/g,
    defaultOn: true,
  },
  // DOB: a date in a birth-date context (`DOB:`, `date of birth`, `born on`).
  // Bare dates are not detected — a statement date is not a birth date.
  {
    type: "DOB",
    re: new RegExp(`\\b${DOB_LABEL}[ \\t]{0,4}[:#=-]?[ \\t]{0,4}(${DATE_SHAPE})(?!\\d)`, "gi"),
    group: true,
    valid: plausibleDate,
    defaultOn: true,
  },
  // PHONE (a): the North-American shapes — optional country code, optional
  // parenthesised area code, 3+4. Tops out at ten digits when unseparated,
  // which is why (b) exists.
  {
    type: "PHONE",
    re: /(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\d)/g,
    // Require at least 10 digits total to avoid matching short number runs.
    valid: (m) => (m.replace(/\D/g, "").length >= 10),
    defaultOn: true,
  },
  // PHONE (b): E.164 with no separators — `+` then 8 to 15 digits. This is the
  // format systems NORMALISE to, so it is what arrives from a contact import, a
  // CRM export or a `tel:` link, and (a) missed it in every country. The leading
  // `+` is what makes a bare long digit run unambiguous enough to match.
  {
    type: "PHONE",
    re: /(?<![\d+])\+\d{8,15}(?!\d)/g,
    defaultOn: true,
  },
  // PHONE (c): international and national GROUPED forms — `+44 20 7183 8750`,
  // `020 7183 8750`, `+1-555-0142-8899`. Two or more separated groups and a
  // 10-15 digit total, which excludes a date (8 digits or fewer) and a card
  // (16), both of which have detectors of their own.
  {
    type: "PHONE",
    re: /(?<![\d+])\+?\d{2,4}(?:[ .-]\d{2,5}){2,4}(?!\d)/g,
    valid: (m) => {
      const n = m.replace(/\D/g, "").length;
      return n >= 10 && n <= 15;
    },
    defaultOn: true,
  },
  // ── opt-in heuristics (default OFF; list in `types` to enable) ──
  // ADDRESS: "<number> <Capitalized words> <street suffix>[, unit][, City, ST 12345]"
  // and "P.O. Box <n>". Misses unnumbered / lower-case / non-Latin addresses.
  {
    type: "ADDRESS",
    re: new RegExp(
      `\\b(?:\\d{1,6}[A-Za-z]?[ \\t]{1,3}(?:${CAP_WORD}[ \\t]{1,3}){1,4}${STREET_SUFFIX}\\b\\.?` +
        `(?:,?[ \\t]{1,3}(?:Apt|Suite|Ste|Unit|#)\\.?[ \\t]{0,3}[A-Za-z0-9-]{1,8})?` +
        `(?:,[ \\t]{1,3}${CAP_WORD}(?:[ \\t]${CAP_WORD}){0,2},?[ \\t]{1,3}[A-Z]{2}[ \\t]{1,3}\\d{5}(?:-\\d{4})?)?` +
        `|\\bP\\.?[ \\t]?O\\.?[ \\t]{1,3}Box[ \\t]{1,3}\\d{1,6}\\b)`,
      "g"
    ),
    defaultOn: false,
  },
  // PERSON (a): honorific- or label-anchored names ("Dr. Ada Lovelace",
  // "Patient: Ada Lovelace").
  {
    type: "PERSON",
    re: new RegExp(
      `\\b(?:${HONORIFIC}|${PERSON_LABEL}[ \\t]{0,3}[:#-]?)[ \\t]{1,4}(${NAME_WORD}(?:[ \\t]{1,3}[A-Z]\\.)?(?:[ \\t]{1,3}${NAME_WORD}){0,2})(?![A-Za-z])`,
      "g"
    ),
    group: true,
    defaultOn: false,
  },
  // PERSON (b): bare "First [M.] Last [Last]" capitalized runs. Inherently
  // low precision (any Title Case phrase); a stop-list trims sentence starters.
  {
    type: "PERSON",
    re: new RegExp(`\\b${NAME_WORD}(?:[ \\t][A-Z]\\.)?(?:[ \\t]${NAME_WORD}){1,2}(?![A-Za-z])`, "g"),
    trim: trimPersonStop,
    defaultOn: false,
  },
];

interface Span {
  start: number;
  end: number;
  type: DetectorLabel;
  value: string;
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

type TrieNode = Map<string, TrieNode> & { end?: boolean };

/** Escaped prefix-trie alternation over the values: at each position the regex
 *  walks the trie (cost bounded by the trie's branching, not the dictionary
 *  size) and prefers the longest value (children before the empty branch). */
function trieRegex(values: string[]): string {
  const root: TrieNode = new Map();
  for (const v of values) {
    let node = root;
    for (const ch of v) {
      let next = node.get(ch);
      if (!next) node.set(ch, (next = new Map()));
      node = next;
    }
    node.end = true;
  }
  const render = (node: TrieNode): string => {
    const alts = Array.from(node.keys()).sort().map((ch) => escapeRe(ch) + render(node.get(ch)!));
    if (node.end) alts.push("");
    return alts.length === 1 && alts[0] !== "" ? alts[0] : `(?:${alts.join("|")})`;
  };
  return render(root);
}

/** Every occurrence of every known value, case-insensitive and matched as a
 *  whole word, overlapping occurrences merged into one span. One escaped trie alternation compiled once
 *  per call; at each position the longest value wins and the scan resumes one
 *  character later, so every occurrence of every value is covered. Values are
 *  never logged or thrown. */
function detectKnown(text: string, known: string[]): Span[] {
  const values = Array.from(new Set(known.filter((v) => v.trim().length > 0)));
  if (values.length === 0) return [];
  // Bounded so a value that is also an ordinary word does not rewrite prose,
  // and a name is not an occurrence inside a longer name. `\w` boundaries
  // rather than `\b` so a value whose own edge is punctuation still matches.
  const re = new RegExp(`(?<!\\w)(?:${trieRegex(values)})(?!\\w)`, "gi");
  const raw: Array<[number, number]> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    raw.push([m.index, m.index + m[0].length]);
    re.lastIndex = m.index + 1; // also find overlapping occurrences
  }
  const merged: Span[] = [];
  for (const [s, e] of raw) {
    const last = merged[merged.length - 1];
    if (last && s < last.end) {
      if (e > last.end) {
        last.end = e;
        last.value = text.slice(last.start, e);
      }
    } else {
      merged.push({ start: s, end: e, type: "KNOWN", value: text.slice(s, e) });
    }
  }
  return merged;
}

function detect(text: string, types: DetectorLabel[], known: string[]): Span[] {
  const enabled = new Set(types);
  // KNOWN first: an application-supplied value is the most authoritative label
  // when it ties with a structured detector on the same span.
  const spans: Span[] = known.length ? detectKnown(text, known) : [];
  // Built-ins first, so a custom rule can never take a span from one.
  for (const det of [...DETECTORS, ...CUSTOM_DETECTORS]) {
    if (!enabled.has(det.type)) continue;
    det.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = det.re.exec(text)) !== null) {
      if (m.index === det.re.lastIndex) det.re.lastIndex++; // guard zero-width
      let value: string | null = det.group ? m[1] : m[0];
      if (det.trim) value = det.trim(value);
      if (value === null) continue;
      // Group / trimmed spans are the LAST component of the match, so the
      // offset from the match end is exact.
      const start = m.index + m[0].length - value.length;
      if (det.valid && !det.valid(value)) continue;
      spans.push({ start, end: start + value.length, type: det.type, value });
    }
  }
  // Resolve overlaps as a UNION: sort by start, then longest (ties keep the
  // DETECTORS order via stable sort). A span fully inside one already kept is
  // dropped; a span that extends past it is clipped to the uncovered tail and
  // kept under its own type — so no character matched by any enabled detector
  // (or any dictionary value) survives, whatever else overlaps it.
  spans.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: Span[] = [];
  let lastEnd = -1;
  for (const s of spans) {
    if (s.start >= lastEnd) {
      kept.push(s);
      lastEnd = s.end;
    } else if (s.end > lastEnd) {
      kept.push({ start: lastEnd, end: s.end, type: s.type, value: text.slice(lastEnd, s.end) });
      lastEnd = s.end;
    }
  }
  return kept;
}

function replacement(
  span: Span,
  mode: RedactMode,
  counters: Map<string, string>,
  perType: Map<DetectorLabel, number>
): string {
  if (mode === "mask") return `[${span.type}]`;
  // KNOWN values were matched case-insensitively, so hash and tag keys are too.
  const keyValue = span.type === "KNOWN" ? span.value.toLowerCase() : span.value;
  if (mode === "hash") {
    const h = createHash("sha256").update(keyValue).digest("hex").slice(0, 8);
    return `<${span.type}_${h}>`;
  }
  // tag: consistent per value (same value → same tag within this call).
  const key = `${span.type}:${keyValue}`;
  let tag = counters.get(key);
  if (!tag) {
    const n = (perType.get(span.type) ?? 0) + 1;
    perType.set(span.type, n);
    tag = `<${span.type}_${n}>`;
    counters.set(key, tag);
  }
  return tag;
}

/** Fail-closed check of a caller-supplied opaque id — a `decisionId`, a
 *  `principal` — before it reaches the audit line. Accepts `undefined` (the
 *  field is simply absent); rejects anything that is not a short,
 *  control-character-free string, with a fixed message that never echoes the
 *  value. The id is never parsed. Shared with `screen`, so both primitives
 *  apply exactly the same bounds. @internal */
export function validateOpaqueId(
  value: unknown,
  field: string,
  error: (message: string) => Error
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > DECISION_ID_MAX_LENGTH) {
    throw error(`${field} must be a string of 1-${DECISION_ID_MAX_LENGTH} characters`);
  }
  if (DECISION_ID_CONTROL_CHARS.test(value)) {
    throw error(`${field} must not contain control characters`);
  }
  return value;
}

const sanitizeError = (message: string): Error => new SanitizeError(message);
/** The structured (default-on) detector types, in priority order. */
export const DEFAULT_PII_TYPES: readonly PiiType[] = Array.from(
  new Set(DETECTORS.filter((d) => d.defaultOn).map((d) => d.type as PiiType))
);

// ── registering a detector for your own vocabulary ──
//
// Held apart from DETECTORS so a custom rule can never shadow a built-in:
// registerDetector refuses a label already in use, and the scan runs the
// built-ins first.
const CUSTOM_DETECTORS: Detector[] = [];
const LABEL_RE = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/;
const RESERVED_LABELS = new Set(["KNOWN"]);

// A catastrophic pattern cannot be timed by starting a clock, calling exec and
// checking the clock afterwards: it never returns, so the check never runs and
// the guard hangs the process it was meant to protect. So the probe measures
// GROWTH on inputs short enough that even an exponential pattern finishes —
// four more characters costs an exponential 16x and a linear one nothing.
const REDOS_PROBE_PAIRS: ReadonlyArray<[number, number]> = [
  [14, 18],
  [22, 26],
  [30, 34],
];
// Linear grows ~1.2x over that step, quadratic ~1.4x, cubic ~1.7x. Exponentials
// are far above: `(a+)+$` is 16x and `(a|aa)+$` — golden-ratio base — is 6.7x.
const REDOS_GROWTH_LIMIT = 3.0;
const REDOS_NOISE_FLOOR_MS = 2;
const REDOS_ABSOLUTE_MS = 250;
const REDOS_PROBE_SHAPES = ["a", "0", "A-", " ", "aA0-_.", "\u00e9"];
const REDOS_PROBE_TAILS = ["~", ""];

/** True when `body` applies `+`, `*` or `{n,}` outside a character class and
 *  outside an escape. */
function hasUnboundedQuantifier(body: string): boolean {
  let inClass = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "+" || c === "*") return true;
    else if (c === "{") {
      const close = body.indexOf("}", i);
      if (close !== -1 && body.slice(i + 1, close).endsWith(",")) return true;
    }
  }
  return false;
}

/** The quantified group whose body is itself unboundedly quantified —
 *  `(a+)+`, `(\d+)*`, `([a-z]*){2,}` — or null. The dominant catastrophic
 *  family, and detectable without executing anything. */
function findNestedQuantifier(pattern: string): string | null {
  const starts: number[] = [];
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\") {
      i++;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      continue;
    }
    if (c === "[") inClass = true;
    else if (c === "(") starts.push(i);
    else if (c === ")" && starts.length) {
      const openAt = starts.pop() as number;
      let quantified = false;
      const next = pattern[i + 1];
      if (next === "+" || next === "*") quantified = true;
      else if (next === "{") {
        const close = pattern.indexOf("}", i + 1);
        if (close !== -1 && pattern.slice(i + 2, close).endsWith(",")) quantified = true;
      }
      if (quantified && hasUnboundedQuantifier(pattern.slice(openAt + 1, i))) {
        return pattern.slice(openAt, i + 2);
      }
    }
  }
  return null;
}

/** Refuse a pattern that backtracks catastrophically, at registration. A floor,
 *  not a proof: one that passes can still be slow on an input these shapes do
 *  not model; one that fails is definitely unsafe. */
export function probeForBacktracking(re: RegExp, label: string, kind = "detector"): void {
  const nested = findNestedQuantifier(re.source);
  if (nested !== null) {
    throw new SanitizeError(
      `${kind} "${label}": ${nested} nests one unbounded quantifier inside another, which ` +
        `backtracks catastrophically on input that nearly matches. Use a single quantifier, ` +
        `or make the inner one bounded.`
    );
  }
  const probe = new RegExp(re.source, re.flags.replace("g", ""));
  const elapsed = (text: string): number => {
    let best = Infinity;
    for (let i = 0; i < 3; i++) {
      const t = performance.now();
      probe.test(text);
      best = Math.min(best, performance.now() - t);
    }
    return best;
  };
  for (const shape of REDOS_PROBE_SHAPES) {
    for (const tail of REDOS_PROBE_TAILS) {
      for (const [nSmall, nLarge] of REDOS_PROBE_PAIRS) {
        const small = elapsed(shape.repeat(Math.max(1, Math.floor(nSmall / shape.length))) + tail);
        const large = elapsed(shape.repeat(Math.max(2, Math.floor(nLarge / shape.length))) + tail);
        if (large > REDOS_ABSOLUTE_MS) {
          throw new SanitizeError(
            `${kind} "${label}": the pattern took ${large.toFixed(0)}ms on a short input. ` +
              `A detector runs over every document, so it has to be linear.`
          );
        }
        if (large > REDOS_NOISE_FLOOR_MS) {
          if (large > small * REDOS_GROWTH_LIMIT) {
            throw new SanitizeError(
              `${kind} "${label}": the pattern backtracks catastrophically — its cost grew ` +
                `${(large / small).toFixed(0)}x for ${nLarge - nSmall} more characters, where a ` +
                `linear pattern barely moves. Anchor the repetition, or replace a nested ` +
                `quantifier such as (a+)+ with a single one.`
            );
          }
          break; // readable and well-behaved at this length
        }
        // Too fast to measure: try a longer input rather than passing on a non-reading.
      }
    }
  }
}

/**
 * Register a detector for an identifier this package does not know.
 *
 * `label` is the tag the redaction carries (`<ALIEN_NUMBER_1>`) and the key it
 * is counted under in the report. `pattern` is matched against the whole text;
 * `validate` is an optional check on each matched value, the way the built-in
 * card rule applies a Luhn check — return `false` to reject a match.
 *
 * ```ts
 * registerDetector("ALIEN_NUMBER", /\bA[- ]?\d{8,9}\b/);
 * ```
 *
 * Registered detectors are **on by default**, like the built-in structured
 * rules, and selectable by label through `types`. Register at start-up: the
 * registry is module-wide, and a detector added while a scan runs does not
 * apply to it.
 *
 * Refused: a label already in use (a built-in, `KNOWN`, or one registered with a
 * different pattern — silently replacing the `SSN` rule with a weaker one is
 * exactly the change nobody would notice), a pattern that backtracks
 * catastrophically, and a label that is not `UPPER_SNAKE_CASE`. Registering the
 * same label with an identical pattern again is a no-op.
 *
 * The value-free contract is unchanged and not yours to widen: the report
 * carries counts by label, never values. `validate` is the one place a value is
 * visible — it must not log, store, or transmit what it is shown.
 */
export function registerDetector(
  label: string,
  pattern: RegExp,
  opts: { validate?: (value: string) => boolean } = {}
): void {
  if (typeof label !== "string" || !LABEL_RE.test(label)) {
    throw new SanitizeError(
      "detector label must be UPPER_SNAKE_CASE (letters, digits, underscores)"
    );
  }
  if (RESERVED_LABELS.has(label) || DETECTORS.some((d) => d.type === label)) {
    throw new SanitizeError(`detector "${label}": that label is built in and cannot be replaced`);
  }
  if (!(pattern instanceof RegExp)) {
    throw new SanitizeError(`detector "${label}": pattern must be a RegExp`);
  }
  if (opts.validate !== undefined && typeof opts.validate !== "function") {
    throw new SanitizeError(`detector "${label}": validate must be a function`);
  }
  const existing = CUSTOM_DETECTORS.find((d) => d.type === label);
  if (existing) {
    if (existing.re.source === pattern.source) return; // an import that ran twice
    throw new SanitizeError(`detector "${label}" is already registered with a different pattern`);
  }
  probeForBacktracking(pattern, label);
  const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
  CUSTOM_DETECTORS.push({
    type: label,
    re: new RegExp(pattern.source, flags),
    valid: opts.validate,
    defaultOn: true,
  });
}

/** The labels registered with {@link registerDetector}, in registration order.
 *  The patterns are not returned: a detector for an internal identifier format
 *  is not something to hand back out. */
export function registeredDetectors(): readonly string[] {
  return CUSTOM_DETECTORS.map((d) => d.type);
}

/** Empty the registry. **For tests only** — an application that could
 *  unregister a detector mid-run could quietly stop redacting an identifier,
 *  and nothing in the audit trail would distinguish that from a document with
 *  none in it. */
export function _clearCustomDetectors(): void {
  CUSTOM_DETECTORS.length = 0;
}

/** `DETECTOR_VERSION` when only the built-ins are in force; otherwise it carries
 *  a short digest of the registered set, so an audit record says what was
 *  actually screening. A hash, not the patterns: the record stays value-free. */
export function effectiveDetectorVersion(): string {
  if (CUSTOM_DETECTORS.length === 0) return DETECTOR_VERSION;
  const material = CUSTOM_DETECTORS.map((d) => `${d.type}\u0000${d.re.source}`).join("\n");
  const digest = createHash("sha256").update(material, "utf8").digest("hex").slice(0, 8);
  return `${DETECTOR_VERSION}+custom.${digest}`;
}

/**
 * Redact PII from `text`. Pure and deterministic. Fail-closed: throws
 * {@link SanitizeError} on any internal error rather than returning partially
 * processed (potentially leaking) text.
 */
export function sanitize(text: string, opts: SanitizeOptions = {}): SanitizeResult {
  const mode: RedactMode = opts.mode ?? "tag";
  // A registered detector is on by default the way a built-in structured rule
  // is — registering it IS the opt-in — and is selectable by label like any other.
  const types =
    opts.types ?? [...(DEFAULT_PII_TYPES as DetectorLabel[]), ...registeredDetectors()];
  if (typeof text !== "string") {
    throw new SanitizeError("input must be a string (extract document text first)");
  }
  const decisionId = validateOpaqueId(opts.decisionId, "decisionId", sanitizeError);
  // Length-bounded first (an audit field), then the ONE principal rule every
  // boundary applies — non-empty, no control characters.
  const principalId = validateOpaqueId(opts.principal, "principal", sanitizeError);
  const principal =
    principalId === undefined ? undefined : assertPrincipal(principalId, sanitizeError);
  const known = opts.known ?? [];
  if (!Array.isArray(known) || known.some((v) => typeof v !== "string")) {
    // Value-free by design: the message never echoes the offending entry.
    throw new SanitizeError("known must be an array of strings");
  }
  try {
    const spans = detect(text, types, known);
    const counters = new Map<string, string>();
    const perTypeTag = new Map<DetectorLabel, number>();
    const counts: Partial<Record<DetectorLabel, number>> = {};

    // Rebuild the string, replacing spans left→right.
    let out = "";
    let cursor = 0;
    for (const s of spans) {
      out += text.slice(cursor, s.start);
      out += replacement(s, mode, counters, perTypeTag);
      cursor = s.end;
      counts[s.type] = (counts[s.type] ?? 0) + 1;
    }
    out += text.slice(cursor);

    const report: SanitizeReport = { mode, detectorVersion: effectiveDetectorVersion(), counts, total: spans.length };
    if (decisionId !== undefined) report.decisionId = decisionId;
    if (principal !== undefined) report.principal = principal;
    return { text: out, report };
  } catch (e) {
    throw new SanitizeError(String((e as Error)?.message ?? e));
  }
}
