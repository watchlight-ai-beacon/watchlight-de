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
  types?: PiiType[];
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
  counts: Partial<Record<PiiType, number>>;
  /** Total redactions. */
  total: number;
  /** The `decisionId` supplied by the caller, if any (validated, never interpreted). */
  decisionId?: string;
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
  type: PiiType;
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
  { type: "SSN", re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, defaultOn: true },
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
  {
    type: "PHONE",
    re: /(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\d)/g,
    // Require at least 10 digits total to avoid matching short number runs.
    valid: (m) => (m.replace(/\D/g, "").length >= 10),
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
  type: PiiType;
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

/** Every occurrence of every known value, case-insensitive, overlapping
 *  occurrences merged into one span. One escaped trie alternation compiled once
 *  per call; at each position the longest value wins and the scan resumes one
 *  character later, so every occurrence of every value is covered. Values are
 *  never logged or thrown. */
function detectKnown(text: string, known: string[]): Span[] {
  const values = Array.from(new Set(known.filter((v) => v.trim().length > 0)));
  if (values.length === 0) return [];
  const re = new RegExp(trieRegex(values), "gi");
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

function detect(text: string, types: PiiType[], known: string[]): Span[] {
  const enabled = new Set(types);
  // KNOWN first: an application-supplied value is the most authoritative label
  // when it ties with a structured detector on the same span.
  const spans: Span[] = known.length ? detectKnown(text, known) : [];
  for (const det of DETECTORS) {
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
  perType: Map<PiiType, number>
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

/** Fail-closed check of a caller-supplied correlation id before it reaches the
 *  audit line. Accepts `undefined` (no correlation); rejects anything that is
 *  not a short, control-character-free string. The id is never parsed. */
function validateDecisionId(id: unknown): string | undefined {
  if (id === undefined) return undefined;
  if (typeof id !== "string" || id.length === 0 || id.length > DECISION_ID_MAX_LENGTH) {
    throw new SanitizeError(`decisionId must be a string of 1-${DECISION_ID_MAX_LENGTH} characters`);
  }
  if (DECISION_ID_CONTROL_CHARS.test(id)) {
    throw new SanitizeError("decisionId must not contain control characters");
  }
  return id;
}
/** The structured (default-on) detector types, in priority order. */
export const DEFAULT_PII_TYPES: readonly PiiType[] = Array.from(
  new Set(DETECTORS.filter((d) => d.defaultOn).map((d) => d.type))
);

/**
 * Redact PII from `text`. Pure and deterministic. Fail-closed: throws
 * {@link SanitizeError} on any internal error rather than returning partially
 * processed (potentially leaking) text.
 */
export function sanitize(text: string, opts: SanitizeOptions = {}): SanitizeResult {
  const mode: RedactMode = opts.mode ?? "tag";
  const types = opts.types ?? (DEFAULT_PII_TYPES as PiiType[]);
  if (typeof text !== "string") {
    throw new SanitizeError("input must be a string (extract document text first)");
  }
  const decisionId = validateDecisionId(opts.decisionId);
  const known = opts.known ?? [];
  if (!Array.isArray(known) || known.some((v) => typeof v !== "string")) {
    // Value-free by design: the message never echoes the offending entry.
    throw new SanitizeError("known must be an array of strings");
  }
  try {
    const spans = detect(text, types, known);
    const counters = new Map<string, string>();
    const perTypeTag = new Map<PiiType, number>();
    const counts: Partial<Record<PiiType, number>> = {};

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

    const report: SanitizeReport = { mode, detectorVersion: DETECTOR_VERSION, counts, total: spans.length };
    if (decisionId !== undefined) report.decisionId = decisionId;
    return { text: out, report };
  } catch (e) {
    throw new SanitizeError(String((e as Error)?.message ?? e));
  }
}
