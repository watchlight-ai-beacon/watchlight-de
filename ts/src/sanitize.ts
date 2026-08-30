// govern.sanitize — governed data minimization at the agent boundary.
//
// Strip PII from text BEFORE an agent reads it. Deterministic, in-process,
// fail-closed. This is the Developer-Edition baseline detector: high-precision
// STRUCTURED PII via rules (email, phone, SSN, credit card w/ Luhn, IBAN, IPv4,
// API keys). Names/addresses need NER — an opt-in / Enterprise stage — so recall
// is honestly bounded by the enabled detectors and surfaced in the report.
//
// Operates on extracted TEXT. Document extraction (PDF/docx → text, across all
// layers) is a separate step: you never hand the agent a "redacted PDF" (its
// hidden layers leak) — you hand it redacted text.

import { createHash } from "node:crypto";

/** PII categories the deterministic detector recognizes. */
export type PiiType =
  | "EMAIL"
  | "PHONE"
  | "SSN"
  | "CREDIT_CARD"
  | "IBAN"
  | "IPV4"
  | "API_KEY";

/** How a detected value is replaced. */
export type RedactMode = "tag" | "mask" | "hash";

export const DETECTOR_VERSION = "de-rules-1";

/** Raised when sanitization cannot complete — fail-closed: the caller must NOT
 *  fall back to raw content. */
export class SanitizeError extends Error {
  constructor(message: string) {
    super(`sanitize failed (fail-closed): ${message}`);
    this.name = "SanitizeError";
  }
}

export interface SanitizeOptions {
  /** Replacement strategy. Default `"tag"` (consistent `<EMAIL_1>` placeholders). */
  mode?: RedactMode;
  /** Restrict to these PII types. Default: all deterministic types. */
  types?: PiiType[];
}

export interface SanitizeReport {
  mode: RedactMode;
  detectorVersion: string;
  /** Count of redactions per type. Value-free by construction — never the values. */
  counts: Partial<Record<PiiType, number>>;
  /** Total redactions. */
  total: number;
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
  /** Optional validator on the raw match; false drops it. */
  valid?: (m: string) => boolean;
}

const DETECTORS: Detector[] = [
  { type: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  // API keys / tokens with well-known prefixes (before generic patterns).
  { type: "API_KEY", re: /\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g },
  { type: "SSN", re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  {
    type: "CREDIT_CARD",
    re: /\b(?:\d[ -]?){13,19}\b/g,
    valid: (m) => {
      const d = m.replace(/[ -]/g, "");
      return d.length >= 13 && d.length <= 19 && luhnOk(d);
    },
  },
  { type: "IBAN", re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,3})?\b/g },
  {
    type: "IPV4",
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    valid: (m) => m.split(".").every((o) => Number(o) <= 255),
  },
  {
    type: "PHONE",
    re: /(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\d)/g,
    // Require at least 10 digits total to avoid matching short number runs.
    valid: (m) => (m.replace(/\D/g, "").length >= 10),
  },
];

interface Span {
  start: number;
  end: number;
  type: PiiType;
  value: string;
}

function detect(text: string, types: PiiType[]): Span[] {
  const enabled = new Set(types);
  const spans: Span[] = [];
  for (const det of DETECTORS) {
    if (!enabled.has(det.type)) continue;
    det.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = det.re.exec(text)) !== null) {
      const value = m[0];
      if (det.valid && !det.valid(value)) continue;
      spans.push({ start: m.index, end: m.index + value.length, type: det.type, value });
      if (m.index === det.re.lastIndex) det.re.lastIndex++; // guard zero-width
    }
  }
  // Resolve overlaps: sort by start, then longest; drop any span overlapping one
  // already kept (first detector wins by the DETECTORS order via stable sort).
  spans.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const kept: Span[] = [];
  let lastEnd = -1;
  for (const s of spans) {
    if (s.start >= lastEnd) {
      kept.push(s);
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
  if (mode === "hash") {
    const h = createHash("sha256").update(span.value).digest("hex").slice(0, 8);
    return `<${span.type}_${h}>`;
  }
  // tag: consistent per value (same value → same tag within this call).
  const key = `${span.type}:${span.value}`;
  let tag = counters.get(key);
  if (!tag) {
    const n = (perType.get(span.type) ?? 0) + 1;
    perType.set(span.type, n);
    tag = `<${span.type}_${n}>`;
    counters.set(key, tag);
  }
  return tag;
}

/**
 * Redact PII from `text`. Pure and deterministic. Fail-closed: throws
 * {@link SanitizeError} on any internal error rather than returning partially
 * processed (potentially leaking) text.
 */
export function sanitize(text: string, opts: SanitizeOptions = {}): SanitizeResult {
  const mode: RedactMode = opts.mode ?? "tag";
  const types = opts.types ?? (DETECTORS.map((d) => d.type) as PiiType[]);
  if (typeof text !== "string") {
    throw new SanitizeError("input must be a string (extract document text first)");
  }
  try {
    const spans = detect(text, types);
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

    return {
      text: out,
      report: { mode, detectorVersion: DETECTOR_VERSION, counts, total: spans.length },
    };
  } catch (e) {
    throw new SanitizeError(String((e as Error)?.message ?? e));
  }
}
