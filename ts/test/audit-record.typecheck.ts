// Compile-time check (run by audit-sink.test.mjs via tsc --noEmit): the exported
// `AuditRecord` union describes every record kind the SDK writes, narrows on
// `event`, and breaks a sink at COMPILE time when a record kind changes shape.
// The `@ts-expect-error` lines below are the drift demonstration: each one
// compiles only because the access next to it is an ERROR today. If a field were
// renamed INTO one of those names, the directive would become unused and this
// file would fail instead — the check bites in both directions.
// Not part of the package build.
import {
  govern,
  Watchlight,
  type AttenuationRecord,
  type AuditRecord,
  type AuditRecordBase,
  type AuditSink,
  type DecisionRecord,
  type EgressRecord,
  type SanitizationRecord,
  type ScreeningRecord,
  type UnknownAuditRecord,
} from "../dist/index";

// ── 1. the typed happy path: one exhaustive sink, no casts, no `unknown` ──
// A sixth record kind makes the `never` assignment fail; a renamed or removed
// field makes the read next to it fail.
const rows: string[] = [];

const typedSink: AuditSink = (r: AuditRecord) => {
  switch (r.event) {
    case undefined:
      rows.push(`decision ${r.principal} ${r.decision} ${r.decision_id ?? "-"} ${r.approved === true}`);
      return;
    case "sanitization":
      rows.push(`sanitization ${r.mode} ${r.detector} ${r.total} ${r.counts.SSN ?? 0} ${r.principal ?? "-"}`);
      return;
    case "screening":
      rows.push(`screening ${r.mode} ${r.detector} ${r.total} ${r.flagged} ${r.counts.PROMPT_LEAK ?? 0}`);
      return;
    case "egress":
      rows.push(`egress ${r.principal} ${r.replaced} ${r.withheld === true}`);
      return;
    case "attenuation":
      rows.push(`attenuation ${r.node_id} ${r.parent_id ?? "-"} ${r.depth} ${r.tools.join("+")} ${r.decision}`);
      return;
    default: {
      // A record kind added without a case here stops the build.
      const unhandled: never = r;
      return unhandled;
    }
  }
};

// The base fields are readable without narrowing at all, and every kind is
// accepted where the common shape is asked for.
const summarize = (r: AuditRecord): string => `${r.ts} ${r.agent} ${r.intent} ${r.resource}`;
const commonOnly = (r: AuditRecordBase): string => `${r.ts} ${r.agent} ${r.intent} ${r.resource}`;
const base = (r: AuditRecord): string => commonOnly(r);

// `"event" in r` narrows too — the same test `countAuditRecords` makes.
const isDecision = (r: AuditRecord): r is DecisionRecord => !("event" in r);

// ── 2. the escape hatch: an untyped sink still satisfies AuditSink ──
// This is the pre-union signature, unchanged, and it still compiles.
const legacySink: AuditSink = (record: Readonly<Record<string, unknown>>) => {
  rows.push(String(record.ts));
};
const namedHatchSink: AuditSink = (record: UnknownAuditRecord) => {
  rows.push(JSON.stringify(record));
};
const mutableBagSink: AuditSink = (record: Record<string, unknown>) => {
  rows.push(String(record["event"] ?? "decision"));
};
// …and a record of any kind is assignable to the untyped form, so a typed sink
// can forward whole records to code that was written against the bag.
const forward = (r: AuditRecord): UnknownAuditRecord => r;

// A sink is still accepted where the SDK asks for one.
const configured = new Watchlight({ agent: "typecheck-agent", auditSink: typedSink, auditFile: false });
const alsoConfigured = new Watchlight({ agent: "typecheck-agent", auditSink: legacySink, auditFile: false });

// ── 3. drift demonstration — each access below is an error TODAY ──
declare const decision: DecisionRecord;
declare const sanitization: SanitizationRecord;
declare const screening: ScreeningRecord;
declare const egress: EgressRecord;
declare const attenuation: AttenuationRecord;
declare const anyRecord: AuditRecord;

// A RENAMED field: the trail writes `decision_id`, never `decisionId`. Under the
// untyped bag this read silently yielded `undefined` forever.
// @ts-expect-error `decisionId` is not a field of a decision record
const renamed = decision.decisionId;

// A field read off the WRONG kind: an attenuation record has no decision_id.
// @ts-expect-error attenuation records carry no `decision_id`
const wrongKind = attenuation.decision_id;

// A field that does not exist on any kind — the shape a sink invents by mistake.
// @ts-expect-error no record kind carries a `user` field
const invented = sanitization.user;

// Not every kind names a principal: `screening` and `sanitization` carry one only
// when the caller passed it, and `attenuation` never does.
// @ts-expect-error attenuation records carry no `principal`
const noPrincipal = attenuation.principal;

// A kind-specific field is not readable before narrowing.
// @ts-expect-error `replaced` exists only on an egress record
const unnarrowed = anyRecord.replaced;

// The optional fields are optional, not guaranteed.
// @ts-expect-error `withheld` is `true | undefined`, not `boolean`
const notBoolean: boolean = egress.withheld;

// The value vocabularies are closed, so a typo in a comparison is caught.
// @ts-expect-error `Allowed` is not a decision verdict
const badVerdict = decision.decision === "Allowed";
// @ts-expect-error an attenuation is only ever Allow or Deny
const badScopeVerdict = attenuation.decision === "NeedsApproval";
// @ts-expect-error `screening` is the event name, not `screen`
const badEvent = screening.event === "screen";

// ── 4. the field list, in one place, checked against the types ──
// Every field of every kind is named here. A field ADDED to a record type — the
// change a reader cannot otherwise notice — makes the matching object literal
// incomplete and stops the build, so the table in
// examples/showcase/audit-forensics/README.md cannot drift from the types.
const decisionFields: Record<keyof DecisionRecord, true> = {
  ts: true, agent: true, actor_chain: true, event: true, principal: true,
  intent: true, resource: true, decision: true, decision_id: true, approved: true,
};
const sanitizationFields: Record<keyof SanitizationRecord, true> = {
  ts: true, agent: true, actor_chain: true, intent: true, event: true, resource: true,
  mode: true, detector: true, counts: true, total: true, decision_id: true, principal: true,
};
const screeningFields: Record<keyof ScreeningRecord, true> = {
  ts: true, agent: true, actor_chain: true, intent: true, event: true, resource: true,
  mode: true, detector: true, counts: true, total: true, flagged: true,
  decision_id: true, principal: true,
};
const egressFields: Record<keyof EgressRecord, true> = {
  ts: true, agent: true, actor_chain: true, principal: true, intent: true, event: true,
  resource: true, replaced: true, decision_id: true, withheld: true,
};
const attenuationFields: Record<keyof AttenuationRecord, true> = {
  ts: true, agent: true, intent: true, event: true, node_id: true, resource: true,
  decision: true, depth: true, tools: true, parent_id: true, reason: true,
};

// The default governor takes a typed sink too.
async function documented(): Promise<string[]> {
  const g = govern.as("typecheck-agent");
  await g.authorize({ action: "read", resource: "doc.txt" });
  return rows;
}

export {
  typedSink, legacySink, namedHatchSink, mutableBagSink, forward, summarize, base,
  isDecision, configured, alsoConfigured, documented,
  renamed, wrongKind, invented, noPrincipal, unnarrowed, notBoolean,
  badVerdict, badScopeVerdict, badEvent,
  decisionFields, sanitizationFields, screeningFields, egressFields, attenuationFields,
};
