// The identity model, running — subject, actor, and delegation chain (Node).
//
//   npm i -g @watchlight/sdk          # or: cd ts && npm install && npm run build
//   node examples/showcase/identity/identity.mjs
//
// Runs offline: no API key, no network, no identity provider. ONE governor and
// ONE policy set for the whole example; every named agent is a view of the same
// engine. The script prints, for each call, the verdict and the identity fields
// of the audit record it produced, and exits non-zero if any verdict or record
// shape changes.
//
// It makes the three cases of docs/identity-model.md concrete:
//
//   1. an agent acting alone        principal = Agent::"flight-booker"
//   2. the same agent for a person  principal = User::"…", same actor
//   3. a sub-agent under a parent   principal unchanged, ordered actor chain
//
// then shows the four things a caller cannot do (supply the actor key, extend
// the chain, rename a delegate, rename it through a per-call override), and the
// two identity sources — a verified token's subject claim and a local session
// lookup — producing the identical call.
//
// The policies and their golden tests live in one file:
//
//   watchlight policy test examples/showcase/identity/policy.suite.json
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);

// Resolve the SDK from an installed package first, then from the in-repo build.
function loadSdk() {
  const candidates = ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", import.meta.url))];
  for (const spec of candidates) {
    try { return require(spec); } catch (e) { if (e?.code !== "MODULE_NOT_FOUND") throw e; }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}
const { Watchlight, ReservedContextError, principals } = loadSdk();

const here = dirname(fileURLToPath(import.meta.url));
const auditDir = join(here, ".watchlight");

// Resources this example authorizes against. Nothing here is a real system:
// the point is which identity the engine reads, not what the action does.
const TRIP = "trip/AX8821";
const ITINERARY = "itinerary/AX8821";
const SEAT = "seat/AX8821";
const TRACE = "trace/AX8821";
const NOTES = "memory/traveller-notes";
const ROUTE = "route/AMS-LIS";

// ── one engine, one policy set, many named agents ────────────────────────────

// Every audit record — from every named agent and every delegate — arrives
// here, because a view shares the trail and the sink with the governor it came
// from. That shared stream, told apart by `agent` and `actor_chain`, is what
// makes the three cases comparable below.
const records = [];

const govern = new Watchlight({
  agent: "trip-platform",
  auditDir,
  auditSink: (record) => { records.push(record); },
});
govern.load(join(here, "policy.suite.json")); // {"policies": [...]} — the file the suite tests

const POLICIES_AFTER_LOAD = govern.policyCount;

// Naming agents costs nothing: `as` returns a VIEW of this governor — same
// engine, same compiled policies, same trail, same sink — with a different name
// stamped on the records and read by the policies as `context.actor`.
const booker = govern.as("flight-booker");
const memory = govern.as("memory-writer");

const POLICIES_AFTER_NAMING = govern.policyCount;

// ── assertions ───────────────────────────────────────────────────────────────

const failures = [];

function check(condition, what) {
  console.log(`  ${condition ? "OK " : "FAIL"} ${what}`);
  if (!condition) failures.push(what);
}

/** The identity fields of an audit record, in one line: who acted, through
 *  whose delegation, and on whose behalf. */
function identityOf(record) {
  const chain = record.actor_chain;
  const shown = chain ? `[${chain.join(" > ")}]` : "(none)";
  return `agent=${(record.agent ?? "-").padEnd(14)} chain=${shown.padEnd(34)} principal=${record.principal ?? "-"}`;
}

/** One governed decision, plus the audit record it wrote. */
async function decide(gov, action, resource, { principal, context } = {}) {
  const before = records.length;
  const result = await gov.authorize({ action, principal, resource, context });
  const record = records.length > before ? records.at(-1) : {};
  console.log(`    ${action.padEnd(14)} -> ${result.decision.padEnd(6)} ${identityOf(record)}`);
  return { result, record };
}

/** Assert that a call the SDK must refuse throws, and writes nothing. */
async function refused(what, thunk, expected) {
  const before = records.length;
  try {
    await thunk();
    console.log(`    ${what}: NOT refused`);
    failures.push(what);
    return;
  } catch (error) {
    if (!(error instanceof expected)) throw error;
    console.log(`    ${what}\n      -> ${error.name}: ${error.message}`);
  }
  check(records.length === before, `${what} — refused before the engine, so no record was written`);
}

// ── the three cases ──────────────────────────────────────────────────────────

/** An agent alone, the same agent for a person, a sub-agent under it. */
async function threeCases() {
  const traveller = principals.user("db:4412");

  console.log("\ncase 1 — the agent acting alone (no principal: the agent is the subject)");
  const { result: alone, record: aloneRecord } = await decide(booker, "cache", ROUTE);
  // The same agent, acting alone, may NOT book: the booking policy wants a
  // person subject. A narrower grant for the autonomous case, same runtime.
  const { result: deniedAlone } = await decide(booker, "book", TRIP);

  console.log("\ncase 2 — the same agent acting for a person (same actor, different subject)");
  const { result: forPerson, record: personRecord } =
    await decide(booker, "book", TRIP, { principal: traveller });

  console.log("\ncase 3 — a sub-agent under the booking agent (subject unchanged, chain extended)");
  // `scope` is the parent's authority; `delegate` narrows it AND appends the
  // sub-agent to the actor chain, so one call produces both the confined
  // authority and the delegated identity.
  const root = await booker.scope({ tools: ["search", "book", "pick_seat", "trace"] });
  const picker = booker.delegate(root, "seat-picker", { tools: ["search", "pick_seat", "trace"] });
  const { result: sub, record: subRecord } =
    await decide(picker, "pick_seat", SEAT, { principal: traveller });
  // The delegate is not the booking runtime, so the booking policy — which
  // names the LEAF actor — does not match it.
  const { result: subBook } = await decide(picker, "book", TRIP, { principal: traveller });

  check(alone.decision === "Allow", "case 1: the agent alone may warm the cache");
  check(deniedAlone.decision === "Deny", "case 1: the agent alone may not book");
  check(aloneRecord.principal === 'Agent::"flight-booker"',
    'case 1: the subject is the typed agent reference Agent::"flight-booker"');
  check(!("actor_chain" in aloneRecord),
    "case 1: no actor_chain on the record — the call is outside any delegation");

  check(forPerson.decision === "Allow", "case 2: the same agent may book for a person");
  check(personRecord.principal === 'User::"db:4412"',
    'case 2: the subject is the person, User::"db:4412"');
  check(personRecord.agent === aloneRecord.agent && personRecord.agent === "flight-booker",
    "case 2: the actor is unchanged — one runtime, two subjects");
  check(!("actor_chain" in personRecord), "case 2: still no actor_chain");

  check(sub.decision === "Allow", "case 3: the sub-agent may pick a seat for the person");
  check(subBook.decision === "Deny", "case 3: the sub-agent may not book");
  check(subRecord.agent === "seat-picker", "case 3: the leaf actor is the sub-agent");
  check(JSON.stringify(subRecord.actor_chain) === JSON.stringify(["flight-booker", "seat-picker"]),
    "case 3: the ordered chain is [flight-booker > seat-picker], root first");
  check(subRecord.principal === personRecord.principal,
    "case 3: the subject is unchanged — delegation adds an actor, not a subject");
  check(JSON.stringify([...picker.actorChain]) === JSON.stringify(["flight-booker", "seat-picker"]),
    "case 3: the governor carries the same chain the record does");

  return { picker, cases: { alone: aloneRecord, "for a person": personRecord, "sub-agent": subRecord } };
}

// ── one policy per identity field ────────────────────────────────────────────

async function policiesPerField(picker) {
  const traveller = principals.user("db:4412");
  const other = principals.user("sso:8f3c2b7e");

  console.log("\na person's own authority — the acting runtime is irrelevant");
  const { result: own } = await decide(booker, "cancel_trip", TRIP, { principal: traveller });
  const { result: ownOtherRuntime } = await decide(memory, "cancel_trip", TRIP, { principal: traveller });
  const { result: notTheirs } = await decide(booker, "cancel_trip", TRIP, { principal: other });
  check(own.decision === "Allow", "the traveller may cancel their own trip");
  check(ownOtherRuntime.decision === "Allow",
    "a different runtime acting for the same traveller is allowed too");
  check(notTheirs.decision === "Deny", "another traveller may not cancel that trip");

  console.log("\na tool restricted to one runtime — context.actor, whoever it acts for");
  const { result: writer } = await decide(memory, "write_memory", NOTES, { principal: traveller });
  const { result: nonWriter } = await decide(booker, "write_memory", NOTES, { principal: traveller });
  check(writer.decision === "Allow", "the memory-writer runtime may write memory");
  check(nonWriter.decision === "Deny", "another runtime may not, for the same person");

  console.log("\nmembership anywhere in the chain — context.actor_chain.contains(...)");
  const { result: delegated } = await decide(picker, "trace", TRACE, { principal: traveller });
  const { result: outside } = await decide(memory, "trace", TRACE, { principal: traveller });
  check(delegated.decision === "Allow",
    "the sub-agent may trace: the booking agent is in its chain");
  check(outside.decision === "Deny",
    "an agent outside that delegation may not, though the subject is the same");
}

// ── what a caller cannot do ──────────────────────────────────────────────────

/** The actor keys are the SDK's. A caller can neither invent a delegation nor
 *  extend one through the context, and cannot rename a delegate. */
async function callerCannot(picker) {
  const traveller = principals.user("db:4412");

  console.log("\nsupplying the actor key through context");
  await refused('context={ actor: "memory-writer" } on a flight-booker call',
    () => booker.authorize({ action: "write_memory", resource: NOTES, principal: traveller,
      context: { actor: "memory-writer" } }),
    ReservedContextError);

  console.log("\nextending the chain through context");
  await refused("context={ actor_chain: [...] } claiming a delegation that did not happen",
    () => memory.authorize({ action: "trace", resource: TRACE, principal: traveller,
      context: { actor_chain: ["flight-booker", "memory-writer"] } }),
    ReservedContextError);

  console.log("\nrenaming a delegate");
  await refused('picker.as("row-checker")', () => picker.as("row-checker"), TypeError);
  await refused("the same rename through the per-call agent override",
    () => picker.authorize({ action: "trace", resource: TRACE, principal: traveller,
      agent: "row-checker" }),
    TypeError);

  console.log("\n(an identical value is not a conflict — the guard refuses disagreement, not the key)");
  const { result: same } =
    await decide(booker, "book", TRIP, { principal: traveller, context: { actor: "flight-booker" } });
  check(same.decision === "Allow", "a context.actor equal to the SDK's own value is accepted");
}

// ── both identity sources, one call ──────────────────────────────────────────

// A stand-in for a token your application has ALREADY verified — this example
// verifies nothing and implies no particular identity provider. Only the
// subject claim is used: a username or an email can be reassigned, which would
// point an old audit record at a different person; `sub` does not move.
const VERIFIED_CLAIMS = { sub: "8f3c2b7e", preferred_username: "traveller-42" };

// A stand-in for a local session store and users table — the case with no
// identity provider at all. The row's primary key is the subject, not the
// display name, for the same reason.
const SESSIONS = { "session-1f2e": { user_id: 4412 } };
const USERS = { 4412: { id: 4412, display_name: "window-seat regular", tier: "gold" } };

/** Namespaced so two identity sources can never collide on one id. */
function subjectFromToken(claims) {
  return principals.user(`sso:${claims.sub}`);
}

function subjectFromSession(sessionId) {
  const row = USERS[SESSIONS[sessionId].user_id];  // your session store, then the row
  return principals.user(`db:${row.id}`);          // the primary key, never the display name
}

/** ONE call site. Whatever established the subject, the call is identical. */
function readItinerary(subject) {
  return decide(booker, "read_itinerary", ITINERARY, { principal: subject });
}

async function identitySources() {
  console.log("\ntwo identity sources, one call");
  const { result: fromToken, record: tokenRecord } = await readItinerary(subjectFromToken(VERIFIED_CLAIMS));
  const { result: fromSession, record: sessionRecord } = await readItinerary(subjectFromSession("session-1f2e"));

  check(fromToken.decision === "Allow" && fromSession.decision === "Allow",
    "both subjects reach the same Allow");
  const shape = (record) => JSON.stringify(Object.fromEntries(
    Object.entries(record).filter(([k]) => !["ts", "decision_id", "principal"].includes(k))));
  check(shape(tokenRecord) === shape(sessionRecord),
    "the two records differ in the subject id and nothing else");
  check(tokenRecord.principal === 'User::"sso:8f3c2b7e"' && sessionRecord.principal === 'User::"db:4412"',
    "each subject is namespaced by the source that established it");
}

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log("one engine, one policy set, many named agents");
  console.log(`    policies loaded              ${POLICIES_AFTER_LOAD}`);
  console.log("    named agents                 flight-booker, memory-writer (views of one engine)");
  console.log(`    policies after naming them   ${POLICIES_AFTER_NAMING}`);
  check(POLICIES_AFTER_LOAD === 7, "the policy set is the 7 policies in policy.suite.json");
  check(POLICIES_AFTER_NAMING === POLICIES_AFTER_LOAD,
    "naming agents did not reload or recompile a single policy");
  check(booker.policyCount === memory.policyCount && memory.policyCount === govern.policyCount,
    "every view reports the same policy count — it is the same engine");

  const { picker, cases } = await threeCases();
  check(govern.policyCount === POLICIES_AFTER_LOAD,
    "delegating did not grow the policy set either");

  await policiesPerField(picker);
  await callerCannot(picker);
  await identitySources();

  console.log("\nthe three cases, side by side in the one audit stream");
  for (const [label, record] of Object.entries(cases)) {
    const line = {};
    for (const key of ["agent", "actor_chain", "principal", "intent", "decision"]) {
      if (key in record) line[key] = record[key];
    }
    console.log(`    ${label.padEnd(13)} ${JSON.stringify(line)}`);
  }

  console.log();
  if (failures.length) {
    console.log(`FAILED: ${failures.length} assertion(s) did not hold`);
    return 1;
  }
  console.log("OK — three cases, three identities, one engine and one policy set.");
  return 0;
}

main().then((code) => process.exit(code)).catch((e) => { console.error(e); process.exit(1); });
