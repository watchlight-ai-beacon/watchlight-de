// Human-in-the-loop, end to end: hold, approve out of band, resume exactly once (Node).
//
//   npm i -g @watchlight/sdk          # or: cd ts && npm install && npm run build
//   cd examples/showcase/human-in-the-loop
//   export APPROVER_SECRET="$(openssl rand -hex 32)"
//
//   node agent.mjs request      # 1. NeedsApproval → pending request written; nothing deleted
//   node approve.mjs            # 2. a human signs a grant for that request
//   node agent.mjs resume       # 3. grant verified → approved decision → the delete runs ONCE
//                               #    then: the same grant replayed → refused; an SDK token
//                               #    replayed → refused
//
// The `delete` permit in policy.suite.json carries
// @enforcement_effect("require_approval"), so the engine answers NeedsApproval
// instead of Allow. The SDK then calls `onNeedsApproval` BEFORE the tool body:
//
//   * no grant on disk    → write the pending request, return false → the SDK throws
//                           NeedsApproval; the body never runs;
//   * a verified grant    → return true → the SDK mints a single-use approval token
//                           in this process, re-authorizes, and only then runs the
//                           body once, writing an `approved: true` decision record.
//
// Every phase exits non-zero if the record store's delete counter, the audit
// records, or a replay check contradicts the expected outcome.
//
// The same file that the agent loads is also a policy test suite:
//
//   watchlight policy test examples/showcase/human-in-the-loop/policy.suite.json
import { join } from "node:path";
import * as hitl from "./hitl.mjs";

const { Watchlight, NeedsApproval } = hitl.loadSdk();

const RECORD = "rec-42";

/** Stands in for the system of record. Every delete increments `deletes`. */
class RecordStore {
  deletes = 0;
  delete(recordId) {
    this.deletes += 1;
    return `delete #${this.deletes}: record/${recordId} removed`;
  }
}
const store = new RecordStore();

const govern = new Watchlight({ agent: "records-agent", auditDir: hitl.AUDIT_DIR });
govern.load(join(hitl.HERE, "policy.suite.json")); // {"policies": [...]} — the file the suite tests

/** The approval hook. Runs on a NeedsApproval verdict, before the body. */
function holdOrResume({ decisionId, principal, intent, resource }) {
  if (hitl.peekGrant() === null) {
    hitl.writePending(decisionId, principal, intent, resource);
    console.log(`hold:    pending request written to ${hitl.rel(hitl.PENDING)}; the delete did not run`);
    return false;
  }
  const { grant, why } = hitl.takeGrant(principal, intent, resource, hitl.approverSecret());
  if (grant === null) {
    // A grant that does not verify is discarded — it is not a new request.
    console.log(`refused: ${why}; the delete did not run`);
    return false;
  }
  console.log(`resume:  grant verified and consumed — approves pending ${grant.pending_decision_id}`);
  return true;
}

const deleteRecord = govern.tool(async function deleteRecord(recordId) {
  return store.delete(recordId);
}, {
  intent: "delete",
  resource: (recordId) => `record/${recordId}`,
  onNeedsApproval: holdOrResume,
});

// ── assertions ───────────────────────────────────────────────────────────────

const failures = [];
function check(condition, what) {
  console.log(`  ${condition ? "✓" : "✗"} ${what}`);
  if (!condition) failures.push(what);
}

function finish() {
  console.log();
  if (failures.length) {
    console.log(`FAILED: ${failures.length} assertion(s) did not hold`);
    return 1;
  }
  console.log("OK");
  return 0;
}

const parse = (line) => { try { return line ? JSON.parse(line) : {}; } catch { return {}; } };

// ── phase 1: request ─────────────────────────────────────────────────────────

async function request() {
  hitl.reset();
  console.log(`attempt: delete record/${RECORD}`);
  const before = hitl.auditLines().length;
  try {
    await deleteRecord(RECORD);
    check(false, "the delete was held for approval");
  } catch (e) {
    if (!(e instanceof NeedsApproval)) throw e;
    console.log(`held:    ${e.message}`);
    const line = hitl.auditLine(e.decisionId) ?? "";
    console.log(`pending decision record:\n  ${line || "(no record written)"}`);
    check(store.deletes === 0, `the record store never received the delete (deletes=${store.deletes})`);
    check(hitl.readPending() !== null, "a pending request is on disk for the approver");
    check(parse(line).decision === "NeedsApproval", "the audit record is a NeedsApproval hold");
    check(hitl.auditLines().length - before === 1, "exactly one decision record was written");
  }
  console.log("\nnext: node approve.mjs   (then: node agent.mjs resume)");
  return finish();
}

// ── phase 2: resume ──────────────────────────────────────────────────────────

async function resume() {
  const grant = hitl.peekGrant();
  if (grant === null) {
    console.log("no grant on disk — run 'node agent.mjs request', then 'node approve.mjs'");
    return 2;
  }
  const pendingId = grant.pending_decision_id;
  const replayCopy = { ...grant }; // what anyone who read the file would hold

  console.log(`attempt: delete record/${RECORD} (grant on disk for pending ${pendingId})`);
  const before = hitl.auditLines().length;
  let outcome;
  try {
    outcome = await deleteRecord(RECORD);
  } catch (e) {
    if (!(e instanceof NeedsApproval)) throw e;
    // The grant on disk did not verify (tampered, expired, wrong request).
    // It has been discarded; nothing ran. Start over with 'request'.
    check(false, "the grant verified and the delete resumed");
    return finish();
  }
  console.log(`result:  ${outcome}`);

  const newLines = hitl.auditLines().slice(before);
  const approvedLine = newLines.at(-1) ?? "";
  const approved = parse(approvedLine);
  const pendingLine = hitl.auditLine(pendingId) ?? "";
  const pending = parse(pendingLine);

  console.log("\npending decision record (written by 'request'):");
  console.log(`  ${pendingLine || "(not found)"}`);
  console.log("approved decision record (written now):");
  console.log(`  ${approvedLine || "(none)"}`);
  console.log(`join:    grant.pending_decision_id ${pendingId} → approved decision ${approved.decision_id}`);

  check(store.deletes === 1, `the delete ran exactly once (deletes=${store.deletes})`);
  check(pending.decision === "NeedsApproval", "the pending record is a NeedsApproval hold");
  check(approved.decision === "Allow" && approved.approved === true, "the approved record is Allow with approved: true");
  check(
    pending.principal === approved.principal && pending.intent === approved.intent && pending.resource === approved.resource,
    "both records name the same principal, intent and resource",
  );
  check(newLines.length === 2 && parse(newLines[0]).decision === "NeedsApproval",
    "the resume re-evaluated the policy (a fresh hold) before applying the approval");
  check(hitl.peekGrant() === null, "the grant was consumed");

  // Replay 1: present the consumed grant again.
  console.log("\nreplay: presenting the consumed grant again");
  hitl.plantGrant(replayCopy);
  try {
    await deleteRecord(RECORD);
    check(false, "the replayed grant was refused");
  } catch (e) {
    if (!(e instanceof NeedsApproval)) throw e;
    check(store.deletes === 1, `the replayed grant was refused; deletes still ${store.deletes}`);
  }
  check(hitl.readPending() === null, "a refused replay does not open a new pending request");

  // Replay 2: a well-signed grant naming a request that is not the outstanding one. Anyone
  // holding the secret can sign one (see README); the agent still refuses it.
  console.log("\nreplay: presenting a signed grant for a request that is not the outstanding one");
  hitl.writeGrant(
    { decision_id: "00000000-0000-4000-8000-000000000000", principal: govern.agent,
      action: "delete", resource: `record/${RECORD}` },
    hitl.approverSecret(),
  );
  try {
    await deleteRecord(RECORD);
    check(false, "the grant for a non-outstanding request was refused");
  } catch (e) {
    if (!(e instanceof NeedsApproval)) throw e;
    check(store.deletes === 1, `the grant for a non-outstanding request was refused; deletes still ${store.deletes}`);
  }

  // Replay 3: present the same SDK approval token twice.
  console.log("\nreplay: presenting the same SDK approval token twice (probe resource)");
  const probe = "record/rec-probe";
  const token = govern.mintApproval({ action: "delete", resource: probe });
  const first = await govern.authorize({ action: "delete", resource: probe, approval: token });
  const second = await govern.authorize({ action: "delete", resource: probe, approval: token });
  check(first.decision === "Allow" && first.approved === true, "a fresh token downgrades NeedsApproval to Allow once");
  check(second.decision === "NeedsApproval" && second.approved === false,
    "the same token presented again is refused (single use)");

  return finish();
}

async function main(argv) {
  if (argv[0] === "request") return request();
  if (argv[0] === "resume") return resume();
  console.log("usage: node agent.mjs request | resume   (see the header comment)");
  return 2;
}

main(process.argv.slice(2)).then((code) => process.exit(code)).catch((e) => { console.error(e); process.exit(1); });
