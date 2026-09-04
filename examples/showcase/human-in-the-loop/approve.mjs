// The out-of-band approver: show the human what the agent is asking for, then
// sign a grant for exactly that request.
//
//   export APPROVER_SECRET="$(openssl rand -hex 32)"   # same shell as 'agent.mjs resume'
//   node approve.mjs            # approve the pending request → grant.json (pending stays until consumed)
//   node approve.mjs --deny     # refuse it → pending removed, no grant, nothing runs
//
// The pending request names the action, the resource and the decision id — never
// the tool's arguments. The grant is signed with HMAC-SHA256 under
// $APPROVER_SECRET, is bound to the pending request's (principal, action,
// resource), expires after five minutes and can be consumed once.
import * as fs from "node:fs";
import * as hitl from "./hitl.mjs";

function main(argv) {
  const pending = hitl.readPending();
  if (pending === null) {
    console.log(`no pending request at ${hitl.rel(hitl.PENDING)} — run 'node agent.mjs request' first`);
    return 2;
  }

  console.log("pending request");
  for (const key of ["decision_id", "principal", "action", "resource"]) {
    console.log(`  ${key.padEnd(12)} ${pending[key]}`);
  }

  if (argv.includes("--deny")) {
    fs.rmSync(hitl.PENDING, { force: true });
    console.log("\ndenied — pending request removed; no grant written, the action will not run");
    return 0;
  }

  const grant = hitl.writeGrant(pending, hitl.approverSecret());
  console.log(`\napproved — grant written to ${hitl.rel(hitl.GRANT)}`);
  console.log(`  pending_decision_id ${grant.pending_decision_id}`);
  console.log(`  bound to            ${grant.principal} / ${grant.action} / ${grant.resource}`);
  console.log(`  valid for           ${hitl.GRANT_TTL_MS / 1000}s, single use`);
  console.log("\nnow run: node agent.mjs resume");
  return 0;
}

process.exit(main(process.argv.slice(2)));
