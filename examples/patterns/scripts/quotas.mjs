// quotas — a durable counter source feeding a quota policy through `tool()`,
// run against the real engine.
//
// The suite proves the policy's verdicts for a given `reads_this_hour`. This
// proves the number gets there: an async `counterSource` is read with
// `countersAsync` inside an async `context` binding, awaited before the
// decision, so a governed tool is allowed under the durable quota and denied at
// it — with the local audit file switched off entirely.
import { loadSdk, checks } from "./_sdk.mjs";
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";

const { Watchlight, Denied, CounterSourceError } = loadSdk();
const t = checks("quotas");

const UNDER_QUOTA =
  'permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 100 };';
const CEILING =
  'forbid(principal, action == Action::"read", resource) when { context.reads_this_hour >= 100 };';

// Stand-in for the durable store the `auditSink` writes to: rows in, count out.
const db = {
  rows: [],
  insert(_table, record) { this.rows.push(record); },
  // The read side — a network call in real life, hence the promise.
  async countDecisions({ principal, intent, after, until }) {
    return this.rows.filter((r) =>
      r.event === undefined && r.decision === "Allow" &&
      r.principal === principal && (intent === undefined || r.intent === intent) &&
      r.ts > after && r.ts <= until).length;
  },
};

const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-pattern-quotas-"));
const govern = new Watchlight({
  agent: "doc-agent",
  auditDir,
  auditFile: false,                                   // the store is the only trail
  auditSink: (record) => db.insert("agent_audit", record),
  counterSource: (q) => db.countDecisions({
    principal: q.principal, intent: q.intent, after: q.window.start, until: q.window.end,
  }),
});
govern.allow(UNDER_QUOTA, "reads-within-hourly-quota");
govern.allow(CEILING, "hard-ceiling-on-reads");

const user = (o) => `User::"${o.userId}"`;
let bodyRuns = 0;

const readDoc = govern.tool(function fetchDocument(o) { bodyRuns++; return `doc:${o.docId}`; }, {
  intent: "read",
  principal: user,
  resource: (o) => `doc/${o.docId}`,
  context: async (o) => {
    try {
      const c = await govern.countersAsync({ principal: user(o), intent: "read", window: "1h" });
      return c.truncated ? {} : { reads_this_hour: c.count };
    } catch {
      return {};   // no counter → the condition can't evaluate → Deny, audited
    }
  },
});

try {
  const call = (n) => readDoc({ userId: "u1", docId: `d${n}` });

  t.ok("no local audit file is written", !fs.existsSync(join(auditDir, "audit.jsonl")));
  t.ok("the first read is allowed — the durable count is 0", (await call(0)) === "doc:d0");
  t.ok("the Allow reached the store the count is read from",
    db.rows.filter((r) => r.decision === "Allow").length === 1);

  // Fill the store to the quota, then the next call must be denied.
  for (let i = 1; i < 100; i++) await call(i);
  t.ok("100 reads are admitted", bodyRuns === 100);

  let denied = null;
  try { await call(100); } catch (e) { denied = e; }
  t.ok("the 101st is denied by the durable count", denied instanceof Denied);
  t.ok("the tool body never ran on the denial", bodyRuns === 100);
  t.ok("the denial says only 'not authorized'", denied?.reason === "not authorized");
  t.ok("the denial is on the trail the store holds",
    db.rows.some((r) => r.event === undefined && r.decision === "Deny"));

  // A synchronous binding cannot read an async source: it fails closed by name,
  // never falling back to a local file that is not even being written.
  const syncBound = govern.tool(function fetchDocument2(o) { bodyRuns++; return "doc"; }, {
    intent: "read",
    principal: user,
    context: (o) => ({ reads_this_hour: govern.counters({ principal: user(o), intent: "read" }).count }),
  });
  let refused = null;
  try { await syncBound({ userId: "u1" }); } catch (e) { refused = e; }
  t.ok("a synchronous binding over an async source fails closed",
    refused instanceof CounterSourceError && /countersAsync/.test(refused.message));
  t.ok("…and that body never ran either", bodyRuns === 100);
} finally {
  fs.rmSync(auditDir, { recursive: true, force: true });
}

t.done();
