// @watchlight/sdk async `context` binding test.
//
// A counter source may be asynchronous — that is its purpose, since a durable
// store is a network call. A quota policy reads the count out of Cedar
// `context`. This asserts the two compose through `tool()`: an async `context`
// binding is AWAITED before the decision, so the count the policy evaluates is
// the one the binding returned — not the empty context a dropped promise leaves
// behind. The synchronous form is asserted to behave exactly as before.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, Denied, NeedsApproval, CounterSourceError, UnresolvedContextError } =
  require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const rejects = async (p, Type) => {
  try { await p; return null; } catch (e) { return e instanceof Type ? e : null; }
};

// The quotas pattern's policy, verbatim.
const UNDER_QUOTA =
  'permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 100 };';
const CEILING =
  'forbid(principal, action == Action::"read", resource) when { context.reads_this_hour >= 100 };';
const USER = 'User::"u1"';

const quota = (g) => g.allow(UNDER_QUOTA, "reads-within-hourly-quota").allow(CEILING, "hard-ceiling-on-reads");

const gov = (opts = {}) => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-actx-"));
  const g = new Watchlight({ agent: "actx-agent", auditDir, ...opts });
  quota(g);
  return { g, auditDir };
};

async function main() {
  console.log("the synchronous form is unchanged");
  {
    const { g } = gov();
    const ran = [];
    const read = g.tool(function fetchDoc(o) { ran.push(o.docId); return `doc:${o.docId}`; }, {
      intent: "read",
      principal: () => USER,
      resource: (o) => `doc/${o.docId}`,
      context: { reads_this_hour: 3 },
    });
    ok("a fixed context object still allows under quota", (await read({ docId: "a" })) === "doc:a");

    const seen = [];
    const readFn = g.tool(function fetchDoc2(o) { ran.push(o.docId); return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: (o) => { seen.push(o); return { reads_this_hour: o.count }; },
    });
    ok("a synchronous function context still allows under quota", (await readFn({ count: 99 })) === "doc");
    ok("…and is called with the tool's arguments", seen.length === 1 && seen[0].count === 99);
    const denied = await rejects(readFn({ count: 100 }), Denied);
    ok("…and still denies over quota", denied !== null);
    ok("the body never ran on the denial", ran.length === 2);
    ok("the denial reason is the uniform one", denied && denied.reason === "not authorized");
  }
  {
    const { g } = gov();
    let bodyRuns = 0;
    const boom = new Error("binding failed");
    const read = g.tool(function fetchDoc(o) { bodyRuns++; return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: () => { throw boom; },
    });
    const err = await rejects(read({}), Error);
    ok("a throwing synchronous binding still propagates", err === boom);
    ok("…and the body never ran", bodyRuns === 0);
  }

  console.log("an async binding is awaited before the decision");
  {
    const { g } = gov();
    const order = [];
    const seen = [];
    const read = g.tool(function fetchDoc(o) { order.push("body"); return "doc"; }, {
      intent: "read",
      principal: () => USER,
      resource: (o) => `doc/${o.docId}`,
      context: async (o) => {
        seen.push(o);
        await new Promise((r) => setTimeout(r, 1));
        order.push("context");
        return { reads_this_hour: o.count };
      },
    });
    ok("under quota the call is allowed", (await read({ docId: "a", count: 99 })) === "doc");
    ok("the binding is awaited BEFORE the body runs", order.join(",") === "context,body");
    ok("…and is called with the tool's arguments", seen.length === 1 && seen[0].docId === "a");

    order.length = 0;
    const denied = await rejects(read({ docId: "a", count: 100 }), Denied);
    ok("over quota the call is denied", denied !== null);
    ok("…and the body never ran", order.join(",") === "context");
    ok("…with the uniform denial reason", denied && denied.reason === "not authorized");
  }
  {
    const { g } = gov();
    let bodyRuns = 0;
    const boom = new Error("store unreachable");
    const read = g.tool(function fetchDoc() { bodyRuns++; return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: async () => { throw boom; },
    });
    const err = await rejects(read({}), Error);
    ok("a rejecting async binding propagates", err === boom);
    ok("…and the body never ran (fail-closed)", bodyRuns === 0);
  }
  {
    // A binding that returns a promise without being declared `async` is the
    // same shape and is awaited the same way.
    const { g } = gov();
    const read = g.tool(function fetchDoc() { return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: () => Promise.resolve({ reads_this_hour: 1 }),
    });
    ok("a promise-returning binding is awaited too", (await read({})) === "doc");
  }
  {
    // The approval re-authorization sees the SAME resolved context, and the
    // binding is resolved once per call, not once per authorize.
    const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-actx-"));
    const g = new Watchlight({ agent: "actx-agent", auditDir });
    g.allow('@enforcement_effect("require_approval")\npermit(principal, action == Action::"read", resource) when { context.reads_this_hour < 100 };', "read");
    let resolved = 0;
    let bodyRuns = 0;
    const read = g.tool(function fetchDoc() { bodyRuns++; return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: async () => { resolved++; return { reads_this_hour: 1 }; },
      onNeedsApproval: () => true,
    });
    ok("an approved call runs on the awaited context", (await read({})) === "doc");
    ok("…and the binding was resolved once for the call", resolved === 1);

    const hold = g.tool(function fetchDoc2() { bodyRuns++; return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: async () => ({ reads_this_hour: 1 }),
    });
    ok("an unconfirmed approval still holds", (await rejects(hold({}), NeedsApproval)) !== null);
    ok("…and only the approved body ran", bodyRuns === 1);
  }

  console.log("a durable counter source feeding a quota policy through tool()");
  {
    // The end-to-end case: no local audit file at all, every record mirrored to
    // a store, and the count read back from that store — asynchronously.
    const store = [];
    let stored = 0;
    const queries = [];
    const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-actx-"));
    const g = new Watchlight({
      agent: "actx-agent",
      auditDir,
      auditFile: false,
      auditSink: (record) => { store.push(record); },
      counterSource: async (q) => { queries.push(q); return stored; },
    });
    quota(g);

    let bodyRuns = 0;
    const read = g.tool(function fetchDoc(o) { bodyRuns++; return `doc:${o.docId}`; }, {
      intent: "read",
      principal: () => USER,
      resource: (o) => `doc/${o.docId}`,
      context: async (o) => {
        const c = await g.countersAsync({ principal: USER, intent: "read", window: "1h" });
        return c.truncated ? {} : { reads_this_hour: c.count };
      },
    });

    stored = 99;
    ok("under the durable quota the tool runs", (await read({ docId: "a" })) === "doc:a");
    ok("…and the count came from the store, not the local file",
      queries.length === 1 && queries[0].principal === USER && queries[0].intent === "read");
    ok("…and the decision was mirrored to the sink", store.some((r) => r.decision === "Allow"));

    stored = 100;
    const denied = await rejects(read({ docId: "b" }), Denied);
    ok("at the durable quota the tool is denied", denied !== null);
    ok("…and the body never ran", bodyRuns === 1);
    ok("…and the denial is on the trail", store.some((r) => r.decision === "Deny"));

    // The old workaround is still refused rather than silently answered from a
    // local file that is not even being written.
    const sync = g.tool(function fetchDoc2() { bodyRuns++; return "doc"; }, {
      intent: "read",
      principal: () => USER,
      context: () => ({ reads_this_hour: g.counters({ principal: USER, intent: "read", window: "1h" }).count }),
    });
    const e = await rejects(sync({}), CounterSourceError);
    ok("a synchronous binding over an async source still fails closed by name",
      e !== null && /countersAsync/.test(e.message));
    ok("…and that body never ran either", bodyRuns === 1);
  }

  // ── authorize(): an unresolved promise is refused, not evaluated ─────────
  // The async binding is a tool() feature. `authorize` takes a resolved record,
  // and `{...promise}` spreads to nothing — so before this guard a promise
  // handed to `authorize` produced a plain Deny with the quota key missing,
  // indistinguishable from a policy refusing the call. TypeScript rejects it at
  // compile time; plain JavaScript callers had no such warning.
  {
    const records = [];
    const g = new Watchlight({
      agent: "actx-agent", auditFile: false, auditSink: (r) => records.push(r),
    });
    g.allow(UNDER_QUOTA, "reads-within-hourly-quota");

    const pending = (async () => ({ reads_this_hour: 0 }))();
    let thrown = null;
    try {
      await g.authorize({ action: "read", resource: "doc", principal: USER, context: pending });
    } catch (e) { thrown = e; }
    await pending;   // the SDK does not dispose of what the caller made

    ok("authorize refuses an unresolved promise context",
      thrown instanceof UnresolvedContextError, String(thrown && thrown.name));
    ok("…naming the fix rather than the engine's entity types",
      thrown !== null && /countersAsync/.test(thrown.message));
    ok("…and writes no decision record, because it is not a decision",
      records.length === 0, `records=${records.length}`);

    const d = await g.authorize({
      action: "read", resource: "doc", principal: USER,
      context: { reads_this_hour: 0 },
    });
    ok("a resolved record still decides normally", d.decision === "Allow", d.decision);
    ok("…and that one IS on the trail", records.length === 1, `records=${records.length}`);
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
