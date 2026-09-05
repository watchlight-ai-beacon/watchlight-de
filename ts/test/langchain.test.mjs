// @watchlight/sdk LangChain / LangGraph.js adapter test — governTool authorizes
// a tool's invoke via the in-process engine, allows permitted tools, denies the
// rest fail-closed (body never runs), preserves the tool's other members, and
// maps intents. Uses a mock StructuredTool (name + invoke + a passthrough
// member) so no LangChain install is needed.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, governTool, governTools, Denied } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

// Minimal StructuredTool-like mock: name, invoke, description, a helper method.
function mockTool(name) {
  let ran = 0;
  return {
    name,
    description: `mock ${name}`,
    invoke: async (input) => { ran++; return `${name}:${JSON.stringify(input)}`; },
    ranCount: () => ran,
  };
}

async function main() {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-lc-"));
  const governor = new Watchlight({ agent: "lc-agent", auditDir });
  governor.allow('permit(principal, action == Action::"research", resource);', "allow-research");

  const search = mockTool("web_search");
  const wire = mockTool("wire_transfer");

  // intent defaults to the tool name; map web_search→research, wire_transfer→transfer.
  const govSearch = governTool(search, { governor, intent: "research" });
  const govWire = governTool(wire, { governor, intent: "transfer" });

  ok("governed tool preserves name", govSearch.name === "web_search");
  ok("governed tool preserves other members", govSearch.description === "mock web_search");

  // Permitted → invoke runs, returns the tool's result.
  const out = await govSearch.invoke({ query: "cedar" });
  ok("permitted tool invoke runs", out === 'web_search:{"query":"cedar"}');
  ok("underlying tool executed once", search.ranCount() === 1);

  // Denied → throws Denied, underlying tool never runs.
  let denied = null;
  try { await govWire.invoke({ to: "acct-9", amount: 1000 }); } catch (e) { denied = e; }
  ok("unpermitted tool invoke throws Denied", denied instanceof Denied, String(denied));
  ok("denied tool body NEVER executed (fail-closed)", wire.ranCount() === 0);

  // Original tools are not mutated (governTool returns a view).
  ok("original tool invoke untouched", typeof search.invoke === "function" && search !== govSearch);

  // governTools maps an array with intentFor.
  const [gs, gw] = governTools([mockTool("web_search"), mockTool("wire_transfer")], {
    governor,
    intentFor: (n) => ({ web_search: "research", wire_transfer: "transfer" }[n] ?? n),
  });
  ok("governTools allows mapped-permitted", (await gs.invoke({ q: "x" })).startsWith("web_search:"));
  let arrDenied = false;
  try { await gw.invoke({ a: 1 }); } catch { arrDenied = true; }
  ok("governTools denies mapped-unpermitted", arrDenied);

  // Audit: value-free, decisions recorded, no arg values.
  const raw = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("decisions audited", raw.includes('"resource":"tool/web_search"') && raw.includes('"decision":"Deny"'));
  ok("audit value-free (no tool args)", !raw.includes("acct-9") && !raw.includes("1000") && !raw.includes("cedar"));

  // ── onResult (egress): govern what the tool RETURNS ──
  const fetchDoc = mockTool("fetch_doc");
  const infos = [];
  const govFetch = governTool(fetchDoc, {
    governor, intent: "research",
    onResult: (result, info) => { infos.push(info); return typeof result === "string" ? "[redacted-doc]" : undefined; },
  });
  ok("governTool onResult replacement reaches the caller", (await govFetch.invoke({ id: 1 })) === "[redacted-doc]");
  ok("underlying tool ran once before egress", fetchDoc.ranCount() === 1);
  ok("onResult info carries intent/resource/principal/decisionId",
    infos[0]?.intent === "research" && infos[0]?.resource === "tool/fetch_doc" && infos[0]?.principal === 'Agent::"lc-agent"' && typeof infos[0]?.decisionId === "string",
    JSON.stringify(infos[0]));

  ok("an unannotated permit puts no obligations key on the hook info", infos.length >= 1 && !("obligations" in infos[0]));

  // The hook receives the SAME obligations the decision carries.
  const og = new Watchlight({ agent: "lc-oblig-agent", auditDir: fs.mkdtempSync(join(os.tmpdir(), "wl-oblig-")) });
  og.allow('@obligate_redact("ssn, email")\n@obligate_max_items("3")\npermit(principal, action == Action::"read", resource);', "read-redacted");
  const oInfos = [];
  const govRead = governTool(mockTool("read_doc"), { governor: og, intent: "read", onResult: (r, info) => { oInfos.push(info); return undefined; } });
  await govRead.invoke({ id: 7 });
  const oDecision = await og.authorize({ action: "read", resource: "tool/read_doc" });
  ok("governTool onResult info carries the decision's obligations",
    oInfos.length === 1 && oInfos[0].obligations !== undefined && JSON.stringify(oInfos[0].obligations) === JSON.stringify(oDecision.obligations)
      && oInfos[0].obligations.redact.length === 2 && oInfos[0].obligations.maxItems === 3, JSON.stringify([oInfos[0], oDecision.obligations]));

  const pt = governTool(mockTool("pt_tool"), { governor, intent: "research", onResult: () => undefined });
  ok("void onResult passes the result through", (await pt.invoke({ a: 1 })) === 'pt_tool:{"a":1}');

  const bad = governTool(mockTool("bad_tool"), { governor, intent: "research", onResult: () => { throw new Error("screen failed"); } });
  let badErr = null, badOut;
  try { badOut = await bad.invoke({ q: "SENSITIVE" }); } catch (e) { badErr = e; }
  ok("throwing onResult fails closed (error propagates, raw never returned)", badErr?.message === "screen failed" && badOut === undefined, String(badErr));

  const [gtool] = governTools([mockTool("web_search")], { governor, intentFor: () => "research", onResult: () => "X" });
  ok("governTools applies onResult to every tool", (await gtool.invoke({})) === "X");

  const recs = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const dec = recs.find((r) => r.resource === "tool/fetch_doc" && r.decision === "Allow");
  const egr = recs.find((r) => r.event === "egress" && r.resource === "tool/fetch_doc");
  ok("egress record joined to the decision by decision_id",
    dec && egr && egr.decision_id === dec.decision_id && egr.decision_id === infos[0].decisionId && egr.replaced === true, JSON.stringify([dec, egr]));
  ok("passthrough egress record replaced:false", recs.some((r) => r.event === "egress" && r.resource === "tool/pt_tool" && r.replaced === false && !r.withheld));
  ok("withheld egress record on hook failure", recs.some((r) => r.event === "egress" && r.resource === "tool/bad_tool" && r.withheld === true));
  const raw2 = fs.readFileSync(join(auditDir, "audit.jsonl"), "utf8");
  ok("egress audit value-free (no raw or replaced payload)", !raw2.includes("redacted-doc") && !raw2.includes("SENSITIVE") && !raw2.includes("screen failed"));

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
