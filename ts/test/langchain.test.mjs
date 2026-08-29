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

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(2); });
