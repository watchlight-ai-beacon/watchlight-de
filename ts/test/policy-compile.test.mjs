// A policy that does not compile never leaves a set that decides without it.
//
// The engine compiles asynchronously, at `ready()` or the first decision. A
// policy that does not compile used to be dropped together with the rest of
// its batch, and later decisions ran without them — a dropped `forbid` turned
// its denials into allows. Now the failure sticks: `ready()` and every
// decision throw PolicyCompileError, naming the policy and its file, until
// `reload()` replaces the set.
//
// The Python twin is `tests/test_policy_compile.py`.
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, PolicyCompileError } = require("../dist/index.js");
const CLI = join(dirname(new URL(import.meta.url).pathname), "..", "dist", "cli.js");

const PERMIT_ALL = "permit(principal, action, resource);";
const FORBID_WIRE = 'forbid(principal, action == Action::"wire", resource);';
const BROKEN_FORBID = 'forbid(principal, action == Action::"delete", resource) when { ;';

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const rejection = async (p) => {
  try { await p; } catch (e) { return e; }
  return null;
};

async function main() {
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-compile-"));
  const write = (name, entries) => {
    const p = join(dir, name);
    fs.writeFileSync(p, JSON.stringify(entries));
    return p;
  };
  const gov = () => new Watchlight({ agent: "compiler", auditDir: dir });
  const outcome = async (g, action) => {
    try { return (await g.authorize({ action, principal: 'User::"u"' })).decision; }
    catch (e) { return e; }
  };

  // ── a file with a valid permit and a broken forbid ──
  {
    const file = write("mixed.json", [
      { name: "all", code: PERMIT_ALL },
      { name: "no-delete", code: BROKEN_FORBID },
    ]);
    const g = gov().load(file);
    const e = await rejection(g.ready());
    ok("ready() rejects with PolicyCompileError",
      e instanceof PolicyCompileError && e.policy === "no-delete" && e.source === file, String(e));
    ok("...naming the policy and the file", e && e.message.includes("no-delete") && e.message.includes("mixed.json"));
    for (const action of ["read", "delete", "wire", "read"]) {
      const r = await outcome(g, action);
      ok(`after it, '${action}' is refused (sticky), never decided`, r instanceof PolicyCompileError, String(r));
    }
    const s = await rejection(g.scope({ tools: ["x"] }));
    ok("a scope is refused too", s instanceof PolicyCompileError, String(s));
  }

  // ── the error surfaces at the first decision when ready() is skipped ──
  {
    const g = gov().allow(PERMIT_ALL, "all").allow(BROKEN_FORBID, "no-delete").allow(FORBID_WIRE, "no-wire");
    const first = await outcome(g, "delete");
    const later = await outcome(g, "wire");
    ok("the first decision throws PolicyCompileError, not a request error",
      first instanceof PolicyCompileError, String(first));
    ok("a later decision is still refused — never an Allow past a dropped forbid",
      later instanceof PolicyCompileError, String(later));
  }

  // ── two loads: the second file's broken forbid keeps the first file's forbids ──
  {
    const first = write("first.json", [{ name: "all", code: PERMIT_ALL }, { name: "no-wire", code: FORBID_WIRE }]);
    const second = write("second.json", [
      { name: "read", code: 'permit(principal, action == Action::"read", resource);' },
      { name: "no-delete", code: BROKEN_FORBID },
    ]);
    const g = gov().load(first);
    ok("the first file decides", (await outcome(g, "wire")) === "Deny" && (await outcome(g, "read")) === "Allow");
    g.load(second);
    const e = await rejection(g.ready());
    ok("loading a second file with a broken forbid rejects", e instanceof PolicyCompileError, String(e));
    ok("...and 'wire' is still never allowed", (await outcome(g, "wire")) instanceof PolicyCompileError);
    ok("...nor 'delete'", (await outcome(g, "delete")) instanceof PolicyCompileError);
  }

  // ── concurrent first decisions cannot race past the failure ──
  {
    const g = gov().allow(PERMIT_ALL, "all").allow(BROKEN_FORBID, "no-delete");
    const results = await Promise.all(["read", "delete", "read", "delete"].map((a) => outcome(g, a)));
    ok("concurrent first decisions are all refused",
      results.every((r) => r instanceof PolicyCompileError), results.map(String).join(" | "));
  }

  // ── reload: a broken set is refused; a good one recovers ──
  {
    const g = gov().allow(PERMIT_ALL, "all").allow(FORBID_WIRE, "no-wire");
    ok("before the reload the set decides", (await outcome(g, "wire")) === "Deny");
    const file = write("reload.json", [{ name: "all", code: PERMIT_ALL }, { name: "no-delete", code: BROKEN_FORBID }]);
    g.reload(file);
    const e = await rejection(g.ready());
    ok("a reload with a broken forbid rejects at ready()",
      e instanceof PolicyCompileError && e.source === file, String(e));
    ok("...and nothing is decided under it", (await outcome(g, "delete")) instanceof PolicyCompileError);
    ok("...not even what the old set allowed", (await outcome(g, "read")) instanceof PolicyCompileError);
    g.reload({ policies: [{ name: "all", code: PERMIT_ALL }, { name: "no-wire", code: FORBID_WIRE }] });
    await g.ready();
    ok("a successful reload recovers", (await outcome(g, "read")) === "Allow" && (await outcome(g, "wire")) === "Deny");
  }

  // ── the error keeps the kind and cuts the engine's detail short ──
  {
    const secret = "s3cr3t-" + "x".repeat(80);
    const g = gov().allow(`forbid(principal, action, resource) when { context.k == "${secret}" ; };`, "leaky");
    const e = await rejection(g.ready());
    const m = e ? e.message : "";
    const detail = m.slice(m.indexOf("(") + 1, m.indexOf("). "));
    const [kind, ...rest] = detail.split(": ");
    ok("the message names the policy, never the full source text",
      e instanceof PolicyCompileError && m.includes('"leaky"') && !m.includes(secret) && !m.includes("add_policy failed"), m);
    ok("...kind and detail are each at most 40 characters",
      kind.length <= 40 && rest.join(": ").length <= 40, detail);
  }

  // ── the CLI ──
  {
    write("cli.json", [{ name: "all", code: PERMIT_ALL }, { name: "no-delete", code: BROKEN_FORBID }]);
    const suite = join(dir, "suite.json");
    fs.writeFileSync(suite, JSON.stringify({ policyFile: "cli.json", tests: [{ action: "delete", expect: "Deny" }] }));
    const r = spawnSync(process.execPath, [CLI, "policy", "test", suite], { encoding: "utf8" });
    ok("CLI exits 2 naming the policy that does not compile",
      r.status === 2 && r.stderr.includes("no-delete"), `${r.status} ${r.stderr}`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
