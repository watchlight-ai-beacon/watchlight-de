// Loading a policy file never leaves a governor empty by accident.
//
// A missing path, a directory, invalid JSON, an unrecognised shape, a malformed
// entry, and a file that holds no policies all throw, naming the file — they
// used to load nothing without a word, and a governor with no policies denies
// every call. An empty set loads only with `{ allowEmpty: true }`. One policy
// object per file (the MCP PEP's shape) loads as one policy.
//
// The Python twin is `tests/test_policy_loading.py`.
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight } = require("../dist/index.js");

const HERE = dirname(new URL(import.meta.url).pathname);
const CLI = join(HERE, "..", "dist", "cli.js");
const EXAMPLES = join(HERE, "..", "..", "examples");
const READ = 'permit(principal, action == Action::"read", resource);';

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const thrown = (fn) => {
  try { fn(); } catch (e) { return e; }
  return null;
};

async function main() {
  const dir = fs.mkdtempSync(join(os.tmpdir(), "wl-load-"));
  const write = (name, data) => {
    const p = join(dir, name);
    fs.writeFileSync(p, typeof data === "string" ? data : JSON.stringify(data));
    return p;
  };
  const gov = () => new Watchlight({ agent: "loader", auditDir: dir });
  const allowed = async (g, action = "read", context) =>
    (await g.authorize({ action, principal: 'User::"u"', context })).allowed;

  // ── the accepted shapes ──
  for (const [label, data] of [
    ["a list", [{ name: "read", code: READ }]],
    ["{policies: [...]}", { policies: [{ name: "read", code: READ }] }],
    ["a single policy object", { name: "read", code: READ }],
    ["a single object with PEP fields", { id: "read", name: "read", description: "d", code: READ, active: true }],
  ]) {
    const g = gov().load(write("shape.json", data), { force: true });
    ok(`${label} loads one policy`, g.policyCount === 1 && (await allowed(g)), String(g.policyCount));
  }

  const mcp = gov().load(join(EXAMPLES, "mcp.policy.json"));
  ok("examples/mcp.policy.json loads one policy", mcp.policyCount === 1, String(mcp.policyCount));
  ok("...which allows a read tool",
    await allowed(mcp, "call", { mcp: { tool: "search_repositories" } }));
  ok("...and denies a destructive one",
    !(await allowed(mcp, "call", { mcp: { tool: "delete_repository" } })));

  for (const name of fs.readdirSync(EXAMPLES).filter((n) => n.endsWith(".policy.json")).sort()) {
    ok(`examples/${name} loads at least one policy`, gov().load(join(EXAMPLES, name)).policyCount >= 1);
  }

  // ── refusals, each naming the file ──
  {
    const g = gov();
    const later = join(dir, "later.policy.json");
    const e = thrown(() => g.load(later));
    ok("a missing file throws naming the path",
      e && e.code === "ENOENT" && e.message.includes("later.policy.json"), String(e));
    ok("...and loads nothing", g.policyCount === 0);
    write("later.policy.json", [{ name: "read", code: READ }]);
    ok("...and is not remembered: it loads once it exists", g.load(later).policyCount === 1);
  }
  {
    const e = thrown(() => gov().load(dir));
    ok("a directory throws", e && e.code === "EISDIR" && /directory/.test(e.message), String(e));
  }
  {
    const e = thrown(() => gov().load(write("broken.json", "[{")));
    ok("invalid JSON throws naming the file", e && e.message.includes("broken.json is not valid JSON"), String(e));
  }

  for (const [label, data, fragment] of [
    ["an empty list", [], "defines no policies"],
    ["an empty policies list", { policies: [] }, "defines no policies"],
    ["an empty object", {}, 'neither "policies" nor "code"'],
    ["an object without code", { name: "x" }, 'neither "policies" nor "code"'],
    ["a suite with policyFile", { policyFile: "p.json", tests: [] }, "policy test suite"],
    ["policies not a list", { policies: { name: "x", code: READ } }, '"policies" must be a list'],
    ["both policies and code", { policies: [], code: READ }, 'both "policies" and "code"'],
    ["a JSON string", "permit(principal, action, resource);", "is a string"],
    ["JSON null", null, "is null"],
    ["an entry that is a string", [READ], "is a string, not"],
    ["an entry without code", [{ name: "x" }], 'no Cedar "code"'],
    ["an entry with blank code", [{ name: "x", code: "   " }], 'no Cedar "code"'],
    ["a non-string name", [{ name: 7, code: READ }], '"name" must be a string'],
    ["an inactive entry", [{ name: "off", code: READ, active: false }], '"active": false'],
  ]) {
    const p = write("bad.policy.json", JSON.stringify(data));
    const g = gov();
    const e = thrown(() => g.load(p));
    ok(`${label} throws (${fragment})`,
      e && e.message.includes(fragment) && e.message.includes("bad.policy.json") && g.policyCount === 0,
      String(e));
    fs.writeFileSync(p, JSON.stringify([{ name: "read", code: READ }]));
    ok(`...and is not remembered (${label})`, g.load(p).policyCount === 1);
  }

  {
    const g = gov();
    const e = thrown(() => g.load(write("half.json", [{ name: "read", code: READ }, { name: "broken" }])));
    ok("one bad entry loads none of the file",
      e && e.message.includes('policy "broken"') && g.policyCount === 0 && !(await allowed(g)), String(e));
  }

  // ── an empty set, on purpose ──
  {
    const g = gov();
    ok("allowEmpty loads an explicitly empty set",
      g.load(write("none.json", { policies: [] }), { allowEmpty: true }).policyCount === 0 && !(await allowed(g)));
    ok("allowEmpty does not excuse a missing file",
      thrown(() => g.load(join(dir, "absent.json"), { allowEmpty: true })) !== null);
    ok("allowEmpty does not excuse a bad shape",
      thrown(() => g.load(write("obj.json", { name: "x" }), { allowEmpty: true })) !== null);
  }

  // ── reload reads the same shapes ──
  {
    const g = gov().allow('permit(principal, action == Action::"list", resource);');
    g.reload(write("one.json", { name: "read", code: READ }));
    ok("reload accepts a single policy object",
      g.policyCount === 1 && (await allowed(g)) && !(await allowed(g, "list")));
    for (const data of [{ name: "x" }, [{ name: "x" }], { name: "r", code: READ, active: false }]) {
      const e = thrown(() => g.reload(write("bad-reload.json", data)));
      ok(`reload refuses ${JSON.stringify(data)} and keeps the set`,
        e !== null && g.policyCount === 1 && (await allowed(g)), String(e));
    }
    const e = thrown(() => g.reload({ policies: [{ name: "x" }] }));
    ok("reload refuses a malformed in-memory entry",
      e && e.message.includes('no Cedar "code"') && g.policyCount === 1, String(e));
  }

  // ── the CLI ──
  write("empty.json", []);
  write("single.json", { name: "read", code: READ });
  const suite = (fields) =>
    write("suite.json", { tests: [{ action: "read", expect: "Allow" }], ...fields });
  for (const [label, fields, fragment] of [
    ["a missing policyFile", { policyFile: "absent.json" }, "no such policy file"],
    ["an empty policyFile", { policyFile: "empty.json" }, "defines no policies"],
    ["empty inline policies", { policies: [] }, "defines no policies"],
    ["a malformed inline policy", { policies: [{ name: "x" }] }, 'no Cedar "code"'],
    ["no policies at all", {}, "declares no policies"],
  ]) {
    const r = spawnSync(process.execPath, [CLI, "policy", "test", suite(fields)], { encoding: "utf8" });
    ok(`CLI exits 2 on ${label}`, r.status === 2 && r.stderr.includes(fragment), `${r.status} ${r.stderr}`);
  }
  {
    const r = spawnSync(process.execPath, [CLI, "policy", "test", suite({ policyFile: "single.json" })], { encoding: "utf8" });
    ok("CLI loads a single-object policy file", r.status === 0, `${r.status} ${r.stderr}`);
  }

  // ── what the file is made of: encoding, JSON, and what a message echoes ──
  {
    const latin1 = join(dir, "latin1.json");
    fs.writeFileSync(latin1, Buffer.concat([
      Buffer.from('[{"name": "caf'), Buffer.from([0xe9]),
      Buffer.from('", "code": "permit(principal, action, resource);"}]'),
    ]));
    const e = thrown(() => gov().load(latin1));
    ok("invalid UTF-8 throws naming the file", e && e.message.includes("latin1.json is not valid UTF-8"), String(e));

    const bom = join(dir, "bom.json");
    fs.writeFileSync(bom, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify([{ name: "read", code: READ }]))]));
    ok("a byte-order mark is not part of the JSON", gov().load(bom).policyCount === 1);

    const secret = "do-not-echo-this-value";
    const broken = write("broken2.json", '[{"name": "x",\n  "code": ' + secret + "}]");
    const j = thrown(() => gov().load(broken));
    ok("a JSON error never quotes the file", j && !j.message.includes(secret) && !j.message.includes('"x"'), String(j));
    ok("...and names the line and column where the parser gives a position",
      j && (/line 2 column \d+/.test(j.message) || /is not valid JSON$/.test(j.message)), String(j));

    const loop = join(dir, "loop.json");
    fs.symlinkSync(loop, loop);
    const l = thrown(() => gov().load(loop));
    ok("a symlink loop is not reported as missing",
      l && l.code === "ELOOP" && l.message.includes("cannot read policy file"), String(l));

    if (typeof process.getuid !== "function" || process.getuid() !== 0) {
      const locked = write("locked.json", [{ name: "read", code: READ }]);
      fs.chmodSync(locked, 0);
      const a = thrown(() => gov().load(locked));
      fs.chmodSync(locked, 0o600);
      ok("an unreadable file is EACCES, not missing and not invalid JSON",
        a && a.code === "EACCES" && a.message.includes("cannot read policy file") && !/JSON/.test(a.message), String(a));
    }

    const long = "x".repeat(500);
    const t = thrown(() => gov().load(write("long.json", [{ name: "n", code: READ, active: long }])));
    ok("an echoed value is cut short", t && !t.message.includes(long) && t.message.includes("…"), String(t));
  }
  {
    write("uncompilable.json", [{ name: "broken", code: "permit(principal, action, resource) when { ;" }]);
    const r = spawnSync(process.execPath, [CLI, "policy", "test", suite({ policyFile: "uncompilable.json" })], { encoding: "utf8" });
    ok("CLI exits 2 on a policy the engine cannot compile, with a real message",
      r.status === 2 && /watchlight: \S/.test(r.stderr) && !r.stderr.includes("undefined"), `${r.status} ${r.stderr}`);
  }

  {
    const open = write("open.json", '[{"name": "x", "code": "permit(');
    const e = thrown(() => gov().load(open));
    ok("an unterminated string is reported where it starts (as in Python)",
      e && e.message.includes("line 1 column 24"), String(e));
    const n = thrown(() => gov().load(write("longname.json", [{ name: "n".repeat(200) }])));
    ok("a long name is cut inside its quotes",
      n && n.message.includes(`policy "${"n".repeat(39)}…" in`), String(n));
  }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
