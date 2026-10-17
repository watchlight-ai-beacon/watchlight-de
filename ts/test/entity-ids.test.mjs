// The request helpers build only references the engine accepts, in the one
// spelling it accepts, and refuse every id it would refuse.
//
// The engine (@watchlight/engine 0.2.3) reads a request reference with a strict
// parser: a quote, an apostrophe and a backslash must be escaped as `\"`, `\'`
// and `\\`, and a character that is not printable must be written as `\u{…}`.
// The helpers escape the first group and refuse the second. The shared fixture
// tests/fixtures/entity-ids.json holds the cases both lanes must agree on; the
// Python twin is tests/test_entity_ids.py.
import { createRequire } from "node:module";
import * as fs from "node:fs";

const require = createRequire(import.meta.url);
const { Watchlight, principals, policyEntityRef } = require("../dist/index.js");
const { Engine } = require("@watchlight/engine");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};

const FIXTURE = JSON.parse(
  fs.readFileSync(new URL("../../tests/fixtures/entity-ids.json", import.meta.url), "utf8")
).cases;

const accepts = async (engine, principal) => {
  try { await engine.authorize({ principal, action: "t", resource: "r", context: {} }); return true; }
  catch { return false; }
};
// The id with only a quote, an apostrophe and a backslash escaped: what a
// caller would write without the helper's refusal.
const raw = (id) => 'User::"' + id.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/'/g, "\\'") + '"';
const refuses = (fn) => { try { fn(); return null; } catch (e) { return e; } };

async function main() {
  const engine = await Engine.create();

  for (const c of FIXTURE) {
    if (c.user === null) {
      const e = refuses(() => principals.user(c.id));
      ok(`${c.label}: refused, value-free`, e instanceof TypeError && !String(e.message).includes(c.id), String(e));
      ok(`${c.label}: the engine refuses it too`, (await accepts(engine, raw(c.id))) === false);
      continue;
    }
    const ref = principals.user(c.id);
    ok(`${c.label}: the reference both lanes build`, ref === c.user, JSON.stringify(ref));
    ok(`${c.label}: the same string as forPolicy`, ref === policyEntityRef("User", c.id));
    ok(`${c.label}: the engine accepts it`, await accepts(engine, ref));
    const g = new Watchlight({ agent: "ids", auditFile: false, auditSink: () => {} });
    g.allow(`permit(principal == ${policyEntityRef("User", c.id)}, action == Action::"t", resource);`);
    ok(`${c.label}: it matches the policy for this id`,
      (await g.authorize({ action: "t", principal: ref })).allowed === true);
    ok(`${c.label}: and not one for a neighbouring id`,
      (await g.authorize({ action: "t", principal: principals.user(c.id + "x") })).allowed === false);
  }

  // A lone surrogate is a Cs code point: refused, like the engine.
  for (const id of ["a\ud800b", "\udc00"]) {
    ok(`a lone surrogate is refused (${JSON.stringify(id)})`, refuses(() => principals.user(id)) instanceof TypeError);
  }

  ok("an apostrophe is escaped in the spelling the engine accepts",
    principals.user("o'brien@example.com") === "User::\"o\\'brien@example.com\"" &&
    (await accepts(engine, "User::\"o'brien@example.com\"")) === false &&
    (await accepts(engine, principals.user("o'brien@example.com"))) === true);
  ok("NUL is escaped for policy text as the engine spells it",
    policyEntityRef("User", "a\u0000b") === 'User::"a\\0b"' &&
    (await accepts(engine, 'User::"a\\0b"')) && !(await accepts(engine, 'User::"a\\u{0}b"')));
  for (const name of ["a\u00a0b", "a\u200bb", "\u0301a"]) {
    const e = refuses(() => new Watchlight({ agent: name, auditFile: false }));
    ok(`an unprintable agent name is refused at the name (${JSON.stringify(name)})`,
      e instanceof TypeError && e.message.includes("must not contain a character the engine requires"), String(e));
  }

  // Code point by code point, in the middle and at the start of an id: the
  // helper never builds a reference the engine refuses. The other direction is
  // checked only where the lane's Unicode data assigns the code point: a lane
  // whose data is older than the engine's refuses a newly assigned character
  // the engine accepts, which fails closed.
  const unassigned = /^\p{Cn}$/u;
  const accepted = [], refused = [];
  const points = [];
  for (let cp = 0; cp < 0x20000; cp++) points.push(cp);
  for (let cp = 0x20000; cp < 0x40000; cp += 61) points.push(cp);
  for (let cp = 0xe0000; cp < 0xe1000; cp++) points.push(cp);
  for (const cp of points) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    for (const id of ["a" + ch + "b", ch + "b"]) {
      let ref;
      try { ref = principals.user(id); } catch {
        if (!unassigned.test(ch) && !"\u0000\t\n\r\u007f".includes(ch) && (await accepts(engine, raw(id)))) {
          refused.push(cp.toString(16));
        }
        continue;
      }
      if (!(await accepts(engine, ref))) accepted.push(cp.toString(16));
    }
  }
  ok("every id the helper accepts is one the engine accepts", accepted.length === 0, accepted.slice(0, 10).join(","));
  ok("every assigned character the helper refuses is one the engine refuses", refused.length === 0, refused.slice(0, 10).join(","));

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(1); });
