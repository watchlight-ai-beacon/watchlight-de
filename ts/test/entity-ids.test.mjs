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
const { Watchlight, principals, policyEntityRef, entityRef, entityKey } = require("../dist/index.js");
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

  // ── entity type names ────────────────────────────────────────────────────
  // A type is one or more identifiers joined by `::`. The check is a split on
  // `::` plus a per-part test, which must accept exactly what the earlier
  // whole-string pattern accepted, and run in linear time on any input.
  const OLD_TYPE_NAME = /^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$/;
  // policyEntityRef checks the type and bounds nothing else, so the answer is
  // the type check's alone, at any length.
  const typeAccepted = (type) => {
    try { policyEntityRef(type, "x"); return true; } catch { return false; }
  };
  const keyAccepted = (type) => entityKey(`${type}::"x"`, "User")[0] === type && type !== "";
  ok("entityRef checks the type too", (() => { try { entityRef("A::", "x"); return false; } catch { return true; } })());
  for (const type of ["User", "_", "_a1", "App::User", "A::B::C", "a_1::_2::Z9"]) {
    ok(`type ${JSON.stringify(type)} is accepted`, typeAccepted(type) && keyAccepted(type));
  }
  for (const type of ["", "::", "::User", "User::", "A::::B", "A:::B", "A:B", ":A", "A:", "1A",
                      "A::1B", "A-B", "A B", "A::B ", "Ü", "A::ü", "A\n", "A::B\n"]) {
    ok(`type ${JSON.stringify(type)} is refused`, !typeAccepted(type) && !keyAccepted(type));
  }
  // Every string up to five characters over an alphabet that reaches each
  // branch of the grammar gets the same answer as the earlier pattern.
  const alphabet = ["a", "Z", "_", "0", ":", "-"];
  let mismatches = [];
  const walk = (prefix, depth) => {
    if (typeAccepted(prefix) !== OLD_TYPE_NAME.test(prefix)) mismatches.push(prefix);
    if (depth === 0) return;
    for (const c of alphabet) walk(prefix + c, depth - 1);
  };
  walk("", 5);
  ok("type check agrees with the earlier pattern on every short string", mismatches.length === 0,
     mismatches.slice(0, 10).map((m) => JSON.stringify(m)).join(","));
  // Long inputs built to make a backtracking matcher retry finish quickly.
  const longInputs = [
    "a" + "::a".repeat(200_000) + "::",
    "a" + "::a".repeat(200_000) + ":",
    "a" + "::a".repeat(200_000) + "!",
    "a".repeat(1_000_000) + "!",
    ":".repeat(1_000_001),
    "a" + "::a".repeat(200_000),
  ];
  const started = process.hrtime.bigint();
  const answers = longInputs.map((t) => typeAccepted(t) && keyAccepted(t));
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  ok("long type names get the right answer", answers.join(",") === "false,false,false,false,false,true", answers.join(","));
  ok("long type names are checked in linear time", elapsedMs < 5000, `${elapsedMs.toFixed(1)} ms`);

  console.log(`\n${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
}

main().catch((e) => { console.error("FATAL:", e); process.exit(1); });
