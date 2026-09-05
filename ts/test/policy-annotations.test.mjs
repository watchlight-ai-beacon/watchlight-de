// @watchlight/sdk — `@enforcement_effect` is checked when a policy loads.
// Mirrors the Python suite tests/test_policy_annotations.py.
//
// The defect this answers: the engine maps an `@enforcement_effect` value it
// does not implement to no effect at all. For the verbs that escalate a `forbid`
// that is the closed direction — a dropped `terminate` leaves a plain deny. For
// `require_approval` on a `permit` it is the OPEN direction: a dropped hold
// leaves an unconditional allow. So a one-character typo in the value silently
// turned a human-in-the-loop gate into a permit, with no error and no warning.
//
// What is asserted here:
//   * every accepted value still loads, and `require_approval` still yields
//     NeedsApproval — a correct policy is untouched;
//   * a value the engine does not implement throws `PolicyError` at load, naming
//     the value, the accepted set and the policy;
//   * the annotation is READ, not grepped: the same text inside a Cedar string
//     literal, or in a comment, is not an annotation and is not rejected;
//   * a near miss for the annotation NAME warns and still loads (an arbitrary
//     annotation is legitimate Cedar, so this can never throw);
//   * `load()` is atomic: one bad policy in a file loads none of it;
//   * both lanes carry the same accepted set and the same wording — proven
//     against src/watchlight/_annotations.py and the shared fixture.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const {
  Watchlight,
  PolicyError,
  ENFORCEMENT_EFFECTS,
  ENFORCEMENT_EFFECT_ANNOTATION,
} = require("../dist/index.js");
const {
  isNearMiss,
  nearMissMessage,
  parsePolicyAnnotations,
  unrecognizedEffectMessage,
} = require("../dist/annotations.js");

const here = dirname(fileURLToPath(import.meta.url));
const REPO = join(here, "..", "..");
const CLI = join(here, "..", "dist", "cli.js");
const fixture = JSON.parse(
  fs.readFileSync(join(REPO, "tests", "fixtures", "enforcement_effects.json"), "utf8")
);

let pass = 0,
  fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) {
    console.log(`  ✓ ${name}`);
    pass++;
  } else {
    console.log(`  ✗ ${name} ${detail}`);
    fail++;
  }
};
/** Run `fn`, returning the error it threw (or null) — never letting it escape. */
const caught = async (fn) => {
  try {
    await fn();
    return null;
  } catch (e) {
    return e;
  }
};
/** Run `fn` with console.warn captured, returning everything it warned. */
const warnings = (fn) => {
  const lines = [];
  const original = console.warn;
  console.warn = (...args) => lines.push(args.join(" "));
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return lines;
};

const tmp = () => fs.mkdtempSync(join(os.tmpdir(), "wl-annotations-"));
const PERMIT = 'permit(principal, action == Action::"wire", resource);';
const governor = () => new Watchlight({ agent: "probe", auditDir: tmp() });
const decide = (gov) => gov.authorize({ action: "wire", resource: "acct" }).then((r) => r.decision);

// ── the reproduction, closed ───────────────────────────────────────────────
console.log("@enforcement_effect is checked at load");

{
  const gov = governor();
  gov.allow(`@enforcement_effect("require_approval")\n${PERMIT}`, "wire-approval");
  ok("a correct value still holds the permit for a human", (await decide(gov)) === "NeedsApproval");
  ok("…and it loaded", gov.policyCount === 1);
}

for (const value of fixture.rejected_values) {
  const gov = governor();
  const err = await caught(() => gov.allow(`@enforcement_effect("${value}")\n${PERMIT}`, "wire-approval"));
  ok(
    `a value the engine does not implement is refused at load: "${value}"`,
    err instanceof PolicyError && err.value === value && err.policy === "wire-approval",
    err ? `unexpected: ${err.message}` : "did not throw"
  );
  ok(`…and "${value}" did not count as loaded`, gov.policyCount === 0);
}

{
  const err = await caught(() =>
    governor().allow(`@enforcement_effect("needs_approval")\n${PERMIT}`, "wire-approval")
  );
  ok(
    "the message names the value, the accepted set and the policy",
    err.message.includes('"needs_approval"') &&
      err.message.includes('policy "wire-approval"') &&
      ENFORCEMENT_EFFECTS.every((e) => err.message.includes(e))
  );
  ok("the error carries the accepted set", err.accepted.join(",") === ENFORCEMENT_EFFECTS.join(","));
  ok("it is named PolicyError", err.name === "PolicyError");
}

for (const effect of ENFORCEMENT_EFFECTS) {
  const gov = governor();
  const err = await caught(() => gov.allow(`@enforcement_effect("${effect}")\n${PERMIT}`, "p"));
  ok(`every accepted value loads: ${effect}`, err === null && gov.policyCount === 1, err?.message ?? "");
}

{
  const gov = governor();
  gov.allow(PERMIT, "plain");
  ok("a policy with no annotation at all is untouched", (await decide(gov)) === "Allow");
}

// ── read, do not grep ──────────────────────────────────────────────────────
console.log("the annotation is read, not grepped");

{
  // The one a regex gets wrong: the annotation's own text, inside a Cedar string.
  const code =
    '@enforcement_effect("require_approval")\n' +
    'permit(principal, action == Action::"wire", resource)\n' +
    'when { context.note == "@enforcement_effect(\\"not_a_real_value\\")" };';
  const gov = governor();
  const err = await caught(() => gov.allow(code, "quoted"));
  ok("the annotation text inside a Cedar string is not an annotation", err === null, err?.message ?? "");
  const decision = await gov.authorize({
    action: "wire",
    resource: "acct",
    context: { note: '@enforcement_effect("not_a_real_value")' },
  });
  ok(
    "…the real annotation still governs; the quoted one is just a string",
    decision.decision === "NeedsApproval"
  );
}

{
  const code =
    'permit(principal, action == Action::"wire", resource)\n' +
    'when { context.note == "@enforcement_effect(\\"not_a_real_value\\")" };';
  const gov = governor();
  const err = await caught(() => gov.allow(code, "quoted-only"));
  ok("a bogus value quoted in an unannotated policy's body is ignored", err === null && gov.policyCount === 1);
}

{
  const gov = governor();
  const err = await caught(() =>
    gov.allow(`// @enforcement_effect("not_a_real_value")\n${PERMIT}`, "commented")
  );
  ok("the annotation in a comment is not an annotation", err === null && gov.policyCount === 1);
}

{
  // Literals are read raw, so what the engine decodes an escape to is unknown:
  // staying quiet is the only option that cannot refuse a policy it accepts.
  const gov = governor();
  const err = await caught(() =>
    gov.allow('@enforcement_effect("require\\u{5f}approval")\n' + PERMIT, "escaped")
  );
  ok("a value carrying an escape is left to the engine", err === null && gov.policyCount === 1);
}

{
  const code =
    '@enforcement_effect("require_approval")\n' +
    'permit(principal, action == Action::"wire", resource)\n' +
    'when { context.note == "a;b" };';
  const gov = governor();
  const err = await caught(() => gov.allow(code, "semicolon"));
  ok("a semicolon inside a string does not start a new policy", err === null && gov.policyCount === 1);
}

{
  // The engine takes one policy per `allow`, but the parser reads a whole
  // source, so a pasted pair is checked to the end rather than only at the top.
  const code =
    `@enforcement_effect("require_approval")\n${PERMIT}\n` +
    '@enforcement_effect("not_a_real_value")\n' +
    'permit(principal, action == Action::"read", resource);';
  const err = await caught(() => governor().allow(code, "wire-set"));
  ok(
    "a bad effect on a later policy in the source is still caught",
    err instanceof PolicyError && err.value === "not_a_real_value"
  );
}

{
  const gov = governor();
  const err = await caught(() =>
    gov.allow('@enforcement_effect("terminate")\nforbid(principal, action == Action::"read", resource);', "kill")
  );
  ok("an annotated forbid loads", err === null && gov.policyCount === 1);
}

// ── the annotation NAME ────────────────────────────────────────────────────
console.log("a misspelled annotation NAME warns, and never throws");

for (const name of fixture.near_miss_names) {
  const gov = governor();
  const lines = warnings(() => gov.allow(`@${name}("require_approval")\n${PERMIT}`, "typo"));
  ok(
    `a near miss warns and still loads: @${name}`,
    gov.policyCount === 1 &&
      isNearMiss(name) &&
      lines.length === 1 &&
      lines[0].includes(`\`@${name}\``) &&
      lines[0].includes("near miss")
  );
}

for (const name of fixture.not_near_miss_names) {
  const gov = governor();
  // "8" so the value is legal for every name here, `@obligate_max_items` included.
  const lines = warnings(() => gov.allow(`@${name}("8")\n${PERMIT}`, "annotated"));
  ok(
    `an ordinary user annotation is silent: @${name}`,
    gov.policyCount === 1 && !isNearMiss(name) && lines.length === 0,
    lines.join(" | ")
  );
}

{
  const gov = governor();
  const lines = warnings(() =>
    gov.allow(`@enforcement_effect("require_approval")\n${PERMIT}`, "correct")
  );
  ok("the exact name never warns", lines.length === 0 && !isNearMiss(ENFORCEMENT_EFFECT_ANNOTATION));
}

{
  // The line the check must not cross: an annotation the SDK does not read is
  // valid Cedar, so a name it cannot vouch for is a warning, never a refusal.
  const gov = governor();
  const err = await caught(() =>
    warnings(() => gov.allow(`@enforcment_effect("not_a_real_value_either")\n${PERMIT}`, "typo"))
  );
  ok("a near-miss name never throws", err === null && gov.policyCount === 1);
}

// ── load() ─────────────────────────────────────────────────────────────────
console.log("load() is whole-file or nothing");

{
  const dir = tmp();
  const file = join(dir, "watchlight.policy.json");
  fs.writeFileSync(
    file,
    JSON.stringify([
      { name: "good", code: PERMIT },
      { name: "bad", code: `@enforcement_effect("needs_approval")\n${PERMIT}` },
    ])
  );
  const gov = new Watchlight({ agent: "probe", auditDir: dir });
  const err = await caught(() => gov.load(file));
  ok("a file with one bad policy loads none of it", err instanceof PolicyError && err.policy === "bad");
  ok("…and the governor is left exactly as it was", gov.policyCount === 0);
  fs.writeFileSync(file, JSON.stringify([{ name: "good", code: PERMIT }]));
  gov.load(file);
  ok("…and the source was not remembered, so a fixed file loads", gov.policyCount === 1);
}

{
  const dir = tmp();
  const file = join(dir, "watchlight.policy.json");
  fs.writeFileSync(
    file,
    JSON.stringify([{ name: "wire", code: `@enforcement_effect("require_approval")\n${PERMIT}` }])
  );
  const gov = new Watchlight({ agent: "probe", auditDir: dir });
  gov.load(file);
  ok("a correct file is unaffected", gov.policyCount === 1 && (await decide(gov)) === "NeedsApproval");
}

{
  const dir = tmp();
  const file = join(dir, "watchlight.policy.json");
  fs.writeFileSync(
    file,
    JSON.stringify([{ name: "typo", code: `@enforcment_effect("require_approval")\n${PERMIT}` }])
  );
  const gov = new Watchlight({ agent: "probe", auditDir: dir });
  const lines = warnings(() => gov.load(file));
  ok("load warns once for a near miss", lines.length === 1);
}

// ── the CLI ────────────────────────────────────────────────────────────────
console.log("the CLI reports the refusal");

{
  const dir = tmp();
  const suite = join(dir, "suite.json");
  fs.writeFileSync(
    suite,
    JSON.stringify({
      policies: [{ name: "wire", code: `@enforcement_effect("needs_approval")\n${PERMIT}` }],
      tests: [{ action: "wire", resource: "acct", expect: "NeedsApproval" }],
    })
  );
  const run = spawnSync(process.execPath, [CLI, "policy", "test", suite], { encoding: "utf8", cwd: dir });
  ok(
    "`watchlight policy test` exits 2 and names the value, instead of testing a different policy",
    run.status === 2 &&
      run.stderr.includes("needs_approval") &&
      run.stderr.includes("is not an effect this engine implements"),
    `status=${run.status} stderr=${run.stderr.trim().slice(0, 200)}`
  );
}

// ── the parser, directly ───────────────────────────────────────────────────
console.log("the parser");

{
  const parsed = parsePolicyAnnotations(
    `@a("1")\n@b("2")\n${PERMIT}\n@c\nforbid(principal, action, resource);`
  );
  ok(
    "one entry per policy, in source order",
    JSON.stringify(parsed) ===
      JSON.stringify([[{ name: "a", value: "1" }, { name: "b", value: "2" }], [{ name: "c" }]])
  );
  ok(
    "an unreadable source is handed to the engine",
    parsePolicyAnnotations('@enforcement_effect("unterminated') === undefined &&
      parsePolicyAnnotations('@enforcement_effect("x"') === undefined &&
      parsePolicyAnnotations("@123bad\npermit(principal, action, resource);") === undefined
  );
}

// ── the two lanes cannot drift ─────────────────────────────────────────────
console.log("parity with the Python lane");

{
  // The accepted set lives in exactly two places. This reads the other one.
  const source = fs.readFileSync(join(REPO, "src", "watchlight", "_annotations.py"), "utf8");
  const block = /ENFORCEMENT_EFFECTS: Tuple\[str, \.\.\.\] = \(([\s\S]*?)\)/.exec(source);
  const values = block ? [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : [];
  ok(
    "the Python lane carries the same accepted set, in the same order",
    values.join(",") === ENFORCEMENT_EFFECTS.join(","),
    `python=${values.join(",")}`
  );
}

{
  const where = fixture.where.replace("{policy}", "wire-approval");
  const expectedError = fixture.error_template
    .replace("{where}", where)
    .replace("{annotation}", ENFORCEMENT_EFFECT_ANNOTATION)
    .replace("{value}", "needs_approval")
    .replace("{accepted}", ENFORCEMENT_EFFECTS.join(", "));
  ok(
    "the refusal wording matches the shared fixture",
    unrecognizedEffectMessage(where, "needs_approval") === expectedError,
    unrecognizedEffectMessage(where, "needs_approval")
  );
  const expectedWarning = fixture.warning_template
    .replace("{where}", where)
    .replace("{written}", "enforcment_effect")
    .replace("{annotation}", ENFORCEMENT_EFFECT_ANNOTATION);
  ok(
    "the warning wording matches the shared fixture",
    nearMissMessage(where, "enforcment_effect") === expectedWarning,
    nearMissMessage(where, "enforcment_effect")
  );
  ok("the annotation name matches the shared fixture", fixture.annotation === ENFORCEMENT_EFFECT_ANNOTATION);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
