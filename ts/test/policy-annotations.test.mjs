// @watchlight/sdk — `@enforcement_effect` is refused at load when the engine
// cannot honour it. Mirrors the Python suite tests/test_policy_annotations.py.
//
// The defect this answers: an `@enforcement_effect` value the engine did not
// implement was dropped. For `require_approval` on a `permit` that is the OPEN
// direction: a dropped hold leaves an unconditional allow. A misspelled
// annotation NAME did the same, because Cedar accepts any annotation name.
//
// The engine (`@watchlight/engine` >= 0.2.3) now refuses both when a policy is
// added, with a typed error; the SDK maps it to `PolicyError`. The engine
// compiles asynchronously, so the refusal surfaces at `ready()` or the next
// decision, and every decision throws it until `reload()`. What is asserted:
//   * every accepted value still loads, and `require_approval` still yields
//     NeedsApproval;
//   * a value the engine does not implement is a `PolicyError` with code
//     UNRECOGNISED_ENFORCEMENT_EFFECT, naming the policy;
//   * a near-miss annotation name is a `PolicyError` with code
//     ENFORCEMENT_EFFECT_NAME_NEAR_MISS; any other annotation loads;
//   * a set holding a refused policy never decides;
//   * a Cedar syntax error is a `PolicyCompileError`, never a `PolicyError`;
//   * the cases are the shared fixture's, so both lanes refuse the same ones.
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
  PolicyCompileError,
  ENFORCEMENT_EFFECT_ANNOTATION,
  ENFORCEMENT_EFFECT_NAME_NEAR_MISS,
  POLICY_ERROR_CODES,
  UNRECOGNISED_ENFORCEMENT_EFFECT,
} = require("../dist/index.js");
const engineModule = require("@watchlight/engine");

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
const caught = async (fn) => {
  try {
    await fn();
    return null;
  } catch (e) {
    return e;
  }
};

if (!engineModule.PolicyAnnotationError) {
  console.log("  - skipped: needs @watchlight/engine >= 0.2.3 (PolicyAnnotationError)");
  process.exit(0);
}

const tmp = () => fs.mkdtempSync(join(os.tmpdir(), "wl-annotations-"));
const PERMIT = 'permit(principal, action == Action::"wire", resource);';
const governor = () => new Watchlight({ agent: "probe", auditDir: tmp() });
const decide = (gov) => gov.authorize({ action: "wire", resource: "acct" }).then((r) => r.decision);
const annotated = (name, value) => `@${name}("${value}")\n${PERMIT}`;

console.log("a correct policy is untouched");
{
  const gov = governor().allow(annotated(ENFORCEMENT_EFFECT_ANNOTATION, "require_approval"));
  ok("require_approval still holds the permit for a human", (await decide(gov)) === "NeedsApproval");
}
for (const effect of fixture.accepted_values) {
  const err = await caught(() => governor().allow(annotated(ENFORCEMENT_EFFECT_ANNOTATION, effect)).ready());
  ok(`"${effect}" loads`, err === null, String(err));
}
for (const name of fixture.not_near_miss_names) {
  const gov = governor().allow(annotated(name, "1"));
  ok(`@${name} is the developer's own and loads`, (await decide(gov)) === "Allow");
}

console.log("refused, with a typed code");
for (const value of fixture.rejected_values) {
  const gov = governor().allow(annotated(ENFORCEMENT_EFFECT_ANNOTATION, value), "wire-approval");
  const err = await caught(() => gov.ready());
  ok(
    `"${value}" is refused as UNRECOGNISED_ENFORCEMENT_EFFECT`,
    err instanceof PolicyError &&
      err.code === UNRECOGNISED_ENFORCEMENT_EFFECT &&
      err.policy === "wire-approval",
    String(err)
  );
  const again = await caught(() => decide(gov));
  ok(`…and the set never decides`, again instanceof PolicyError, String(again));
}
for (const name of fixture.near_miss_names) {
  const gov = governor().allow(annotated(name, "require_approval"), "typo");
  const err = await caught(() => gov.ready());
  ok(
    `@${name} is refused as ENFORCEMENT_EFFECT_NAME_NEAR_MISS`,
    err instanceof PolicyError && err.code === ENFORCEMENT_EFFECT_NAME_NEAR_MISS && err.policy === "typo",
    String(err)
  );
}
{
  const err = await caught(() =>
    governor().allow(annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval"), "wire-approval").ready()
  );
  ok("it is named PolicyError", err?.name === "PolicyError");
  ok('the message names the policy', String(err?.message).startsWith('policy "wire-approval": '));
  ok("…and the value", String(err?.message).includes("needs_approval"));
  ok("…and not the engine's internals", !String(err?.message).includes("add_policy failed"));
}
{
  const err = await caught(() => governor().allow("permit(principal, action ==", "broken").ready());
  ok("a Cedar syntax error is a PolicyCompileError", err instanceof PolicyCompileError);
  ok("…never a PolicyError", !(err instanceof PolicyError));
}
ok(
  "the codes are the engine's",
  [...POLICY_ERROR_CODES].sort().join() === [...engineModule.POLICY_ANNOTATION_ERROR_CODES].sort().join()
);
ok(
  "…and the shared fixture's",
  [...POLICY_ERROR_CODES].sort().join() === Object.values(fixture.codes).sort().join()
);

console.log("read, not grepped");
{
  const code =
    'permit(principal, action == Action::"wire", resource) ' +
    'when { context.note == "@enforcement_effect(\\"needs_approval\\")" };';
  ok("the text inside a Cedar string is not an annotation", (await caught(() => governor().allow(code).ready())) === null);
  ok(
    "…nor in a comment",
    (await caught(() => governor().allow(`// @enforcement_effect("needs_approval")\n${PERMIT}`).ready())) === null
  );
}

console.log("whole sets");
{
  const dir = tmp();
  const file = join(dir, "watchlight.policy.json");
  fs.writeFileSync(
    file,
    JSON.stringify([
      { name: "good", code: PERMIT },
      { name: "bad", code: annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval") },
    ])
  );
  const gov = new Watchlight({ agent: "probe", auditDir: dir }).load(file);
  const err = await caught(() => gov.ready());
  ok(
    "a file with a refused policy surfaces it, naming the policy and the file",
    err instanceof PolicyError && err.policy === "bad" && err.source === file,
    String(err)
  );
  ok("…and the set never decides", (await caught(() => decide(gov))) instanceof PolicyError);
  gov.reload({ policies: [{ name: "good", code: PERMIT }] });
  ok("a reload with a set that loads decides again", (await decide(gov)) === "Allow");
}

console.log("the CLI");
{
  const dir = tmp();
  const suite = join(dir, "suite.json");
  fs.writeFileSync(
    suite,
    JSON.stringify({
      policies: [{ name: "wire", code: annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval") }],
      tests: [{ action: "wire", resource: "acct", expect: "NeedsApproval" }],
    })
  );
  const done = spawnSync(process.execPath, [CLI, "policy", "test", suite], { cwd: dir, encoding: "utf8" });
  ok("the CLI refuses rather than testing a different policy", done.status !== 0, done.stdout + done.stderr);
  ok("…naming the value", (done.stdout + done.stderr).includes("needs_approval"));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
