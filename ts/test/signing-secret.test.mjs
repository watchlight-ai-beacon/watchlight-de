// `signingSecret` — the name, the deprecated alias, and rotation.
//
// The value signs scope tokens, and approval tokens when no separate approval
// secret is configured, so it is named for what it signs rather than for one
// kind of token. `tokenSecret` is the former name: it still works, at lower
// precedence, warns once, and is refused when it contradicts the new name.
//
// It also accepts an ORDERED LIST. The first entry signs; every entry verifies,
// so rotating is two ordinary deploys instead of a cutover: add the new secret
// at the front, wait out the longest token lifetime, drop the old one.
import { createRequire } from "node:module";
import { join } from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

const require = createRequire(import.meta.url);
const { Watchlight, ScopeTokenError, SIGNING_SECRET_CONFLICT_MESSAGE } = require("../dist/index.js");

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) { console.log(`  ✓ ${name}`); pass++; }
  else { console.log(`  ✗ ${name} ${detail}`); fail++; }
};
const threw = (fn) => { try { fn(); return null; } catch (e) { return e; } };
const rejected = async (p) => { try { await p; return null; } catch (e) { return e; } };

const OLD = "an-old-signing-secret-32-bytes-x";
const NEW = "a-new-signing-secret-32-bytes-yy";
const WARNING = "former name of";
const ANY = '@enforcement_effect("require_approval")\npermit(principal, action, resource);';

const gov = (opts = {}) => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "wl-sig-"));
  const g = new Watchlight({ agent: "sig-agent", auditDir, ...opts });
  g.allow(ANY, "any");
  return g;
};
const mintScope = async (g) => (await g.scope({ tools: ["read"] })).toToken();
const held = (g, approval) =>
  g.authorize({ principal: "U", action: "a", resource: "r", ...(approval ? { approval } : {}) });

const withWarnSpy = async (fn) => {
  const orig = console.warn;
  const warns = [];
  console.warn = (...a) => warns.push(a.map(String).join(" "));
  try { return await fn(warns); } finally { console.warn = orig; }
};
/** The deprecation notice is once per PROCESS, so reset it between checks. */
const { __resetSigningSecretWarning: resetWarning } = require("../dist/index.js");

async function main() {
  delete process.env.WATCHLIGHT_SIGNING_SECRET;
  delete process.env.WATCHLIGHT_TOKEN_SECRET;
  delete process.env.WATCHLIGHT_APPROVAL_SECRET;

  console.log("the name");
  {
    const token = await mintScope(gov({ signingSecret: NEW }));
    const scope = await gov({ signingSecret: NEW }).scopeFromToken(token);
    ok("the new name works", JSON.stringify(scope.allowedTools) === '["read"]');
  }
  {
    resetWarning();
    const warns = await withWarnSpy(async (w) => {
      const token = await mintScope(gov({ tokenSecret: NEW }));
      const scope = await gov({ signingSecret: NEW }).scopeFromToken(token);
      ok("the old name still works", JSON.stringify(scope.allowedTools) === '["read"]');
      gov({ tokenSecret: NEW });        // a second governor on the old name
      return w;
    });
    const notices = warns.filter((w) => w.includes(WARNING));
    ok("…and warns exactly once per process", notices.length === 1);
    ok("the notice names the replacement",
      notices[0].includes("signingSecret") && notices[0].includes("WATCHLIGHT_SIGNING_SECRET"));
  }
  {
    resetWarning();
    const warns = await withWarnSpy(async (w) => { gov({ signingSecret: NEW }); return w; });
    ok("the new name alone does not warn", warns.filter((w) => w.includes(WARNING)).length === 0);
  }
  {
    const err = threw(() => gov({ signingSecret: NEW, tokenSecret: OLD }));
    ok("both names with different values are refused at construction",
      err instanceof ScopeTokenError && err.code === "mismatch");
    ok("…with the fixed message", err && err.message.includes(SIGNING_SECRET_CONFLICT_MESSAGE));
    ok("…and never echoing either secret",
      err && !err.message.includes(NEW) && !err.message.includes(OLD));
    ok("both names with the SAME value are accepted",
      threw(() => gov({ signingSecret: NEW, tokenSecret: NEW })) === null);
  }

  console.log("the environment variables");
  {
    resetWarning();
    process.env.WATCHLIGHT_SIGNING_SECRET = NEW;
    const warns = await withWarnSpy(async (w) => {
      const token = await mintScope(gov());
      const scope = await gov({ signingSecret: NEW }).scopeFromToken(token);
      ok("WATCHLIGHT_SIGNING_SECRET is read", JSON.stringify(scope.allowedTools) === '["read"]');
      return w;
    });
    ok("…without a deprecation notice", warns.filter((w) => w.includes(WARNING)).length === 0);
    delete process.env.WATCHLIGHT_SIGNING_SECRET;
  }
  {
    resetWarning();
    process.env.WATCHLIGHT_TOKEN_SECRET = NEW;
    const warns = await withWarnSpy(async (w) => {
      const token = await mintScope(gov());
      const scope = await gov({ signingSecret: NEW }).scopeFromToken(token);
      ok("WATCHLIGHT_TOKEN_SECRET still works", JSON.stringify(scope.allowedTools) === '["read"]');
      return w;
    });
    ok("…and warns", warns.filter((w) => w.includes(WARNING)).length === 1);
    delete process.env.WATCHLIGHT_TOKEN_SECRET;
  }
  {
    process.env.WATCHLIGHT_SIGNING_SECRET = OLD;
    const token = await mintScope(gov({ signingSecret: NEW }));
    const scope = await gov({ signingSecret: NEW }).scopeFromToken(token);
    ok("an option outranks the environment", JSON.stringify(scope.allowedTools) === '["read"]');
    process.env.WATCHLIGHT_TOKEN_SECRET = NEW;
    ok("two environment variables that disagree are refused",
      threw(() => gov())?.code === "mismatch");
    process.env.WATCHLIGHT_SIGNING_SECRET = NEW;
    ok("…and are accepted when identical", threw(() => gov()) === null);
    delete process.env.WATCHLIGHT_SIGNING_SECRET;
    delete process.env.WATCHLIGHT_TOKEN_SECRET;
  }

  {
    // Precedence is by NAME, not by option-versus-environment: during the rename
    // the new environment variable must not be ignored because some code still
    // passes the old argument.
    process.env.WATCHLIGHT_SIGNING_SECRET = NEW;
    ok("the new env var conflicting with the old option is refused",
      threw(() => gov({ tokenSecret: OLD }))?.code === "mismatch");
    ok("…and agreeing with it is accepted", threw(() => gov({ tokenSecret: NEW })) === null);
    delete process.env.WATCHLIGHT_SIGNING_SECRET;
    process.env.WATCHLIGHT_TOKEN_SECRET = OLD;
    ok("the old env var conflicting with the new option is refused",
      threw(() => gov({ signingSecret: NEW }))?.code === "mismatch");
    delete process.env.WATCHLIGHT_TOKEN_SECRET;
  }
  {
    // Set, but holding no usable secret: refused rather than resolved to
    // "unset", which would quietly leave approvals on a random per-process key.
    for (const value of [",", " ", " , "]) {
      process.env.WATCHLIGHT_SIGNING_SECRET = value;
      ok(`an env var holding only ${JSON.stringify(value)} is refused`,
        threw(() => gov())?.code === "no_secret");
    }
    process.env.WATCHLIGHT_SIGNING_SECRET = "";
    ok("an EMPTY env var is genuinely unset", threw(() => gov()) === null);
    delete process.env.WATCHLIGHT_SIGNING_SECRET;
  }

  console.log("configureDefault applies every option");
  {
    const { configureDefault, govern } = require("../dist/index.js");
    const rows = new Map();
    const store = { add: (id, expiresAt) => { rows.set(id, expiresAt); return true; } };
    // Every configure call must land BEFORE the first record: a later call
    // naming one option must merge onto the earlier ones, not replace them.
    configureDefault({
      auditDir: fs.mkdtempSync(join(os.tmpdir(), "wl-sig-")),
      approvalStore: store,
      counterSource: () => 11,
    });
    const g = configureDefault({ signingSecret: NEW });   // names only the secret
    g.allow(ANY, "any");
    ok("the default governor is the one configured", g === govern);
    const token = g.mintApproval({ principal: "U", action: "a", resource: "r" });
    const d = await g.authorize({ principal: "U", action: "a", resource: "r", approval: token });
    ok("the approval is honoured", d.decision === "Allow");
    ok("…and the configured store was written to, not the per-process default", rows.size === 1);
    ok("the counter source is applied", g.counters({ principal: "U" }).count === 11);
    // The signing secret reached the approval keys, so another process holding
    // the same value verifies a token it minted.
    const other = gov({ signingSecret: NEW });
    const foreign = other.mintApproval({ principal: "U", action: "a", resource: "r" });
    ok("the signing secret drives approvals across processes",
      (await g.authorize({ principal: "U", action: "a", resource: "r", approval: foreign })).decision === "Allow");
    ok("a later call naming only the secret keeps the store and the source",
      rows.size >= 1 && g.counters({ principal: "U" }).count === 11);
  }

  console.log("rotation: an ordered list");
  {
    const token = await mintScope(gov({ signingSecret: NEW }));
    const scope = await gov({ signingSecret: [NEW] }).scopeFromToken(token);
    ok("a single value behaves as a one-entry list",
      JSON.stringify(scope.allowedTools) === '["read"]');
  }
  {
    // Deploy one: the new secret goes to the FRONT, the old one stays.
    const token = await mintScope(gov({ signingSecret: OLD }));
    const during = await gov({ signingSecret: [NEW, OLD] }).scopeFromToken(token);
    ok("a token minted under the previous secret verifies while it is listed",
      JSON.stringify(during.allowedTools) === '["read"]');
    // Deploy two: the old secret is gone, and so are the tokens it signed.
    const err = await rejected(gov({ signingSecret: [NEW] }).scopeFromToken(token));
    ok("…and is refused once it is dropped", err instanceof ScopeTokenError && err.code === "signature");
  }
  {
    const token = await mintScope(gov({ signingSecret: [NEW, OLD] })); // signed with the FIRST
    const after = await gov({ signingSecret: [NEW] }).scopeFromToken(token);
    ok("a token minted under the new entry verifies from the moment it is added",
      JSON.stringify(after.allowedTools) === '["read"]');
  }
  {
    const token = await mintScope(gov({ signingSecret: "a-third-signing-secret-32-bytes-" }));
    const err = await rejected(gov({ signingSecret: [NEW, OLD] }).scopeFromToken(token));
    ok("an unverifiable token is a plain signature failure", err.code === "signature");
    ok("the error never says which entry was tried, or how many there are",
      !err.message.includes(NEW) && !err.message.includes(OLD) &&
      !/\b\d\b/.test(err.message));
  }
  {
    const err = await rejected(gov({ signingSecret: [NEW, OLD] }).scopeFromToken("not-a-token"));
    ok("a non-signature failure is not retried across entries", err.code === "malformed");
  }
  {
    const weak = threw(() => gov({ signingSecret: [NEW, "short"] }));
    ok("every entry must meet the minimum length", weak?.code === "weak_secret");
    ok("…and the error never echoes an entry", !weak.message.includes("short"));
    ok("an empty list fails closed", threw(() => gov({ signingSecret: [] }))?.code === "no_secret");
    ok("a list of blanks fails closed too",
      threw(() => gov({ signingSecret: ["", "   "] }))?.code === "no_secret");
  }
  {
    const token = await mintScope(gov({ signingSecret: OLD }));
    process.env.WATCHLIGHT_SIGNING_SECRET = `${NEW}, ${OLD}`;
    const scope = await gov().scopeFromToken(token);
    ok("the environment variable takes a comma-separated list",
      JSON.stringify(scope.allowedTools) === '["read"]');
    delete process.env.WATCHLIGHT_SIGNING_SECRET;
  }

  console.log("the same list drives approvals");
  {
    const token = gov({ signingSecret: OLD }).mintApproval({ principal: "U", action: "a", resource: "r" });
    ok("an approval minted under the previous secret verifies while it is listed",
      (await held(gov({ signingSecret: [NEW, OLD] }), token)).decision === "Allow");
    ok("…and is refused once it is dropped",
      (await held(gov({ signingSecret: [NEW] }), token)).decision === "NeedsApproval");
  }
  {
    const token = gov({ signingSecret: [NEW, OLD] }).mintApproval({ principal: "U", action: "a", resource: "r" });
    ok("an approval minted under the new entry verifies immediately",
      (await held(gov({ signingSecret: [NEW] }), token)).decision === "Allow");
  }
  {
    const token = gov({ approvalSecret: OLD }).mintApproval({ principal: "U", action: "a", resource: "r" });
    ok("an approval-secret list rotates independently",
      (await held(gov({ approvalSecret: [NEW, OLD] }), token)).decision === "Allow" &&
      (await held(gov({ approvalSecret: [NEW] }), token)).decision === "NeedsApproval");
  }
  {
    const minter = gov({ signingSecret: NEW, approvalSecret: OLD });
    const token = minter.mintApproval({ principal: "U", action: "a", resource: "r" });
    ok("an approvalSecret overrides the signingSecret for approvals",
      (await held(gov({ signingSecret: NEW }), token)).decision === "NeedsApproval" &&
      (await held(gov({ approvalSecret: OLD }), token)).decision === "Allow");
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
