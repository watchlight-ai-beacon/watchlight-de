// Shared by every pattern script: locate the @watchlight/sdk build.
//
// Resolution order: an installed package (`npm i -g @watchlight/sdk` — check.sh
// puts the global module root on NODE_PATH), then the in-repo build (`ts/dist`,
// produced by `cd ts && npm run build`). Anything else is a hard error so a
// missing SDK fails the check instead of skipping it.
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);

export function loadSdk() {
  const candidates = ["@watchlight/sdk", fileURLToPath(new URL("../../../ts/dist/index.js", import.meta.url))];
  for (const spec of candidates) {
    try {
      return require(spec);
    } catch (e) {
      if (e?.code !== "MODULE_NOT_FOUND") throw e;
    }
  }
  throw new Error("@watchlight/sdk not found — 'npm i -g @watchlight/sdk' or build it with 'cd ts && npm run build'");
}

/** Minimal assertion runner shared by the scripts: prints one line per check
 *  and exits non-zero if any failed, mirroring `watchlight policy test`. */
export function checks(title) {
  let pass = 0, fail = 0;
  console.log(`pattern script — ${title}\n`);
  return {
    ok(name, cond, detail = "") {
      if (cond) { console.log(`  ✓ ${name}`); pass++; }
      else { console.log(`  ✗ ${name}${detail ? `  (${detail})` : ""}`); fail++; }
    },
    done() {
      console.log(`\n${pass} passed, ${fail} failed (${pass + fail} total)`);
      process.exit(fail ? 1 : 0);
    },
  };
}
