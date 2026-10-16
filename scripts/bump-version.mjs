#!/usr/bin/env node
// Bump the Transit version across every file that carries it, in lockstep.
// Usage: node scripts/bump-version.mjs <x.y.z>
//
// A Tauri app's version lives in three DECLARED places that MUST stay
// identical, or `release.yml`'s tag-vs-config assertion rejects the tag:
//   - package.json                 "version"
//   - src-tauri/tauri.conf.json     "version"   (drives the bundle/artifact version)
//   - src-tauri/Cargo.toml          [workspace.package] version
//
// ...and in two LOCKFILES derived from them. Those are easy to forget by hand
// and CI catches them late — a lockfile-freshness failure on a version-only
// commit reads like a mystery — so this script owns them too:
//   - package-lock.json             root "version" AND packages[""].version
//   - src-tauri/Cargo.lock          one [[package]] entry per workspace crate
//
// We do targeted single-line text replacements (not JSON/TOML round-trips)
// so the diff is exactly the version line in each file — no incidental
// reformatting of CSP strings, dependency tables, etc. Cargo.lock is the one
// exception: cargo regenerates it, because hand-patching ten [[package]]
// entries is how you end up with a malformed lock.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(
    "Usage: node scripts/bump-version.mjs <x.y.z>\n" +
      "  <x.y.z> must be a plain semver release (e.g. 0.1.0). Pre-release /\n" +
      "  build-metadata suffixes are not used for tagged prod releases.",
  );
  process.exit(1);
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

// The npm package name, used to anchor the package-lock edits. Read from
// package.json rather than hardcoded, so a rename can't quietly turn those
// edits into no-ops — the match-count assertion below would fail loudly.
const pkgName = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")).name;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// [relative path, match regex, replacement, expected match count (default 1)].
// The JSON files: first "version" key (top-level). Cargo.toml: the only
// line-anchored `version = "x.y.z"` literal is [workspace.package]'s — every
// dependency uses inline `{ version = "…" }` or `version.workspace = true`.
const SEMVERISH = '\\d+\\.\\d+\\.\\d+[^"]*';
const edits = [
  ["package.json", new RegExp(`("version":\\s*")${SEMVERISH}(")`), `$1${version}$2`],
  ["src-tauri/tauri.conf.json", new RegExp(`("version":\\s*")${SEMVERISH}(")`), `$1${version}$2`],
  ["src-tauri/Cargo.toml", new RegExp(`^(version = ")${SEMVERISH}(")`, "m"), `$1${version}$2`],
  // package-lock.json carries OUR version twice — the root object and
  // packages[""] — and npm's lockfile-freshness check fails if either lags.
  // Those two are the only places the lock pairs our package NAME with a
  // version, so anchoring on the name cannot touch a dependency's entry. The
  // expected count of 2 is load-bearing: if npm's lockfile shape changes and
  // only one spot matches, this fails instead of silently half-bumping.
  [
    "package-lock.json",
    new RegExp(
      `("name":\\s*"${escapeRe(pkgName)}",\\s*\\n\\s*"version":\\s*")${SEMVERISH}(")`,
      "g",
    ),
    `$1${version}$2`,
    2,
  ],
];

let failed = false;
for (const [rel, re, repl, expected = 1] of edits) {
  const path = join(repoRoot, rel);
  const before = readFileSync(path, "utf8");
  const matches = before.match(re);
  if (!matches) {
    console.error(`✗ ${rel}: version pattern not found — file shape changed?`);
    failed = true;
    continue;
  }
  if (re.global && matches.length !== expected) {
    console.error(
      `✗ ${rel}: expected ${expected} version occurrence(s), found ${matches.length} — ` +
        "file shape changed? Refusing to half-bump.",
    );
    failed = true;
    continue;
  }
  const oldVer = (String(matches[0]).match(/\d+\.\d+\.\d+[^"]*/) || ["?"])[0];
  const after = before.replace(re, repl);
  if (after === before) {
    console.log(`= ${rel}: already at ${version}`);
  } else {
    writeFileSync(path, after);
    console.log(`✓ ${rel}: ${oldVer} → ${version}`);
  }
}
if (failed) {
  process.exit(1);
}

// Cargo.lock holds a [[package]] entry per workspace crate, each carrying the
// workspace version. Let cargo rewrite it from the Cargo.toml just edited:
// `--offline` forbids network access, so no DEPENDENCY can drift here — only
// our own crates' versions move. (`npm install --package-lock-only` offers no
// such guarantee, which is why package-lock is patched textually above.)
const cargoDir = join(repoRoot, "src-tauri");
try {
  execFileSync("cargo", ["metadata", "--format-version", "1", "--offline"], {
    cwd: cargoDir,
    stdio: "ignore",
  });
} catch {
  console.error(
    "✗ src-tauri/Cargo.lock: could not refresh it (`cargo metadata --offline` failed).\n" +
      "  Run `cargo check` in src-tauri/ before committing — CI's lockfile check\n" +
      "  fails if the workspace crates still carry the old version.",
  );
  process.exit(1);
}

// Verify rather than trust: confirm the lock really moved. Every workspace
// crate is named `transit*`, and they are the only entries carrying our
// version, so any left behind is a bug in the refresh above.
const lock = readFileSync(join(cargoDir, "Cargo.lock"), "utf8");
const stale = [...lock.matchAll(/\[\[package\]\]\nname = "(transit[a-z_]*)"\nversion = "([^"]+)"/g)]
  .filter((m) => m[2] !== version)
  .map((m) => `${m[1]}@${m[2]}`);
if (stale.length > 0) {
  console.error(
    `✗ src-tauri/Cargo.lock: workspace crates still at the old version: ${stale.join(", ")}`,
  );
  process.exit(1);
}
console.log(`✓ src-tauri/Cargo.lock: workspace crates at ${version}`);

console.log(
  `\nVersion set to ${version} in package.json, tauri.conf.json, Cargo.toml,\n` +
    "package-lock.json, and Cargo.lock.",
);
console.log(
  `Next: move CHANGELOG.md [Unreleased] items into "## [${version}] - <date>",\n` +
    `then commit, merge to main, and \`git tag v${version} && git push origin v${version}\`.`,
);
