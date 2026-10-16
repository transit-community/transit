#!/usr/bin/env node
// Print the CHANGELOG.md section for one version, for use as a GitHub
// Release body and the download page's release notes.
// Usage: node scripts/extract-changelog.mjs <x.y.z>
//
// Finds the "## [x.y.z]" heading (optionally followed by " - <date>") and
// prints every line up to the next "## " heading, with HTML comments
// stripped — comments are repo-internal notes, and this output is published
// (GitHub Release body, versions.json notes_md, updater latest.json notes).
// Exits non-zero with a clear message if the section is missing, empty
// (comments-only counts as empty), or holds an unbalanced comment marker —
// so release.yml fails loudly instead of publishing internal notes.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { stripHtmlComments } from "./lib/strip-html-comments.mjs";

const version = process.argv[2];
if (!version) {
  console.error("Usage: node scripts/extract-changelog.mjs <x.y.z>");
  process.exit(2);
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(join(repoRoot, "CHANGELOG.md"), "utf8").split(/\r?\n/);

// Escape regex metacharacters (the dots) in the version.
const v = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const headingRe = new RegExp(`^## \\[${v}\\]`);

const start = lines.findIndex((l) => headingRe.test(l));
if (start === -1) {
  console.error(
    `extract-changelog: no "## [${version}]" section in CHANGELOG.md.\n` +
      `Add a dated section for ${version} (move items out of [Unreleased]) before tagging.`,
  );
  process.exit(1);
}

let end = lines.length;
for (let i = start + 1; i < lines.length; i++) {
  if (/^## /.test(lines[i])) {
    end = i;
    break;
  }
}

let body = lines
  .slice(start + 1, end)
  .join("\n")
  .trim();
try {
  body = stripHtmlComments(body).trim();
} catch (e) {
  console.error(`extract-changelog: "## [${version}]" section: ${e.message}`);
  process.exit(1);
}
if (!body) {
  console.error(
    `extract-changelog: the "## [${version}]" section is empty ` +
      "(HTML comments are stripped — a comments-only section counts as empty).",
  );
  process.exit(1);
}
process.stdout.write(body + "\n");
