// Strip HTML comment blocks from a Markdown document. `extract-changelog.mjs`
// pipes the tagged CHANGELOG section through this before it becomes the
// GitHub Release body, so repo-internal comment blocks never reach a
// published copy. Exits non-zero on an unbalanced comment marker so the
// release fails loudly instead of publishing a mangled changelog.

import { readFileSync } from "node:fs";

import { stripHtmlComments } from "./lib/strip-html-comments.mjs";

const file = process.argv[2];
if (!file) {
  console.error("Usage: node scripts/strip-md-comments.mjs <file>");
  process.exit(2);
}

try {
  process.stdout.write(stripHtmlComments(readFileSync(file, "utf8")));
} catch (e) {
  console.error(`strip-md-comments: ${file}: ${e.message}`);
  process.exit(1);
}
