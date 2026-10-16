// Strip HTML comments (<!-- ... -->) from Markdown destined for publication.
//
// CHANGELOG.md is a public artifact: extract-changelog.mjs feeds the GitHub
// Release body. Authors keep repo-internal notes in HTML comments
// (e.g. the CLAUDE.md §18 per-turn cost-impact records) — those must never
// ship: the v6.1.1 cost-impact comment rendered as visible text on the public
// downloads page, whose Markdown renderer escapes raw HTML. Every publish
// path routes through this helper.
//
// Throws on an unbalanced marker instead of guessing: a stray `<!--` would
// swallow real notes in a browser and render as garbage through the
// downloads Worker's escape-first renderer. Accepted limitation: a literal
// `<!--` inside a code span is treated as a comment opener — don't put
// comment markers in changelog code examples.

export function stripHtmlComments(text) {
  const stripped = text.replace(/<!--[\s\S]*?-->/g, "");
  const leftover = stripped.match(/<!--|-->/);
  if (leftover) {
    throw new Error(
      `unbalanced HTML comment marker "${leftover[0]}" — ` +
        "balance it (or remove it) so internal notes can be stripped cleanly",
    );
  }
  // Collapse the blank hole a stripped comment block leaves behind.
  return stripped.replace(/\n{3,}/g, "\n\n");
}
