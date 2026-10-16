// The publish-boundary sanitizer for CHANGELOG-derived output (extract-
// changelog.mjs + strip-md-comments.mjs). Pins the reason it exists: the
// v6.1.1 §18 cost-impact comment shipped to the public downloads page.
import { describe, expect, it } from "vitest";

import { stripHtmlComments } from "./strip-html-comments.mjs";

describe("stripHtmlComments", () => {
  it("passes comment-free markdown through unchanged", () => {
    const md = "### Added\n\n- **A feature** with `code` and 5 < 6.\n";
    expect(stripHtmlComments(md)).toBe(md);
  });

  it("strips a multi-line internal comment block without leaving a blank hole", () => {
    const md =
      "## [6.1.1] - 2026-08-15\n\n" +
      "<!-- Per-turn cost impact (CLAUDE.md §18): internal architecture\n" +
      "     notes that must never reach the downloads page. -->\n\n" +
      "### Added\n\n- A feature.\n";
    const out = stripHtmlComments(md);
    expect(out).toBe("## [6.1.1] - 2026-08-15\n\n### Added\n\n- A feature.\n");
    expect(out).not.toContain("CLAUDE.md");
  });

  it("strips multiple comments, including inline ones", () => {
    const out = stripHtmlComments("a <!-- one --> b\n<!-- two -->\nc\n");
    expect(out).toBe("a  b\n\nc\n");
  });

  it("throws on an unterminated opener instead of guessing", () => {
    expect(() => stripHtmlComments("notes\n<!-- oops no close\nmore\n")).toThrow(
      /unbalanced HTML comment marker "<!--"/,
    );
  });

  it("throws on a stray closer", () => {
    expect(() => stripHtmlComments("notes --> more\n")).toThrow(
      /unbalanced HTML comment marker "-->"/,
    );
  });
});
