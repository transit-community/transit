// Find & Replace helpers for the multi-line paste confirmation dialog
// (v2.6.3). Pure string functions so PasteConfirmDialog stays a thin view:
// the match set the counter displays is computed here, and replace-all
// consumes that exact set — what you see counted is what gets replaced.
//
// Matching is LITERAL only (no user-facing regex mode). The needle is
// regex-escaped and compiled with the `i` flag for case-insensitive mode
// rather than lowercasing haystack + needle: Unicode case folding can
// change string length ('İ'.toLowerCase() is two code units), which would
// shift every offset used for selection, scrolling, and replacement.

/** Options for {@link findMatches}. */
export interface FindOptions {
  caseSensitive: boolean;
  wholeWord: boolean;
}

/** A match as UTF-16 code-unit offsets into the original text, `[start, end)`. */
export interface MatchRange {
  start: number;
  end: number;
}

/** Escape a literal string for embedding in a RegExp source. */
export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const WORD_CHAR = /[A-Za-z0-9_]/;

function isWordBoundary(text: string, index: number): boolean {
  // Offsets outside the string count as boundaries (start/end of text).
  if (index < 0 || index >= text.length) return true;
  return !WORD_CHAR.test(text[index]);
}

/**
 * All non-overlapping literal occurrences of `query` in `text`, left to
 * right. Empty query → no matches. `wholeWord` filters on the characters
 * adjacent to the match (word chars = `[A-Za-z0-9_]`), so `/`, `.`, `-`,
 * `:` neighbors — interface names, IPs, ports — still count as boundaries.
 */
export function findMatches(text: string, query: string, options: FindOptions): MatchRange[] {
  if (query.length === 0) return [];
  const re = new RegExp(escapeRegExp(query), options.caseSensitive ? "g" : "gi");
  const matches: MatchRange[] = [];
  // exec loop: a non-empty literal always matches ≥ 1 code unit, so
  // lastIndex strictly advances and the loop terminates.
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    if (options.wholeWord && !(isWordBoundary(text, start - 1) && isWordBoundary(text, end))) {
      continue;
    }
    matches.push({ start, end });
  }
  return matches;
}

/**
 * Replace one range with `replacement` via slice surgery. Never routes the
 * replacement through `String.prototype.replace`, so `$&` / `$1` / `$$`
 * stay verbatim.
 */
export function replaceRange(text: string, range: MatchRange, replacement: string): string {
  return text.slice(0, range.start) + replacement + text.slice(range.end);
}

/**
 * Replace every provided range (sorted, non-overlapping — the shape
 * {@link findMatches} returns) in a single pass. Because this consumes
 * precomputed ranges and never rescans its own output, a replacement that
 * contains the query (`sh` → `ssh`) substitutes exactly once per original
 * match.
 */
export function replaceAllMatches(
  text: string,
  matches: readonly MatchRange[],
  replacement: string,
): string {
  let out = "";
  let cursor = 0;
  for (const m of matches) {
    out += text.slice(cursor, m.start) + replacement;
    cursor = m.end;
  }
  return out + text.slice(cursor);
}

/**
 * Index of the first match starting at or after `fromOffset`, wrapping to 0
 * past the end; -1 when there are no matches. Used after replace-one to land
 * on the match now occupying the edited region's position.
 */
export function nextMatchIndex(matches: readonly MatchRange[], fromOffset: number): number {
  if (matches.length === 0) return -1;
  const i = matches.findIndex((m) => m.start >= fromOffset);
  return i === -1 ? 0 : i;
}
