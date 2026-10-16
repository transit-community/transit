import type { ReactNode } from "react";

/**
 * Lightweight JSON syntax highlighter for the API response pane. Tokenizes
 * a pretty-printed JSON string and wraps keys / strings / numbers /
 * literals in colored spans, returning React nodes (never
 * `dangerouslySetInnerHTML`, so device data can't inject markup).
 *
 * Punctuation and whitespace pass through as plain text, so rendered
 * inside a `<pre>` the structure + indentation are preserved. Above
 * `MAX_HIGHLIGHT_BYTES` the raw text is returned unhighlighted — a huge
 * payload would produce too many spans to lay out smoothly (and it's
 * already byte-capped upstream at 8 MiB).
 */

const MAX_HIGHLIGHT_BYTES = 200_000;

// One pass: a JSON string (optionally a key when followed by `:`), a
// literal (true/false/null), or a number. Everything else is plain text.
const TOKEN =
  /("(?:\\.|[^"\\])*"(\s*:)?)|(\btrue\b|\bfalse\b|\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

export function highlightJson(text: string): ReactNode {
  if (text.length > MAX_HIGHLIGHT_BYTES) return text;

  const nodes: ReactNode[] = [];
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(text)) !== null) {
    const [full, str, colon, lit, num] = m;
    if (m.index > last) nodes.push(text.slice(last, m.index));

    if (str !== undefined) {
      if (colon) {
        // A string immediately before `:` is an object KEY.
        const keyStr = full.slice(0, full.length - colon.length);
        nodes.push(
          <span key={key++} className="text-sky-700 dark:text-sky-300">
            {keyStr}
          </span>,
        );
        nodes.push(colon);
      } else {
        nodes.push(
          <span key={key++} className="text-emerald-700 dark:text-emerald-400">
            {full}
          </span>,
        );
      }
    } else if (lit !== undefined) {
      nodes.push(
        <span key={key++} className="text-purple-600 dark:text-purple-400">
          {full}
        </span>,
      );
    } else if (num !== undefined) {
      nodes.push(
        <span key={key++} className="text-amber-700 dark:text-amber-400">
          {full}
        </span>,
      );
    }
    last = m.index + full.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}
