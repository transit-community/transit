/**
 * Line-based syntax highlighter for the SSH terminal.
 *
 * Wraps regex matches in ANSI SGR escapes BEFORE the byte stream
 * reaches `term.write()`. The strategy is line-buffered: chunks
 * accumulate in `pending` until a `\n` arrives, then each completed
 * line is matched against the pattern set and flushed with colors
 * injected. Trailing partial lines flush after a 30 ms idle timer
 * (driven by the caller — see `TerminalPane`) so prompts that lack a
 * final newline still render promptly.
 *
 * Why line-based, not full-buffer:
 *  - Regex over the entire scrollback on every chunk is wasteful.
 *  - Partial-line matches risk false positives mid-token.
 *  - The `term.registerDecoration` API can't cleanly span character
 *    ranges and creates per-decoration DOM overhead.
 *
 * Alt-screen detection: when the device sends `\x1b[?1049h` (or 1047 /
 * 47 — see escapes.ts), we pause highlighting until the matching `l`
 * sequence. `vi`, `less`, `top` and friends drive the screen via
 * absolute cursor positions; line-based regex matching is meaningless
 * there and would corrupt the alt-screen state.
 */

import { ALT_SCREEN_ENTER, ALT_SCREEN_EXIT, wrap } from "./escapes";
import { DEFAULT_PATTERNS, type Pattern } from "./patterns";

interface Match {
  start: number;
  end: number;
  patternIndex: number;
}

export class LineHighlighter {
  private pending = "";
  private inAltScreen = false;

  constructor(private patterns: Pattern[] = DEFAULT_PATTERNS) {}

  /**
   * Swap the active pattern set in place. The pending-line buffer and
   * alt-screen state survive — `TerminalPane` calls this when the
   * device record (and so its vendor pack) resolves after mount, which
   * may be mid-stream.
   */
  setPatterns(patterns: Pattern[]): void {
    this.patterns = patterns;
  }

  /**
   * Feed a chunk and return what should be written to the terminal.
   * Stateful: subsequent calls share the line buffer.
   *
   * When `enabled` is false, the highlighter still tracks alt-screen
   * state (so toggling on mid-session doesn't desync) but passes the
   * input through verbatim.
   */
  feed(chunk: string, enabled: boolean): string {
    this.trackAltScreen(chunk);

    if (!enabled || this.inAltScreen) {
      // Even when disabled, flush whatever was buffered so it doesn't
      // get accidentally highlighted on a future toggle. The line
      // buffer only holds value while highlighting is on.
      const flushed = this.pending + chunk;
      this.pending = "";
      return flushed;
    }

    const combined = this.pending + chunk;
    const lastNewline = combined.lastIndexOf("\n");
    if (lastNewline === -1) {
      this.pending = combined;
      return "";
    }

    const complete = combined.slice(0, lastNewline + 1);
    this.pending = combined.slice(lastNewline + 1);

    // Highlight each line independently — match indices are line-local.
    return complete
      .split("\n")
      .map((line, idx, arr) => {
        // The split produces a trailing "" after the final \n; that's
        // the boundary, not a real line. Skip the highlighter for it.
        if (idx === arr.length - 1) return line;
        return this.highlightLine(line);
      })
      .join("\n");
  }

  /**
   * Flush pending bytes (e.g. a partial prompt) without highlighting.
   * Called by the caller's idle timer.
   */
  flush(): string {
    const out = this.pending;
    this.pending = "";
    return out;
  }

  /**
   * Reset state. Call when the user disconnects or on test setup.
   */
  reset(): void {
    this.pending = "";
    this.inAltScreen = false;
  }

  /**
   * Whether the remote is currently in alt-screen mode (last seen
   * `\x1b[?1049h` / `1047h` / `47h` with no matching exit).
   *
   * `TerminalPane` reads this after every `feed()` to drive the
   * "full-screen TUI in progress" safety banner: a renderer that
   * fails to paint the alt-screen content (canvas-addon edge case,
   * unsupported sequence, etc.) still lets the user know the remote
   * is awaiting input — so a blind Enter doesn't accept an
   * invisible `[Ok]` button against the highlighted default.
   */
  isInAltScreen(): boolean {
    return this.inAltScreen;
  }

  /**
   * Walk the line, find non-overlapping matches across all patterns,
   * inject ANSI wraps around each. Earlier patterns win on overlap.
   */
  private highlightLine(line: string): string {
    if (line.length === 0) return line;

    const matches: Match[] = [];
    for (let pi = 0; pi < this.patterns.length; pi++) {
      const re = this.patterns[pi].regex;
      // Must clone-via-lastIndex-reset because shared regex state would
      // mean test order or chunk boundaries change matching behavior.
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        matches.push({ start: m.index, end: m.index + m[0].length, patternIndex: pi });
        // Defensive: zero-width matches would loop forever.
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    }

    if (matches.length === 0) return line;

    // Sort by start ascending, then by patternIndex ascending (earlier
    // pattern wins on the same start).
    matches.sort((a, b) => a.start - b.start || a.patternIndex - b.patternIndex);

    // Greedy non-overlap: keep the first match for each region; skip
    // any subsequent match whose [start,end) overlaps an already-kept
    // match. This means a later pattern that "extends" a kept match
    // is dropped — acceptable; document in tests.
    const kept: Match[] = [];
    let cursor = 0;
    for (const m of matches) {
      if (m.start < cursor) continue;
      kept.push(m);
      cursor = m.end;
    }

    let out = "";
    let pos = 0;
    for (const m of kept) {
      out += line.slice(pos, m.start);
      out += wrap(line.slice(m.start, m.end), this.patterns[m.patternIndex].color);
      pos = m.end;
    }
    out += line.slice(pos);
    return out;
  }

  private trackAltScreen(chunk: string): void {
    // Reset lastIndex on each call — these regexes are global so they
    // carry state we don't want.
    ALT_SCREEN_ENTER.lastIndex = 0;
    ALT_SCREEN_EXIT.lastIndex = 0;

    let lastEnter = -1;
    let lastExit = -1;
    let m: RegExpExecArray | null;
    while ((m = ALT_SCREEN_ENTER.exec(chunk)) !== null) {
      lastEnter = m.index;
    }
    while ((m = ALT_SCREEN_EXIT.exec(chunk)) !== null) {
      lastExit = m.index;
    }

    // Whichever toggle came last in the chunk wins.
    if (lastEnter > lastExit) this.inAltScreen = true;
    else if (lastExit > lastEnter) this.inAltScreen = false;
  }
}
