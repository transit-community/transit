/**
 * ANSI SGR escape helpers for the line-based syntax highlighter.
 *
 * We stick to the 16-color palette (codes 30–37 / 90–97) for maximum
 * compatibility with xterm.js's WebGL renderer and with whatever
 * embedded terminals the user might paste output into. Bright variants
 * are used where the standard variant looks muted on a black bg.
 */

export type AnsiColor =
  | "red"
  | "green"
  | "yellow"
  | "blue"
  | "magenta"
  | "cyan"
  | "brightYellow"
  | "brightRed"
  | "brightGreen";

const FG: Record<AnsiColor, number> = {
  red: 31,
  green: 32,
  yellow: 33,
  blue: 34,
  magenta: 35,
  cyan: 36,
  brightRed: 91,
  brightGreen: 92,
  brightYellow: 93,
};

const RESET = "\x1b[0m";

export function wrap(text: string, color: AnsiColor): string {
  return `\x1b[${FG[color]}m${text}${RESET}`;
}

/**
 * Toggle bytes for the xterm "alternate screen buffer" — the mode `vi`,
 * `less`, `top`, etc. switch into for full-screen rendering. We pause
 * highlighting while the alt screen is active because cell-level cursor
 * movement breaks line-based regex matching (a single line on screen
 * may correspond to many cursor jumps in the byte stream).
 *
 * Both variants exist in the wild — modern apps overwhelmingly use 1049
 * (which also saves/restores the cursor) but 1047 / 47 still appear.
 */
export const ALT_SCREEN_ENTER = /\x1b\[\?(1049|1047|47)h/g;
export const ALT_SCREEN_EXIT = /\x1b\[\?(1049|1047|47)l/g;
