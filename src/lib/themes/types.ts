import type { ITheme } from "@xterm/xterm";

/**
 * Phase 7a C5 — theme system types.
 *
 * Each theme has two halves:
 *   - `chrome`: a map of shadcn / Tailwind CSS variables (HSL space
 *     format — "240 10% 3.9%", no `hsl()` wrapper, matching the
 *     existing index.css convention). Applied at runtime via
 *     `document.documentElement.style.setProperty`, which takes
 *     precedence over the static `:root` / `.dark` blocks in
 *     index.css.
 *   - `xterm`: an `ITheme` for xterm.js, driving terminal
 *     foreground / background / cursor + 16 ANSI colors. Applied
 *     in TerminalPane via `term.options.theme = ...`.
 *
 * Both halves stay in sync — the terminal recolors when the chrome
 * recolors. xterm.js doesn't share CSS variables with the React
 * tree, so the two have to be defined together.
 */

export interface Theme {
  /** Stable identifier persisted to user prefs + Device.theme. */
  id: string;
  /** Human-readable name in the picker. */
  name: string;
  /** Light vs dark. Drives the `<html class="dark">` toggle so
   *  Tailwind's dark: utilities still resolve correctly when a
   *  theme overrides the CSS vars. */
  mode: "light" | "dark";
  /** SPDX-ish license string for the docs/security/licenses.md
   *  bundle listing. "Apache-2.0" for our own themes. */
  license: string;
  /** Upstream URL the palette was sourced from, or `null` for
   *  themes we authored ourselves. */
  upstream: string | null;
  /** shadcn CSS variable map. Keys are var names *without* the
   *  leading "--". Values are HSL space-separated strings (e.g.
   *  "240 10% 3.9%"). */
  chrome: Record<string, string>;
  /** xterm.js terminal theme. */
  xterm: ITheme;
}
