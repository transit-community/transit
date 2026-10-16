/**
 * Font availability for the Settings → Terminal font picker.
 *
 * The backend's `list_monospace_fonts` enumerates the OS font
 * database, but "installed on the OS" is not "usable by this
 * webview" — WebKit refuses to serve some system families to web
 * content (SF Mono being the canonical macOS case), and xterm.js
 * draws through canvas, which follows the same CSS font resolution.
 * Listing a font the renderer would silently substitute is worse
 * than not listing it, so we keep only families a canvas metric
 * probe confirms the webview actually resolves.
 */

import { listMonospaceFonts } from "@/lib/api";

/** Wide/narrow glyph mix — metric differences between families show
 *  up reliably at this length. */
const PROBE_TEXT = "mmmMMMwwwiiilll|||@#%WW10O";

/**
 * Whether the webview can actually render `family` (vs silently
 * substituting a generic). Measures the probe text in the candidate
 * with a monospace fallback and again with a serif fallback; a
 * family that changes NEITHER measurement isn't being resolved by
 * the renderer. Each candidate measurement is preceded by a reset
 * to the bare generic, so an unparseable family name (which leaves
 * `ctx.font` untouched) reads as unavailable rather than as a false
 * positive. Returns true when probing is unavailable (jsdom,
 * headless) — the caller falls back to the unfiltered list rather
 * than hiding everything.
 */
export function isFontRenderable(family: string): boolean {
  let ctx: CanvasRenderingContext2D | null;
  try {
    ctx = document.createElement("canvas").getContext("2d");
  } catch {
    return true;
  }
  if (!ctx) return true;
  try {
    const quoted = `"${family.replaceAll('"', "")}"`;
    const measureAs = (stack: string, reset: string): number => {
      ctx.font = `16px ${reset}`;
      ctx.font = `16px ${stack}`;
      return ctx.measureText(PROBE_TEXT).width;
    };
    const mono = measureAs("monospace", "monospace");
    const serif = measureAs("serif", "serif");
    return (
      measureAs(`${quoted}, monospace`, "monospace") !== mono ||
      measureAs(`${quoted}, serif`, "serif") !== serif
    );
  } catch {
    return true;
  }
}

/**
 * Families Transit ships itself, declared as `@font-face` in
 * `index.css` (v6.1.0).
 *
 * They must be listed explicitly because `list_monospace_fonts` scans
 * the OS font database and a webfont is not in it — the backend cannot
 * see these, by construction. They are also the only non-Apple faces
 * available on macOS at all: WKWebView refuses user-installed fonts to
 * web content, so bundling is the mechanism, not a convenience.
 *
 * Ordered best-default-first; the picker shows them ahead of the OS
 * list under their own heading.
 */
export const BUNDLED_FONTS = ["JetBrains Mono", "Cascadia Mono"] as const;

/**
 * The font list the picker should offer: Transit's bundled families
 * first, then OS-detected monospace families filtered to what this
 * webview can render. Falls back to the unfiltered OS list if the probe
 * filtered everything (probe misbehavior shouldn't blank the picker).
 *
 * ⚠️ Awaits `document.fonts.ready` before probing. Without it the metric
 * probe races our own `@font-face` loads and reports Transit's bundled
 * fonts as unrenderable — the picker would then hide the only fonts we
 * can guarantee.
 */
export async function loadSelectableMonospaceFonts(): Promise<string[]> {
  const detected = await listMonospaceFonts();
  if (typeof document !== "undefined" && document.fonts?.ready) {
    try {
      await document.fonts.ready;
    } catch {
      // Probing an unloaded font is a false negative, not a crash —
      // carry on and let the fallback below cover it.
    }
  }
  const renderable = detected.filter(isFontRenderable);
  const os = renderable.length > 0 ? renderable : detected;
  // Dedup: a user who ALSO installed JetBrains Mono system-wide would
  // otherwise see it twice (the OS scan finds it even where the webview
  // won't serve it).
  const bundled = BUNDLED_FONTS.filter((f) => !os.includes(f));
  return [...bundled, ...os];
}
