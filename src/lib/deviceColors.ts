/**
 * Per-device accent colors (Phase 1 color coding; custom hex v6.3.0).
 *
 * A device's `color` field stores a curated TOKEN or (since v6.3.0) a
 * strict `#rrggbb` HEX, or null. Tokens resolve to theme-aware CSS custom
 * properties defined in `src/index.css` (`--device-<token>`, with
 * light/dark variants), so a token accent recolors automatically when the
 * theme's light/dark mode changes. A custom hex is one value in both
 * modes — that trade-off is the user's to make (the picker says so). An
 * unknown or absent value renders with no accent (graceful fallback), so
 * the backend can widen the palette later without breaking older
 * `transit.toml` files.
 */
export const DEVICE_COLORS = ["red", "amber", "green", "blue", "purple", "cyan", "slate"] as const;

export type DeviceColor = (typeof DEVICE_COLORS)[number];

export const DEVICE_COLOR_LABELS: Record<DeviceColor, string> = {
  red: "Red",
  amber: "Amber",
  green: "Green",
  blue: "Blue",
  purple: "Purple",
  cyan: "Cyan",
  slate: "Slate",
};

const KNOWN = new Set<string>(DEVICE_COLORS);

/** Whether `token` is a recognized CURATED palette color. Deliberately
 *  token-only — labels and token-specific UI key off this. For "is this
 *  a storable accent value at all" use `isAccentValue`. */
export function isDeviceColor(token: string | null | undefined): token is DeviceColor {
  return token != null && KNOWN.has(token);
}

/** Strict 6-digit hex (`#rrggbb`), case-insensitive. The narrowness is
 *  deliberate: this predicate participates in SANITIZING persisted blobs
 *  (uiStore button bars) and inventory values, so it must never pass
 *  anything that could smuggle CSS (`url(…)`, `var(…)`, keywords).
 *  3/4/8-digit forms are refused on purpose — one canonical shape keeps
 *  stored values and comparisons boring. */
const ACCENT_HEX_RE = /^#[0-9a-f]{6}$/i;

/** Whether `value` is a strict custom-hex accent (v6.3.0). */
export function isAccentHex(value: string | null | undefined): value is string {
  return value != null && ACCENT_HEX_RE.test(value);
}

/** Whether `value` is a valid accent VALUE — curated token OR strict hex.
 *  This is the storage/sanitizer predicate (schemas, persisted-blob
 *  coercion); still strict enough that a hand-edited blob can't inject an
 *  arbitrary CSS value. */
export function isAccentValue(value: string | null | undefined): boolean {
  return isDeviceColor(value) || isAccentHex(value);
}

/**
 * Resolve an accent value to a CSS color string, or `undefined` when
 * unset/unknown (caller renders no accent). Tokens map to their
 * theme-aware custom property; a strict hex passes through verbatim
 * (normalized lowercase). Used for the left-edge accent on the sidebar
 * row, session tab, and terminal pane.
 */
export function deviceColorVar(token: string | null | undefined): string | undefined {
  if (isDeviceColor(token)) return `hsl(var(--device-${token}))`;
  if (isAccentHex(token)) return token.toLowerCase();
  return undefined;
}

/**
 * Subtle background + border tint for a colored surface (the button-bar
 * per-button shade). Mixes the accent down so it reads as a tint over the
 * surface rather than a solid swatch; token accents stay theme-aware
 * because the underlying var is. Returns `undefined` when the value is
 * unset/unknown so the caller keeps its default styling.
 */
export function deviceColorTint(
  token: string | null | undefined,
): { backgroundColor: string; borderColor: string } | undefined {
  const base = deviceColorVar(token);
  if (!base) return undefined;
  return {
    backgroundColor: `color-mix(in srgb, ${base} 22%, transparent)`,
    borderColor: `color-mix(in srgb, ${base} 50%, transparent)`,
  };
}

/** Canonical stored form of an accent value: a valid hex lowercases,
 *  everything else passes through untouched. Call at WRITE sites (the
 *  picker, persisted-blob sanitizers) so equality on stored values never
 *  depends on which case a hand-edited file happened to use. Read-side
 *  normalization alone (deviceColorVar) leaves `#FFAA00` and `#ffaa00`
 *  comparing unequal everywhere else. */
export function normalizeAccent(value: string): string {
  return isAccentHex(value) ? value.toLowerCase() : value;
}

/** Perceived-luminance check for a custom hex — decides whether an icon
 *  drawn ON the solid swatch reads better dark or light. Only the picker
 *  renders anything on a solid accent (every other consumer draws
 *  borders, stripes, or 22% tints), so this stays picker-purpose. Rec.
 *  601 luma — cheap and adequate for icon contrast. */
export function hexIsLight(hex: string): boolean {
  if (!isAccentHex(hex)) return false;
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return 0.299 * r + 0.587 * g + 0.114 * b > 160;
}
