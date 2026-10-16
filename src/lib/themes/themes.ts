import type { Theme } from "./types";

/**
 * Theme registry. Thirteen themes:
 *
 *   1. Transit Default (own — 2026-07 blue-to-teal brand palette)
 *   2. One Dark Pro (MIT) — Binaryify
 *   3. Dracula (MIT)
 *   4. GitHub Dark (MIT, Primer)
 *   5. GitHub Light (MIT, Primer)
 *   6. Tokyo Night (MIT) — enkia
 *   7. Catppuccin Mocha (MIT)
 *   8. Catppuccin Latte (MIT)
 *   9. Nord (MIT) — Arctic Ice Studio
 *  10. Gruvbox Dark (MIT) — morhetz
 *  11. Royal & Gold (own — royal purple #461D7C + gold #FDD023)
 *  12. Transit Twilight (own — original twilight-indigo dark scheme,
 *      teal + amber accents; no third-party palette)
 *  13. Transit Classic (own — the pre-2026-07 neutral default,
 *      preserved for users who prefer the original look)
 *
 * Each palette's source colors are stable across the upstream's
 * versions; we transcribe rather than depend on a third-party
 * Tailwind plugin to keep the build hermetic. Upstream URLs are
 * captured on each theme object for the docs/security/licenses.md
 * bundled-themes listing.
 *
 * shadcn's CSS-var convention: `--background: <H> <S>% <L>%` (no
 * `hsl()` wrapper, space-separated). The class `bg-background`
 * then resolves via `hsl(var(--background))` and Tailwind's
 * opacity utilities still work (`bg-background/50`). Keep the
 * convention.
 */

export const TRANSIT_DEFAULT: Theme = {
  id: "transit-default",
  name: "Transit Default",
  mode: "dark",
  license: "Apache-2.0",
  upstream: null,
  // 2026-07 brand refresh (Transit_AI_Brand_Guide.pdf, blue-to-teal
  // gradient system): Ink #0A0A0B page background, Panel #15151A
  // raised surfaces, Transit Blue #2A83FE primary actions with Ink
  // text (5.4:1 — white on this blue is only 3.7:1 and fails AA at
  // button-size text; the brand pairs its fills with Ink, exactly as
  // the teal era did), and the brand Muted #8A8A92 for secondary
  // text. Primary was Transit Teal #54EAD8 until 2026-07-22 (decision:
  // blue IS the brand primary; teal reads as the gradient accent) —
  // teal lives on in the terminal's brightCyan. Mirrors the `.dark`
  // block in index.css — keep the two in sync so the pre-JS first
  // paint matches the applied theme. The pre-refresh neutral scheme
  // lives on as TRANSIT_CLASSIC below.
  chrome: {
    background: "240 5% 4.1%", // Ink #0A0A0B
    foreground: "0 0% 98%",
    card: "240 11% 9.2%", // Panel #15151A
    "card-foreground": "0 0% 98%",
    popover: "240 11% 9.2%",
    "popover-foreground": "0 0% 98%",
    primary: "215 99% 58%", // Transit Blue #2A83FE (teal → blue 2026-07-22)
    "primary-foreground": "240 5% 4.1%", // Ink text on blue (5.4:1)
    secondary: "240 3.7% 15.9%",
    "secondary-foreground": "0 0% 98%",
    muted: "240 3.7% 15.9%",
    "muted-foreground": "240 4% 56%", // brand Muted #8A8A92 (5.8:1 on Ink)
    accent: "215 20% 12%", // blue-tinted hover fill
    "accent-foreground": "0 0% 98%",
    destructive: "0 62.8% 30.6%",
    "destructive-foreground": "0 0% 98%",
    border: "240 3.7% 15.9%",
    input: "240 3.7% 15.9%",
    ring: "215 99% 58%", // Transit Blue #2A83FE focus ring (matches primary)
  },
  xterm: {
    background: "#0a0a0b",
    foreground: "#fafafa",
    cursor: "#2a83fe",
    selectionBackground: "#FFEB3B66",
    black: "#1a1a1a",
    red: "#ef4444",
    green: "#22c55e",
    yellow: "#eab308",
    blue: "#2a83fe",
    magenta: "#d946ef",
    cyan: "#2ab9fe",
    white: "#fafafa",
    brightBlack: "#404040",
    brightRed: "#f87171",
    brightGreen: "#4ade80",
    brightYellow: "#facc15",
    brightBlue: "#5ba6fe",
    brightMagenta: "#e879f9",
    brightCyan: "#54ead8",
    brightWhite: "#ffffff",
  },
};

export const TRANSIT_CLASSIC: Theme = {
  id: "transit-classic",
  name: "Transit Classic",
  mode: "dark",
  license: "Apache-2.0",
  upstream: null,
  // The pre-2026-07 neutral default, preserved verbatim for anyone
  // who prefers the original look over the brand refresh.
  chrome: {
    background: "240 10% 3.9%",
    foreground: "0 0% 98%",
    card: "240 10% 3.9%",
    "card-foreground": "0 0% 98%",
    popover: "240 10% 3.9%",
    "popover-foreground": "0 0% 98%",
    primary: "0 0% 98%",
    "primary-foreground": "240 5.9% 10%",
    secondary: "240 3.7% 15.9%",
    "secondary-foreground": "0 0% 98%",
    muted: "240 3.7% 15.9%",
    "muted-foreground": "240 5% 64.9%",
    accent: "240 3.7% 15.9%",
    "accent-foreground": "0 0% 98%",
    destructive: "0 62.8% 30.6%",
    "destructive-foreground": "0 0% 98%",
    border: "240 3.7% 15.9%",
    input: "240 3.7% 15.9%",
    ring: "240 4.9% 83.9%",
  },
  xterm: {
    background: "#0a0a0a",
    foreground: "#fafafa",
    cursor: "#fafafa",
    selectionBackground: "#FFEB3B66",
    black: "#1a1a1a",
    red: "#ef4444",
    green: "#22c55e",
    yellow: "#eab308",
    blue: "#3b82f6",
    magenta: "#d946ef",
    cyan: "#06b6d4",
    white: "#fafafa",
    brightBlack: "#404040",
    brightRed: "#f87171",
    brightGreen: "#4ade80",
    brightYellow: "#facc15",
    brightBlue: "#60a5fa",
    brightMagenta: "#e879f9",
    brightCyan: "#22d3ee",
    brightWhite: "#ffffff",
  },
};

export const ONE_DARK_PRO: Theme = {
  id: "one-dark-pro",
  name: "One Dark Pro",
  mode: "dark",
  license: "MIT",
  upstream: "https://github.com/Binaryify/OneDark-Pro",
  chrome: {
    background: "220 13% 18%", // #282c34
    foreground: "220 14% 71%", // #abb2bf
    card: "220 13% 18%",
    "card-foreground": "220 14% 71%",
    popover: "220 13% 18%",
    "popover-foreground": "220 14% 71%",
    primary: "220 14% 71%",
    "primary-foreground": "220 13% 18%",
    secondary: "220 13% 23%",
    "secondary-foreground": "220 14% 71%",
    muted: "220 13% 23%",
    "muted-foreground": "220 9% 55%",
    accent: "220 13% 23%",
    "accent-foreground": "220 14% 71%",
    destructive: "355 65% 65%", // #e06c75
    "destructive-foreground": "0 0% 98%",
    border: "220 13% 26%",
    input: "220 13% 26%",
    ring: "207 82% 66%", // #61afef
  },
  xterm: {
    background: "#282c34",
    foreground: "#abb2bf",
    cursor: "#528bff",
    selectionBackground: "#FFEB3B66",
    black: "#282c34",
    red: "#e06c75",
    green: "#98c379",
    yellow: "#e5c07b",
    blue: "#61afef",
    magenta: "#c678dd",
    cyan: "#56b6c2",
    white: "#abb2bf",
    brightBlack: "#5c6370",
    brightRed: "#e06c75",
    brightGreen: "#98c379",
    brightYellow: "#e5c07b",
    brightBlue: "#61afef",
    brightMagenta: "#c678dd",
    brightCyan: "#56b6c2",
    brightWhite: "#ffffff",
  },
};

export const DRACULA: Theme = {
  id: "dracula",
  name: "Dracula",
  mode: "dark",
  license: "MIT",
  upstream: "https://github.com/dracula/dracula-theme",
  chrome: {
    background: "231 15% 18%", // #282a36
    foreground: "60 30% 96%", // #f8f8f2
    card: "231 15% 18%",
    "card-foreground": "60 30% 96%",
    popover: "231 15% 18%",
    "popover-foreground": "60 30% 96%",
    primary: "265 89% 78%", // #bd93f9
    "primary-foreground": "231 15% 18%",
    secondary: "232 14% 31%", // #44475a
    "secondary-foreground": "60 30% 96%",
    muted: "232 14% 31%",
    "muted-foreground": "225 27% 51%", // #6272a4
    accent: "326 100% 74%", // #ff79c6
    "accent-foreground": "231 15% 18%",
    destructive: "0 100% 67%", // #ff5555
    "destructive-foreground": "60 30% 96%",
    border: "232 14% 31%",
    input: "232 14% 31%",
    ring: "265 89% 78%",
  },
  xterm: {
    background: "#282a36",
    foreground: "#f8f8f2",
    cursor: "#f8f8f2",
    selectionBackground: "#FFEB3B66",
    black: "#21222c",
    red: "#ff5555",
    green: "#50fa7b",
    yellow: "#f1fa8c",
    blue: "#bd93f9",
    magenta: "#ff79c6",
    cyan: "#8be9fd",
    white: "#f8f8f2",
    brightBlack: "#6272a4",
    brightRed: "#ff6e6e",
    brightGreen: "#69ff94",
    brightYellow: "#ffffa5",
    brightBlue: "#d6acff",
    brightMagenta: "#ff92df",
    brightCyan: "#a4ffff",
    brightWhite: "#ffffff",
  },
};

export const GITHUB_DARK: Theme = {
  id: "github-dark",
  name: "GitHub Dark",
  mode: "dark",
  license: "MIT",
  upstream: "https://primer.style/foundations/primitives/color",
  chrome: {
    background: "215 28% 6%", // #0d1117
    foreground: "213 13% 82%", // #c9d1d9
    card: "215 28% 6%",
    "card-foreground": "213 13% 82%",
    popover: "215 28% 6%",
    "popover-foreground": "213 13% 82%",
    primary: "213 100% 74%", // #79c0ff
    "primary-foreground": "215 28% 6%",
    secondary: "215 14% 15%", // #21262d
    "secondary-foreground": "213 13% 82%",
    muted: "215 14% 15%",
    "muted-foreground": "215 14% 57%", // #8b949e
    accent: "215 14% 15%",
    "accent-foreground": "213 13% 82%",
    destructive: "6 96% 73%", // #ff7b72
    "destructive-foreground": "0 0% 98%",
    border: "215 14% 21%",
    input: "215 14% 21%",
    ring: "213 100% 74%",
  },
  xterm: {
    background: "#0d1117",
    foreground: "#c9d1d9",
    cursor: "#c9d1d9",
    selectionBackground: "#FFEB3B66",
    black: "#484f58",
    red: "#ff7b72",
    green: "#7ee787",
    yellow: "#d29922",
    blue: "#79c0ff",
    magenta: "#d2a8ff",
    cyan: "#a5d6ff",
    white: "#c9d1d9",
    brightBlack: "#6e7681",
    brightRed: "#ffa198",
    brightGreen: "#56d364",
    brightYellow: "#e3b341",
    brightBlue: "#79c0ff",
    brightMagenta: "#d2a8ff",
    brightCyan: "#a5d6ff",
    brightWhite: "#f0f6fc",
  },
};

export const GITHUB_LIGHT: Theme = {
  id: "github-light",
  name: "GitHub Light",
  mode: "light",
  license: "MIT",
  upstream: "https://primer.style/foundations/primitives/color",
  chrome: {
    background: "0 0% 100%", // #ffffff
    foreground: "220 14% 16%", // #24292f
    card: "0 0% 100%",
    "card-foreground": "220 14% 16%",
    popover: "0 0% 100%",
    "popover-foreground": "220 14% 16%",
    primary: "212 92% 45%", // #0969da
    "primary-foreground": "0 0% 100%",
    secondary: "210 17% 95%", // #eaeef2
    "secondary-foreground": "220 14% 16%",
    muted: "210 17% 95%",
    "muted-foreground": "215 14% 35%", // #57606a
    accent: "210 17% 95%",
    "accent-foreground": "220 14% 16%",
    destructive: "355 79% 47%", // #cf222e
    "destructive-foreground": "0 0% 98%",
    border: "210 18% 87%", // #d0d7de
    input: "210 18% 87%",
    ring: "212 92% 45%",
  },
  xterm: {
    background: "#ffffff",
    foreground: "#24292f",
    cursor: "#24292f",
    selectionBackground: "#FFEB3B66",
    black: "#24292f",
    red: "#cf222e",
    green: "#1a7f37",
    yellow: "#9a6700",
    blue: "#0969da",
    magenta: "#8250df",
    cyan: "#1b7c83",
    white: "#6e7781",
    brightBlack: "#57606a",
    brightRed: "#a40e26",
    brightGreen: "#116329",
    brightYellow: "#4d2d00",
    brightBlue: "#0550ae",
    brightMagenta: "#6639ba",
    brightCyan: "#3192aa",
    brightWhite: "#8c959f",
  },
};

export const TOKYO_NIGHT: Theme = {
  id: "tokyo-night",
  name: "Tokyo Night",
  mode: "dark",
  license: "MIT",
  upstream: "https://github.com/enkia/tokyo-night-vscode-theme",
  chrome: {
    background: "234 26% 13%", // #1a1b26
    foreground: "230 75% 86%", // #c0caf5
    card: "234 26% 13%",
    "card-foreground": "230 75% 86%",
    popover: "234 26% 13%",
    "popover-foreground": "230 75% 86%",
    primary: "217 92% 76%", // #7aa2f7
    "primary-foreground": "234 26% 13%",
    secondary: "234 20% 21%", // #292e42
    "secondary-foreground": "230 75% 86%",
    muted: "234 20% 21%",
    "muted-foreground": "230 18% 60%", // #9aa5ce
    accent: "266 86% 79%", // #bb9af7
    "accent-foreground": "234 26% 13%",
    destructive: "350 91% 71%", // #f7768e
    "destructive-foreground": "0 0% 98%",
    border: "234 20% 21%",
    input: "234 20% 21%",
    ring: "217 92% 76%",
  },
  xterm: {
    background: "#1a1b26",
    foreground: "#c0caf5",
    cursor: "#c0caf5",
    selectionBackground: "#FFEB3B66",
    black: "#15161e",
    red: "#f7768e",
    green: "#9ece6a",
    yellow: "#e0af68",
    blue: "#7aa2f7",
    magenta: "#bb9af7",
    cyan: "#7dcfff",
    white: "#a9b1d6",
    brightBlack: "#414868",
    brightRed: "#f7768e",
    brightGreen: "#9ece6a",
    brightYellow: "#e0af68",
    brightBlue: "#7aa2f7",
    brightMagenta: "#bb9af7",
    brightCyan: "#7dcfff",
    brightWhite: "#c0caf5",
  },
};

export const CATPPUCCIN_MOCHA: Theme = {
  id: "catppuccin-mocha",
  name: "Catppuccin Mocha",
  mode: "dark",
  license: "MIT",
  upstream: "https://github.com/catppuccin/catppuccin",
  chrome: {
    background: "240 21% 15%", // #1e1e2e (base)
    foreground: "226 64% 88%", // #cdd6f4 (text)
    card: "240 21% 15%",
    "card-foreground": "226 64% 88%",
    popover: "240 21% 15%",
    "popover-foreground": "226 64% 88%",
    primary: "267 84% 81%", // #cba6f7 (mauve)
    "primary-foreground": "240 21% 15%",
    secondary: "237 16% 23%", // #313244 (surface0)
    "secondary-foreground": "226 64% 88%",
    muted: "237 16% 23%",
    "muted-foreground": "228 24% 72%", // #a6adc8 (subtext0)
    accent: "189 71% 73%", // #94e2d5 (teal)
    "accent-foreground": "240 21% 15%",
    destructive: "343 81% 75%", // #f38ba8 (red)
    "destructive-foreground": "240 21% 15%",
    border: "234 13% 31%", // #45475a (surface1)
    input: "234 13% 31%",
    ring: "267 84% 81%",
  },
  xterm: {
    background: "#1e1e2e",
    foreground: "#cdd6f4",
    cursor: "#f5e0dc",
    selectionBackground: "#FFEB3B66",
    black: "#45475a",
    red: "#f38ba8",
    green: "#a6e3a1",
    yellow: "#f9e2af",
    blue: "#89b4fa",
    magenta: "#f5c2e7",
    cyan: "#94e2d5",
    white: "#bac2de",
    brightBlack: "#585b70",
    brightRed: "#f38ba8",
    brightGreen: "#a6e3a1",
    brightYellow: "#f9e2af",
    brightBlue: "#89b4fa",
    brightMagenta: "#f5c2e7",
    brightCyan: "#94e2d5",
    brightWhite: "#a6adc8",
  },
};

export const CATPPUCCIN_LATTE: Theme = {
  id: "catppuccin-latte",
  name: "Catppuccin Latte",
  mode: "light",
  license: "MIT",
  upstream: "https://github.com/catppuccin/catppuccin",
  chrome: {
    background: "220 23% 95%", // #eff1f5 (base)
    foreground: "234 16% 35%", // #4c4f69 (text)
    card: "220 23% 95%",
    "card-foreground": "234 16% 35%",
    popover: "220 23% 95%",
    "popover-foreground": "234 16% 35%",
    primary: "266 85% 58%", // #8839ef (mauve)
    "primary-foreground": "0 0% 100%",
    secondary: "223 16% 83%", // #ccd0da (surface0)
    "secondary-foreground": "234 16% 35%",
    muted: "223 16% 83%",
    "muted-foreground": "233 13% 41%", // #5c5f77 (subtext1)
    accent: "183 74% 35%", // #179299 (teal)
    "accent-foreground": "0 0% 100%",
    destructive: "347 87% 44%", // #d20f39 (red)
    "destructive-foreground": "0 0% 100%",
    border: "225 14% 77%", // #bcc0cc (surface1)
    input: "225 14% 77%",
    ring: "266 85% 58%",
  },
  xterm: {
    background: "#eff1f5",
    foreground: "#4c4f69",
    cursor: "#dc8a78",
    selectionBackground: "#FFEB3B66",
    black: "#5c5f77",
    red: "#d20f39",
    green: "#40a02b",
    yellow: "#df8e1d",
    blue: "#1e66f5",
    magenta: "#ea76cb",
    cyan: "#179299",
    white: "#acb0be",
    brightBlack: "#6c6f85",
    brightRed: "#d20f39",
    brightGreen: "#40a02b",
    brightYellow: "#df8e1d",
    brightBlue: "#1e66f5",
    brightMagenta: "#ea76cb",
    brightCyan: "#179299",
    brightWhite: "#bcc0cc",
  },
};

export const NORD: Theme = {
  id: "nord",
  name: "Nord",
  mode: "dark",
  license: "MIT",
  upstream: "https://www.nordtheme.com/",
  chrome: {
    background: "220 16% 22%", // #2e3440 (nord0)
    foreground: "219 28% 88%", // #d8dee9 (nord4)
    card: "220 16% 22%",
    "card-foreground": "219 28% 88%",
    popover: "220 16% 22%",
    "popover-foreground": "219 28% 88%",
    primary: "210 34% 63%", // #81a1c1 (nord9)
    "primary-foreground": "220 16% 22%",
    secondary: "222 16% 28%", // #3b4252 (nord1)
    "secondary-foreground": "219 28% 88%",
    muted: "222 16% 28%",
    "muted-foreground": "219 19% 67%", // #abb2bf-ish
    accent: "179 25% 65%", // #88c0d0 (nord8 / frost2)
    "accent-foreground": "220 16% 22%",
    destructive: "354 42% 56%", // #bf616a (nord11)
    "destructive-foreground": "0 0% 98%",
    border: "220 17% 32%", // #434c5e (nord2)
    input: "220 17% 32%",
    ring: "210 34% 63%",
  },
  xterm: {
    background: "#2e3440",
    foreground: "#d8dee9",
    cursor: "#d8dee9",
    selectionBackground: "#FFEB3B66",
    black: "#3b4252",
    red: "#bf616a",
    green: "#a3be8c",
    yellow: "#ebcb8b",
    blue: "#81a1c1",
    magenta: "#b48ead",
    cyan: "#88c0d0",
    white: "#e5e9f0",
    brightBlack: "#4c566a",
    brightRed: "#bf616a",
    brightGreen: "#a3be8c",
    brightYellow: "#ebcb8b",
    brightBlue: "#81a1c1",
    brightMagenta: "#b48ead",
    brightCyan: "#8fbcbb",
    brightWhite: "#eceff4",
  },
};

export const GRUVBOX_DARK: Theme = {
  id: "gruvbox-dark",
  name: "Gruvbox Dark",
  mode: "dark",
  license: "MIT",
  upstream: "https://github.com/morhetz/gruvbox",
  chrome: {
    background: "0 0% 16%", // #282828
    foreground: "44 87% 81%", // #ebdbb2
    card: "0 0% 16%",
    "card-foreground": "44 87% 81%",
    popover: "0 0% 16%",
    "popover-foreground": "44 87% 81%",
    primary: "60 56% 44%", // #b8bb26 (green)
    "primary-foreground": "0 0% 16%",
    secondary: "30 8% 25%", // #3c3836
    "secondary-foreground": "44 87% 81%",
    muted: "30 8% 25%",
    "muted-foreground": "40 17% 56%", // #a89984
    accent: "32 90% 59%", // #fabd2f (yellow)
    "accent-foreground": "0 0% 16%",
    destructive: "6 96% 60%", // #fb4934
    "destructive-foreground": "0 0% 98%",
    border: "28 13% 32%", // #504945
    input: "28 13% 32%",
    ring: "60 56% 44%",
  },
  xterm: {
    background: "#282828",
    foreground: "#ebdbb2",
    cursor: "#ebdbb2",
    selectionBackground: "#FFEB3B66",
    black: "#282828",
    red: "#cc241d",
    green: "#98971a",
    yellow: "#d79921",
    blue: "#458588",
    magenta: "#b16286",
    cyan: "#689d6a",
    white: "#a89984",
    brightBlack: "#928374",
    brightRed: "#fb4934",
    brightGreen: "#b8bb26",
    brightYellow: "#fabd2f",
    brightBlue: "#83a598",
    brightMagenta: "#d3869b",
    brightCyan: "#8ec07c",
    brightWhite: "#ebdbb2",
  },
};

export const ROYAL_GOLD: Theme = {
  id: "royal-gold",
  name: "Royal & Gold",
  mode: "dark",
  license: "Apache-2.0",
  upstream: null,
  // Anchored on a royal purple `#461D7C` (HSL 265 62%
  // 30%) + vegas gold `#FDD023` (HSL 47 98% 56%). Background is a
  // deeper variant of the purple for WCAG-AA contrast against the
  // gold-tinted foreground.
  chrome: {
    background: "266 62% 13%", // deep royal purple, derived
    foreground: "48 71% 80%", // warm cream
    card: "266 62% 13%",
    "card-foreground": "48 71% 80%",
    popover: "266 62% 13%",
    "popover-foreground": "48 71% 80%",
    primary: "265 62% 30%", // #461D7C — royal purple
    "primary-foreground": "48 71% 80%",
    secondary: "265 30% 22%",
    "secondary-foreground": "48 71% 80%",
    muted: "265 30% 22%",
    "muted-foreground": "48 50% 65%",
    accent: "47 98% 56%", // #FDD023 — gold
    "accent-foreground": "266 62% 13%",
    destructive: "0 75% 50%",
    "destructive-foreground": "0 0% 98%",
    border: "265 35% 30%",
    input: "265 35% 30%",
    ring: "47 98% 56%",
  },
  xterm: {
    background: "#1F0D38",
    foreground: "#F5E5A0",
    cursor: "#FDD023",
    selectionBackground: "#FFEB3B66",
    black: "#1F0D38",
    red: "#C84B31",
    green: "#7FB069",
    yellow: "#FDD023",
    blue: "#9D8DF1",
    magenta: "#D77BCE",
    cyan: "#65C9C9",
    white: "#F5E5A0",
    brightBlack: "#461D7C",
    brightRed: "#E37C68",
    brightGreen: "#A0CE91",
    brightYellow: "#FFE066",
    brightBlue: "#B4A8F4",
    brightMagenta: "#E5A2DC",
    brightCyan: "#8FDADA",
    brightWhite: "#FFF7D0",
  },
};

export const TRANSIT_TWILIGHT: Theme = {
  id: "transit-twilight",
  name: "Transit Twilight",
  mode: "dark",
  license: "Apache-2.0",
  upstream: null,
  // Original Transit scheme — a deep twilight indigo with a teal primary
  // and an amber accent. Own design (no third-party palette transcribed),
  // so there's nothing to attribute.
  chrome: {
    background: "222 30% 11%",
    foreground: "220 24% 90%",
    card: "222 30% 11%",
    "card-foreground": "220 24% 90%",
    popover: "222 30% 11%",
    "popover-foreground": "220 24% 90%",
    primary: "176 60% 52%",
    "primary-foreground": "222 30% 11%",
    secondary: "222 24% 18%",
    "secondary-foreground": "220 24% 90%",
    muted: "222 24% 18%",
    "muted-foreground": "220 14% 62%",
    accent: "38 92% 60%",
    "accent-foreground": "222 30% 11%",
    destructive: "0 70% 55%",
    "destructive-foreground": "0 0% 98%",
    border: "222 20% 22%",
    input: "222 20% 22%",
    ring: "176 60% 52%",
  },
  xterm: {
    background: "#0e1322",
    foreground: "#dce2f0",
    cursor: "#43d6c4",
    selectionBackground: "#FFEB3B66",
    black: "#1a2236",
    red: "#e8617a",
    green: "#5fc98a",
    yellow: "#e6b05a",
    blue: "#5b9cf0",
    magenta: "#b98bf0",
    cyan: "#43d6c4",
    white: "#dce2f0",
    brightBlack: "#46527a",
    brightRed: "#f2829a",
    brightGreen: "#7fd9a4",
    brightYellow: "#f2c878",
    brightBlue: "#82b6f5",
    brightMagenta: "#cfa9f5",
    brightCyan: "#6ee5d6",
    brightWhite: "#f2f5fc",
  },
};

export const THEMES: Record<string, Theme> = {
  [TRANSIT_DEFAULT.id]: TRANSIT_DEFAULT,
  [TRANSIT_CLASSIC.id]: TRANSIT_CLASSIC,
  [ONE_DARK_PRO.id]: ONE_DARK_PRO,
  [DRACULA.id]: DRACULA,
  [GITHUB_DARK.id]: GITHUB_DARK,
  [GITHUB_LIGHT.id]: GITHUB_LIGHT,
  [TOKYO_NIGHT.id]: TOKYO_NIGHT,
  [CATPPUCCIN_MOCHA.id]: CATPPUCCIN_MOCHA,
  [CATPPUCCIN_LATTE.id]: CATPPUCCIN_LATTE,
  [NORD.id]: NORD,
  [GRUVBOX_DARK.id]: GRUVBOX_DARK,
  [ROYAL_GOLD.id]: ROYAL_GOLD,
  [TRANSIT_TWILIGHT.id]: TRANSIT_TWILIGHT,
};

export const THEME_LIST: readonly Theme[] = [
  TRANSIT_DEFAULT,
  TRANSIT_CLASSIC,
  ONE_DARK_PRO,
  DRACULA,
  GITHUB_DARK,
  GITHUB_LIGHT,
  TOKYO_NIGHT,
  CATPPUCCIN_MOCHA,
  CATPPUCCIN_LATTE,
  NORD,
  GRUVBOX_DARK,
  ROYAL_GOLD,
  TRANSIT_TWILIGHT,
];

export const DEFAULT_THEME_ID = TRANSIT_DEFAULT.id;

/** Resolve an id to a Theme, falling back to Transit Default. */
export function getTheme(id: string | null | undefined): Theme {
  if (!id) return TRANSIT_DEFAULT;
  return THEMES[id] ?? TRANSIT_DEFAULT;
}
