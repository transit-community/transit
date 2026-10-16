import { describe, expect, it } from "vitest";

import { applyTheme } from "./apply";
import { DEFAULT_THEME_ID, getTheme, GRUVBOX_DARK, THEME_LIST } from "./themes";

describe("theme registry", () => {
  it("ships 13 themes", () => {
    expect(THEME_LIST.length).toBe(13);
  });

  it("every theme has a unique id", () => {
    const ids = new Set(THEME_LIST.map((t) => t.id));
    expect(ids.size).toBe(THEME_LIST.length);
  });

  it("every theme carries the same set of required chrome vars", () => {
    const required = [
      "background",
      "foreground",
      "card",
      "card-foreground",
      "popover",
      "popover-foreground",
      "primary",
      "primary-foreground",
      "secondary",
      "secondary-foreground",
      "muted",
      "muted-foreground",
      "accent",
      "accent-foreground",
      "destructive",
      "destructive-foreground",
      "border",
      "input",
      "ring",
    ];
    for (const theme of THEME_LIST) {
      for (const key of required) {
        expect(theme.chrome[key], `${theme.id} missing ${key}`).toBeDefined();
      }
    }
  });

  it("every theme has an xterm theme with the 16 ANSI colors", () => {
    const required = [
      "background",
      "foreground",
      "black",
      "red",
      "green",
      "yellow",
      "blue",
      "magenta",
      "cyan",
      "white",
      "brightBlack",
      "brightRed",
      "brightGreen",
      "brightYellow",
      "brightBlue",
      "brightMagenta",
      "brightCyan",
      "brightWhite",
    ];
    for (const theme of THEME_LIST) {
      for (const key of required) {
        expect(
          (theme.xterm as Record<string, unknown>)[key],
          `${theme.id} missing xterm.${key}`,
        ).toBeDefined();
      }
    }
  });

  it("Transit Default wears the 2026-07 brand palette (blue primary since 2026-07-22)", () => {
    const t = getTheme("transit-default");
    // Ink #0A0A0B page background; Panel #15151A raised surfaces.
    expect(t.chrome.background).toBe("240 5% 4.1%");
    expect(t.chrome.card).toBe("240 11% 9.2%");
    // Transit Blue #2A83FE primary with Ink text (5.4:1 — white on
    // this blue fails AA at button-size). Teal → blue by maintainer decision,
    // 2026-07-22; must stay mirrored in index.css's `.dark` block.
    expect(t.chrome.primary).toBe("215 99% 58%");
    expect(t.chrome["primary-foreground"]).toBe("240 5% 4.1%");
    // Transit Blue #2A83FE focus ring (matches primary).
    expect(t.chrome.ring).toBe("215 99% 58%");
    // Terminal carries the brand: blue cursor, brand blue/cyan ANSI;
    // Transit Teal survives as brightCyan.
    expect(t.xterm.cursor).toBe("#2a83fe");
    expect(t.xterm.blue).toBe("#2a83fe");
    expect(t.xterm.cyan).toBe("#2ab9fe");
    expect(t.xterm.brightCyan).toBe("#54ead8");
  });

  it("Transit Classic preserves the pre-refresh neutral default", () => {
    const t = getTheme("transit-classic");
    expect(t.mode).toBe("dark");
    expect(t.license).toBe("Apache-2.0");
    expect(t.upstream).toBeNull();
    // The exact pre-2026-07 TRANSIT_DEFAULT values.
    expect(t.chrome.background).toBe("240 10% 3.9%");
    expect(t.chrome.primary).toBe("0 0% 98%");
    expect(t.chrome.ring).toBe("240 4.9% 83.9%");
    expect(t.xterm.cursor).toBe("#fafafa");
    expect(t.xterm.blue).toBe("#3b82f6");
  });

  it("Royal & Gold uses royal purple + gold", () => {
    const theme = getTheme("royal-gold");
    // royal purple #461D7C → HSL 265 62% 30%
    expect(theme.chrome.primary).toBe("265 62% 30%");
    // gold #FDD023 → HSL 47 98% 56%
    expect(theme.chrome.accent).toBe("47 98% 56%");
    expect(theme.xterm.background).toBe("#1F0D38");
    expect(theme.xterm.cursor).toBe("#FDD023");
  });

  it("Transit Twilight is an own (Apache-2.0, no upstream) dark scheme", () => {
    const tw = getTheme("transit-twilight");
    expect(tw.license).toBe("Apache-2.0");
    expect(tw.upstream).toBeNull();
    expect(tw.mode).toBe("dark");
  });

  it("getTheme falls back to Transit Default on unknown id", () => {
    expect(getTheme("nonexistent").id).toBe(DEFAULT_THEME_ID);
    expect(getTheme(null).id).toBe(DEFAULT_THEME_ID);
    expect(getTheme(undefined).id).toBe(DEFAULT_THEME_ID);
  });

  it("light themes are flagged mode='light' for the dark-class toggle", () => {
    const lightIds = THEME_LIST.filter((t) => t.mode === "light").map((t) => t.id);
    expect(lightIds).toContain("github-light");
    expect(lightIds).toContain("catppuccin-latte");
    expect(lightIds.length).toBe(2);
  });
});

describe("applyTheme", () => {
  it("writes every chrome var onto :root", () => {
    applyTheme(GRUVBOX_DARK);
    const root = document.documentElement;
    for (const [name, value] of Object.entries(GRUVBOX_DARK.chrome)) {
      expect(root.style.getPropertyValue(`--${name}`)).toBe(value);
    }
  });

  it("adds the `dark` class for dark themes", () => {
    applyTheme(GRUVBOX_DARK);
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("removes the `dark` class for light themes", () => {
    document.documentElement.classList.add("dark");
    applyTheme(getTheme("github-light"));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("tags the data-theme-id attribute on :root", () => {
    applyTheme(GRUVBOX_DARK);
    expect(document.documentElement.dataset.themeId).toBe(GRUVBOX_DARK.id);
  });
});
