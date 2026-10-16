import { describe, expect, it } from "vitest";

import {
  DEVICE_COLORS,
  DEVICE_COLOR_LABELS,
  deviceColorTint,
  deviceColorVar,
  hexIsLight,
  isAccentHex,
  isAccentValue,
  isDeviceColor,
  normalizeAccent,
} from "./deviceColors";

describe("isDeviceColor", () => {
  it("accepts every curated token", () => {
    for (const token of DEVICE_COLORS) {
      expect(isDeviceColor(token)).toBe(true);
    }
  });

  it("rejects unknown tokens, hex values, empty string, null, and undefined", () => {
    expect(isDeviceColor("bogus")).toBe(false);
    expect(isDeviceColor("BLUE")).toBe(false); // case-sensitive
    // Deliberately token-only: a hex is a valid ACCENT (isAccentValue)
    // but never a curated token — labels key off this.
    expect(isDeviceColor("#3b82f6")).toBe(false);
    expect(isDeviceColor("")).toBe(false);
    expect(isDeviceColor(null)).toBe(false);
    expect(isDeviceColor(undefined)).toBe(false);
  });
});

describe("isAccentHex / isAccentValue (v6.3.0 custom hex)", () => {
  it("accepts strict 6-digit hex, either case", () => {
    expect(isAccentHex("#3b82f6")).toBe(true);
    expect(isAccentHex("#FFAA00")).toBe(true);
    expect(isAccentValue("#3b82f6")).toBe(true);
  });

  it("isAccentValue accepts every curated token too", () => {
    for (const token of DEVICE_COLORS) {
      expect(isAccentValue(token)).toBe(true);
    }
  });

  it("rejects everything CSS-shaped that is not a strict #rrggbb", () => {
    // Short/long hex forms — one canonical shape only.
    expect(isAccentHex("#fff")).toBe(false);
    expect(isAccentHex("#ffaa00cc")).toBe(false);
    // Injection-shaped values the sanitizer must never pass.
    expect(isAccentValue("url(red)")).toBe(false);
    expect(isAccentValue("var(--device-red)")).toBe(false);
    expect(isAccentValue("javascript:alert(1)")).toBe(false);
    expect(isAccentValue("red; background: url(x)")).toBe(false);
    expect(isAccentValue("chartreuse")).toBe(false);
    expect(isAccentValue("3b82f6")).toBe(false); // missing '#'
    expect(isAccentValue("#3b82fg")).toBe(false); // non-hex digit
    expect(isAccentValue("")).toBe(false);
    expect(isAccentValue(null)).toBe(false);
    expect(isAccentValue(undefined)).toBe(false);
  });
});

describe("deviceColorVar", () => {
  it("resolves a known token to its themed CSS variable", () => {
    expect(deviceColorVar("red")).toBe("hsl(var(--device-red))");
    expect(deviceColorVar("slate")).toBe("hsl(var(--device-slate))");
  });

  it("passes a strict hex through verbatim, normalized lowercase (v6.3.0)", () => {
    expect(deviceColorVar("#3b82f6")).toBe("#3b82f6");
    expect(deviceColorVar("#FFAA00")).toBe("#ffaa00");
  });

  it("returns undefined for unset or unknown values (renders no accent)", () => {
    expect(deviceColorVar(null)).toBeUndefined();
    expect(deviceColorVar(undefined)).toBeUndefined();
    expect(deviceColorVar("")).toBeUndefined();
    expect(deviceColorVar("chartreuse")).toBeUndefined();
    expect(deviceColorVar("#fff")).toBeUndefined();
    expect(deviceColorVar("url(red)")).toBeUndefined();
  });
});

describe("palette metadata", () => {
  it("has a human label for every token", () => {
    for (const token of DEVICE_COLORS) {
      expect(DEVICE_COLOR_LABELS[token]).toBeTruthy();
    }
  });
});

describe("deviceColorTint", () => {
  it("returns a theme-aware background + border tint for a valid token", () => {
    const tint = deviceColorTint("blue");
    expect(tint).toBeDefined();
    expect(tint!.backgroundColor).toContain("--device-blue");
    expect(tint!.backgroundColor).toContain("color-mix");
    // Border is a stronger mix than the background.
    expect(tint!.borderColor).toContain("--device-blue");
  });

  it("tints a custom hex through the same color-mix (v6.3.0)", () => {
    const tint = deviceColorTint("#ffaa00");
    expect(tint).toBeDefined();
    expect(tint!.backgroundColor).toContain("#ffaa00");
    expect(tint!.backgroundColor).toContain("color-mix");
  });

  it("returns undefined for unset/unknown values (caller keeps default style)", () => {
    expect(deviceColorTint(null)).toBeUndefined();
    expect(deviceColorTint(undefined)).toBeUndefined();
    expect(deviceColorTint("")).toBeUndefined();
    expect(deviceColorTint("chartreuse")).toBeUndefined();
  });
});

describe("normalizeAccent (write-site canonicalization)", () => {
  it("lowercases a valid hex and leaves everything else untouched", () => {
    expect(normalizeAccent("#FFAA00")).toBe("#ffaa00");
    expect(normalizeAccent("#ffaa00")).toBe("#ffaa00");
    // Tokens and junk pass through — normalization never invents
    // validity (the sanitizer decides what's stored, this decides case).
    expect(normalizeAccent("red")).toBe("red");
    expect(normalizeAccent("BLUE")).toBe("BLUE");
    expect(normalizeAccent("")).toBe("");
  });
});

describe("hexIsLight (picker check-icon contrast)", () => {
  it("classifies light and dark hexes", () => {
    expect(hexIsLight("#ffffff")).toBe(true);
    expect(hexIsLight("#ffee88")).toBe(true);
    expect(hexIsLight("#000000")).toBe(false);
    expect(hexIsLight("#1e3a8a")).toBe(false);
  });

  it("is false for non-hex input (tokens use the fixed white check)", () => {
    expect(hexIsLight("red")).toBe(false);
    expect(hexIsLight("")).toBe(false);
  });
});
