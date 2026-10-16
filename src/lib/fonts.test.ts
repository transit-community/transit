import { afterEach, describe, expect, it, vi } from "vitest";

import { listMonospaceFonts } from "@/lib/api";
import { isFontRenderable, loadSelectableMonospaceFonts } from "@/lib/fonts";

vi.mock("@/lib/api", () => ({
  listMonospaceFonts: vi.fn(async () => ["Fira Code", "JetBrains Mono"]),
}));

afterEach(() => {
  vi.restoreAllMocks();
});

/** Stub canvas whose measureText width is a pure function of the last
 *  `ctx.font` assignment — lets the tests model "family resolves /
 *  doesn't resolve" without a real renderer. */
function stubCanvas(widthFor: (font: string) => number): void {
  const ctx = {
    font: "",
    measureText(_text: string) {
      return { width: widthFor(this.font) } as TextMetrics;
    },
  };
  const realCreate = document.createElement.bind(document);
  vi.spyOn(document, "createElement").mockImplementation((tag: string) => {
    if (tag !== "canvas") return realCreate(tag);
    return { getContext: () => ctx } as unknown as HTMLCanvasElement;
  });
}

describe("isFontRenderable", () => {
  it("returns true when canvas probing is unavailable (jsdom default)", () => {
    // jsdom's getContext returns null — the probe must not filter.
    expect(isFontRenderable("Anything")).toBe(true);
  });

  it("detects a family the renderer resolves (width differs from the generics)", () => {
    stubCanvas((font) => {
      if (font.includes('"Real Mono"')) return 100;
      return font.includes("serif") && !font.includes("monospace") ? 50 : 60;
    });
    expect(isFontRenderable("Real Mono")).toBe(true);
  });

  it("filters a family the renderer substitutes (no metric change against either generic)", () => {
    stubCanvas((font) => (font.includes("serif") && !font.includes("monospace") ? 50 : 60));
    expect(isFontRenderable("Ghost Font")).toBe(false);
  });
});

describe("loadSelectableMonospaceFonts", () => {
  // v6.1.0: Transit's own bundled families come first, then the OS list.
  // The bundled ones can never come from `listMonospaceFonts` — that
  // scans the OS font database and a webfont is not in it.
  it("puts bundled families ahead of the detected list", async () => {
    await expect(loadSelectableMonospaceFonts()).resolves.toEqual([
      "Cascadia Mono",
      "Fira Code",
      "JetBrains Mono",
    ]);
  });

  it("keeps only renderable OS families, but bundled ones are never probed away", async () => {
    stubCanvas((font) => {
      if (font.includes('"JetBrains Mono"')) return 100;
      return font.includes("serif") && !font.includes("monospace") ? 50 : 60;
    });
    await expect(loadSelectableMonospaceFonts()).resolves.toEqual([
      "Cascadia Mono",
      "JetBrains Mono",
    ]);
  });

  it("falls back to the unfiltered OS list when the probe filters everything", async () => {
    stubCanvas((font) => (font.includes("serif") && !font.includes("monospace") ? 50 : 60));
    await expect(loadSelectableMonospaceFonts()).resolves.toEqual([
      "Cascadia Mono",
      "Fira Code",
      "JetBrains Mono",
    ]);
    expect(vi.mocked(listMonospaceFonts)).toHaveBeenCalled();
  });

  it("still offers the bundled fonts when the OS scan finds nothing at all", async () => {
    // The macOS case in the extreme, and the whole point of bundling:
    // WKWebView refuses user-installed fonts, so what the OS reports may
    // be unusable. Transit's own faces must survive that.
    vi.mocked(listMonospaceFonts).mockResolvedValueOnce([]);
    await expect(loadSelectableMonospaceFonts()).resolves.toEqual([
      "JetBrains Mono",
      "Cascadia Mono",
    ]);
  });

  it("does not list a bundled family twice when the OS also has it installed", async () => {
    vi.mocked(listMonospaceFonts).mockResolvedValueOnce(["Cascadia Mono", "JetBrains Mono"]);
    const fonts = await loadSelectableMonospaceFonts();
    expect(fonts.filter((f) => f === "JetBrains Mono")).toHaveLength(1);
    expect(fonts.filter((f) => f === "Cascadia Mono")).toHaveLength(1);
  });
});
