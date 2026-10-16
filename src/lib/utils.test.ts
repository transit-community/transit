import { describe, expect, it } from "vitest";
import { cn, formatTokens } from "./utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("a", "b")).toBe("a b");
  });

  it("dedupes Tailwind classes via tailwind-merge", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });

  it("filters falsy values", () => {
    expect(cn("a", false, undefined, null, "b")).toBe("a b");
  });
});

describe("formatTokens", () => {
  it("renders small counts verbatim", () => {
    expect(formatTokens(0)).toBe("0");
    expect(formatTokens(999)).toBe("999");
  });

  it("renders thousands as k", () => {
    expect(formatTokens(1000)).toBe("1.0k");
    expect(formatTokens(18243)).toBe("18.2k");
  });

  it("renders millions as M", () => {
    expect(formatTokens(2_500_000)).toBe("2.5M");
  });

  it("never emits a dollar sign", () => {
    expect(formatTokens(18243)).not.toContain("$");
  });
});
