import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { highlightJson } from "./jsonHighlight";

describe("highlightJson", () => {
  it("preserves the full text verbatim (no device bytes lost or altered)", () => {
    const json = '{\n  "name": "R1",\n  "count": 42,\n  "up": true,\n  "x": null\n}';
    const { container } = render(<pre>{highlightJson(json)}</pre>);
    expect(container.textContent).toBe(json);
  });

  it("emits colored spans for keys / strings / numbers / literals", () => {
    const json = '{ "k": "v", "n": 1, "b": false }';
    const { container } = render(<pre>{highlightJson(json)}</pre>);
    // key + string + number + literal → at least four highlighted tokens.
    expect(container.querySelectorAll("span").length).toBeGreaterThanOrEqual(4);
  });

  it("never injects markup from string content (returns text nodes/spans only)", () => {
    const json = '{ "x": "<img src=x onerror=alert(1)>" }';
    const { container } = render(<pre>{highlightJson(json)}</pre>);
    // The angle brackets survive as TEXT, and no <img> element is created.
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("returns raw text unchanged above the size cap", () => {
    const big = '"' + "a".repeat(200_001) + '"';
    expect(highlightJson(big)).toBe(big);
  });
});
