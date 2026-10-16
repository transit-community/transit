/**
 * Defense-in-depth: assert AI-emitted text containing `<script>` /
 * `<iframe>` / `onerror=` payloads renders as TEXT, never as an
 * executable DOM element.
 *
 * Two layers of defense make this safe today:
 *   1. ReactMarkdown without `rehype-raw` strips/escapes raw HTML
 *      in markdown — that's what these tests pin.
 *   2. The Tauri CSP (`script-src 'self'` in tauri.conf.json) would
 *      block inline script execution even if a `<script>` element
 *      somehow reached the DOM. That layer isn't testable from
 *      jsdom (happy-dom doesn't enforce CSP), so the property pin
 *      lives here.
 *
 * If a future refactor adds `rehype-raw` (or its equivalent) to the
 * assistant render path, these tests fail. That's the goal — the
 * change should be a deliberate security review, not silent.
 *
 * Maps to OWASP LLM02 (insecure output handling). See
 * the threat model (T2 / T12).
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

// The ONLY mock in this file: the v6.3.0 save-to-file IPC. Everything
// else stays real on purpose — these are render-boundary XSS pins.
vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    saveChatSnippet: vi.fn(async () => "/tmp/snippet.py"),
  };
});

import { ChatBubble } from "@/components/ChatBubble";
import { saveChatSnippet, type ChatMessage } from "@/lib/api";

// ---------------------------------------------------------------------
// XSS payload fixtures
// ---------------------------------------------------------------------

const SCRIPT_PAYLOAD = `<script>alert('xss')</script>`;
const IFRAME_PAYLOAD = `<iframe src="javascript:alert(1)"></iframe>`;
const IMG_ONERROR_PAYLOAD = `<img src=x onerror="alert(1)">`;

/**
 * Assertion: no executable element type appears in the rendered DOM.
 * Covers `<script>`, `<iframe>`, and any element with an `on*`
 * attribute (the React-specific representation is `on*` props, but
 * happy-dom exposes them as DOM attributes when serialized).
 */
function assertNoExecutableElements(container: HTMLElement): void {
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("iframe")).toBeNull();
  // `<img onerror>` — if the markdown render dropped it, `img` is
  // absent; if it kept the tag but stripped on*, `img` survives but
  // without the attribute. Either is safe.
  const img = container.querySelector("img");
  if (img !== null) {
    for (const attr of img.attributes) {
      expect(attr.name.toLowerCase()).not.toMatch(/^on/);
    }
  }
}

// ---------------------------------------------------------------------
// User-role bubble — plain text via React's default escaping.
// ---------------------------------------------------------------------

describe("ChatBubble — user message XSS defense", () => {
  it("renders <script> payload as visible text, not a script element", () => {
    const message: ChatMessage = { role: "user", text: SCRIPT_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
    expect(container.textContent).toContain("alert('xss')");
  });

  it("renders <iframe> payload as visible text", () => {
    const message: ChatMessage = { role: "user", text: IFRAME_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
    expect(container.textContent).toContain("iframe");
  });

  it("renders <img onerror=...> payload without executable attribute", () => {
    const message: ChatMessage = { role: "user", text: IMG_ONERROR_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
    expect(container.textContent).toContain("onerror");
  });
});

// ---------------------------------------------------------------------
// Assistant-role bubble — markdown via ReactMarkdown WITHOUT rehype-raw.
// This is the critical path: model output is the attacker-influenced
// surface, so the strictest assertion belongs here.
// ---------------------------------------------------------------------

describe("ChatBubble — assistant message XSS defense", () => {
  it("renders <script> payload from model output without creating a script element", () => {
    const message: ChatMessage = { role: "assistant", text: SCRIPT_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
    // The text portion (`alert('xss')`) survives as visible content
    // — that's the expected behavior of react-markdown without
    // rehype-raw: HTML is treated as inert text, not as DOM.
    expect(container.textContent).toContain("alert('xss')");
  });

  it("renders <iframe> payload without creating an iframe element", () => {
    const message: ChatMessage = { role: "assistant", text: IFRAME_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
  });

  it("renders <img onerror=...> payload without firing onerror", () => {
    const message: ChatMessage = { role: "assistant", text: IMG_ONERROR_PAYLOAD };
    const { container } = render(<ChatBubble message={message} />);

    assertNoExecutableElements(container);
  });

  it("positive control: ordinary markdown still renders", () => {
    // Sanity check: the defense doesn't accidentally break legitimate
    // markdown. If a future refactor disables ReactMarkdown entirely,
    // this fails — the assistant pane would degrade visibly.
    const message: ChatMessage = {
      role: "assistant",
      text: "**bold** and `code` and a [link](https://example.com)",
    };
    const { container } = render(<ChatBubble message={message} />);

    expect(container.querySelector("strong")).not.toBeNull();
    expect(container.querySelector("code")).not.toBeNull();
    expect(container.querySelector("a")).not.toBeNull();
  });
});

// ---------------------------------------------------------------------
// Tool-use bubble — output goes into a <pre>, never interpreted as HTML.
// ---------------------------------------------------------------------

describe("ChatBubble — tool_use output XSS defense", () => {
  it("renders <script> in tool output inside <pre>, not as a DOM script", async () => {
    const message: ChatMessage = {
      role: "tool_use",
      id: "tu_1",
      name: "read_scrollback",
      input: { session_id: "vEX1", max_bytes: 4096 },
      output: SCRIPT_PAYLOAD,
      is_error: false,
    };
    const { container, getByRole } = render(<ChatBubble message={message} />);

    // Tool-use bubbles start collapsed; expand so the output region
    // mounts. userEvent.click wraps the state update in act().
    await userEvent.click(getByRole("button"));

    assertNoExecutableElements(container);
    // The expanded output region contains the literal script text
    // formatted as plain text, not interpreted as DOM.
    expect(container.textContent).toContain("alert('xss')");
    // There's a <pre> rendering the output verbatim — confirming it
    // hasn't been interpreted, just stringified.
    expect(container.querySelectorAll("pre").length).toBeGreaterThan(0);
  });
});

describe("ChatBubble — code-block Save button (v6.3.0)", () => {
  const codeMessage: ChatMessage = {
    role: "assistant",
    text: "```python\nprint('interfaces')\n```",
  };

  it("is hidden without the canSaveSnippets gate (the default)", () => {
    render(<ChatBubble message={codeMessage} />);
    expect(screen.queryByTestId("code-block-save")).not.toBeInTheDocument();
  });

  it("saves via the path-less IPC with the fence-derived filename", async () => {
    render(<ChatBubble message={codeMessage} canSaveSnippets />);
    await userEvent.click(screen.getByTestId("code-block-save"));
    expect(saveChatSnippet).toHaveBeenCalledTimes(1);
    const [contents, suggested] = vi.mocked(saveChatSnippet).mock.calls[0];
    expect(contents).toContain("print('interfaces')");
    expect(suggested).toBe("snippet.py");
  });
});
