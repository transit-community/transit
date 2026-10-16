import { describe, expect, it } from "vitest";

import { LineHighlighter } from "./highlighter";
import { DEFAULT_PATTERNS, patternsForVendor, type Pattern } from "./patterns";

/**
 * The wrap shape we expect the highlighter to emit. Pinned by tests
 * so a future refactor of escapes.ts can't silently change the output.
 */
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";
const BRIGHT_RED = "\x1b[91m";
const BRIGHT_GREEN = "\x1b[92m";
const BRIGHT_YELLOW = "\x1b[93m";
const RESET = "\x1b[0m";

function feedAll(h: LineHighlighter, chunks: string[], enabled = true): string {
  return chunks.map((c) => h.feed(c, enabled)).join("");
}

describe("LineHighlighter", () => {
  describe("disabled passthrough", () => {
    it("returns the chunk unchanged when disabled", () => {
      const h = new LineHighlighter();
      expect(h.feed("interface ge-0/0/0 is up\n", false)).toBe("interface ge-0/0/0 is up\n");
    });

    it("empties the pending buffer when toggled off mid-stream", () => {
      const h = new LineHighlighter();
      // Buffer a partial line while enabled.
      expect(h.feed("partial prompt> ", true)).toBe("");
      // Toggling off should flush whatever was buffered.
      expect(h.feed("more text\n", false)).toBe("partial prompt> more text\n");
    });
  });

  describe("default patterns", () => {
    const fixture = (out: string) => feedAll(new LineHighlighter(), [out]);

    it("colors `up` green and `down` red on interface state lines", () => {
      const result = fixture("ge-0/0/0    up    up\n");
      expect(result).toContain(`${GREEN}up${RESET}`);
      expect(result).not.toContain("down");

      const downResult = fixture("ge-0/0/1    down  down\n");
      expect(downResult).toContain(`${RED}down${RESET}`);
    });

    // -----------------------------------------------------------------
    // Interface error counters (user request, 2026-09-02).
    // -----------------------------------------------------------------
    describe("error counters are zero-aware", () => {
      it("REGRESSION: the plural `errors` used to match nothing at all", () => {
        // `severity-error` was /\b(ERROR|ERR|...)\b/ — the trailing \b
        // cannot hold between the `r` and the `s`, so the singular
        // highlighted and the plural did not. Every interface counter
        // uses the plural, so the most-read line in troubleshooting was
        // the one line that never lit up.
        const result = fixture("  12 errors detected\n");
        expect(result).toContain(`${RED}12 errors${RESET}`);
      });

      it("paints a NON-ZERO count red — the thing you are hunting", () => {
        const result = fixture("  5 input errors, 0 CRC, 0 frame, 0 overrun\n");
        expect(result).toContain(`${RED}5 input errors${RESET}`);
      });

      it("paints a ZERO count green, NOT red", () => {
        // The whole point of the zero-awareness: `0 input errors` is the
        // healthy case on every interface. Painting it red would teach
        // the eye to ignore the colour.
        const result = fixture("  0 output errors, 0 collisions, 1 interface resets\n");
        expect(result).toContain(`${GREEN}0 output errors${RESET}`);
        expect(result).not.toContain(`${RED}0 output errors${RESET}`);
      });

      it("handles multi-digit counts", () => {
        expect(fixture("  1234 output errors\n")).toContain(`${RED}1234 output errors${RESET}`);
        // A padded zero is still zero.
        expect(fixture("  00 input errors\n")).toContain(`${GREEN}00 input errors${RESET}`);
      });

      it("handles the count-AFTER shape, both polarities on one line", () => {
        // Junos `show interfaces extensive` / Arista counter tables put
        // the count after a colon. This line is the proof that the two
        // polarities coexist: an all-clear and a fault, same line.
        const result = fixture("    Errors: 0, Drops: 0, Framing errors: 3\n");
        expect(result).toContain(`${GREEN}Errors: 0${RESET}`);
        expect(result).toContain(`${RED}Framing errors: 3${RESET}`);
      });

      it("wins the overlap against the bare severity keyword", () => {
        // `highlightLine` keeps matches by EARLIEST START, and the
        // counter span includes the number, so it begins before the bare
        // `errors` match and claims the region. Exactly one wrap.
        const result = fixture("  7 crc errors\n");
        expect(result).toContain(`${RED}7 crc errors${RESET}`);
        expect(result.match(/errors/g)?.length).toBe(1);
      });

      it("does NOT treat an arbitrary preceding word as a counter qualifier", () => {
        // The qualifier list is closed on purpose. With a greedy `\w+`,
        // prose like "5 configuration errors" would be read as a counter
        // and swallow the sentence. The count must not be wrapped here;
        // the bare keyword still highlights.
        const result = fixture("  5 configuration errors were found\n");
        expect(result).not.toContain(`${RED}5 configuration errors${RESET}`);
        expect(result).toContain(`${RED}errors${RESET}`);
      });

      it("FALSE POSITIVE GUARD: a syslog day-of-month is not an error count", () => {
        // An optional qualifier plus `errors?` reads "Mar 10 ERROR ..."
        // as the counter "10 ERROR". A syslog severity is SINGULAR and a
        // counter is PLURAL, so the unqualified form demands the plural.
        // This caught the first draft; keep it.
        const result = fixture("Mar 10 ERROR something failed\n");
        expect(result).toContain(`${RED}ERROR${RESET}`);
        expect(result).not.toContain(`${RED}10 ERROR${RESET}`);
      });

      it("FALSE POSITIVE GUARD: a singular severity with a colon is not a counter", () => {
        // Same asymmetry on the count-AFTER shape: `ERROR: 0` must not
        // read as an all-clear counter and go green.
        const result = fixture("  ERROR: 0 packets forwarded\n");
        expect(result).not.toContain(`${GREEN}ERROR: 0${RESET}`);
        expect(result).toContain(`${RED}ERROR${RESET}`);
      });

      it("does not green unrelated zero counters", () => {
        // `0 CRC` and `0 collisions` are not error counters — only the
        // word "error(s)" opts a span into this treatment.
        const result = fixture("  0 CRC, 0 collisions, 0 ignored\n");
        expect(result).not.toContain(`${GREEN}0 CRC${RESET}`);
        expect(result).not.toContain(`${GREEN}0 collisions${RESET}`);
      });

      it("leaves the singular severity keyword behaving as before", () => {
        expect(fixture("  %SYS-3-ERROR: broke\n")).toContain(`${RED}ERROR${RESET}`);
        expect(fixture("  Total error count: 4\n")).toContain(`${RED}error${RESET}`);
      });
    });

    it("treats `administratively down` as a single multi-word match", () => {
      const result = fixture("ge-0/0/2 is administratively down\n");
      expect(result).toContain(`${RED}administratively down${RESET}`);
      // Should NOT also wrap the inner "down" — non-overlap rule.
      expect(result.match(/down/g)?.length).toBe(1);
    });

    it("wraps BGP states green / yellow", () => {
      const result = fixture("Peer 10.0.0.1 ESTABLISHED for 1d 2h\n");
      expect(result).toContain(`${GREEN}ESTABLISHED${RESET}`);

      const idle = fixture("Peer 10.0.0.2 IDLE\n");
      expect(idle).toContain(`${YELLOW}IDLE${RESET}`);
    });

    it("colors severity keywords with the right tier", () => {
      expect(fixture("Mar 10 ERROR something failed\n")).toContain(`${RED}ERROR${RESET}`);
      expect(fixture("Mar 10 CRITICAL link loss\n")).toContain(`${BRIGHT_RED}CRITICAL${RESET}`);
      expect(fixture("Mar 10 WARNING bgp flap\n")).toContain(`${YELLOW}WARNING${RESET}`);
    });

    it("colors IPv4, MAC, and VLAN tokens", () => {
      const result = fixture("host 10.0.0.1 mac 00:11:22:33:44:55 vlan 100\n");
      expect(result).toContain(`${CYAN}10.0.0.1${RESET}`);
      expect(result).toContain(`${MAGENTA}00:11:22:33:44:55${RESET}`);
      expect(result).toContain(`${BRIGHT_YELLOW}vlan 100${RESET}`);
    });

    it("matches Cisco dot-form MACs", () => {
      const result = fixture("MAC: aabb.ccdd.eeff\n");
      expect(result).toContain(`${MAGENTA}aabb.ccdd.eeff${RESET}`);
    });

    it("matches IPv4 with /prefix", () => {
      const result = fixture("route 10.0.0.0/24 via 192.168.1.1\n");
      expect(result).toContain(`${CYAN}10.0.0.0/24${RESET}`);
      expect(result).toContain(`${CYAN}192.168.1.1${RESET}`);
    });
  });

  describe("non-matching content", () => {
    it("passes through plain prose unchanged", () => {
      const h = new LineHighlighter();
      const input = "this is a plain log line with no keywords of interest\n";
      expect(h.feed(input, true)).toBe(input);
    });

    it("does not match `up` inside a longer word", () => {
      const h = new LineHighlighter();
      const result = h.feed("backup-config-uploaded\n", true);
      expect(result).toBe("backup-config-uploaded\n");
    });

    it("does not match `down` inside `download`", () => {
      const h = new LineHighlighter();
      const result = h.feed("Downloading config from server\n", true);
      expect(result).toBe("Downloading config from server\n");
    });
  });

  describe("line buffering", () => {
    it("buffers chunks without a newline and emits nothing", () => {
      const h = new LineHighlighter();
      expect(h.feed("partial line without newl", true)).toBe("");
      expect(h.feed("ine yet ", true)).toBe("");
    });

    it("emits the completed line when the newline arrives", () => {
      const h = new LineHighlighter();
      h.feed("interface up", true);
      const result = h.feed(" status\n", true);
      expect(result).toBe(`interface ${GREEN}up${RESET} status\n`);
    });

    it("handles a chunk with multiple completed lines and a partial trailer", () => {
      const h = new LineHighlighter();
      const result = h.feed("line one up\nline two down\nline three par", true);
      expect(result).toBe(`line one ${GREEN}up${RESET}\nline two ${RED}down${RESET}\n`);
      // The trailing "line three par" stays buffered.
      expect(h.feed("tial\n", true)).toBe("line three partial\n");
    });

    it("flush() returns the trailing partial line and clears it", () => {
      const h = new LineHighlighter();
      h.feed("prompt> ", true);
      expect(h.flush()).toBe("prompt> ");
      expect(h.flush()).toBe("");
    });
  });

  describe("alt-screen bypass", () => {
    it("passes content through unchanged while in alt screen", () => {
      const h = new LineHighlighter();
      // Before alt-screen entry, normal highlighting applies.
      expect(h.feed("interface up\n", true)).toBe(`interface ${GREEN}up${RESET}\n`);
      // Enter alt screen — subsequent feeds bypass highlighting.
      const enter = "\x1b[?1049h";
      h.feed(enter, true);
      const altContent = "vi: line 1 up\n";
      expect(h.feed(altContent, true)).toBe(altContent);
    });

    it("resumes highlighting after the alt screen exits", () => {
      const h = new LineHighlighter();
      h.feed("\x1b[?1049h", true);
      h.feed("inside alt up\n", true);
      // Exit alt screen — and emit a fresh chunk WITH a trailing
      // newline so the highlighter has a complete line to operate on.
      // (Without the newline, the exit byte stays buffered into the
      // next call, which is fine — xterm.js still receives the byte
      // since we never strip toggles from the output stream.)
      h.feed("\x1b[?1049l\n", true);
      const after = h.feed("after exit up\n", true);
      expect(after).toBe(`after exit ${GREEN}up${RESET}\n`);
    });

    it("recognizes the legacy 1047 / 47 alt-screen toggles", () => {
      const h47 = new LineHighlighter();
      h47.feed("\x1b[?47h", true);
      expect(h47.feed("alt up\n", true)).toBe("alt up\n");

      const h1047 = new LineHighlighter();
      h1047.feed("\x1b[?1047h", true);
      expect(h1047.feed("alt up\n", true)).toBe("alt up\n");
    });
  });

  describe("isInAltScreen()", () => {
    // The safety banner in TerminalPane reads this getter after every
    // feed() to know whether the remote is awaiting input in a full-
    // screen TUI. A regression that drops alt-screen tracking would
    // remove the only signal protecting users from blind-Enter on an
    // invisible `[Ok]` button (e.g. needrestart's "restart services"
    // dialog) when the renderer fails to paint.
    it("starts false on a fresh instance", () => {
      const h = new LineHighlighter();
      expect(h.isInAltScreen()).toBe(false);
    });

    it("flips true on `?1049h` and back to false on `?1049l`", () => {
      const h = new LineHighlighter();
      h.feed("\x1b[?1049h", true);
      expect(h.isInAltScreen()).toBe(true);
      h.feed("\x1b[?1049l", true);
      expect(h.isInAltScreen()).toBe(false);
    });

    it("tracks legacy `?47h` / `?47l` and `?1047h` / `?1047l`", () => {
      const h47 = new LineHighlighter();
      h47.feed("\x1b[?47h", true);
      expect(h47.isInAltScreen()).toBe(true);
      h47.feed("\x1b[?47l", true);
      expect(h47.isInAltScreen()).toBe(false);

      const h1047 = new LineHighlighter();
      h1047.feed("\x1b[?1047h", true);
      expect(h1047.isInAltScreen()).toBe(true);
      h1047.feed("\x1b[?1047l", true);
      expect(h1047.isInAltScreen()).toBe(false);
    });

    it("reflects state even when highlighting is disabled", () => {
      const h = new LineHighlighter();
      // The banner runs regardless of the per-device syntax-highlighting
      // pref, so trackAltScreen must run on the disabled-passthrough path.
      h.feed("\x1b[?1049h", false);
      expect(h.isInAltScreen()).toBe(true);
    });

    it("reset() clears alt-screen state", () => {
      const h = new LineHighlighter();
      h.feed("\x1b[?1049h", true);
      expect(h.isInAltScreen()).toBe(true);
      h.reset();
      expect(h.isInAltScreen()).toBe(false);
    });
  });

  describe("custom patterns", () => {
    it("uses a caller-provided pattern set when supplied", () => {
      const patterns: Pattern[] = [{ name: "test", regex: /\bFOO\b/g, color: "magenta" }];
      const h = new LineHighlighter(patterns);
      const result = h.feed("the FOO marker\n", true);
      expect(result).toBe(`the ${MAGENTA}FOO${RESET} marker\n`);
    });

    it("earlier patterns win on overlap", () => {
      const patterns: Pattern[] = [
        { name: "first", regex: /\babc\b/g, color: "red" },
        { name: "second", regex: /\babc\s+def\b/g, color: "green" },
      ];
      const h = new LineHighlighter(patterns);
      const result = h.feed("abc def\n", true);
      // First pattern matched "abc"; second pattern's "abc def" overlaps
      // and is dropped. The remaining " def" stays unwrapped.
      expect(result).toBe(`${RED}abc${RESET} def\n`);
    });
  });

  describe("reset()", () => {
    it("clears pending buffer and alt-screen state", () => {
      const h = new LineHighlighter();
      h.feed("partial", true);
      h.feed("\x1b[?1049h", true);
      h.reset();
      // After reset, the next feed should highlight (not be in alt screen)
      // and not include the "partial" prefix.
      expect(h.feed("up\n", true)).toBe(`${GREEN}up${RESET}\n`);
    });
  });

  describe("vendor packs (patternsForVendor)", () => {
    it("returns the default set untouched for unknown / missing vendors", () => {
      expect(patternsForVendor(null)).toBe(DEFAULT_PATTERNS);
      expect(patternsForVendor(undefined)).toBe(DEFAULT_PATTERNS);
      expect(patternsForVendor("acme_custom")).toBe(DEFAULT_PATTERNS);
      expect(patternsForVendor("pan_os")).toBe(DEFAULT_PATTERNS);
      expect(patternsForVendor("linux")).toBe(DEFAULT_PATTERNS);
    });

    it("prepends a pack for every cisco-family tag (incl. the cisco_nxos alias)", () => {
      for (const tag of ["cisco_ios", "cisco_ios_xe", "nxos", "cisco_nxos", "arista_eos"]) {
        const ps = patternsForVendor(tag);
        expect(ps.length).toBeGreaterThan(DEFAULT_PATTERNS.length);
        expect(ps[0].name.startsWith("cisco-")).toBe(true);
      }
    });

    it("colors cisco syslog mnemonics by severity band", () => {
      const h = new LineHighlighter(patternsForVendor("cisco_ios"));
      expect(h.feed("%SYS-5-CONFIG_I: Configured from console\n", true)).toContain(
        `${CYAN}%SYS-5-CONFIG_I${RESET}`,
      );
      expect(h.feed("%LINK-3-UPDOWN: Interface Gi0/1\n", true)).toContain(
        `${YELLOW}%LINK-3-UPDOWN${RESET}`,
      );
      expect(h.feed("%SYS-2-MALLOCFAIL: out of memory\n", true)).toContain(
        `${BRIGHT_RED}%SYS-2-MALLOCFAIL${RESET}`,
      );
    });

    it("highlights interface-status vocabulary, pack winning overlaps", () => {
      const h = new LineHighlighter(patternsForVendor("arista_eos"));
      // "err-disabled" also matches the generic severity-error's \bERR\b
      // at the same start — the prepended pack must win the span.
      const out = h.feed("Et1 err-disabled  Et2 connected  Et3 notconnect\n", true);
      expect(out).toContain(`${BRIGHT_RED}err-disabled${RESET}`);
      expect(out).toContain(`${GREEN}connected${RESET}`);
      expect(out).toContain(`${RED}notconnect${RESET}`);
    });

    it("junos pack: commit complete, truncated Establ, alarm classes", () => {
      const h = new LineHighlighter(patternsForVendor("junos"));
      expect(h.feed("commit complete\n", true)).toBe(`${BRIGHT_GREEN}commit complete${RESET}\n`);
      expect(h.feed("10.255.0.2 65001 Establ\n", true)).toContain(`${GREEN}Establ${RESET}`);
      expect(h.feed("Major  PEM 0 Not OK\n", true)).toContain(`${BRIGHT_RED}Major${RESET}`);
      expect(h.feed("Minor  Fan tray slow\n", true)).toContain(`${YELLOW}Minor${RESET}`);
    });

    it("setPatterns swaps the pack in place without losing buffered state", () => {
      const h = new LineHighlighter(); // default set — no junos pack
      expect(h.feed("commit ", true)).toBe(""); // partial line buffered
      h.setPatterns(patternsForVendor("junos"));
      expect(h.feed("complete\n", true)).toBe(`${BRIGHT_GREEN}commit complete${RESET}\n`);
    });
  });
});
