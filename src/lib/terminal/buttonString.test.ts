import { describe, expect, it, vi } from "vitest";

import {
  type ButtonSegment,
  executeButtonString,
  parseButtonString,
  PAUSE_MS,
} from "@/lib/terminal/buttonString";

/** Flatten the byte segments of a parse to a number[] (drops delay/paste). */
function bytesOf(segments: ButtonSegment[]): number[] {
  return segments.flatMap((s) => (s.kind === "bytes" ? Array.from(s.bytes) : []));
}

const utf8 = (s: string) => Array.from(new TextEncoder().encode(s));

describe("parseButtonString", () => {
  it("encodes plain text as UTF-8 bytes", () => {
    expect(bytesOf(parseButtonString("show version"))).toEqual(utf8("show version"));
  });

  it("\\r → CR (Enter)", () => {
    expect(bytesOf(parseButtonString("show ver\\r"))).toEqual([...utf8("show ver"), 0x0d]);
  });

  it("\\n → LF", () => {
    expect(bytesOf(parseButtonString("a\\nb"))).toEqual([0x61, 0x0a, 0x62]);
  });

  it("\\e → ESC", () => {
    expect(bytesOf(parseButtonString("\\e"))).toEqual([0x1b]);
  });

  it("\\033 octal → ESC", () => {
    expect(bytesOf(parseButtonString("\\033"))).toEqual([0x1b]);
  });

  it("1–3 octal digits each → one byte; a 4th octal digit is literal", () => {
    expect(bytesOf(parseButtonString("\\7"))).toEqual([0o7]);
    expect(bytesOf(parseButtonString("\\41"))).toEqual([0o41]); // '!'
    expect(bytesOf(parseButtonString("\\101"))).toEqual([0o101]); // 'A'
    expect(bytesOf(parseButtonString("\\1011"))).toEqual([0o101, 0x31]); // 'A' + '1'
  });

  it("\\\\ → a single literal backslash", () => {
    expect(bytesOf(parseButtonString("a\\\\b"))).toEqual([0x61, 0x5c, 0x62]);
  });

  it("unrecognized escape drops the backslash (emits the char)", () => {
    expect(bytesOf(parseButtonString("\\q"))).toEqual([0x71]); // 'q'
  });

  it("a trailing backslash is a literal backslash", () => {
    expect(bytesOf(parseButtonString("x\\"))).toEqual([0x78, 0x5c]);
  });

  it("\\p splits the run with a 1s delay segment, in order", () => {
    expect(parseButtonString("a\\pb")).toEqual([
      { kind: "bytes", bytes: Uint8Array.from([0x61]) },
      { kind: "delay", ms: PAUSE_MS },
      { kind: "bytes", bytes: Uint8Array.from([0x62]) },
    ]);
  });

  it("\\v becomes a paste segment, in order", () => {
    expect(parseButtonString("a\\vb").map((s) => s.kind)).toEqual(["bytes", "paste", "bytes"]);
  });

  it("empty string → no segments", () => {
    expect(parseButtonString("")).toEqual([]);
  });
});

describe("executeButtonString", () => {
  function makeDeps() {
    return {
      sendInput: vi.fn().mockResolvedValue(undefined),
      readClipboard: vi.fn().mockResolvedValue("PASTED"),
      delay: vi.fn().mockResolvedValue(undefined),
    };
  }

  it("sends a command + Enter as one no-pad-base64 chunk", async () => {
    const d = makeDeps();
    await executeButtonString("show version\\r", "s1", d);
    expect(d.sendInput).toHaveBeenCalledTimes(1);
    expect(d.sendInput).toHaveBeenCalledWith("s1", btoa("show version\r").replace(/=+$/, ""));
  });

  it("executes segments strictly in order: bytes → delay → paste → bytes", async () => {
    const d = makeDeps();
    const order: string[] = [];
    d.sendInput.mockImplementation(async (_id: string, b64: string) => {
      order.push(`send:${atob(b64 + "===".slice((b64.length + 3) % 4))}`);
    });
    d.delay.mockImplementation(async (ms: number) => {
      order.push(`delay:${ms}`);
    });
    d.readClipboard.mockResolvedValue("X");
    await executeButtonString("a\\p\\vb", "s1", d);
    expect(order).toEqual(["send:a", `delay:${PAUSE_MS}`, "send:X", "send:b"]);
  });

  it("\\v reads the clipboard and sends it; an empty clipboard sends nothing", async () => {
    const d = makeDeps();
    d.readClipboard.mockResolvedValue("");
    await executeButtonString("\\v", "s1", d);
    expect(d.readClipboard).toHaveBeenCalledTimes(1);
    expect(d.sendInput).not.toHaveBeenCalled();
  });
});
