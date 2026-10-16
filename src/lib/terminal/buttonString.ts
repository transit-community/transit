// SecureCRT-style "Send String" parser + executor for the v1.4.0 button bar.
//
// A button's value is a single string that may interleave literal text with
// escape codes (matching SecureCRT's documented Send String codes):
//
//   \r        carriage return (Enter)
//   \n        line feed (newline)
//   \e        ESC (0x1B)            \033 / \###  1–3 octal digits → one byte
//   \p        pause one second
//   \v        paste the clipboard contents
//   \\        a literal backslash
//   \<other>  the literal <other> char (the backslash is dropped)
//
// Because `\p` and `\v` interleave with bytes, a value is a *sequence* of
// segments executed in order — not a single send. The executor is
// dependency-injected (sendInput / readClipboard / delay) so it unit-tests
// without Tauri, the real clipboard, or real timers.

import { encodeBytesToBase64 } from "@/lib/terminal/bytes";

/** One step of a parsed Send String. */
export type ButtonSegment =
  { kind: "bytes"; bytes: Uint8Array } | { kind: "delay"; ms: number } | { kind: "paste" };

/** Milliseconds for a single `\p` pause (SecureCRT = one second). */
export const PAUSE_MS = 1000;

const CR = 0x0d;
const LF = 0x0a;
const ESC = 0x1b;

function isOctalDigit(ch: string): boolean {
  return ch >= "0" && ch <= "7";
}

/**
 * Parse a button value into an ordered list of segments. Consecutive literal
 * / control bytes coalesce into one `bytes` segment; `\p` and `\v` split the
 * run. Literal text is UTF-8 encoded.
 */
export function parseButtonString(input: string): ButtonSegment[] {
  const segments: ButtonSegment[] = [];
  const encoder = new TextEncoder();
  let bytes: number[] = [];

  const pushText = (s: string) => {
    for (const b of encoder.encode(s)) bytes.push(b);
  };
  const flush = () => {
    if (bytes.length > 0) {
      segments.push({ kind: "bytes", bytes: Uint8Array.from(bytes) });
      bytes = [];
    }
  };

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (ch !== "\\") {
      pushText(ch);
      continue;
    }
    // Backslash escape. A trailing backslash is a literal backslash.
    if (i + 1 >= input.length) {
      pushText("\\");
      break;
    }
    const next = input[i + 1];
    switch (next) {
      case "r":
        bytes.push(CR);
        i += 1;
        break;
      case "n":
        bytes.push(LF);
        i += 1;
        break;
      case "e":
        bytes.push(ESC);
        i += 1;
        break;
      case "\\":
        pushText("\\");
        i += 1;
        break;
      case "p":
        flush();
        segments.push({ kind: "delay", ms: PAUSE_MS });
        i += 1;
        break;
      case "v":
        flush();
        segments.push({ kind: "paste" });
        i += 1;
        break;
      default:
        if (isOctalDigit(next)) {
          // 1–3 octal digits → one byte (e.g. \033 = ESC). Clamp to a byte.
          let digits = "";
          let j = i + 1;
          while (j < input.length && digits.length < 3 && isOctalDigit(input[j])) {
            digits += input[j];
            j += 1;
          }
          bytes.push(parseInt(digits, 8) & 0xff);
          i = j - 1;
        } else {
          // Unrecognized escape — emit the char literally, drop the backslash.
          pushText(next);
          i += 1;
        }
        break;
    }
  }

  flush();
  return segments;
}

/** Injected side-effects so the executor is testable in isolation. */
export interface ButtonExecDeps {
  sendInput: (sessionId: string, dataB64: string) => Promise<void>;
  readClipboard: () => Promise<string>;
  delay: (ms: number) => Promise<void>;
}

/**
 * Execute a parsed Send String against `sessionId`, in order: byte runs go
 * out via `sendInput`, `\p` awaits `delay`, `\v` reads the clipboard and
 * sends it (directly — an explicit user-authored macro is NOT routed through
 * the multi-line-paste gate). Empty clipboard sends nothing.
 */
export async function executeButtonString(
  input: string,
  sessionId: string,
  deps: ButtonExecDeps,
): Promise<void> {
  const encoder = new TextEncoder();
  for (const seg of parseButtonString(input)) {
    if (seg.kind === "bytes") {
      await deps.sendInput(sessionId, encodeBytesToBase64(seg.bytes));
    } else if (seg.kind === "delay") {
      await deps.delay(seg.ms);
    } else {
      const text = await deps.readClipboard();
      if (text.length > 0) {
        await deps.sendInput(sessionId, encodeBytesToBase64(encoder.encode(text)));
      }
    }
  }
}
