// No-pad base64 codec for PTY bytes — mirrors Phase 2b's IPC encoding
// (Rust `STANDARD_NO_PAD`). Shared by TerminalPane (keystrokes + output
// decoding) and the v1.4.0 button bar's Send-String executor, so both sides
// use one canonical encoder.

/** Raw bytes, NOT a string — UTF-8 decoding happens at the caller's
 *  streaming decoder so multibyte chars split across PTY chunks reassemble
 *  instead of degrading to U+FFFD. */
export function decodeBase64ToBytes(b64: string): Uint8Array {
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function encodeBytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=+$/, "");
}
