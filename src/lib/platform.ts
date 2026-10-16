/**
 * Which desktop platform the webview is running on.
 *
 * Used for keyboard-shortcut decisions, where the answer genuinely
 * differs: macOS puts the primary accelerator on Cmd (which never
 * collides with a terminal control byte), while Windows and Linux put it
 * on Ctrl (which does — see `TerminalPane`'s Ctrl+Shift+C/V handling).
 *
 * Deliberately a UA-string sniff rather than a Tauri IPC call: the value
 * is needed synchronously inside a key handler registered at mount, and
 * an async round-trip would mean the first keystroke after mount used
 * the wrong branch. `userAgentData.platform` is preferred where the
 * webview provides it; `navigator.platform` is the fallback that
 * WKWebView and WebKitGTK still populate.
 */
function detectIsMac(): boolean {
  if (typeof navigator === "undefined") return false;
  const withData = navigator as Navigator & {
    userAgentData?: { platform?: string };
  };
  const platform = withData.userAgentData?.platform ?? navigator.platform ?? "";
  return /mac/i.test(platform);
}

/** True on macOS. Evaluated once — the platform cannot change at runtime. */
export const IS_MAC = detectIsMac();
