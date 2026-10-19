import { emit } from "@tauri-apps/api/event";
import { useEffect } from "react";

import { newChat } from "@/lib/chat";
import { useUiStore } from "@/stores/uiStore";

/**
 * Global app-level keyboard shortcuts.
 *
 * Bindings:
 *   - **Cmd/Ctrl+B** — toggle the device sidebar.
 *   - **Cmd/Ctrl+I** — toggle the session-info panel.
 *   - **Cmd/Ctrl+J** — toggle the chat panel.
 *   - **Cmd/Ctrl+K** — toggle the command palette.
 *   - **Cmd/Ctrl+T** — new AI chat tab.
 *   - **Cmd/Ctrl+Shift+K** — clear the active terminal.
 *
 * The Cmd path (macOS metaKey) is an OS modifier — it's never
 * translated by xterm.js into bytes sent down the PTY. So every
 * `Cmd+letter` UI hotkey fires regardless of which element holds
 * focus, the common editor convention.
 *
 * The Ctrl path is different: `Ctrl+B` is readline backward-char,
 * `Ctrl+I` is Tab, `Ctrl+J` is linefeed. When the terminal owns
 * focus (xterm.js's hidden helper textarea has it) those keys
 * have to reach the PTY, so we defer there. Cmd/Ctrl+K is the
 * exception — palette is primary navigation, always available.
 */

function isTerminalFocused(): boolean {
  const el = document.activeElement;
  if (!el || !(el instanceof Element)) return false;
  // xterm.js focuses a hidden `<textarea class="xterm-helper-textarea">`
  // sitting inside `.xterm-screen`. Either match indicates the
  // terminal is the keystroke owner.
  return el.classList.contains("xterm-helper-textarea") || !!el.closest(".xterm-screen");
}

/** macOS uses Cmd (metaKey), other OSes use Ctrl. */
export function isAccel(e: KeyboardEvent): boolean {
  // Hotkeys must use the platform "accelerator" modifier exclusively —
  // a stray Shift or Alt should not count, otherwise we hijack
  // `Cmd+Shift+B` (which an editor might bind elsewhere) etc.
  if (e.altKey || e.shiftKey) return false;
  // Recognize Cmd on macOS (metaKey) AND Ctrl on the other platforms.
  // We can't reliably detect macOS without UA-sniffing, so accept
  // either modifier as the accelerator and require it to be the only
  // one set. Cmd+Ctrl together is rejected too.
  const meta = e.metaKey;
  const ctrl = e.ctrlKey;
  return meta !== ctrl;
}

/**
 * Cmd/Ctrl+Shift+K — clear the active terminal. Distinct from the bindings
 * `isAccel` covers because it REQUIRES Shift (which `isAccel` rejects, so the
 * Shift doesn't collide with the Cmd/Ctrl+K command palette). Exactly one of
 * Cmd/Ctrl, never Alt.
 */
function isClearTerminalChord(e: KeyboardEvent): boolean {
  if (e.altKey || !e.shiftKey) return false;
  if (e.metaKey === e.ctrlKey) return false;
  return e.key.toLowerCase() === "k";
}

export function useGlobalHotkeys() {
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const toggleChatPanel = useUiStore((s) => s.toggleChatPanel);
  const toggleCommandPalette = useUiStore((s) => s.toggleCommandPalette);
  const toggleSessionInfoPanel = useUiStore((s) => s.toggleSessionInfoPanel);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Cmd/Ctrl+Shift+K — clear the active terminal. macOS fires this from
      // the native menu accelerator (global menu bar); on Windows/Linux the
      // focused WebView2 swallows menu accelerators, so the webview owns it.
      // When the terminal itself is focused, TerminalPane's xterm key handler
      // claims it (it must ALSO stop xterm from sending the chord to the PTY
      // as 0x0B), so defer here — this branch only covers focus landing
      // elsewhere (chat box, sidebar, dialogs), matching the always-global
      // reach of the macOS menu item.
      if (isClearTerminalChord(e)) {
        if (!isTerminalFocused()) {
          e.preventDefault();
          void emit("menu:clear-terminal");
        }
        return;
      }
      if (!isAccel(e)) return;
      const key = e.key.toLowerCase();
      // Defer to the terminal only on the Ctrl path AND only when the
      // terminal owns focus AND the key isn't the always-on palette.
      // The Cmd path doesn't conflict with PTY codes (macOS Cmd never
      // reaches xterm.js as a byte), so Cmd-anything always fires.
      const usesCtrl = e.ctrlKey;
      if (usesCtrl && key !== "k" && isTerminalFocused()) return;
      if (key === "k") {
        e.preventDefault();
        toggleCommandPalette();
      } else if (key === "b") {
        e.preventDefault();
        toggleSidebar();
      } else if (key === "i") {
        e.preventDefault();
        toggleSessionInfoPanel();
      } else if (key === "j") {
        e.preventDefault();
        toggleChatPanel();
      } else if (key === "t") {
        // New AI chat tab. `newChat()` opens the panel if collapsed and
        // creates a chat at the default model. (On the Ctrl path this
        // only reaches here when the terminal ISN'T focused — the guard
        // above defers Ctrl+<non-k> to the PTY when it is, matching j/b/i.)
        e.preventDefault();
        newChat();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [toggleSidebar, toggleChatPanel, toggleCommandPalette, toggleSessionInfoPanel]);
}
