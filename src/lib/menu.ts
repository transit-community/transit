import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useEffect } from "react";

import { clearScrollback, setMenuChecked } from "@/lib/api";
import { hasPty, resolveActivePaneId, useUiStore } from "@/stores/uiStore";

/** Mirror of `menu::MENU_ID_BUTTON_BAR` (the native View → Button Bar item). */
const MENU_ID_BUTTON_BAR = "view-button-bar";
/** Mirror of `menu::MENU_ID_BROADCAST_BAR` (View → Broadcast Input). */
const MENU_ID_BROADCAST_BAR = "view-broadcast-bar";

/**
 * Wires the v1.4.0 native menu to frontend state. Mount once at App root
 * (alongside `useGlobalHotkeys`).
 *
 *  - Menu → frontend: a `menu:toggle-button-bar` event (the View → Button Bar
 *    click, emitted by the Rust `on_menu_event` handler) flips `showButtonBar`;
 *    a `menu:clear-terminal` event (View → Clear Terminal, CmdOrCtrl+Shift+K)
 *    clears the active session.
 *  - Frontend → menu: whenever `showButtonBar` changes — a menu click, the
 *    bar's own "Hide button bar", or the initial localStorage load — mirror it
 *    back into the checkmark via `set_menu_checked` (best-effort; a no-op if
 *    the menu isn't present, e.g. a future Linux build).
 */
export function useNativeMenu(): void {
  const showButtonBar = useUiStore((s) => s.preferences.showButtonBar);
  const showBroadcastBar = useUiStore((s) => s.preferences.showBroadcastBar);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    void listen("menu:toggle-button-bar", () => {
      const state = useUiStore.getState();
      state.setShowButtonBar(!state.preferences.showButtonBar);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    void listen("menu:toggle-broadcast-bar", () => {
      const state = useUiStore.getState();
      state.setShowBroadcastBar(!state.preferences.showBroadcastBar);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Menu → frontend: View → Clear Terminal (CmdOrCtrl+Shift+K) clears the
  // FOCUSED PANE — the same pair as the right-click tab → Clear
  // (`TerminalArea.requestClear`): wipe the backend ring + emit the
  // per-session `ui:clear-terminal:{id}` the pane listens for to run
  // `term.clear()`. Resolved via `resolveActivePaneId`, NOT `activeTabId`:
  // since v4.4.0 a tab can hold several panes, and the tab id names only the
  // primary. Right-click tab → Clear stays a TAB action (it clears that tab's
  // primary) — the accelerator is the pane-level one.
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    void listen("menu:clear-terminal", () => {
      // v6.4.0 — the FOCUSED PANE, not the tab's primary. TerminalPane claims
      // the Cmd/Ctrl+Shift+K chord itself and emits this same event, so before
      // this fix pressing it in a split's right pane cleared the LEFT one.
      const state = useUiStore.getState();
      const activeId = resolveActivePaneId(state);
      const { sessions } = state;
      if (!activeId) return;
      // Only a PTY tab has a scrollback ring and an xterm to wipe. An API or
      // Files tab has neither, so skip rather than fire a doomed IPC (the
      // `.catch` below would swallow it, but a no-op read like this is
      // cheaper and states the intent).
      const tab = sessions.find((t) => t.sessionId === activeId);
      if (!tab || !hasPty(tab)) return;
      void clearScrollback(activeId).catch(() => {});
      void emit(`ui:clear-terminal:${activeId}`);
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Menu → frontend: Window → Jump to Session… / Sort Tabs Alphabetically
  // (v6.1.0).
  //
  // "Jump to session" is NOT a new UI — the command palette's Sessions
  // group has always listed a Focus entry per open session. What was
  // missing is any way to discover that, which a menu item with the
  // Cmd/Ctrl+K hint fixes for free. The sort is a one-shot reorder; new
  // tabs still append.
  useEffect(() => {
    const unlisteners: UnlistenFn[] = [];
    let cancelled = false;
    const attach = (event: string, run: () => void) => {
      void listen(event, run).then((fn) => {
        if (cancelled) fn();
        else unlisteners.push(fn);
      });
    };
    attach("menu:jump-to-session", () => {
      // Scoped to sessions: the full palette leads with one "Connect to …"
      // per inventory device, so on a real fleet the open-session entries
      // sit far below the fold and the menu item looks broken. Opening
      // (never toggling) also means a second click can't close it.
      useUiStore.getState().openCommandPalette("sessions");
    });
    attach("menu:sort-tabs", () => {
      useUiStore.getState().sortSessionsByLabel();
    });
    return () => {
      cancelled = true;
      unlisteners.forEach((fn) => fn());
    };
  }, []);

  // Menu → frontend: App → About Transit on Windows/Linux (macOS shows
  // the native About panel and never emits this). Opens Settings → About,
  // which already renders the app version, license, and Report-an-issue
  // link — a consistent cross-platform About without a bespoke dialog.
  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    void listen("menu:about", () => {
      useUiStore.getState().openSettingsDialog("about");
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    void setMenuChecked(MENU_ID_BUTTON_BAR, showButtonBar).catch(() => {});
  }, [showButtonBar]);

  useEffect(() => {
    void setMenuChecked(MENU_ID_BROADCAST_BAR, showBroadcastBar).catch(() => {});
  }, [showBroadcastBar]);
}
