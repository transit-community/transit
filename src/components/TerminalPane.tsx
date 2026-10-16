import { useQuery } from "@tanstack/react-query";
import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { WebglAddon } from "@xterm/addon-webgl";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { Terminal } from "@xterm/xterm";
import { ChevronDown, ChevronUp, ExternalLink, Power, X } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { PasteConfirmDialog } from "@/components/dialogs/PasteConfirmDialog";
import {
  consoleSendBreak,
  disconnectSession,
  listDevices,
  resizePty,
  sendInput,
  type DeviceMeta,
  type PtyClosedPayload,
  type PtyOutputPayload,
} from "@/lib/api";
import { deviceColorVar } from "@/lib/deviceColors";
import { useRestartLocalShell } from "@/lib/localShell";
import { useReconnectSession } from "@/lib/mutations";
import { IS_MAC } from "@/lib/platform";
import { toastError, toastInfo } from "@/lib/toast";
import { decodeBase64ToBytes, encodeBytesToBase64 } from "@/lib/terminal/bytes";
import { LineHighlighter } from "@/lib/terminal/highlighter";
import { patternsForVendor } from "@/lib/terminal/patterns";
import { DEFAULT_THEME_ID, getTheme } from "@/lib/themes";
import {
  TERMINAL_FONT_FAMILY_DEFAULT,
  TERMINAL_FONT_SIZE_DEFAULT,
  useUiStore,
} from "@/stores/uiStore";

/**
 * Phase 2c/3 terminal pane built on xterm.js.
 *
 * Responsibilities:
 *  - Mount a `Terminal` with the WebGL renderer and the fit addon.
 *  - Stream `pty:{id}:output` event bytes (after optional keyword
 *    highlighting) into `term.write()`.
 *  - Forward every keystroke via `term.onData` → `sendInput` IPC.
 *  - Negotiate cols/rows on container resize via `term.onResize` →
 *    `resizePty` IPC (debounced).
 *  - Block device-initiated clipboard writes by returning `true` from
 *    the OSC 52 handler.
 *  - Confirm multi-line pastes before forwarding (single-line goes
 *    straight through `term.paste`).
 *
 * Per-device preference: if `device.syntax_highlighting === true`,
 * each completed line passes through the `LineHighlighter` before
 * `term.write`. The default is OFF (matches the user's preference for
 * the unmodified black/white terminal as the baseline).
 *
 * Phase 3: this component is prop-driven (one instance per open tab,
 * managed by `TerminalArea`). Each pane has its own xterm.js, its
 * own scrollback, its own listeners on `pty:{sessionId}:output` and
 * `:closed`. Tabs hidden by Radix `[data-state="inactive"]` keep
 * their pane mounted (forceMount) so scrollback survives switches.
 * The `active` prop flips true when this pane's tab becomes the
 * visible one — we re-fit on that transition because xterm.js's
 * dimensions are stale while the pane was display:none'd.
 */
export interface TerminalPaneProps {
  /** Backend session UUID. Drives the event topic and every command. */
  sessionId: string;
  /** Inventory device id (for the header label + per-device prefs lookup). */
  deviceId: string;
  /** True when the remote closed the channel. Disables stdin + flips
   *  the disconnect button to "Close". */
  ended: boolean;
  /** True when this pane's tab is the visible one. Used to re-fit
   *  on tab activation (display:none → display:block transitions
   *  may not always trigger ResizeObserver in WKWebView). */
  active: boolean;
  /** v6.4.0 — true when this pane's tab holds more than one pane, i.e. the
   *  focus ring and "Move to own tab" are meaningful. An un-split tab shows
   *  neither: there is nothing to disambiguate and nowhere to move to.
   *
   *  Note the focus RING is drawn by `PaneTree` on the pane wrapper, not here:
   *  this component's own root already carries the per-device accent border
   *  (v3.2.0), and a ring on the wrapper composes with it instead of fighting
   *  it. Which is also why there is no `focused` prop — the pane doesn't need
   *  to know, only to REPORT focus (see the container's `onFocus`). */
  inSplit?: boolean;
  /** v6.4.0 — lift this pane out into its own top-level tab. Only rendered
   *  when `inSplit`. */
  onMoveOut?: () => void;
  /** v4.4.0 — this is a local-shell tab (`kind: "local"`). Switches the
   *  dead-pane Enter gesture from device-reconnect to restart-in-place
   *  (`restart_local_shell`), since a local shell has no inventory device. */
  isLocal?: boolean;
}

/**
 * Search-addon options: highlight ALL matches (not just the active one)
 * with a yellow overlay + overview-ruler ticks. Requires the Terminal's
 * `allowProposedApi: true`; colors are tuned for the black terminal bg.
 */
const SEARCH_OPTIONS = {
  decorations: {
    matchBackground: "#8a6d00",
    matchOverviewRuler: "#d7a300",
    activeMatchBackground: "#f5c518",
    activeMatchColorOverviewRuler: "#ffdd55",
  },
} as const;

export function TerminalPane({
  sessionId,
  deviceId,
  ended,
  active,
  inSplit = false,
  onMoveOut,
  isLocal,
}: TerminalPaneProps) {
  const markSessionEnded = useUiStore((s) => s.markSessionEnded);
  const removeSession = useUiStore((s) => s.removeSession);
  const setActivePane = useUiStore((s) => s.setActivePane);

  // Look up the device record so we can read its per-device prefs.
  // Cached by Sidebar's listDevices query — a fresh fetch is not needed.
  const { data: devices } = useQuery({
    queryKey: ["devices"],
    queryFn: listDevices,
  });
  const device: DeviceMeta | undefined = devices?.find((d) => d.id === deviceId);
  const highlightingEnabled = device?.syntax_highlighting === true;
  const quickCopyPasteEnabled = device?.quick_copy_paste === true;
  // Per-device accent (Phase 1): a left-edge stripe down the whole pane,
  // matching the device's sidebar row + tab.
  const paneAccent = deviceColorVar(device?.color);
  // Console sessions carry a synthetic "console-*" deviceId (see
  // useConnectConsoleCable); only they support a serial BREAK.
  const isConsole = deviceId.startsWith("console-");
  const sendBreak = () => {
    void consoleSendBreak(sessionId)
      .then(() => toastInfo("Break sent"))
      .catch((e) => toastError(`Break failed: ${e instanceof Error ? e.message : String(e)}`));
  };

  // ---------------------------------------------------------------------
  // Refs that survive re-renders (xterm.js + addons + highlighter).
  // ---------------------------------------------------------------------
  const containerRef = useRef<HTMLDivElement | null>(null);
  // v6.4.0 — the pane's outermost element, used only to OBSERVE focus (see the
  // focus-reporting effect). Listeners are attached imperatively rather than as
  // JSX handlers: this div is a layout container, not an interactive control,
  // and `onFocus`/`onMouseDown` props on a plain div read as (and lint as) an
  // interaction affordance that would then owe a role + keyboard handler.
  const paneRootRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const searchRef = useRef<SearchAddon | null>(null);
  const highlighterRef = useRef<LineHighlighter | null>(null);
  const flushTimerRef = useRef<number | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  // One streaming TextDecoder per session. PTY chunking is byte-
  // oriented, so a multibyte UTF-8 char can split across two
  // `pty:{id}:output` events; a fresh decoder per event would emit
  // U+FFFD for each half. `{ stream: true }` carries the partial
  // sequence across chunks; the closed handler flushes the remainder
  // and the subscribe effect resets the decoder on sessionId change.
  const decoderRef = useRef<TextDecoder | null>(null);

  // Stable refs to the latest toggle states. Event handlers (mount-once
  // effects) read `*Ref.current` so we don't re-subscribe to PTY
  // events / re-attach DOM listeners when a toggle flips.
  const enabledRef = useRef(highlightingEnabled);
  useEffect(() => {
    enabledRef.current = highlightingEnabled;
  }, [highlightingEnabled]);

  const quickCopyPasteRef = useRef(quickCopyPasteEnabled);
  useEffect(() => {
    quickCopyPasteRef.current = quickCopyPasteEnabled;
  }, [quickCopyPasteEnabled]);

  // The mount-once key handler (registered inside the xterm.js bootstrap
  // effect) reads these via refs so it picks up the live values without
  // a re-mount when the session transitions to ended or the device id
  // shifts under a right-pane reconnect.
  const endedRef = useRef(ended);
  useEffect(() => {
    endedRef.current = ended;
  }, [ended]);

  const reconnect = useReconnectSession();
  const restartLocal = useRestartLocalShell();
  const reconnectInFlightRef = useRef(false);
  const triggerReconnectRef = useRef<() => void>(() => {});
  // Set by the paste effect below so the key handler (registered at
  // mount, in a different effect) can route Ctrl+Shift+V through the
  // SAME multi-line confirm gate every other paste trigger uses.
  const dispatchPasteRef = useRef<(text: string) => void>(() => {});
  useEffect(() => {
    triggerReconnectRef.current = () => {
      if (!endedRef.current) return;
      // Guard against Enter-key bounce: the mutation hasn't yet flipped
      // isPending on the second press, so an in-flight ref is the only
      // race-free check.
      if (reconnectInFlightRef.current) return;
      reconnectInFlightRef.current = true;
      const onSettled = () => {
        reconnectInFlightRef.current = false;
      };
      if (isLocal) {
        // A local shell has no inventory device — restart it in place under
        // the same session id rather than a device-reconnect.
        restartLocal.mutate(sessionId, { onSettled });
      } else {
        reconnect.mutate({ oldSessionId: sessionId, deviceId }, { onSettled });
      }
    };
  }, [reconnect, restartLocal, sessionId, deviceId, isLocal]);

  // ---------------------------------------------------------------------
  // Multi-line paste confirmation.
  // ---------------------------------------------------------------------
  const [pendingPaste, setPendingPaste] = useState<string | null>(null);
  // v1.4.0 — confirm before disconnecting a LIVE session (a misclick
  // shouldn't silently drop the connection). Only the live path is
  // gated; an already-ended tab's "Close" button removes it with no prompt.
  const [pendingDisconnect, setPendingDisconnect] = useState(false);
  // Settings → General. Read live so a mid-session change applies to the
  // next click without a remount.
  const warnOnSessionClose = useUiStore((s) => s.preferences.warnOnSessionClose);

  const [closedReason, setClosedReason] = useState<string | null>(null);

  // Console auto-reconnect resumes a session under the SAME id — no
  // sessionId swap, no remount — so the PTY-subscribe effect below never
  // re-runs to clear the closed side-effects (unlike the right-pane
  // reconnect, which swaps the id). When the tab un-ends, drop the
  // "session ended" banner and re-enable stdin so input flows again. We
  // deliberately do NOT clear the terminal — the point is to resume in
  // place with scrollback intact.
  useEffect(() => {
    if (!ended) {
      setClosedReason(null);
      if (termRef.current) termRef.current.options.disableStdin = false;
    }
  }, [ended]);

  // Phase 7a C8 — in-pane scrollback search overlay. xterm.js's
  // SearchAddon owns the highlight/cycle logic; we render a small
  // input + chevrons + close button at the bottom-right of the pane.
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  // Live match position/count from the search addon's onDidChangeResults.
  // count === -1 means the addon capped counting; 0 = no matches.
  const [searchResults, setSearchResults] = useState<{ index: number; count: number } | null>(null);

  // NOTE (v6.1.0): the React mirror of the highlighter's alt-screen state
  // is gone along with the amber safety banner that was its only consumer
  // — the banner covered for a renderer bug that no longer occurs, and by
  // then it fired on every `nano`.
  //
  // ⚠️ The HIGHLIGHTER's own alt-screen tracking (`LineHighlighter`) stays
  // and must not be removed: highlighting is BYPASSED while the alt screen
  // is up, which is what lets `vi`, `less` and `top` render correctly
  // (§17). That lives in the highlighter, not here.

  // ---------------------------------------------------------------------
  // Mount the terminal once. Tear down on unmount.
  // ---------------------------------------------------------------------
  useEffect(() => {
    if (!containerRef.current) return;

    // Read the active theme + font size synchronously from the
    // zustand store at mount-time so the terminal is born with the
    // right palette and cell size. Separate effects below reapply
    // these on subsequent preference changes without re-mounting
    // xterm.js.
    const prefs = useUiStore.getState().preferences;
    const activeThemeId = prefs.themeId ?? DEFAULT_THEME_ID;
    const initialTheme = getTheme(activeThemeId).xterm;
    const initialFontSize = prefs.terminalFontSize ?? TERMINAL_FONT_SIZE_DEFAULT;

    const term = new Terminal({
      theme: initialTheme,
      fontFamily: effectiveFontFamily(prefs.terminalFontFamily),
      fontSize: initialFontSize,
      cursorBlink: true,
      // Match the backend ScrollbackRing (32K lines) so Cmd/Ctrl+F searches
      // the full captured history, not just a 10K front window.
      scrollback: 32768,
      // Enables the proposed APIs used below: Unicode v11 width tables
      // (term.unicode.activeVersion) and the search addon's all-match
      // decorations (see runFindNext/runFindPrev).
      allowProposedApi: true,
    });
    const fit = new FitAddon();
    const search = new SearchAddon();
    const unicode11 = new Unicode11Addon();
    term.loadAddon(fit);
    term.loadAddon(search);
    term.loadAddon(unicode11);
    // Correct wide-character (CJK, box-drawing, emoji) cell widths so
    // columns don't drift. Width lives in the core buffer, so the WebGL
    // renderer is unaffected.
    term.unicode.activeVersion = "11";
    term.open(containerRef.current);
    // The WebGL renderer must load after open() — it needs the DOM
    // canvas to exist. Dispose on context loss so xterm.js falls back
    // to the DOM renderer instead of rendering a blank pane.
    const webgl = new WebglAddon();
    webgl.onContextLoss(() => webgl.dispose());
    term.loadAddon(webgl);
    fitIfVisible(fit, containerRef.current);
    term.focus();

    // Intercept Cmd/Ctrl+F before xterm.js translates it into PTY
    // input (Ctrl-F is readline forward-char). Returning false from
    // attachCustomKeyEventHandler tells xterm.js "we handled it,
    // don't pass to onData". We only swallow `keydown` so the
    // matching keyup doesn't double-fire the toggle.
    term.attachCustomKeyEventHandler((e) => {
      const isFindAccel = (e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey;
      if (isFindAccel && e.key.toLowerCase() === "f") {
        if (e.type === "keydown") {
          e.preventDefault();
          setSearchOpen((open) => !open);
        }
        return false;
      }
      // Cmd/Ctrl+Shift+K — clear this terminal. We MUST claim it here
      // because xterm.js translates Ctrl+Shift+K into 0x0B and sends it
      // to the PTY: it computes the control byte as `keyCode - 64`
      // regardless of Shift, so Ctrl+Shift+K is the same byte as Ctrl+K
      // (readline kill-line). Returning false stops that send. The
      // matching native menu accelerator (CmdOrCtrl+Shift+K, menu.rs)
      // only fires on macOS — the focused WebView2 swallows menu
      // accelerators on Windows/Linux — so this is the real shortcut path
      // there. We emit the same `menu:clear-terminal` the menu emits;
      // useNativeMenu clears the active session, which is this focused
      // pane (an inactive pane is display:none and can't hold focus).
      // hotkeys.ts handles the chord when focus is OUTSIDE the terminal.
      const isClearAccel = (e.metaKey || e.ctrlKey) && e.shiftKey && !e.altKey;
      if (isClearAccel && e.key.toLowerCase() === "k") {
        if (e.type === "keydown") {
          e.preventDefault();
          void emit("menu:clear-terminal");
        }
        return false;
      }
      // Cmd/Ctrl + (=/+) grows, Cmd/Ctrl + (-/_) shrinks, Cmd/Ctrl + 0
      // resets to the default. Browser convention; both shifted and
      // unshifted variants are accepted so the user doesn't have to
      // think about whether `=` or `+` is the right key. We bypass the
      // store via getState() to avoid resubscribing the handler on
      // every font-size change (the handler is registered once at
      // mount).
      const isZoomAccel = (e.metaKey || e.ctrlKey) && !e.altKey;
      if (isZoomAccel) {
        // shiftKey true on US layouts when the user presses Cmd+Plus
        // (which is really Cmd+Shift+= on the physical layout). We
        // accept both with and without shift for `+/=` and `-/_`.
        const key = e.key;
        const isGrow = key === "+" || key === "=";
        const isShrink = key === "-" || key === "_";
        const isReset = key === "0" && !e.shiftKey;
        if (isGrow || isShrink || isReset) {
          if (e.type === "keydown") {
            e.preventDefault();
            const { preferences, setTerminalFontSize } = useUiStore.getState();
            const current = preferences.terminalFontSize ?? TERMINAL_FONT_SIZE_DEFAULT;
            if (isGrow) setTerminalFontSize(current + 1);
            else if (isShrink) setTerminalFontSize(current - 1);
            else setTerminalFontSize(null);
          }
          return false;
        }
      }
      // Ctrl+Shift+C / Ctrl+Shift+V — copy and paste on Windows and
      // Linux (v6.1.0). macOS is excluded: Cmd+C/V already work there
      // and don't collide with a control byte, so claiming a second
      // chord would only add a way to get it wrong.
      //
      // ⭐ Returning false is LOAD-BEARING, not tidiness. xterm.js
      // computes the control byte as `keyCode - 64` REGARDLESS of
      // Shift, so Ctrl+Shift+C is byte-identical to Ctrl+C (0x03,
      // SIGINT) and Ctrl+Shift+V to Ctrl+V (0x16). Letting either
      // through would interrupt the running command while the user was
      // trying to copy — the exact accident this feature exists to
      // avoid. Same trap as Ctrl+Shift+K (v1.6.5).
      //
      // The chord is claimed even when there is nothing to copy: a
      // no-op is the correct outcome, whereas falling through would
      // send SIGINT.
      if (!IS_MAC && e.ctrlKey && e.shiftKey && !e.metaKey && !e.altKey) {
        const key = e.key.toLowerCase();
        if (key === "c") {
          if (e.type === "keydown") {
            e.preventDefault();
            const selection = termRef.current?.getSelection() ?? "";
            if (selection.length > 0) void writeText(selection).catch(() => {});
          }
          return false;
        }
        if (key === "v") {
          if (e.type === "keydown") {
            e.preventDefault();
            // Tauri's readText goes through the Rust process, so macOS
            // WKWebView's clipboard-read gate doesn't apply — and the
            // multi-line confirm still fronts the PTY.
            readText()
              .then((text) => dispatchPasteRef.current(text ?? ""))
              .catch(() => {});
          }
          return false;
        }
      }
      // Plain Enter on an ended pane reconnects. We only claim the
      // gesture when stdin is already disabled (ended === true), so a
      // live session's Enter still reaches the PTY untouched. Modifier
      // chords fall through — they never reach the PTY either (stdin
      // is off), but we don't want Shift+Enter / Cmd+Enter etc. to
      // count as the reconnect trigger.
      if (
        endedRef.current &&
        e.key === "Enter" &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        !e.shiftKey
      ) {
        if (e.type === "keydown") {
          e.preventDefault();
          triggerReconnectRef.current();
        }
        return false;
      }
      return true;
    });

    // OSC 52 (clipboard set) — refuse. Returning true tells xterm.js
    // "we handled this, don't apply the default behavior" so the
    // device cannot push content into the user's clipboard.
    term.parser.registerOscHandler(52, () => true);

    // Auto-copy on selection — gated by the quick-copy-paste device
    // pref (read via the ref so a mid-session toggle takes effect
    // without re-mounting). xterm.js fires `onSelectionChange` on
    // every drag-update; we sample the current selection and write
    // it via Tauri's clipboard plugin (NOT navigator.clipboard —
    // macOS WKWebView blocks readText, and using a single surface
    // for read + write keeps the success/failure semantics
    // consistent). Empty-selection events (deselects) are ignored.
    // Failures fold silently — the user can still Cmd/Ctrl-C
    // explicitly.
    const selectionDisposable = term.onSelectionChange(() => {
      if (!quickCopyPasteRef.current) return;
      const text = term.getSelection();
      if (text.length === 0) return;
      void writeText(text).catch(() => {});
    });

    termRef.current = term;
    fitRef.current = fit;
    searchRef.current = search;
    highlighterRef.current = new LineHighlighter();

    // Live match counter for the search overlay (resultIndex/resultCount).
    const searchResultsDisposable = search.onDidChangeResults((e) => {
      setSearchResults({ index: e.resultIndex, count: e.resultCount });
    });

    // Fit on container resize. `fitIfVisible` skips the fit while the
    // pane is hidden (inactive tab => display:none => zero client box):
    // a ResizeObserver DOES fire when the container collapses to 0×0 on
    // tab-switch, and fitting then reflows the buffer into a ~9-column
    // grid and corrupts an in-progress input line (see fitIfVisible).
    const ro = new ResizeObserver(() => {
      fitIfVisible(fit, containerRef.current);
    });
    ro.observe(containerRef.current);

    return () => {
      selectionDisposable.dispose();
      searchResultsDisposable.dispose();
      ro.disconnect();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
      searchRef.current = null;
      highlighterRef.current = null;
      if (flushTimerRef.current !== null) {
        window.clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
    };
  }, []);

  // Reapply xterm.js theme when the user picks a new global theme
  // (Phase 7a C5). xterm.js's `term.options.theme = ...` setter
  // accepts an ITheme; no re-mount needed. Subscribed via the
  // `useUiStore` selector so React triggers this effect on theme
  // change.
  const activeThemeId = useUiStore((s) => s.preferences.themeId);
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.options.theme = getTheme(activeThemeId ?? DEFAULT_THEME_ID).xterm;
  }, [activeThemeId]);

  // Live-update xterm.js font metrics when the user changes the global
  // font size (Cmd+/Cmd-/Cmd+0 or Settings → General) or font family
  // (Settings → General). `fit()` reflows cols/rows for the new cell
  // size — the onResize listener already forwards the new dimensions to
  // the PTY, so readline + TUIs see the correct width immediately.
  // Mount-time read happens in the create block above; this effect
  // handles every subsequent change.
  //
  // The refit is scheduled on the next animation frame, NOT run inline:
  // xterm.js re-measures its cell size in response to the options
  // change, and an inline fit() can compute rows from the OLD cell
  // height — the symptom is the prompt line sliding below the
  // container's bottom border after a few zoom presses. One frame later
  // the metrics have settled and fit() lands on the true geometry.
  // Rapid changes (holding Cmd+) cancel the previous frame's fit; only
  // the final geometry matters.
  const terminalFontSize =
    useUiStore((s) => s.preferences.terminalFontSize) ?? TERMINAL_FONT_SIZE_DEFAULT;
  const terminalFontFamily = useUiStore((s) => s.preferences.terminalFontFamily);
  // Per-device font overrides (v4.1.0) win over the global when set. A
  // hand-edited size below 8 or above 32 falls back / clamps to the same
  // range the global control enforces, so the pane can never be unusable.
  const deviceFontFamily = device?.font_family?.trim() ? device.font_family : null;
  const deviceFontSize =
    device?.font_size && device.font_size >= 8 ? Math.min(32, device.font_size) : null;
  const effectiveFontSize = deviceFontSize ?? terminalFontSize;
  const effectiveFamily = deviceFontFamily ?? terminalFontFamily;
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.options.fontSize = effectiveFontSize;
    term.options.fontFamily = effectiveFontFamily(effectiveFamily);
    const frame = requestAnimationFrame(() => {
      fitIfVisible(fitRef.current, containerRef.current);
    });
    return () => cancelAnimationFrame(frame);
  }, [effectiveFontSize, effectiveFamily]);

  // Per-vendor highlighter packs (§17): swap the pattern set in place
  // once the device record resolves (the devices query may land after
  // mount) or when the vendor changes under an edit. setPatterns
  // preserves the pending-line buffer and alt-screen state — only the
  // pattern list is replaced.
  const deviceVendor = device?.vendor ?? null;
  useEffect(() => {
    highlighterRef.current?.setPatterns(patternsForVendor(deviceVendor));
  }, [deviceVendor]);

  // ---------------------------------------------------------------------
  // Wire xterm.js → IPC: keystrokes, resize, paste.
  // ---------------------------------------------------------------------
  useEffect(() => {
    if (!termRef.current || !sessionId) return;
    const term = termRef.current;

    const dataDisposable = term.onData((data) => {
      if (ended) return;
      const bytes = new TextEncoder().encode(data);
      void sendInput(sessionId, encodeBytesToBase64(bytes)).catch((err) => {
        setClosedReason(`send failed: ${err instanceof Error ? err.message : String(err)}`);
      });
    });

    // Debounce resize IPC so a smooth window drag doesn't flood the
    // backend. 100 ms is below human resize-perception so the PTY
    // catches up before the user starts typing.
    let resizeTimer: number | null = null;
    const resizeDisposable = term.onResize(({ cols, rows }) => {
      if (resizeTimer !== null) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        void resizePty(sessionId, cols, rows).catch(() => {
          // Resize failures (e.g. session already closed) are not
          // user-actionable; fold silently.
        });
      }, 100);
    });

    // Prime the backend with the term's current dimensions. The mount
    // effect's fit() already sized the term to the container, but its
    // synchronous `onResize` fired before this listener attached, so
    // that event was lost. Without this explicit sync the PTY stays at
    // the connect-time 80×24 forever — readline mis-wraps long lines
    // (it CRs back over the prompt when its idea of `cols` overflows)
    // and TUIs like nano draw a 24-row UI inside a taller pane.
    // Same code path on macOS / Windows / Linux; FitAddon and
    // ResizeObserver behave identically across WebView2 / WKWebView /
    // WebKitGTK.
    void resizePty(sessionId, term.cols, term.rows).catch(() => {});

    return () => {
      dataDisposable.dispose();
      resizeDisposable.dispose();
      if (resizeTimer !== null) window.clearTimeout(resizeTimer);
    };
  }, [sessionId, ended]);

  // ---------------------------------------------------------------------
  // Subscribe to PTY events for the current session.
  // ---------------------------------------------------------------------
  useEffect(() => {
    if (!sessionId) return;
    setClosedReason(null);
    highlighterRef.current?.reset();
    termRef.current?.clear();
    // Fresh streaming decoder per session — never carry a partial
    // multibyte sequence from one session's bytes into another's.
    decoderRef.current = new TextDecoder("utf-8", { fatal: false });
    // Reverse the closed-event side-effect when a right-pane reconnect
    // swaps sessionId in place. (Primary-pane reconnects re-mount the
    // whole TabsContent, so the fresh xterm.js instance already starts
    // with stdin enabled — this line is what makes the in-place path
    // work too.)
    if (termRef.current) termRef.current.options.disableStdin = false;

    const outputEvent = `pty:${sessionId}:output`;
    const closedEvent = `pty:${sessionId}:closed`;

    let unlistenOutput: UnlistenFn | undefined;
    let unlistenClosed: UnlistenFn | undefined;
    let unlistenClear: UnlistenFn | undefined;
    let unlistenFocus: UnlistenFn | undefined;
    let cancelled = false;

    void listen<PtyOutputPayload>(outputEvent, (e) => {
      const term = termRef.current;
      const hl = highlighterRef.current;
      const decoder = decoderRef.current;
      if (!term || !hl || !decoder) return;

      const decoded = decoder.decode(decodeBase64ToBytes(e.payload.data_b64), { stream: true });
      const piped = hl.feed(decoded, enabledRef.current);
      if (piped.length > 0) term.write(piped);

      // Schedule a partial-line flush so a prompt without a trailing
      // newline still appears promptly. 30 ms is responsive enough
      // that users don't perceive the gap.
      if (flushTimerRef.current !== null) window.clearTimeout(flushTimerRef.current);
      flushTimerRef.current = window.setTimeout(() => {
        const tail = highlighterRef.current?.flush();
        if (tail && tail.length > 0) termRef.current?.write(tail);
        flushTimerRef.current = null;
      }, 30);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenOutput = fn;
    });

    void listen<PtyClosedPayload>(closedEvent, (e) => {
      setClosedReason(e.payload.reason);
      // Flush the streaming decoder first (a dangling partial
      // multibyte sequence surfaces as U+FFFD rather than vanishing),
      // then any buffered partial line so the final prompt isn't lost.
      const decoderTail = decoderRef.current?.decode() ?? "";
      if (decoderTail.length > 0 && highlighterRef.current) {
        const piped = highlighterRef.current.feed(decoderTail, enabledRef.current);
        if (piped.length > 0) termRef.current?.write(piped);
      }
      const tail = highlighterRef.current?.flush();
      if (tail && tail.length > 0) termRef.current?.write(tail);
      // Disable stdin so the user can't type into a dead session.
      if (termRef.current) termRef.current.options.disableStdin = true;
      markSessionEnded(sessionId);
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenClosed = fn;
    });

    // v1.4.0 "Clear terminal" — the tab context menu emits this when the
    // user clears a session. Wipe the visible xterm; the backend
    // ScrollbackRing is cleared separately (clear_scrollback) so the
    // agent's read_scrollback won't resurface cleared output.
    const clearEvent = `ui:clear-terminal:${sessionId}`;
    void listen(clearEvent, () => {
      termRef.current?.clear();
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenClear = fn;
    });

    // v1.4.1 focus request — the button bar emits this after sending a
    // macro so the cursor returns to the active terminal (a button click
    // steals DOM focus). Same per-session event pattern as the clear event.
    const focusEvent = `ui:focus-terminal:${sessionId}`;
    void listen(focusEvent, () => {
      termRef.current?.focus();
    }).then((fn) => {
      if (cancelled) fn();
      else unlistenFocus = fn;
    });

    return () => {
      cancelled = true;
      unlistenOutput?.();
      unlistenClosed?.();
      unlistenClear?.();
      unlistenFocus?.();
      // Drop the session's decoder; the next sessionId (if any)
      // starts from a clean byte boundary.
      decoderRef.current = null;
    };
  }, [sessionId, markSessionEnded]);

  // ---------------------------------------------------------------------
  // v6.4.0 focus reporting — tell the store when this pane takes focus, so
  // app-level actions (button bar, View → Clear Terminal) target the pane the
  // user is actually in rather than the tab's primary.
  //
  // `focusin` (not `focus`) because it BUBBLES: the element that actually gains
  // focus is xterm.js's hidden textarea deep inside, and this way we catch it
  // without depending on an xterm focus API. `mousedown` covers clicking a
  // non-focusable part of the pane (the header) and lands before focus settles.
  // `setActivePane` ignores an id outside the active tab and a no-op re-focus,
  // so firing these often is cheap.
  // ---------------------------------------------------------------------
  useEffect(() => {
    const node = paneRootRef.current;
    if (!node) return;
    const report = () => setActivePane(sessionId);
    node.addEventListener("focusin", report);
    node.addEventListener("mousedown", report);
    return () => {
      node.removeEventListener("focusin", report);
      node.removeEventListener("mousedown", report);
    };
  }, [sessionId, setActivePane]);

  // ---------------------------------------------------------------------
  // Re-fit when this pane becomes active. Tabs hidden via display:none
  // don't lay out, so xterm.js's cached dimensions are stale; toggling
  // back to display:block doesn't always fire ResizeObserver in
  // WKWebView. An explicit fit() on activation makes tab-switch
  // dimensions reliable across renderers.
  // ---------------------------------------------------------------------
  useEffect(() => {
    if (!active) return;
    // Re-fit now that the pane is laid out again. This is also where a
    // window resize that happened WHILE the pane was hidden (and was
    // skipped by `fitIfVisible`) finally lands — the container has its
    // real client box by the time this activation effect runs.
    fitIfVisible(fitRef.current, containerRef.current);
    // Put the cursor in this pane's terminal on tab activation so the
    // user can type immediately after clicking a tab — no extra click
    // into the pane. Deferred to the next frame: on a tab switch this
    // pane is transitioning from display:none to visible AND the click
    // just moved DOM focus to the Radix tab trigger, so a synchronous
    // focus() here either no-ops on the not-yet-laid-out element or is
    // immediately lost back to the trigger. rAF runs it after layout +
    // paint and after the click settles (the same deferral the
    // tab-rename input uses in TerminalArea). The button-bar focus path
    // doesn't need this — its pane is already visible and stable.
    const focusRaf = requestAnimationFrame(() => {
      termRef.current?.focus();
    });
    return () => cancelAnimationFrame(focusRaf);
  }, [active]);

  // ---------------------------------------------------------------------
  // Clipboard interactions:
  //  - Cmd/Ctrl+V: container `paste` listener — multi-line confirms,
  //    single-line falls through to xterm.js's default path.
  //  - Right-click and middle-click: only when `quick_copy_paste` is on.
  //    Both read the clipboard, then route through the same multi-line
  //    confirm gate.
  // Single mount-once effect; toggle state is read from the ref so a
  // user flipping the device setting mid-session takes effect on the
  // next click without re-attaching listeners.
  // ---------------------------------------------------------------------
  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;

    // Shared dispatcher used by every trigger (Cmd-V, middle-click,
    // right-click, drag-and-drop). Multi-line gates on the confirm
    // dialog; single-line pastes through immediately. The gate matches
    // bare `\r` as well as `\n`: clipboard text with CR-only separators
    // is still "press Enter between each line" to the remote shell, so
    // it must confirm like any other multi-line paste.
    const dispatchPaste = (text: string) => {
      if (text.length === 0) return;
      if (/[\r\n]/.test(text)) {
        setPendingPaste(text);
      } else {
        termRef.current?.paste(text);
      }
    };
    dispatchPasteRef.current = dispatchPaste;

    const onPaste = (event: ClipboardEvent) => {
      const text = event.clipboardData?.getData("text") ?? "";
      if (text.length === 0) return;
      // Only interrupt for multi-line (CR or LF — bare `\r` is Enter
      // to the PTY too). Single-line pastes flow through the default
      // xterm.js path (which fires onData → sendInput).
      if (!/[\r\n]/.test(text)) return;
      // This listener is registered in the CAPTURE phase (see below) so
      // it runs BEFORE xterm.js's own paste handler — which lives on the
      // inner textarea/element and calls `stopPropagation()` while
      // synchronously pasting. `stopImmediatePropagation()` here prevents
      // xterm from ever seeing a multi-line paste, so the confirm/edit
      // dialog is the only path to the PTY. (In the bubble phase this
      // handler never fired for keyboard paste: xterm had already sent
      // the bytes and halted propagation.)
      event.preventDefault();
      event.stopImmediatePropagation();
      setPendingPaste(text);
    };

    const onContextMenu = (event: MouseEvent) => {
      if (!quickCopyPasteRef.current) return;
      event.preventDefault();
      // Tauri's `readText` mediates via the Rust process, so the
      // macOS WKWebView clipboard-read permission gate doesn't apply.
      // `null` is returned when the clipboard is empty; coalesce to
      // the empty string and let `dispatchPaste` no-op. Failures
      // fold silently — user just sees no paste rather than a crash.
      readText()
        .then((text) => dispatchPaste(text ?? ""))
        .catch(() => {});
    };

    const onMouseDown = (event: MouseEvent) => {
      if (!quickCopyPasteRef.current) return;
      // button === 1 is the middle button. We only intervene for
      // middle clicks; left/right are handled elsewhere (left = xterm
      // selection, right = onContextMenu above).
      if (event.button !== 1) return;
      event.preventDefault();
      readText()
        .then((text) => dispatchPaste(text ?? ""))
        .catch(() => {});
    };

    // Text drag-and-dropped onto the terminal would otherwise land in
    // xterm.js's hidden textarea and reach the PTY without the
    // multi-line confirm — a drop is just a paste with a different
    // gesture, so route it through the same gate. dragover must
    // preventDefault or the browser never fires `drop`.
    const onDragOver = (event: DragEvent) => {
      event.preventDefault();
    };

    const onDrop = (event: DragEvent) => {
      event.preventDefault();
      const text = event.dataTransfer?.getData("text/plain") ?? "";
      if (text.length === 0) return;
      dispatchPaste(text);
    };

    // `paste` MUST be capture-phase: xterm.js registers its own paste
    // handler on the inner textarea/element and `stopPropagation()`s in
    // the target phase, so a bubble-phase listener on this container
    // never runs for a keyboard paste. Capturing lets us gate multi-line
    // pastes before xterm sends them to the PTY (security review 2026-07
    // finding #4). Verify manually: Cmd/Ctrl+V a 3-line clipboard into a
    // live session and confirm the paste dialog appears.
    node.addEventListener("paste", onPaste, true);
    node.addEventListener("contextmenu", onContextMenu);
    node.addEventListener("mousedown", onMouseDown);
    node.addEventListener("dragover", onDragOver);
    node.addEventListener("drop", onDrop);
    return () => {
      node.removeEventListener("paste", onPaste, true);
      node.removeEventListener("contextmenu", onContextMenu);
      node.removeEventListener("mousedown", onMouseDown);
      node.removeEventListener("dragover", onDragOver);
      node.removeEventListener("drop", onDrop);
    };
  }, []);

  // Pane-header button: "Close" on an ended tab removes it immediately;
  // "Disconnect" on a LIVE session opens a confirm first (v1.4.0 anti-
  // misclick, mirrors TerminalArea's tab-close confirm) — unless the user
  // has turned the confirm off in Settings → General, in which case this
  // button behaves like the tab's X and disconnects on the click.
  function requestDisconnect() {
    if (ended) {
      removeSession(sessionId);
      return;
    }
    if (!warnOnSessionClose) {
      void confirmDisconnect();
      return;
    }
    setPendingDisconnect(true);
  }

  async function confirmDisconnect() {
    setPendingDisconnect(false);
    try {
      await disconnectSession(sessionId);
    } catch (e) {
      setClosedReason(`disconnect failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    // Phase 3: removing the session from the store also closes the
    // tab — TerminalArea unmounts the corresponding TabsContent on
    // the next render, which disposes this xterm instance.
    removeSession(sessionId);
  }

  // Phase 7a C8 — focus the search input when the overlay opens; clear
  // highlights + return focus to the terminal when it closes.
  useEffect(() => {
    if (searchOpen) {
      searchInputRef.current?.focus();
      searchInputRef.current?.select();
    } else {
      searchRef.current?.clearDecorations();
      setSearchResults(null);
      termRef.current?.focus();
    }
  }, [searchOpen]);

  // All-match highlighting via the search addon's decorations. This needs
  // `allowProposedApi: true` (set on the Terminal above) — without it the
  // decoration path silently no-ops, which is why an earlier revision
  // disabled it. `onDidChangeResults` (wired at mount) then reports the
  // active index + total count for the overlay counter.
  const runFindNext = useCallback(
    (term: string) => searchRef.current?.findNext(term, SEARCH_OPTIONS) ?? false,
    [],
  );
  const runFindPrev = useCallback(
    (term: string) => searchRef.current?.findPrevious(term, SEARCH_OPTIONS) ?? false,
    [],
  );

  function onSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Escape") {
      e.preventDefault();
      setSearchOpen(false);
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      if (searchTerm.length === 0) return;
      if (e.shiftKey) runFindPrev(searchTerm);
      else runFindNext(searchTerm);
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      runFindNext(searchTerm);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      runFindPrev(searchTerm);
    }
  }

  return (
    <div
      ref={paneRootRef}
      className="flex h-full w-full flex-col"
      style={paneAccent ? { borderLeft: `4px solid ${paneAccent}` } : undefined}
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-2">
        <div className="flex items-center gap-3 font-mono text-sm">
          <span className="text-muted-foreground">{ended ? "ended:" : "connected:"}</span>
          <span className="font-medium">{deviceId}</span>
          {highlightingEnabled && (
            <span
              className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[10px] text-emerald-700 dark:text-emerald-400"
              title="Edit the device to disable"
            >
              syntax highlighting
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {isConsole && !ended && (
            <Button
              size="sm"
              variant="outline"
              onClick={sendBreak}
              title="Send a serial BREAK (interrupt boot / reach ROMMON)"
            >
              Break
            </Button>
          )}
          {inSplit && onMoveOut && (
            // v6.4.0 — the exit from a split. Lives in the HEADER rather than a
            // right-click menu because the terminal body already consumes
            // `contextmenu` for quick-copy-paste, so a context menu there would
            // either not open or would break paste.
            <Button
              size="sm"
              variant="outline"
              onClick={onMoveOut}
              title="Move this pane out into its own tab"
            >
              <ExternalLink className="mr-1 h-3.5 w-3.5" />
              Own tab
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={requestDisconnect}>
            <Power className="mr-1 h-3.5 w-3.5" />
            {ended ? "Close" : "Disconnect"}
          </Button>
        </div>
      </header>

      <div className="relative flex-1 overflow-hidden bg-black">
        <div ref={containerRef} className="h-full w-full" data-testid="xterm-host" />

        {/* Phase 7a C8 — scrollback search overlay. Cmd/Ctrl+F
            opens; Enter / Shift+Enter cycles; Esc closes. The
            search runs against xterm.js's rendered buffer
            (10K-line scrollback), separate from the agent's
            ScrollbackRing. */}
        {searchOpen && (
          <div
            data-testid="search-overlay"
            className="absolute bottom-2 right-2 z-10 flex items-center gap-1 rounded-md border border-border bg-background/95 px-2 py-1 shadow-md backdrop-blur"
          >
            <input
              ref={searchInputRef}
              type="text"
              value={searchTerm}
              onChange={(e) => {
                const v = e.target.value;
                setSearchTerm(v);
                if (v.length > 0) runFindNext(v);
                else {
                  searchRef.current?.clearDecorations();
                  setSearchResults(null);
                }
              }}
              onKeyDown={onSearchKeyDown}
              placeholder="Search scrollback…"
              className="w-48 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
              data-testid="search-input"
              aria-label="Search scrollback"
            />
            <span
              className="min-w-[3.5rem] shrink-0 text-center text-[10px] tabular-nums text-muted-foreground"
              data-testid="search-count"
            >
              {searchTerm.length === 0 || searchResults === null
                ? ""
                : searchResults.count === 0
                  ? "0/0"
                  : searchResults.count < 0
                    ? `${searchResults.index + 1}/…`
                    : `${searchResults.index + 1}/${searchResults.count}`}
            </span>
            <button
              type="button"
              onClick={() => runFindPrev(searchTerm)}
              disabled={searchTerm.length === 0}
              className="rounded p-0.5 text-muted-foreground hover:bg-accent disabled:opacity-30"
              aria-label="Find previous"
              title="Find previous (⇧↵ / ↑)"
              data-testid="search-prev"
            >
              <ChevronUp className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => runFindNext(searchTerm)}
              disabled={searchTerm.length === 0}
              className="rounded p-0.5 text-muted-foreground hover:bg-accent disabled:opacity-30"
              aria-label="Find next"
              title="Find next (↵ / ↓)"
              data-testid="search-next"
            >
              <ChevronDown className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              onClick={() => setSearchOpen(false)}
              className="rounded p-0.5 text-muted-foreground hover:bg-accent"
              aria-label="Close search"
              title="Close (Esc)"
              data-testid="search-close"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>

      {closedReason && (
        <div
          className="border-t border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-400"
          role="status"
        >
          {isLocal ? (
            // A local shell has no remote/channel — the SSH bridge's stock
            // "remote closed the channel" reason is nonsensical here, and the
            // in-flight state is the RESTART mutation, not the SSH reconnect.
            <>
              the shell exited —{" "}
              {restartLocal.isPending ? (
                <span className="font-medium">starting a new shell…</span>
              ) : (
                <span className="font-medium">press Enter for a new shell</span>
              )}
            </>
          ) : (
            <>
              session ended: {closedReason} —{" "}
              {reconnect.isPending ? (
                <span className="font-medium">reconnecting…</span>
              ) : (
                <span className="font-medium">press Enter to reconnect</span>
              )}
            </>
          )}
        </div>
      )}

      {/* Multi-line paste confirm + staging editor (extracted v2.6.3 when
          Find & Replace outgrew inline size). `pendingPaste` stays the open
          trigger + initial text; the dialog owns the edited draft and hands
          it back on confirm — what you paste is exactly what's sent. */}
      <PasteConfirmDialog
        open={pendingPaste !== null}
        text={pendingPaste ?? ""}
        onOpenChange={(o) => {
          if (!o) setPendingPaste(null);
        }}
        onConfirm={(draft) => {
          termRef.current?.paste(draft);
          setPendingPaste(null);
        }}
        // Return focus to the terminal when this dialog closes. Radix
        // restores focus to the dialog's TRIGGER on close, but this dialog
        // has no trigger — it's opened from a paste/keypress via the `open`
        // prop — so Radix's restore is a no-op and focus falls to <body>.
        // The xterm cursor then goes hollow and the user has to click back
        // into the pane to type or press Enter (the reported bug). Focus the
        // terminal ourselves; preventDefault stops Radix's no-op trigger
        // refocus. Covers every close path: Paste, Cancel, Esc, click-out.
        // (Same lesson the search overlay learned — see the searchOpen effect.)
        onCloseAutoFocus={(e) => {
          e.preventDefault();
          termRef.current?.focus();
        }}
      />

      <AlertDialog open={pendingDisconnect} onOpenChange={(o) => !o && setPendingDisconnect(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Disconnect session?</AlertDialogTitle>
            <AlertDialogDescription>
              The connection to <span className="font-mono">{deviceId}</span> is still open.
              Disconnecting ends the SSH session.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep open</AlertDialogCancel>
            <AlertDialogAction onClick={confirmDisconnect}>Disconnect</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/** User-chosen family first, stock stack appended — an uninstalled
 *  (but CSS-valid) family falls through to the default look instead of
 *  the renderer's serif fallback. A CSS-invalid value makes the whole
 *  declaration a no-op in the webview, which keeps the previous family
 *  — also safe. */
function effectiveFontFamily(userFamily: string | null): string {
  if (!userFamily) return TERMINAL_FONT_FAMILY_DEFAULT;
  return `${userFamily}, ${TERMINAL_FONT_FAMILY_DEFAULT}`;
}

/**
 * Fit the terminal to its container — but ONLY when the container is
 * actually laid out.
 *
 * An inactive tab is `display:none` (Radix `data-[state=inactive]:hidden`
 * in `ui/tabs.tsx`), which gives its whole subtree a zero client box.
 * FitAddon's `proposeDimensions()` reads
 * `getComputedStyle(parent).width/height`; for an element inside a
 * `display:none` subtree WebKit returns the *computed* value (`"100%"`),
 * so `parseInt("100%")` is `100` — FitAddon proposes ~9 cols × 5 rows
 * (NOT a no-op) and `term.resize()` reflows the buffer into that tiny
 * grid. An in-progress, not-yet-Entered input line is mangled by the
 * reflow, and switching back to the tab can't reconstruct it — the
 * reported bug: typing `R1#This is a line`, switching tabs, and
 * returning shows `R1#This i` with a stray cursor.
 *
 * `clientWidth/clientHeight` are `0` for any element in a `display:none`
 * subtree, so they're a reliable "is this pane visible?" probe. Skipping
 * the fit while hidden leaves cols/rows untouched; the `active`-prop
 * effect re-fits when the pane is shown again, which also absorbs any
 * window resize that happened while it was hidden.
 */
function fitIfVisible(fit: FitAddon | null, container: HTMLElement | null): void {
  if (!fit || !container || container.clientWidth === 0 || container.clientHeight === 0) return;
  try {
    fit.fit();
  } catch {
    // fit() can throw before the container has stable dimensions —
    // benign; a later resize / activation retries.
  }
}
