import { Toaster } from "sonner";

import { ChatNotificationCenter } from "@/components/ChatNotificationCenter";
import { ChatPanel } from "@/components/ChatPanel";
import { CommandPalette } from "@/components/CommandPalette";
import { CapturesDialog } from "@/components/dialogs/CapturesDialog";
import { HostKeyConfirmDialog } from "@/components/dialogs/HostKeyConfirmDialog";
import { ProposeApiCallDialog } from "@/components/dialogs/ProposeApiCallDialog";
import { ProposeCommandDialog } from "@/components/dialogs/ProposeCommandDialog";
import { QuitConfirmDialog } from "@/components/dialogs/QuitConfirmDialog";
import { SettingsDialog } from "@/components/dialogs/SettingsDialog";
import { KeyboardInteractiveDialog } from "@/components/dialogs/KeyboardInteractiveDialog";
import { WeakCryptoConfirmDialog } from "@/components/dialogs/WeakCryptoConfirmDialog";
import { useApplyTheme } from "@/lib/themes";
import { MainArea } from "@/components/MainArea";
import { ApiSidebar } from "@/components/ApiSidebar";
import { FilesSidebar } from "@/components/FilesSidebar";
import { PcapSidebar } from "@/components/PcapSidebar";
import { TerminalSidebar } from "@/components/TerminalSidebar";
import { PanelSwitcher } from "@/components/PanelSwitcher";
import { SessionInfoPanel } from "@/components/SessionInfoPanel";
import { Sidebar } from "@/components/Sidebar";
import { useFilesTransferListener } from "@/lib/filesTransfers";
import { useGlobalHotkeys } from "@/lib/hotkeys";
import { useNativeMenu } from "@/lib/menu";
import { useUiStore } from "@/stores/uiStore";

function App() {
  // ⌘/Ctrl+B → toggle sidebar; ⌘/Ctrl+J → toggle chat panel.
  // Hotkeys are no-ops when the terminal has focus so PTY input
  // (e.g. Ctrl+J = linefeed on a real shell) still works.
  useGlobalHotkeys();

  // v1.4.0 — wire the native menu (View → Button Bar) to frontend state.
  useNativeMenu();

  // v5.0.0 — subscribe once to `files:transfer:update`. App-level because
  // one topic carries every Files session's transfers, they keep running
  // while their tab is backgrounded, and the close/quit guards must see
  // them even with no Files tab mounted (see lib/filesTransfers.ts).
  useFilesTransferListener();

  // Phase 7a C5 — re-apply the user's theme on every change to
  // uiStore.preferences.themeId. Mount-once; the hook subscribes
  // internally.
  useApplyTheme();

  const sidebarView = useUiStore((s) => s.sidebarView);

  return (
    <main className="flex h-screen w-screen flex-col overflow-hidden bg-background text-foreground">
      <div className="flex flex-1 overflow-hidden">
        <>
          <PanelSwitcher />
          {sidebarView === "apis" ? (
            <ApiSidebar />
          ) : sidebarView === "terminal" ? (
            <TerminalSidebar />
          ) : sidebarView === "files" ? (
            <FilesSidebar />
          ) : sidebarView === "pcaps" ? (
            <PcapSidebar />
          ) : (
            <Sidebar />
          )}
          {/* `min-w-0` is load-bearing: without it this flex child's
                default `min-width:auto` refuses to shrink below its
                content's min-content width, so an overflowing tab strip
                inside MainArea blows the column past the viewport and
                creates horizontal overflow on the shell — which the tab
                strip's `scrollIntoView` (now strip-scoped) used to scroll,
                shifting the whole app left. Keeps the tab strip's own
                `overflow-x-auto` the only horizontal scroller. */}
          <div className="min-w-0 flex-1 overflow-hidden">
            <MainArea />
          </div>
          {/* Phase 7a C7 — session-info panel. Sits between MainArea and
                ChatPanel so both right-hand panels can be open at once
                without overlapping. Cmd/Ctrl+I toggles. */}
          <SessionInfoPanel />
          <ChatPanel />
        </>
      </div>
      {/* Self-managing TOFU prompt — listens to host-key:confirm
          events and renders a modal mid-flight during connect. */}
      <HostKeyConfirmDialog />
      {/* Settings dialog — opened from the sidebar footer's gear.
          Hosts the API-keys tab + general preferences. */}
      <SettingsDialog />
      {/* Phase 3 captures & diff dialog, opened from the command palette. */}
      <CapturesDialog />
      {/* Phase 6 propose-command modal — listens for
          `propose-command:request` events from the agent loop's
          ApprovalDispatcher and renders the per-step approval gate
          (Inviolable Rule 3). Cannot be dismissed without explicit
          Approve / Deny / Approve-and-remember click. */}
      <ProposeCommandDialog />
      {/* v4.0.0 — the GET-only propose_api_call approval modal, sibling of
          the command dialog. Same undismissable Rule-3 gate, for the
          agent's read-only controller requests (host-pinned GET). */}
      <ProposeApiCallDialog />
      {/* v2.5.0 multi-chat — always-on notification center. Routes
          app-global propose-command / completion events per chat: the
          ACTIVE chat's approval surfaces as the modal above, every other
          chat's shows as a stacking, clickable card (+ a tab dot). Lives
          outside the chat panel so it observes background loops even
          while the panel is collapsed. */}
      <ChatNotificationCenter />
      {/* Weak-crypto opt-in modal — listens for
          `weak-crypto:confirm` events when the server's strict-
          allowlist negotiation fails (Cisco IOS-XE / older Junos
          ship SHA1-only KEX). T_WEAK_CRYPTO_OPTIN. Cannot be
          dismissed without explicit Cancel / Connect Anyway click;
          remember-checkbox is a separate decision. */}
      <WeakCryptoConfirmDialog />
      <KeyboardInteractiveDialog />
      {/* v1.4.0 — warn before quitting with live sessions. Listens for
          `app:confirm-quit` (emitted by the Rust run-event handler when
          Cmd+Q / window-close is vetoed while sessions are open) and
          confirms before the backend exits. */}
      <QuitConfirmDialog />
      {/* Phase 7a C2 — global command palette. Cmd-K / Ctrl-K
          toggles. Devices + sessions + navigation actions surfaced
          through the centralized registry in src/lib/commands.ts. */}
      <CommandPalette />
      {/* Phase 7a C3 — toast surface (Sonner). Use the typed
          helpers in src/lib/toast.ts (toastSuccess / toastError /
          toastInfo / toastPromise) at every async success/error
          site rather than importing `sonner` directly. */}
      <Toaster
        position="bottom-right"
        richColors
        closeButton
        visibleToasts={3}
        toastOptions={{
          // Hover pauses dismissal by default in Sonner; explicit
          // here so future readers don't have to read upstream docs
          // to understand the behavior.
          classNames: {
            toast: "group",
          },
        }}
      />
    </main>
  );
}

export default App;
