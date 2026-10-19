import { useQuery } from "@tanstack/react-query";
import { openUrl } from "@tauri-apps/plugin-opener";
import { AlertTriangle, BookOpen, Copy, Download, Plus, Terminal } from "lucide-react";
import type { ReactNode } from "react";

import { BroadcastBar } from "@/components/BroadcastBar";
import { ButtonBar } from "@/components/ButtonBar";
import { ImportConnectionsView } from "@/components/import/ImportConnectionsView";
import { TerminalArea } from "@/components/TerminalArea";
import { Button } from "@/components/ui/button";
import { listDevices } from "@/lib/api";
import { toastSuccess } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

const QUICK_START_URL = "https://github.com/transit-community/transit#quick-start";

/**
 * Main work area. Branches:
 *   - At least one session open → `TerminalArea`.
 *   - Inventory query errored → broken-inventory recovery panel.
 *   - Inventory empty + no active device → welcome / onboarding panel.
 *   - Active device but no session → "right-click → Connect" hint.
 *   - Otherwise → "select a device" hint.
 *
 * Phase 7a C10 adds the welcome + broken-inventory full-pane states.
 */
export function MainArea() {
  const activeDeviceId = useUiStore((s) => s.activeDeviceId);
  const importOpen = useUiStore((s) => s.importOpen);
  const hasSessions = useUiStore((s) => s.sessions.length > 0);
  const sidebarView = useUiStore((s) => s.sidebarView);
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });

  // The bulk-import wizard is a focused full-pane takeover — no button bar.
  if (importOpen) {
    return <ImportConnectionsView />;
  }

  // Pick the work-area content. Everything below renders inside a column
  // whose bottom row is the button bar — shown whenever enabled
  // (a persistent toolbar, NOT session-scoped, so it's
  // visible the moment you toggle View → Button Bar, connected or not).
  let content: ReactNode;
  if (hasSessions) {
    content = <TerminalArea />;
  } else if (sidebarView === "terminal") {
    // The local-terminal surface is independent of the SSH inventory, so its
    // empty-state wins over the broken/empty-inventory panels — a new user
    // (empty inventory) who switches to Terminal should see the shell hint,
    // not the SSH "add your first device" onboarding.
    content = (
      <div className="flex h-full w-full items-center justify-center">
        <p className="text-sm text-muted-foreground">
          Launch a shell from the sidebar to open a local terminal.
        </p>
      </div>
    );
  } else if (devicesQuery.error) {
    content = <BrokenInventoryPanel error={devicesQuery.error} />;
  } else if (devicesQuery.data && devicesQuery.data.length === 0) {
    content = <WelcomePanel />;
  } else if (sidebarView === "files") {
    // The Files surface rides the SAME inventory as SSH — so unlike the
    // Terminal branch above, this sits BELOW the broken/empty-inventory
    // panels (a Files user with no devices needs the onboarding too). It
    // only replaces the "right-click → Connect" hint, whose copy would
    // otherwise send a file-transfer user to open an SSH session.
    content = (
      <div className="flex h-full w-full items-center justify-center">
        <p className="text-sm text-muted-foreground" data-testid="files-empty-state">
          Open a file transfer session from the sidebar to browse a device.
        </p>
      </div>
    );
  } else {
    content = (
      <div className="flex h-full w-full items-center justify-center">
        {activeDeviceId ? (
          <div className="text-center">
            <h2 className="font-mono text-xl">{activeDeviceId}</h2>
            <p className="mt-2 text-sm text-muted-foreground">
              Right-click and choose <span className="font-medium">Connect</span> to open an SSH
              session.
            </p>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            Select a device from the sidebar to begin.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col">
      {/* `min-h-0 flex-1 overflow-hidden` lets a fitted xterm shrink so the
          button-bar row below is never pushed off-screen (verified RC2). */}
      <div className="min-h-0 flex-1 overflow-hidden">{content}</div>
      {/* v1.4.0 button bar — persistent across every view
          when enabled. Renders null when off; clicks no-op without an
          active session. */}
      <ButtonBar />
      {/* v2.4.0 broadcast input bar — below the button bar
          when both are on. Renders null when off. Human input (not
          policy-gated); loud red strip + live device count is the safety. */}
      <BroadcastBar />
    </div>
  );
}

function WelcomePanel() {
  const openImport = useUiStore((s) => s.openImport);
  return (
    <div
      data-testid="welcome-panel"
      className="flex h-full w-full items-center justify-center px-6"
    >
      <div className="max-w-md text-center">
        <div className="mb-6 inline-flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10">
          <Terminal className="h-7 w-7 text-primary" />
        </div>
        <h1 className="text-2xl font-semibold tracking-tight">Welcome to Transit</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          An SSH client with an embedded read-only AI for network investigation. Add your first
          device to begin.
        </p>
        <div className="mt-8 flex flex-col items-center gap-3">
          <Button
            type="button"
            size="lg"
            className="gap-2"
            data-testid="welcome-add-device"
            onClick={() => {
              // Sidebar owns the AddDeviceDialog. Synthetic-click the
              // sidebar's existing header button — same pattern the
              // command palette uses (lib/commands.ts).
              const btn = document.querySelector<HTMLButtonElement>('[aria-label="Add device"]');
              btn?.click();
            }}
          >
            <Plus className="h-4 w-4" />
            Add your first device
          </Button>
          <button
            type="button"
            onClick={openImport}
            data-testid="welcome-import"
            className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <Download className="h-3.5 w-3.5" />
            Import from SecureCRT, ssh_config, or CSV
          </button>
          <button
            type="button"
            onClick={() => void openUrl(QUICK_START_URL).catch(() => {})}
            className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            data-testid="welcome-quickstart-link"
          >
            <BookOpen className="h-3.5 w-3.5" />
            View the quick-start guide
          </button>
        </div>
      </div>
    </div>
  );
}

function BrokenInventoryPanel({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);

  const copyError = () => {
    void navigator.clipboard
      .writeText(message)
      .then(() => toastSuccess("Error message copied"))
      .catch(() => {});
  };

  return (
    <div
      data-testid="broken-inventory-panel"
      className="flex h-full w-full items-center justify-center px-6"
    >
      <div className="max-w-xl">
        <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <h1 className="text-xl font-semibold tracking-tight">Inventory file failed to load</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Transit refuses to overwrite an invalid <span className="font-mono">transit.toml</span> —
          fix the file on disk, then refresh from the sidebar header. The full error from the
          loader:
        </p>
        <pre className="mt-4 max-h-64 overflow-auto rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
          {message}
        </pre>
        <div className="mt-4 flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-2"
            onClick={copyError}
            data-testid="broken-inventory-copy"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy error
          </Button>
          <button
            type="button"
            onClick={() =>
              void openUrl("https://github.com/transit-community/transit#inventory-format").catch(
                () => {},
              )
            }
            className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <BookOpen className="h-3.5 w-3.5" />
            Inventory format reference
          </button>
        </div>
      </div>
    </div>
  );
}
