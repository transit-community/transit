import { useMemo, useRef, useState } from "react";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, KeyRound, PanelLeft, PanelLeftClose, Plus, RefreshCw } from "lucide-react";

import { EditionChip, SettingsButton } from "@/components/SettingsButton";
import { ConsoleCablesSection } from "@/components/ConsoleCablesSection";
import { DeviceTree } from "@/components/DeviceTree";
import { EmptyState, InventoryDialogs, useInventoryDialogs } from "@/components/InventoryDialogs";
import { ConsoleConnectDialog } from "@/components/dialogs/ConsoleConnectDialog";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SidebarResizeHandle, useSidebarWidth } from "@/components/SidebarResizeHandle";
import {
  listAuthProfiles,
  listDevices,
  listGroups,
  type DeviceMeta,
  type SerialPortInfo,
} from "@/lib/api";
import { useExportSessions } from "@/lib/exportSessions";
import { interactiveSkipMessage, partitionInteractiveAuth } from "@/lib/interactiveAuth";
import { useConnectDevice, useConnectManyDevices } from "@/lib/mutations";
import { toastInfo } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

export function Sidebar() {
  const [search, setSearch] = useState("");
  const dialogs = useInventoryDialogs();
  const [consoleConnect, setConsoleConnect] = useState<SerialPortInfo | null>(null);
  const openAuthManager = useUiStore((s) => s.openAuthProfileManager);
  const openImport = useUiStore((s) => s.openImport);

  const activeDeviceId = useUiStore((s) => s.activeDeviceId);
  const setActiveDeviceId = useUiStore((s) => s.setActiveDeviceId);
  const sessions = useUiStore((s) => s.sessions);
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const queryClient = useQueryClient();

  // Map device id -> count of open (non-ended) SSH sessions. Recomputed
  // on every sessions change; cheap (O(N) over the small sessions
  // array, and useMemo would be premature optimization at this size).
  //
  // Only `kind: undefined` (SSH/console) tabs count: this dot means "this
  // device has a terminal session open". A local shell's `deviceId` is a
  // shell label, an API tab's is a controller name, and a Files session is
  // a separate surface that keeps its own count in `FilesSidebar` — none of
  // them should light up an inventory row here.
  const connectionCounts = new Map<string, number>();
  for (const tab of sessions) {
    if (tab.ended || tab.kind !== undefined) continue;
    connectionCounts.set(tab.deviceId, (connectionCounts.get(tab.deviceId) ?? 0) + 1);
  }

  const { data, error, isLoading, isRefetching } = useQuery({
    queryKey: ["devices"],
    queryFn: listDevices,
  });

  const { data: groupsData } = useQuery({
    queryKey: ["groups"],
    queryFn: listGroups,
  });

  // Needed only to spot devices whose credential is typed at connect
  // time, so bulk launch can hold them back (v6.1.0).
  const profilesQuery = useQuery({ queryKey: ["authProfiles"], queryFn: listAuthProfiles });

  const connectMutation = useConnectDevice();
  const [connectError, setConnectError] = useState<string | null>(null);
  // Export ALL sessions to an import-compatible CSV. Global action —
  // wired into every sidebar context menu (empty area, device rows, group
  // headers) so "right-click anywhere → Export sessions" works regardless
  // of where the menu was opened. Shared with the v5.0.0 Files sidebar so
  // both write identical files. Secrets are never exported (Rule 1): the
  // backend writes only references (usernames + key-file paths).
  const { exportSessions, exporting } = useExportSessions();

  // v2.8.1 bulk launch ("Launch all" on a multi-selection or group).
  // `bulk` drives the progress banner; the ref backs the Stop button —
  // the mutation's loop polls it between devices, and a ref (unlike
  // state) reads fresh from inside that closure.
  const connectManyMutation = useConnectManyDevices();
  const [bulk, setBulk] = useState<{ done: number; total: number; stopping: boolean } | null>(null);
  const bulkStopRef = useRef(false);

  function handleConnectMany(devices: DeviceMeta[]) {
    // One batch at a time — overlapping batches would break the
    // one-prompt-at-a-time guarantee the sequential loop provides.
    if (devices.length === 0 || connectManyMutation.isPending) return;
    // v6.1.0 — devices that ask for a credential at connect time are held
    // back rather than queued: a bulk launch must never become a stream of
    // credential dialogs (see `partitionInteractiveAuth`).
    const { launchable, interactive } = partitionInteractiveAuth(devices, profilesQuery.data);
    if (interactive.length > 0) {
      toastInfo("Skipped interactive sign-in", {
        description: interactiveSkipMessage(interactive),
      });
    }
    if (launchable.length === 0) return;
    setConnectError(null);
    bulkStopRef.current = false;
    setBulk({ done: 0, total: launchable.length, stopping: false });
    connectManyMutation.mutate(
      {
        deviceIds: launchable.map((d) => d.id),
        onProgress: (done, total) => setBulk((b) => (b ? { ...b, done, total } : b)),
        shouldStop: () => bulkStopRef.current,
      },
      { onSettled: () => setBulk(null) },
    );
  }

  const filtered = useMemo<DeviceMeta[]>(() => {
    if (!data) return [];
    if (!search.trim()) return data;
    const needle = search.trim().toLowerCase();
    return data.filter(
      (d) =>
        d.id.toLowerCase().includes(needle) ||
        d.host.toLowerCase().includes(needle) ||
        (d.group ?? "").toLowerCase().includes(needle),
    );
  }, [data, search]);

  // v6.5.2 — shared, user-draggable rail width.
  const sidebarWidth = useSidebarWidth();

  // Collapsed-sidebar render. After all hooks (rules-of-hooks).
  if (collapsed) {
    return (
      <aside
        data-testid="sidebar-collapsed"
        className="flex h-full w-10 flex-col items-center border-r border-border bg-background py-2"
        aria-label="Devices (collapsed)"
      >
        <button
          type="button"
          onClick={toggleSidebar}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Expand sidebar"
          title="Expand sidebar (⌘/Ctrl+B)"
        >
          <PanelLeft className="h-4 w-4" />
        </button>
      </aside>
    );
  }

  return (
    <aside
      style={{ width: `${sidebarWidth}px` }}
      className="relative flex h-full shrink-0 flex-col border-r border-border bg-background"
    >
      <SidebarResizeHandle />
      <header className="flex h-12 items-center gap-1 border-b border-border px-3">
        <h1 className="flex-1 text-sm font-semibold tracking-wide">Transit</h1>
        <button
          type="button"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["devices"] })}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Refresh inventory"
          title="Refresh"
        >
          <RefreshCw className={isRefetching ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
        </button>
        <button
          type="button"
          onClick={() => dialogs.openAddDevice()}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Add device"
          title="New device"
        >
          <Plus className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={openImport}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Import connections"
          title="Import connections (SecureCRT, ssh_config, CSV, NetBox sync)"
        >
          <Download className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={openAuthManager}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Manage auth profiles"
          title="Manage auth profiles"
          data-testid="sidebar-auth-profiles-button"
        >
          <KeyRound className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={toggleSidebar}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Collapse sidebar"
          title="Collapse sidebar (⌘/Ctrl+B)"
        >
          <PanelLeftClose className="h-4 w-4" />
        </button>
      </header>

      <div className="border-b border-border px-3 py-2">
        <Input
          placeholder="Search devices..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-8"
        />
      </div>

      {error && (
        <div
          className="border-b border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive"
          role="alert"
        >
          {error instanceof Error ? error.message : String(error)}
        </div>
      )}

      {connectError && (
        <div
          className="border-b border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive"
          role="alert"
        >
          <div className="flex items-start justify-between gap-2">
            <span className="break-words">{connectError}</span>
            <button
              type="button"
              onClick={() => setConnectError(null)}
              className="shrink-0 rounded px-1 text-destructive/70 hover:text-destructive"
              aria-label="Dismiss connect error"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {connectMutation.isPending && (
        <div
          className="border-b border-border bg-muted/40 px-4 py-2 text-xs text-muted-foreground"
          role="status"
        >
          Connecting...
        </div>
      )}

      {bulk && (
        <div
          className="flex items-center justify-between gap-2 border-b border-border bg-muted/40 px-4 py-2 text-xs text-muted-foreground"
          role="status"
        >
          <span>
            {bulk.stopping
              ? "Stopping — finishing the current connect…"
              : // `done` counts settled devices; +1 shows the one
                // currently connecting (capped for the final tick).
                `Connecting… ${Math.min(bulk.done + 1, bulk.total)} of ${bulk.total}`}
          </span>
          <button
            type="button"
            onClick={() => {
              bulkStopRef.current = true;
              setBulk((b) => (b ? { ...b, stopping: true } : b));
            }}
            disabled={bulk.stopping}
            className="shrink-0 rounded border border-input px-2 py-0.5 hover:bg-accent disabled:opacity-50"
          >
            Stop
          </button>
        </div>
      )}

      <ContextMenu>
        <ContextMenuTrigger asChild>
          <ScrollArea className="flex-1">
            {/* The ScrollArea's content area must fill its container so
                right-clicks below the last device row land on the
                trigger (and not on dead pixels behind the viewport). */}
            <div className="min-h-full">
              {isLoading ? (
                <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                  Loading inventory...
                </div>
              ) : filtered.length === 0 ? (
                <EmptyState
                  hasSearch={search.length > 0}
                  onAddDevice={() => dialogs.openAddDevice()}
                />
              ) : (
                <DeviceTree
                  devices={filtered}
                  // While searching, hide empty registry groups so the
                  // results are just matching devices (+ their implied
                  // ancestor groups); show the full registry otherwise.
                  groups={search.trim() ? [] : (groupsData ?? [])}
                  activeDeviceId={activeDeviceId}
                  connectionCounts={connectionCounts}
                  onSelectDevice={setActiveDeviceId}
                  onConnectDevice={(device) => {
                    setConnectError(null);
                    setActiveDeviceId(device.id);
                    // Phase 3: each Connect always opens a new tab.
                    // Existing sessions on the same device are left
                    // alone. Close happens via the
                    // tab strip's X, not from the sidebar.
                    connectMutation.mutate(device.id, {
                      onError: (err) => {
                        setConnectError(err instanceof Error ? err.message : String(err));
                      },
                    });
                  }}
                  onConnectMany={handleConnectMany}
                  {...dialogs.treeHandlers}
                  onExportSessions={() => void exportSessions()}
                />
              )}
            </div>
          </ScrollArea>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem onSelect={() => dialogs.openAddDevice()}>New device...</ContextMenuItem>
          <ContextMenuItem onSelect={() => dialogs.openAddGroup()}>New group...</ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem disabled={exporting} onSelect={() => void exportSessions()}>
            Export sessions...
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>

      {/* Phase 7b — console cables pin to the bottom of the sidebar,
          above the footer. The section renders nothing
          when no cables are attached, so it doesn't waste space when
          you're not using one. */}
      <ConsoleCablesSection onSelectCable={setConsoleConnect} />

      <footer className="border-t border-border p-2">
        <div className="flex items-center gap-1.5">
          <div className="min-w-0 flex-1">
            <EditionChip />
          </div>
          <SettingsButton />
        </div>
      </footer>

      {/* The inventory CRUD dialog set + auth-profile manager, shared with
          the Files sidebar. */}
      <InventoryDialogs dialog={dialogs.dialog} onClose={dialogs.close} />
      {/* Console-cable connect is SSH-sidebar only (the Files rail has no
          serial transport), so it stays here. */}
      <ConsoleConnectDialog
        open={consoleConnect !== null}
        onOpenChange={(o) => !o && setConsoleConnect(null)}
        cable={consoleConnect}
      />
    </aside>
  );
}
