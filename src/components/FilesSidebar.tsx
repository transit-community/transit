import { useMemo, useRef, useState } from "react";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, PanelLeft, PanelLeftClose, Plus, RefreshCw } from "lucide-react";

import { EditionChip, SettingsButton } from "@/components/SettingsButton";
import { DeviceTree } from "@/components/DeviceTree";
import { EmptyState, InventoryDialogs, useInventoryDialogs } from "@/components/InventoryDialogs";
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
import { listDevices, listGroups, type DeviceMeta } from "@/lib/api";
import { useExportSessions } from "@/lib/exportSessions";
import { useOpenFilesSession, useOpenFilesSessions } from "@/lib/files";
import { isFilesTab, useUiStore } from "@/stores/uiStore";

/**
 * v5.0.0 — the launcher for the Files (SFTP) surface, the 4th rail tab.
 *
 * Rides the SAME inventory as the SSH sidebar (SecureFX riding SecureCRT's
 * session database): it renders the very same `DeviceTree` — groups, tags,
 * per-host colors, drag-to-regroup, multi-select, and the SHARED collapse
 * state (`preferences.collapsedGroups`, deliberately shared: same tree,
 * same folds) — with the injected launch action swapped from "Connect" to
 * "Open file transfer". Inventory CRUD opens the same dialogs.
 *
 * No device filtering: every inventory entry is SSH-capable by
 * construction (`DeviceMeta` has no transport field — console cables and
 * API controllers live in separate registries), so there is no such thing
 * as a device this surface can't try.
 *
 * A HUMAN surface end to end: the AI agent is structurally blind to Files
 * sessions (plan §2 / threat model T43), so nothing here touches chat or
 * scope.
 */
export function FilesSidebar() {
  const [search, setSearch] = useState("");
  const dialogs = useInventoryDialogs();
  const openAuthManager = useUiStore((s) => s.openAuthProfileManager);

  const activeDeviceId = useUiStore((s) => s.activeDeviceId);
  const setActiveDeviceId = useUiStore((s) => s.setActiveDeviceId);
  const sessions = useUiStore((s) => s.sessions);
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const queryClient = useQueryClient();

  // Per-device FILE-TRANSFER session counts — this sidebar's dot means "a
  // file transfer session is open to this device", entirely independent of
  // the SSH sidebar's terminal count.
  const connectionCounts = new Map<string, number>();
  for (const tab of sessions) {
    if (tab.ended || !isFilesTab(tab)) continue;
    connectionCounts.set(tab.deviceId, (connectionCounts.get(tab.deviceId) ?? 0) + 1);
  }

  const { data, error, isLoading, isRefetching } = useQuery({
    queryKey: ["devices"],
    queryFn: listDevices,
  });
  const { data: groupsData } = useQuery({ queryKey: ["groups"], queryFn: listGroups });

  const { exportSessions, exporting } = useExportSessions();

  const openFiles = useOpenFilesSession();
  const openFilesMany = useOpenFilesSessions();
  const [launchError, setLaunchError] = useState<string | null>(null);
  // Bulk launch progress + Stop, mirroring the SSH sidebar: `bulk` drives
  // the banner and the ref backs Stop (the sequential loop polls it between
  // devices, and a ref — unlike state — reads fresh inside that closure).
  const [bulk, setBulk] = useState<{ done: number; total: number; stopping: boolean } | null>(null);
  const bulkStopRef = useRef(false);

  function handleLaunch(device: DeviceMeta) {
    setLaunchError(null);
    setActiveDeviceId(device.id);
    openFiles.mutate(device.id, {
      onError: (err) => setLaunchError(err instanceof Error ? err.message : String(err)),
    });
  }

  function handleLaunchMany(devices: DeviceMeta[]) {
    // One batch at a time — overlapping batches would break the
    // one-prompt-at-a-time guarantee the sequential loop provides (the
    // host-key / weak-crypto responder maps are single-slot).
    if (devices.length === 0 || openFilesMany.isPending) return;
    setLaunchError(null);
    bulkStopRef.current = false;
    setBulk({ done: 0, total: devices.length, stopping: false });
    openFilesMany.mutate(
      {
        deviceIds: devices.map((d) => d.id),
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

  // Collapsed render. After all hooks (rules-of-hooks).
  if (collapsed) {
    return (
      <aside
        data-testid="files-sidebar-collapsed"
        className="flex h-full w-10 flex-col items-center border-r border-border bg-background py-2"
        aria-label="File transfer (collapsed)"
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
      data-testid="files-sidebar"
      style={{ width: `${sidebarWidth}px` }}
      className="relative flex h-full shrink-0 flex-col border-r border-border bg-background"
    >
      <SidebarResizeHandle />
      <header className="flex h-12 items-center gap-1 border-b border-border px-3">
        <h1 className="flex-1 text-sm font-semibold tracking-wide">Files</h1>
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
          onClick={openAuthManager}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Manage auth profiles"
          title="Manage auth profiles"
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

      {launchError && (
        <div
          className="border-b border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive"
          role="alert"
        >
          <div className="flex items-start justify-between gap-2">
            <span className="break-words">{launchError}</span>
            <button
              type="button"
              onClick={() => setLaunchError(null)}
              className="shrink-0 rounded px-1 text-destructive/70 hover:text-destructive"
              aria-label="Dismiss file transfer error"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {openFiles.isPending && (
        <div
          className="border-b border-border bg-muted/40 px-4 py-2 text-xs text-muted-foreground"
          role="status"
        >
          Opening file transfer...
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
                `Opening… ${Math.min(bulk.done + 1, bulk.total)} of ${bulk.total}`}
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
            <div className="min-h-full">
              {isLoading ? (
                <div className="px-4 py-8 text-center text-xs text-muted-foreground">
                  Loading inventory...
                </div>
              ) : filtered.length === 0 ? (
                // Shared with the SSH sidebar so a first-run user on the Files
                // rail gets the same clickable "+ New device" CTA (F2).
                <EmptyState
                  hasSearch={search.length > 0}
                  onAddDevice={() => dialogs.openAddDevice()}
                />
              ) : (
                <DeviceTree
                  devices={filtered}
                  groups={search.trim() ? [] : (groupsData ?? [])}
                  activeDeviceId={activeDeviceId}
                  connectionCounts={connectionCounts}
                  onSelectDevice={setActiveDeviceId}
                  onConnectDevice={handleLaunch}
                  connectLabel="Open file transfer"
                  onConnectMany={handleLaunchMany}
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

      <footer className="border-t border-border p-2">
        <div className="flex items-center gap-1.5">
          <div className="min-w-0 flex-1">
            <EditionChip />
          </div>
          <SettingsButton />
        </div>
      </footer>

      {/* The SAME inventory CRUD dialog set + auth-profile manager the SSH
          sidebar hosts — editing a device from either rail must behave
          identically, so both render the one shared component. */}
      <InventoryDialogs dialog={dialogs.dialog} onClose={dialogs.close} />
    </aside>
  );
}
