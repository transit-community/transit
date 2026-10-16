import {
  Download,
  GitCompare,
  Info,
  KeyRound,
  MessageSquare,
  PanelLeft,
  Plus,
  RefreshCw,
  Settings,
  Terminal,
  Unplug,
  type LucideIcon,
} from "lucide-react";

import { useQuery, useQueryClient } from "@tanstack/react-query";

import { computeLabels } from "@/components/TerminalArea";
import { type DeviceMeta, listDevices } from "@/lib/api";
import { newChat } from "@/lib/chat";
import { useConnectDevice, useDisconnectSession } from "@/lib/mutations";
import { isFilesTab, useUiStore } from "@/stores/uiStore";

/**
 * Phase 7a C2 — command palette registry.
 *
 * Per Decision A3 (Phase 7 plan §A): centralized registry. The
 * `useCommands` hook reads the relevant stores + queries and returns
 * a flat `CommandItem[]` for the palette to render. ~30 commands in
 * v1; the file stays readable. If it ever grows past ~80, refactor
 * to distributed registration via a Zustand store.
 *
 * Groups (rendered in this order):
 *   - **Navigation** — toggle sidebar / chat / settings,
 *     add device, manage auth profiles, refresh inventory.
 *   - **Devices** — one "Connect to <id>" entry per inventory device.
 *   - **Sessions** — one Focus + one Close entry per open session.
 *
 * The palette uses `cmdk`'s built-in fuzzy filter; each item exposes
 * `keywords` for additional search hits (e.g. host:port matches a
 * device entry).
 */

export interface CommandItem {
  /** Stable id for cmdk's keyboard nav. */
  id: string;
  /** Group heading rendered above the item. */
  group: "Navigation" | "Devices" | "Sessions";
  /** Primary label (what the user sees). */
  label: string;
  /** Optional subtitle rendered below the label. */
  description?: string;
  /** Lucide icon rendered to the left. */
  icon: LucideIcon;
  /** Extra search terms for cmdk's fuzzy filter. */
  keywords?: string[];
  /** Optional shortcut hint (e.g. "⌘B"). Display only — the hotkey
   *  itself is bound elsewhere (`useGlobalHotkeys`). */
  shortcut?: string;
  /** Fires when the user selects the item. Palette closes itself. */
  perform: () => void;
}

export function useCommands(): CommandItem[] {
  // UI store actions
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const toggleChatPanel = useUiStore((s) => s.toggleChatPanel);
  const toggleSessionInfoPanel = useUiStore((s) => s.toggleSessionInfoPanel);
  const openSettings = useUiStore((s) => s.openSettingsDialog);
  const openAuthManager = useUiStore((s) => s.openAuthProfileManager);
  const openImport = useUiStore((s) => s.openImport);
  const openCaptures = useUiStore((s) => s.openCaptures);
  const setActiveTab = useUiStore((s) => s.setActiveTab);
  const sessions = useUiStore((s) => s.sessions);

  // Server state
  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const queryClient = useQueryClient();
  const connectMutation = useConnectDevice();
  const disconnectMutation = useDisconnectSession();

  const devices = devicesQuery.data ?? [];
  const labels = computeLabels(sessions);

  const nav: CommandItem[] = [
    {
      id: "nav-captures",
      group: "Navigation",
      label: "Compare captures / diff output...",
      description: "Capture a command's output and diff two captures",
      icon: GitCompare,
      keywords: ["diff", "compare", "capture", "drift", "show run", "config"],
      perform: () => openCaptures(),
    },
    {
      id: "nav-add-device",
      group: "Navigation",
      label: "Add device...",
      description: "Create a new SSH device entry in the inventory",
      icon: Plus,
      keywords: ["new", "create", "inventory"],
      perform: () => {
        // The Sidebar owns the dialog state for Add device. Hand off
        // by clicking the existing header button — synthetic click
        // avoids prop-drilling another store slot just for this.
        const btn = document.querySelector<HTMLButtonElement>('[aria-label="Add device"]');
        btn?.click();
      },
    },
    {
      id: "nav-import",
      group: "Navigation",
      label: "Import connections...",
      description:
        "Bulk-import devices from SecureCRT, MTPuTTY, MobaXterm, ssh_config, or CSV — or sync from NetBox",
      icon: Download,
      keywords: [
        "bulk",
        "securecrt",
        "scrt",
        "mtputty",
        "putty",
        "mobaxterm",
        "moba",
        "ssh_config",
        "csv",
        "migrate",
        "netbox",
        "sync",
      ],
      perform: openImport,
    },
    {
      id: "nav-auth-profiles",
      group: "Navigation",
      label: "Manage auth profiles...",
      description: "List, edit, and delete saved credentials",
      icon: KeyRound,
      keywords: ["credentials", "ssh", "password", "secret"],
      perform: openAuthManager,
    },
    {
      id: "nav-settings",
      group: "Navigation",
      label: "Open settings...",
      icon: Settings,
      keywords: ["preferences", "config"],
      perform: openSettings,
    },
    {
      id: "nav-toggle-sidebar",
      group: "Navigation",
      label: "Toggle sidebar",
      icon: PanelLeft,
      shortcut: "⌘B",
      perform: toggleSidebar,
    },
    {
      id: "nav-toggle-chat",
      group: "Navigation",
      label: "Toggle chat panel",
      icon: MessageSquare,
      shortcut: "⌘J",
      perform: toggleChatPanel,
    },
    {
      id: "nav-new-chat",
      group: "Navigation",
      label: "New chat",
      description: "Open a new AI chat tab",
      icon: Plus,
      shortcut: "⌘T",
      keywords: ["chat", "tab", "conversation", "ai"],
      perform: newChat,
    },
    {
      id: "nav-toggle-session-info",
      group: "Navigation",
      label: "Toggle session info panel",
      icon: Info,
      shortcut: "⌘I",
      keywords: ["details", "metadata", "info"],
      perform: toggleSessionInfoPanel,
    },
    {
      id: "nav-refresh-inventory",
      group: "Navigation",
      label: "Refresh inventory",
      description: "Re-read transit.toml from disk",
      icon: RefreshCw,
      keywords: ["reload"],
      perform: () => {
        void queryClient.invalidateQueries({ queryKey: ["devices"] });
        void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      },
    },
  ];

  const deviceCommands: CommandItem[] = devices.map((d) => deviceConnectItem(d, connectMutation));

  const sessionCommands: CommandItem[] = sessions.flatMap((s, i) => {
    const label = labels[i] ?? s.deviceId;
    const items: CommandItem[] = [
      {
        id: `session-focus-${s.sessionId}`,
        group: "Sessions" as const,
        label: `Focus ${label}`,
        description: s.ended ? "Session ended (read-only)" : "Switch to this tab",
        icon: Terminal,
        keywords: [s.deviceId, s.sessionId],
        perform: () => setActiveTab(s.sessionId),
      },
    ];
    // Close routes through `disconnect_session`, which has NO files arm —
    // the `files_*` IPC namespace is disjoint by design (plan decision 7),
    // so offering it for a Files tab would drop the tab while leaking the
    // SFTP session and its SSH connection. A Files tab closes from its tab
    // ✕ (which routes to `files_disconnect`); teaching the palette to route
    // by kind is deferred (plan §15).
    if (!isFilesTab(s)) {
      items.push({
        id: `session-close-${s.sessionId}`,
        group: "Sessions" as const,
        label: `Close ${label}`,
        description: s.ended ? "Remove the ended tab" : "Disconnect and close the tab",
        icon: Unplug,
        keywords: [s.deviceId, s.sessionId, "disconnect"],
        perform: () => {
          disconnectMutation.mutate(s.sessionId);
        },
      });
    }
    return items;
  });

  return [...nav, ...deviceCommands, ...sessionCommands];
}

function deviceConnectItem(
  device: DeviceMeta,
  connectMutation: ReturnType<typeof useConnectDevice>,
): CommandItem {
  return {
    id: `device-connect-${device.id}`,
    group: "Devices",
    label: `Connect to ${device.id}`,
    description: `${device.host}:${device.port}${device.group ? ` · ${device.group}` : ""}`,
    icon: Terminal,
    keywords: [device.host, device.vendor, device.group ?? ""].filter(Boolean),
    perform: () => {
      connectMutation.mutate(device.id);
    },
  };
}
