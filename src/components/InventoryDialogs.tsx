import { useState } from "react";

import { AddDeviceDialog } from "@/components/dialogs/AddDeviceDialog";
import { AddGroupDialog } from "@/components/dialogs/AddGroupDialog";
import { AuthProfileManagerDialog } from "@/components/dialogs/AuthProfileManagerDialog";
import { BulkEditDevicesDialog } from "@/components/dialogs/BulkEditDevicesDialog";
import { DeleteConfirmDialog } from "@/components/dialogs/DeleteConfirmDialog";
import { EditDeviceDialog } from "@/components/dialogs/EditDeviceDialog";
import { RenameGroupDialog } from "@/components/dialogs/RenameGroupDialog";
import type { DeviceMeta } from "@/lib/api";
import { useDeleteDevice, useDeleteGroup, useSetDeviceGroup } from "@/lib/mutations";
import { useUiStore } from "@/stores/uiStore";

/**
 * The inventory CRUD surface shared VERBATIM by the SSH `Sidebar` and the
 * v5.0.0 Files `FilesSidebar`: the dialog-state union, the six-dialog JSX, the
 * device/group CRUD callbacks, and the empty-state CTA. It was a ~69-line fork
 * across the two sidebars — editing a device from either rail must behave
 * identically, and a fork drifts. Each sidebar now keeps only what actually
 * differs (its header, search, per-device connection dot, and bulk-launch
 * banner).
 */

export type InventoryDialogState =
  | { kind: "none" }
  | { kind: "add"; group?: string }
  | { kind: "edit"; device: DeviceMeta }
  | { kind: "bulkEdit"; devices: DeviceMeta[] }
  | { kind: "delete"; device: DeviceMeta }
  | { kind: "rename"; path: string }
  | { kind: "addGroup"; parent?: string }
  | { kind: "deleteGroup"; path: string };

/**
 * Owns the dialog-open state and the handlers that open it. Returns the
 * `treeHandlers` bundle to spread straight into `<DeviceTree>` (the seven
 * inventory CRUD props + move-to-group), plus openers for the header /
 * context-menu "New device" / "New group" and the empty-state CTA.
 */
export function useInventoryDialogs() {
  const [dialog, setDialog] = useState<InventoryDialogState>({ kind: "none" });
  const moveDevice = useSetDeviceGroup();

  return {
    dialog,
    close: () => setDialog({ kind: "none" }),
    openAddDevice: (group?: string) => setDialog({ kind: "add", group }),
    openAddGroup: (parent?: string) => setDialog({ kind: "addGroup", parent }),
    /** Spread into `<DeviceTree>` — the inventory CRUD props both sidebars
     *  wire identically. */
    treeHandlers: {
      onEditDevice: (device: DeviceMeta) => setDialog({ kind: "edit", device }),
      // v6.3.0 bulk edit — multi-select or a group header hands N devices
      // over; a single-device selection falls back to the single dialog
      // (its rail has more fields and better validation copy).
      onEditSelection: (devices: DeviceMeta[]) => {
        if (devices.length === 0) return;
        if (devices.length === 1) setDialog({ kind: "edit", device: devices[0] });
        else setDialog({ kind: "bulkEdit", devices });
      },
      onDeleteDevice: (device: DeviceMeta) => setDialog({ kind: "delete", device }),
      onAddDeviceInGroup: (group: string) => setDialog({ kind: "add", group }),
      onAddSubgroup: (parent: string) => setDialog({ kind: "addGroup", parent }),
      onRenameGroup: (path: string) => setDialog({ kind: "rename", path }),
      onDeleteGroup: (path: string) => setDialog({ kind: "deleteGroup", path }),
      onMoveDevice: (id: string, group: string | null) => moveDevice.mutate({ id, group }),
    },
  };
}

/** Renders the six inventory dialogs for the given state, plus the (uiStore-
 *  driven) auth-profile manager both sidebars host. Delete confirmations own
 *  the delete mutations here so the sidebars don't each re-wire them. */
export function InventoryDialogs({
  dialog,
  onClose,
}: {
  dialog: InventoryDialogState;
  onClose: () => void;
}) {
  const deleteMutation = useDeleteDevice();
  const deleteGroupMutation = useDeleteGroup();
  const authManagerOpen = useUiStore((s) => s.authProfileManagerOpen);
  const openAuthManager = useUiStore((s) => s.openAuthProfileManager);
  const closeAuthManager = useUiStore((s) => s.closeAuthProfileManager);

  return (
    <>
      <AddDeviceDialog
        open={dialog.kind === "add"}
        onOpenChange={(o) => !o && onClose()}
        defaultGroup={dialog.kind === "add" ? dialog.group : undefined}
      />
      {dialog.kind === "edit" && (
        <EditDeviceDialog open onOpenChange={(o) => !o && onClose()} device={dialog.device} />
      )}
      {dialog.kind === "bulkEdit" && (
        <BulkEditDevicesDialog
          open
          onOpenChange={(o) => !o && onClose()}
          devices={dialog.devices}
        />
      )}
      {dialog.kind === "delete" && (
        <DeleteConfirmDialog
          open
          onOpenChange={(o) => !o && onClose()}
          title={`Delete ${dialog.device.id}?`}
          description="Removes the device from inventory. The auth profile is unaffected."
          onConfirm={() => deleteMutation.mutateAsync(dialog.device.id)}
        />
      )}
      {dialog.kind === "rename" && (
        <RenameGroupDialog open onOpenChange={(o) => !o && onClose()} oldPath={dialog.path} />
      )}
      <AddGroupDialog
        open={dialog.kind === "addGroup"}
        onOpenChange={(o) => !o && onClose()}
        defaultParent={dialog.kind === "addGroup" ? dialog.parent : undefined}
      />
      {dialog.kind === "deleteGroup" && (
        <DeleteConfirmDialog
          open
          onOpenChange={(o) => !o && onClose()}
          title={`Delete group "${dialog.path}"?`}
          description={
            dialog.path.includes("/")
              ? `Its connections and subgroups move up to "${dialog.path.slice(0, dialog.path.lastIndexOf("/"))}". No devices are deleted.`
              : `Its connections and subgroups become ungrouped (move to the top level). No devices are deleted.`
          }
          onConfirm={() => deleteGroupMutation.mutateAsync(dialog.path)}
        />
      )}
      <AuthProfileManagerDialog
        open={authManagerOpen}
        onOpenChange={(o) => (o ? openAuthManager() : closeAuthManager())}
      />
    </>
  );
}

/** The device-tree empty state, shared by both sidebars so a first-run user
 *  on EITHER rail gets the same clickable "+ New device" CTA (F2 — the Files
 *  sidebar had inlined a text-only substitute with no button). */
export function EmptyState({
  hasSearch,
  onAddDevice,
}: {
  hasSearch: boolean;
  onAddDevice: () => void;
}) {
  if (hasSearch) {
    return (
      <div className="px-4 py-8 text-center text-xs text-muted-foreground">
        No devices match your search.
      </div>
    );
  }
  return (
    <div className="px-4 py-8 text-center text-xs text-muted-foreground">
      <p>No devices yet.</p>
      <p className="mt-2">
        Click <span className="font-medium">+ New device</span> above to add your first host.
      </p>
      <button
        type="button"
        onClick={onAddDevice}
        className="mt-4 rounded-md border border-input bg-background px-3 py-1.5 text-xs hover:bg-accent"
      >
        + New device
      </button>
    </div>
  );
}
