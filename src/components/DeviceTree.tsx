import { useMemo, useState, type MouseEvent } from "react";

import {
  DndContext,
  DragOverlay,
  PointerSensor,
  useDroppable,
  useSensor,
  useSensors,
  type DragEndEvent,
  type DragStartEvent,
} from "@dnd-kit/core";
import { ChevronRight, Folder, FolderOpen } from "lucide-react";

import { DeviceRow } from "@/components/DeviceRow";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import type { DeviceMeta } from "@/lib/api";
import { countLaunchable, usePromptAuthProfileNames } from "@/lib/interactiveAuth";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/uiStore";

// ---------------------------------------------------------------------
// Tree shape.
// ---------------------------------------------------------------------

export type GroupNode = {
  kind: "group";
  /** Last segment, e.g. "Junos" for path "Lab/Junos". */
  name: string;
  /** Full path from root, e.g. "Lab/Junos". Used as the stable key
   *  the backend mutator works against. */
  path: string;
  children: TreeNode[];
};
type DeviceNode = {
  kind: "device";
  device: DeviceMeta;
};
export type TreeNode = GroupNode | DeviceNode;

/** Walk (creating as needed) the nested group chain for a slash-path
 *  and return the leaf group node. Shared by the device-path pass and
 *  the registry pass so an empty registry group converges on the same
 *  node a device would create. */
function ensureGroupPath(root: GroupNode, path: string): GroupNode {
  let cursor = root;
  const segments = path.split("/").filter((s) => s.length > 0);
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    const fullPath = segments.slice(0, i + 1).join("/");
    let child = cursor.children.find(
      (c): c is GroupNode => c.kind === "group" && c.name === segment,
    );
    if (!child) {
      child = { kind: "group", name: segment, path: fullPath, children: [] };
      cursor.children.push(child);
    }
    cursor = child;
  }
  return cursor;
}

/**
 * Build a nested tree from a flat device list plus a registry of known
 * group paths. Devices with `group = "A/B"` end up under root → A → B →
 * device; devices with `group = null` render at root. Registry paths
 * are unioned in so a group with NO devices still renders (created
 * empty, or its last device moved out) — the registry and device-implied
 * paths converge on the same nodes.
 *
 * Output order: groups before devices, alphabetical within each.
 */
export function buildTree(devices: DeviceMeta[], groups: string[] = []): TreeNode[] {
  const root: GroupNode = { kind: "group", name: "", path: "", children: [] };

  for (const d of devices) {
    if (!d.group || d.group.trim() === "") {
      root.children.push({ kind: "device", device: d });
      continue;
    }
    ensureGroupPath(root, d.group).children.push({ kind: "device", device: d });
  }

  // Registry pass: materialize any group path that has no device.
  for (const g of groups) {
    if (g && g.trim() !== "") ensureGroupPath(root, g);
  }

  sortNodes(root);
  return root.children;
}

type DropTargetData = { kind?: string; path?: string };

/**
 * Pure drop resolver (extracted so it's unit-testable without
 * simulating a dnd-kit pointer gesture). Returns the move to apply, or
 * `null` when the drop is a no-op: not over a group target, or dropped
 * back into the device's current group. `path: ""` means the root
 * "ungroup" zone → `group: null`.
 */
export function resolveDeviceMove(
  activeId: string,
  currentGroup: string | null,
  over: DropTargetData | undefined | null,
): { id: string; group: string | null } | null {
  if (!over || over.kind !== "group") return null;
  const target = over.path ?? "";
  if (target === (currentGroup ?? "")) return null;
  return { id: activeId, group: target === "" ? null : target };
}

/**
 * The devices a user can currently SEE, in render order — depth-first
 * over the tree, skipping the contents of collapsed groups. This is
 * the coordinate system for shift-click range selection and the
 * launch order for "Launch all" on a multi-selection: both follow
 * what's on screen, so a row hidden inside a collapsed group can
 * never be silently swept into a range or a launch.
 */
export function flattenVisibleDevices(
  nodes: TreeNode[],
  collapsedGroups: Record<string, boolean>,
): DeviceMeta[] {
  const out: DeviceMeta[] = [];
  for (const n of nodes) {
    if (n.kind === "device") {
      out.push(n.device);
    } else if (collapsedGroups[n.path] !== true) {
      out.push(...flattenVisibleDevices(n.children, collapsedGroups));
    }
  }
  return out;
}

/**
 * Every device under a group folder, subgroups included, in tree
 * order. Unlike `flattenVisibleDevices` this deliberately ignores
 * collapse state — "Launch all in group" names the folder itself,
 * so its collapsed contents are exactly what the user is asking for.
 */
export function collectSubtreeDevices(node: GroupNode): DeviceMeta[] {
  const out: DeviceMeta[] = [];
  for (const c of node.children) {
    if (c.kind === "device") out.push(c.device);
    else out.push(...collectSubtreeDevices(c));
  }
  return out;
}

function sortNodes(node: GroupNode) {
  node.children.sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === "group" ? -1 : 1;
    if (a.kind === "group" && b.kind === "group") return a.name.localeCompare(b.name);
    if (a.kind === "device" && b.kind === "device") return a.device.id.localeCompare(b.device.id);
    return 0;
  });
  for (const c of node.children) {
    if (c.kind === "group") sortNodes(c);
  }
}

// ---------------------------------------------------------------------
// Render.
// ---------------------------------------------------------------------

export interface DeviceTreeProps {
  devices: DeviceMeta[];
  /** Registered (possibly empty) group paths — see `buildTree`. */
  groups: string[];
  activeDeviceId: string | null;
  /** Map from device id → count of open (non-ended) SSH sessions on
   *  that device. Devices not in the map are "not connected". */
  connectionCounts: Map<string, number>;
  onSelectDevice: (id: string) => void;
  onConnectDevice: (device: DeviceMeta) => void;
  /** Wording for the row menu's connect item (see `DeviceRowProps`).
   *  Absent = the SSH sidebar's "Connect" / "Connect (new tab)". */
  connectLabel?: string;
  /** v2.8.1 — bulk launch: open a session to EACH device, in the
   *  given order. Fired by "Launch all (N devices)" on a
   *  multi-selection and "Launch all in group" on a folder. The
   *  caller (Sidebar) connects sequentially so host-key / weak-crypto
   *  prompts appear one at a time. */
  onConnectMany: (devices: DeviceMeta[]) => void;
  onEditDevice: (device: DeviceMeta) => void;
  /** v6.3.0 — bulk edit: hand the selection (or a folder's subtree) to
   *  the tri-state dialog, in visible order. One device falls back to the
   *  single-edit dialog (the InventoryDialogs handler decides). Unlike
   *  Launch all there is no interactive-auth carve-out — every selected
   *  device is editable, so labels use the plain selection count. */
  onEditSelection: (devices: DeviceMeta[]) => void;
  onDeleteDevice: (device: DeviceMeta) => void;
  onAddDeviceInGroup: (groupPath: string) => void;
  onAddSubgroup: (parentPath: string) => void;
  onRenameGroup: (path: string) => void;
  onDeleteGroup: (path: string) => void;
  /** Move a device into `group` (or `null` to ungroup). The drag-drop
   *  commit point. */
  onMoveDevice: (id: string, group: string | null) => void;
  /** Export ALL sessions to a CSV. A global action wired into every
   *  sidebar context menu (device rows + group headers + the empty-area
   *  menu in `Sidebar`) so "right-click anywhere → Export sessions"
   *  works. Not scoped to the clicked node. */
  onExportSessions: () => void;
}

/** Props threaded through the recursive tree render: the public
 *  handlers minus the data lists, plus the selection plumbing that
 *  stays internal to the tree. */
type TreeHandlers = Omit<DeviceTreeProps, "devices" | "groups"> & {
  /** Effective multi-selection: stored ids ∩ visible rows. */
  selectedIds: ReadonlySet<string>;
  /** How many of the selection a bulk launch will actually open —
   *  interactive-auth devices are held back, so this can be lower than
   *  `selectedIds.size` and it is what the menu label must promise. */
  selectionLaunchableCount: number;
  onRowClick: (device: DeviceMeta, e: MouseEvent<HTMLButtonElement>) => void;
  /** Right-click on a row OUTSIDE the selection collapses the
   *  selection to that row before its menu opens (file-manager
   *  convention) — so "Launch all" can never target rows the user
   *  isn't looking at. */
  onRowContextMenu: (device: DeviceMeta) => void;
  onLaunchSelection: () => void;
  onEditSelectionRows: () => void;
  onClearSelection: () => void;
  onLaunchGroup: (node: GroupNode) => void;
  onEditGroup: (node: GroupNode) => void;
};

export function DeviceTree(props: DeviceTreeProps) {
  const tree = useMemo(() => buildTree(props.devices, props.groups), [props.devices, props.groups]);
  const collapsedGroups = useUiStore((s) => s.preferences.collapsedGroups);
  // A small distance threshold separates a drag from a click/right-click
  // so selecting, toggling collapse, and the context menu all keep
  // working on the same elements that are now drag sources / targets.
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 5 } }));
  const [draggingId, setDraggingId] = useState<string | null>(null);

  // v2.8.1 multi-select. Ephemeral by design (dies with the tree, never
  // persisted): `ids` is what the user has picked, `anchor` the base row
  // for shift ranges. Stored ids can go stale when the inventory or the
  // search filter changes — `selectedIds` below intersects against the
  // visible rows every render, so stale entries are inert rather than
  // pruned by effect.
  const [selection, setSelection] = useState<{
    ids: ReadonlySet<string>;
    anchor: string | null;
  }>({ ids: new Set(), anchor: null });

  const visibleDevices = useMemo(
    () => flattenVisibleDevices(tree, collapsedGroups),
    [tree, collapsedGroups],
  );

  const selectedIds = useMemo(() => {
    if (selection.ids.size === 0) return selection.ids;
    const out = new Set<string>();
    for (const d of visibleDevices) {
      if (selection.ids.has(d.id)) out.add(d.id);
    }
    return out;
  }, [selection.ids, visibleDevices]);

  // What "Launch all (N devices)" will ACTUALLY open — interactive-auth
  // devices are held back from a bulk launch, so counting them would make
  // the label promise a session it never opens.
  const promptProfiles = usePromptAuthProfileNames();
  const selectionLaunchableCount = useMemo(
    () =>
      countLaunchable(
        visibleDevices.filter((d) => selectedIds.has(d.id)),
        promptProfiles,
      ),
    [visibleDevices, selectedIds, promptProfiles],
  );

  const onRowClick = (device: DeviceMeta, e: MouseEvent<HTMLButtonElement>) => {
    const id = device.id;
    props.onSelectDevice(id);
    if (e.shiftKey && selection.anchor !== null) {
      // Range = anchor → clicked row, over the VISIBLE order. If the
      // anchor has since been filtered/collapsed away, fall through to
      // a plain single-select instead of guessing a range.
      const order = visibleDevices.map((d) => d.id);
      const a = order.indexOf(selection.anchor);
      const b = order.indexOf(id);
      if (a !== -1 && b !== -1) {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        setSelection({ ids: new Set(order.slice(lo, hi + 1)), anchor: selection.anchor });
        return;
      }
    }
    if (e.metaKey || e.ctrlKey) {
      const ids = new Set(selection.ids);
      if (ids.has(id)) ids.delete(id);
      else ids.add(id);
      setSelection({ ids, anchor: id });
      return;
    }
    setSelection({ ids: new Set([id]), anchor: id });
  };

  const onRowContextMenu = (device: DeviceMeta) => {
    if (!selectedIds.has(device.id)) {
      setSelection({ ids: new Set([device.id]), anchor: device.id });
      props.onSelectDevice(device.id);
    }
  };

  // ONE definition of "the selection, materialized" — visible order, not
  // click order (matches the on-screen top-to-bottom reading of the
  // highlighted rows). Launch and Edit must always agree on this set.
  const selectedDevices = () => visibleDevices.filter((d) => selectedIds.has(d.id));

  const onLaunchSelection = () => props.onConnectMany(selectedDevices());

  const onEditSelectionRows = () => props.onEditSelection(selectedDevices());

  const onClearSelection = () => setSelection({ ids: new Set(), anchor: null });

  const onLaunchGroup = (node: GroupNode) => {
    props.onConnectMany(collectSubtreeDevices(node));
  };

  const onEditGroup = (node: GroupNode) => {
    props.onEditSelection(collectSubtreeDevices(node));
  };

  const onDragStart = (e: DragStartEvent) => setDraggingId(String(e.active.id));
  const onDragEnd = (e: DragEndEvent) => {
    setDraggingId(null);
    const { active, over } = e;
    const activeData = active.data.current as { currentGroup?: string | null } | undefined;
    const move = resolveDeviceMove(
      String(active.id),
      activeData?.currentGroup ?? null,
      over?.data.current as DropTargetData | undefined,
    );
    if (move) props.onMoveDevice(move.id, move.group);
  };

  const draggingDevice = draggingId
    ? (props.devices.find((d) => d.id === draggingId) ?? null)
    : null;

  return (
    <DndContext
      sensors={sensors}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      onDragCancel={() => setDraggingId(null)}
    >
      <ul className="px-1">
        {/* Ungroup target — only present mid-drag so it never clutters
            the resting tree. Dropping a grouped device here clears its
            group. */}
        {draggingId && <UngroupZone />}
        {tree.map((n, i) => (
          <TreeNodeView
            key={nodeKey(n, i)}
            node={n}
            depth={0}
            {...props}
            selectedIds={selectedIds}
            selectionLaunchableCount={selectionLaunchableCount}
            onRowClick={onRowClick}
            onRowContextMenu={onRowContextMenu}
            onLaunchSelection={onLaunchSelection}
            onEditSelectionRows={onEditSelectionRows}
            onClearSelection={onClearSelection}
            onLaunchGroup={onLaunchGroup}
            onEditGroup={onEditGroup}
          />
        ))}
      </ul>
      <DragOverlay>
        {draggingDevice ? (
          <div className="rounded-md border border-border bg-background px-2 py-1 font-mono text-sm shadow-md">
            {draggingDevice.id}
          </div>
        ) : null}
      </DragOverlay>
    </DndContext>
  );
}

/** The mid-drag "drop here to ungroup" band. A droppable with the empty
 *  path so `onDragEnd` reads it as "move to root". */
function UngroupZone() {
  const { setNodeRef, isOver } = useDroppable({ id: "group:", data: { kind: "group", path: "" } });
  return (
    <li>
      <div
        ref={setNodeRef}
        data-testid="ungroup-zone"
        className={cn(
          "mx-1 mb-1 rounded-md border border-dashed px-2 py-1 text-xs text-muted-foreground",
          isOver ? "border-primary bg-primary/10 text-primary" : "border-border",
        )}
      >
        Drop here to ungroup
      </div>
    </li>
  );
}

function nodeKey(n: TreeNode, fallbackIdx: number): string {
  return n.kind === "group" ? `g:${n.path}` : `d:${n.device.id}:${fallbackIdx}`;
}

function TreeNodeView({
  node,
  depth,
  ...handlers
}: { node: TreeNode; depth: number } & TreeHandlers) {
  if (node.kind === "device") {
    const connectionCount = handlers.connectionCounts.get(node.device.id) ?? 0;
    return (
      <li>
        <DeviceRow
          device={node.device}
          active={node.device.id === handlers.activeDeviceId}
          selected={handlers.selectedIds.has(node.device.id)}
          selectionCount={handlers.selectedIds.size}
          selectionLaunchableCount={handlers.selectionLaunchableCount}
          connectionCount={connectionCount}
          depth={depth}
          onClick={(e) => handlers.onRowClick(node.device, e)}
          onRowContextMenu={() => handlers.onRowContextMenu(node.device)}
          onConnect={() => handlers.onConnectDevice(node.device)}
          connectLabel={handlers.connectLabel}
          onLaunchSelection={handlers.onLaunchSelection}
          onEditSelection={handlers.onEditSelectionRows}
          onClearSelection={handlers.onClearSelection}
          onEdit={() => handlers.onEditDevice(node.device)}
          onDelete={() => handlers.onDeleteDevice(node.device)}
          onExport={handlers.onExportSessions}
        />
      </li>
    );
  }
  return <GroupNodeView node={node} depth={depth} {...handlers} />;
}

function GroupNodeView({
  node,
  depth,
  ...handlers
}: { node: GroupNode; depth: number } & TreeHandlers) {
  // Collapse state is persisted (keyed by path) so it survives refresh.
  const collapsed = useUiStore((s) => s.preferences.collapsedGroups[node.path] === true);
  const toggleGroupCollapsed = useUiStore((s) => s.toggleGroupCollapsed);
  const open = !collapsed;

  // Full-subtree count for the "Launch all in group" label — collapse
  // state doesn't matter here (the folder is the unit the user names).
  //
  // Counts what will actually LAUNCH, not what is in the folder:
  // interactive-auth devices are held back (each needs an attended
  // prompt), so including them would make the menu promise one more
  // session than it opens.
  const promptProfiles = usePromptAuthProfileNames();
  // One walk; both counts derive from the same array so they can never
  // describe different device sets. countLaunchable filters this array,
  // so groupDeviceCount <= subtreeDeviceCount always.
  const subtreeDevices = collectSubtreeDevices(node);
  const subtreeDeviceCount = subtreeDevices.length;
  const groupDeviceCount = countLaunchable(subtreeDevices, promptProfiles);

  // Drop target: dragging a device onto this header moves it into this
  // group's path.
  const { setNodeRef, isOver } = useDroppable({
    id: `group:${node.path}`,
    data: { kind: "group", path: node.path },
  });

  const indent = { paddingLeft: `${depth * 12}px` } as const;
  return (
    <li>
      <ContextMenu>
        <ContextMenuTrigger asChild>
          <button
            ref={setNodeRef}
            onClick={() => toggleGroupCollapsed(node.path)}
            className={cn(
              "flex w-full items-center gap-1 rounded-md px-2 py-0.5 text-left text-xs uppercase tracking-wide text-muted-foreground hover:bg-accent",
              isOver && "bg-primary/10 ring-1 ring-inset ring-primary",
            )}
            style={indent}
          >
            <ChevronRight className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-90")} />
            {open ? <FolderOpen className="h-3.5 w-3.5" /> : <Folder className="h-3.5 w-3.5" />}
            <span className="truncate">{node.name}</span>
            {node.children.length === 0 && (
              <span className="ml-1 text-[10px] normal-case text-muted-foreground/50">empty</span>
            )}
          </button>
        </ContextMenuTrigger>
        <ContextMenuContent>
          {groupDeviceCount > 0 && (
            <ContextMenuItem onSelect={() => handlers.onLaunchGroup(node)}>
              Launch all in group ({groupDeviceCount} device{groupDeviceCount === 1 ? "" : "s"})
            </ContextMenuItem>
          )}
          {/* Edit has no interactive-auth carve-out — every device in the
              folder is editable, so this count is the RAW subtree size and
              can exceed the launchable count above. Its condition also
              covers the separator: launchable <= subtree, so if this row
              is absent the launch row is too. */}
          {subtreeDeviceCount > 0 && (
            <ContextMenuItem onSelect={() => handlers.onEditGroup(node)}>
              Edit all in group ({subtreeDeviceCount} device
              {subtreeDeviceCount === 1 ? "" : "s"})...
            </ContextMenuItem>
          )}
          {subtreeDeviceCount > 0 && <ContextMenuSeparator />}
          <ContextMenuItem onSelect={() => handlers.onAddDeviceInGroup(node.path)}>
            New device in this group...
          </ContextMenuItem>
          <ContextMenuItem onSelect={() => handlers.onAddSubgroup(node.path)}>
            New subgroup...
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onSelect={() => handlers.onRenameGroup(node.path)}>
            Rename group...
          </ContextMenuItem>
          <ContextMenuItem
            onSelect={() => handlers.onDeleteGroup(node.path)}
            className="text-destructive focus:text-destructive"
          >
            Delete group...
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onSelect={() => handlers.onExportSessions()}>
            Export sessions...
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
      {open && (
        <ul>
          {node.children.map((c, i) => (
            <TreeNodeView key={nodeKey(c, i)} node={c} depth={depth + 1} {...handlers} />
          ))}
        </ul>
      )}
    </li>
  );
}
