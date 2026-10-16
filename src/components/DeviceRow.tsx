import type { MouseEvent } from "react";

import { useDraggable } from "@dnd-kit/core";
import { CSS } from "@dnd-kit/utilities";
import { Link2 } from "lucide-react";

import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import type { DeviceMeta } from "@/lib/api";
import { deviceColorVar } from "@/lib/deviceColors";
import { cn } from "@/lib/utils";

export interface DeviceRowProps {
  device: DeviceMeta;
  active: boolean;
  /** v2.8.1 — this row is part of the sidebar multi-selection. Plain
   *  click selects one row; Cmd/Ctrl-click toggles; Shift-click
   *  extends over the visible range (see DeviceTree). */
  selected: boolean;
  /** Size of the effective multi-selection. When this row is
   *  `selected` and the count is ≥ 2, the context menu swaps to the
   *  bulk variant (Launch all / Clear selection). */
  selectionCount: number;
  /** How many of the selection will actually launch (interactive-auth
   *  devices are held back). Drives the menu label so it never promises
   *  more sessions than it opens. */
  selectionLaunchableCount: number;
  /** Count of open (non-ended) sessions targeting this device. 0 ==
   *  not connected. >0 == connected; a small count suffix renders
   *  when >1. */
  connectionCount: number;
  /** Tree depth. Drives the left indent (same `depth * 12` formula the
   *  group headers use) so a device and a sibling subgroup at the same
   *  depth line up — and a device nested under a group sits one level
   *  in from it. */
  depth: number;
  /** Selection click — receives the MouseEvent so DeviceTree can read
   *  the shift/cmd/ctrl modifiers. */
  onClick: (e: MouseEvent<HTMLButtonElement>) => void;
  /** Fires as the context menu opens, BEFORE its content renders —
   *  DeviceTree collapses the selection onto this row when it isn't
   *  already part of it. */
  onRowContextMenu: () => void;
  onConnect: () => void;
  /** Override the connect item's wording. Absent = the SSH sidebar's
   *  "Connect" / "Connect (new tab)". The Files sidebar (v5.0.0) renders
   *  the same tree with "Open file transfer" here, so the injected launch
   *  action always names what it actually opens. */
  connectLabel?: string;
  /** Bulk-launch every selected device (multi-selection menu). */
  onLaunchSelection: () => void;
  /** v6.3.0 — bulk-edit every selected device (multi-selection menu).
   *  Labeled by `selectionCount` (no launchability carve-out). */
  onEditSelection: () => void;
  onClearSelection: () => void;
  onEdit: () => void;
  onDelete: () => void;
  /** Export ALL sessions to CSV. Global action (not scoped to this
   *  device) — offered here so "right-click any device → Export sessions"
   *  works, matching the sidebar background + group menus. */
  onExport: () => void;
}

/**
 * One device leaf in the sidebar tree. One-line by design (Phase 7a
 * C6 density pass): a status dot, the device id, and a muted
 * host:port suffix. The dot's status text is sr-only — preserves
 * accessibility + the existing RTL "not connected" assertions
 * without burning horizontal space on a badge.
 */
export function DeviceRow({
  device,
  active,
  selected,
  selectionCount,
  selectionLaunchableCount,
  connectionCount,
  depth,
  onClick,
  onRowContextMenu,
  onConnect,
  connectLabel,
  onLaunchSelection,
  onEditSelection,
  onClearSelection,
  onEdit,
  onDelete,
  onExport,
}: DeviceRowProps) {
  const connected = connectionCount > 0;
  const statusLabel = connected
    ? connectionCount > 1
      ? `connected · ${connectionCount} sessions`
      : "connected"
    : "not connected";
  const hostLabel = device.port !== 22 ? `${device.host}:${device.port}` : device.host;
  // Bulk menu only when the row sits inside a 2+ selection — a
  // single-selected row keeps the ordinary per-device menu.
  const multiMenu = selected && selectionCount > 1;

  // Drag source for moving the device between groups. Pointer-only (the
  // DndContext registers no KeyboardSensor) so the row's Enter→connect
  // binding below is untouched. The pointer sensor's distance
  // activation constraint (set on the DndContext) keeps a plain click
  // or right-click from being read as a drag.
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: device.id,
    data: { kind: "device", currentGroup: device.group ?? null },
  });
  // Per-device accent color (Phase 1) → a left-edge stripe drawn with an
  // inset box-shadow so it never shifts the tree's indent alignment.
  const accent = deviceColorVar(device.color);
  // Indent to match group headers (`depth * 12`), merged with the accent
  // stripe and any in-flight drag transform.
  const rowStyle = {
    paddingLeft: `${depth * 12}px`,
    ...(accent ? { boxShadow: `inset 3px 0 0 0 ${accent}` } : {}),
    ...(transform
      ? { transform: CSS.Translate.toString(transform), opacity: isDragging ? 0.4 : undefined }
      : {}),
  };

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <button
          ref={setNodeRef}
          style={rowStyle}
          {...attributes}
          {...listeners}
          onClick={onClick}
          onContextMenu={onRowContextMenu}
          onDoubleClick={(e) => {
            // Double-click is a Connect shortcut (matches SecureCRT).
            // preventDefault stops the second click from re-firing the
            // single-click select, which would race with the focus
            // shift that the new session tab triggers.
            e.preventDefault();
            onConnect();
          }}
          onKeyDown={(e) => {
            // A focused row + Enter connects. A button's default
            // activation on Enter would fire onClick (= select), which
            // is a less useful binding once the row is already focused.
            // preventDefault keeps that synthesized click from firing
            // so we don't both select-then-connect on the same press.
            if (e.key === "Enter" && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey) {
              e.preventDefault();
              onConnect();
            }
          }}
          data-selected={selected ? "true" : undefined}
          className={cn(
            "flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-sm hover:bg-accent",
            active && "bg-accent",
            // Selection tint outranks the active tint (cn/tailwind-merge
            // keeps the later bg-*), so a multi-selection reads as one
            // uniform highlight across every member row.
            selected && "bg-primary/15",
          )}
        >
          <span
            aria-hidden
            className={cn(
              "h-1.5 w-1.5 shrink-0 rounded-full",
              connected ? "bg-emerald-500" : "bg-muted-foreground/40",
            )}
          />
          <span className="sr-only">{statusLabel}</span>
          {/* Tags deliberately render NO inline chips (decision 2026-08-19):
              at sidebar widths even one chip starves the name — a synced
              device carries three (lab + role:<slug> + dmvpn). The name and
              host own the row; tags stay discoverable in this tooltip and
              actionable via the sidebar tag filter. */}
          <span
            className="min-w-0 truncate font-mono text-sm"
            title={device.tags.length > 0 ? `${device.id} · ${device.tags.join(", ")}` : device.id}
          >
            {device.id}
          </span>
          {device.jump_via && (
            // v6.5.0 — this device tunnels through a jump host. A glyph,
            // not text: the row's width budget belongs to id + host.
            <Link2
              aria-label={`connects via ${device.jump_via}`}
              className="h-3 w-3 shrink-0 text-muted-foreground"
            >
              <title>{`via ${device.jump_via}`}</title>
            </Link2>
          )}
          {connectionCount > 1 && (
            <span className="shrink-0 text-[10px] tabular-nums text-muted-foreground">
              ×{connectionCount}
            </span>
          )}
          {/* min-w floor + ellipsis: without the floor, flex shrinks
              both text spans proportionally, so a long device id
              squeezes even a short host:port into clipping. The
              text-right keeps short addresses on the row edge inside
              the floored box; tooltips recover anything truncated. */}
          <span
            className="ml-auto min-w-24 shrink truncate text-right text-xs text-muted-foreground"
            title={hostLabel}
          >
            {hostLabel}
          </span>
        </button>
      </ContextMenuTrigger>
      <ContextMenuContent>
        {multiMenu ? (
          <>
            <ContextMenuItem onSelect={onLaunchSelection}>
              Launch all ({selectionLaunchableCount} device
              {selectionLaunchableCount === 1 ? "" : "s"})
            </ContextMenuItem>
            {/* Edit counts the WHOLE selection — unlike Launch all there
                is no interactive-auth carve-out (every row is editable). */}
            <ContextMenuItem onSelect={onEditSelection}>
              Edit {selectionCount} devices...
            </ContextMenuItem>
            <ContextMenuItem onSelect={onClearSelection}>Clear selection</ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={onExport}>Export sessions...</ContextMenuItem>
          </>
        ) : (
          <>
            <ContextMenuItem onSelect={onConnect}>
              {connectLabel ?? (connected ? "Connect (new tab)" : "Connect")}
            </ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={onEdit}>Edit device...</ContextMenuItem>
            <ContextMenuItem
              onSelect={onDelete}
              className="text-destructive focus:text-destructive"
            >
              Delete device...
            </ContextMenuItem>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={onExport}>Export sessions...</ContextMenuItem>
          </>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}
