import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  File as FileIcon,
  Folder,
  FolderPlus,
  HardDrive,
  Home,
  Link2,
  RefreshCw,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type DragEvent,
  type KeyboardEvent,
  type MouseEvent,
} from "react";

import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import type { DirListing, FileEntry, LocalRoot } from "@/lib/api";
import { FILES_DND_MIME, serializeFilesDrag, type FilesDragPayload } from "@/lib/fileDnd";
import {
  formatBytes,
  formatMtime,
  joinChildPath,
  parentDir,
  sortEntries,
  type PaneSort,
  type SortKey,
} from "@/lib/fileBrowser";
import { cn } from "@/lib/utils";
import type { PaneSide } from "@/stores/filesStore";

/** Row height in px. Fixed so the virtualizer needs no measurement pass —
 *  every row is one line of text by design. */
const ROW_HEIGHT = 24;

export interface FileListPaneProps {
  side: PaneSide;
  /** The Files session this pane belongs to — carried in the drag payload so
   *  a drop is only ever honored within its own session. */
  sessionId: string;
  /** Pane heading — "Local" or the device label. */
  title: string;
  /** Canonical path to display: the resolved listing's `path` (which the
   *  backend canonicalized), falling back to the requested path while the
   *  first listing is in flight. */
  path: string;
  listing: DirListing | undefined;
  isLoading: boolean;
  error: unknown;
  sort: PaneSort;
  showHidden: boolean;
  /** True while this pane's TAB is visible. Hidden tabs don't lay out, so
   *  the virtualizer's cached rect is stale and must be re-measured when
   *  the tab comes back (the `TerminalPane` re-fit lesson). */
  active: boolean;
  /** Read-only: the remote pane of a dead session. Navigation and
   *  mutations are suppressed while the reconnect banner is up. */
  disabled?: boolean;
  /** Suppress ONLY transfer initiation (the toolbar/context Transfer action),
   *  while leaving browsing intact. The LOCAL pane uses this when the SFTP
   *  session is dead: a local upload has nowhere to land, but the user must
   *  still be able to browse local files (F4). `disabled` implies this. */
  transferDisabled?: boolean;
  /** Local pane only — the roots menu (home, `/`, Windows drives). */
  roots?: LocalRoot[];
  onNavigate: (path: string) => void;
  onHome: () => void;
  onRefresh: () => void;
  onToggleHidden: () => void;
  onSort: (key: SortKey) => void;
  onNewFolder: () => void;
  onRename: (entry: FileEntry) => void;
  onDelete: (entries: FileEntry[]) => void;
  /** Transfer these entries to the OTHER pane's current directory — the
   *  toolbar button, the context-menu item, and a FILE double-click all end
   *  up here. The parent owns the conflict pre-flight and the enqueue. */
  onTransfer: (entries: FileEntry[]) => void;
  /** Verb for this pane's direction: "Download" on the remote side (bytes
   *  come toward the user), "Upload" on the local side. */
  transferVerb: string;
  /** True while a row drag from the OTHER pane is in flight, i.e. this pane
   *  may accept a drop. The parent tracks the source side. */
  canAcceptDrop: boolean;
  /** Parent-driven drop-ring: on macOS the webview never sees the DOM
   *  `dragover` for an in-app drag (wry intercepts the session), so the
   *  parent lights the ring from the native drag event instead. Combined
   *  with the DOM-driven ring for platforms/tests where `dragover` does
   *  fire. */
  dropRingActive: boolean;
  /** A row drag started here (the payload) or ended (`null`). The parent
   *  stashes the payload; the transfer is completed from the stash (never
   *  from `dataTransfer`, which wry doesn't deliver to the DOM drop). */
  onDragChange: (payload: FilesDragPayload | null) => void;
  /** A drop landed on this pane — the parent transfers the stashed drag to
   *  this side. Carries no payload: `dataTransfer` is not trusted/read. */
  onDropRows: () => void;
}

/**
 * One side of the dual-pane file browser (v5.0.0). Local and remote render
 * through this same component — the differences are all props (the remote
 * side additionally shows POSIX permissions, the local side offers a roots
 * menu), so the two panes can never drift in behavior.
 *
 * Rows are virtualized (`@tanstack/react-virtual`): a 10k-entry server
 * directory is routine, and the backend caps a listing at 20 000 entries
 * with a `truncated` flag which this pane surfaces explicitly.
 *
 * Selection is component-local ephemeral state (never a store): it dies
 * with the directory, exactly like `DeviceTree`'s sidebar selection, whose
 * click conventions it copies (plain / Cmd-Ctrl toggle / Shift range over
 * render order).
 */
export function FileListPane({
  side,
  sessionId,
  title,
  path,
  listing,
  isLoading,
  error,
  sort,
  showHidden,
  active,
  disabled = false,
  transferDisabled = false,
  roots,
  onNavigate,
  onHome,
  onRefresh,
  onToggleHidden,
  onSort,
  onNewFolder,
  onRename,
  onDelete,
  onTransfer,
  transferVerb,
  canAcceptDrop,
  dropRingActive,
  onDragChange,
  onDropRows,
}: FileListPaneProps) {
  const isRemote = side === "remote";
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [draft, setDraft] = useState(path);
  const [dropTarget, setDropTarget] = useState(false);
  const [selection, setSelection] = useState<{ names: ReadonlySet<string>; anchor: string | null }>(
    {
      names: new Set(),
      anchor: null,
    },
  );

  // Follow the authoritative path: the backend canonicalizes what the user
  // typed, so the bar must show what was actually read, not the input. The
  // selection resets with it (names are only meaningful in one directory).
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  useEffect(() => {
    setDraft(path);
    setSelection({ names: new Set(), anchor: null });
  }, [path]);

  const rows = useMemo(
    () => sortEntries(listing?.entries ?? [], sort, showHidden),
    [listing, sort, showHidden],
  );

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  // A pane that mounted inside a HIDDEN tab (Radix `forceMount` +
  // `display:none`) measured 0×0, so its visible window is empty. The
  // browser's ResizeObserver fires when the box appears — this re-measure
  // is the belt to that braces, matching TerminalPane's explicit re-fit on
  // activation (which exists because WKWebView doesn't always deliver it).
  useEffect(() => {
    if (active) virtualizer.measure();
  }, [active, virtualizer]);

  // Effective selection: stored names ∩ current rows, so an entry deleted
  // or filtered out (hidden toggle) is inert rather than pruned by effect.
  const selected = useMemo(() => {
    if (selection.names.size === 0) return selection.names;
    const out = new Set<string>();
    for (const r of rows) if (selection.names.has(r.name)) out.add(r.name);
    return out;
  }, [selection.names, rows]);

  const selectedEntries = useMemo(() => rows.filter((r) => selected.has(r.name)), [rows, selected]);

  const childPath = (entry: FileEntry) => joinChildPath(listing?.path ?? path, entry.name);

  const open = (entry: FileEntry) => {
    if (disabled) return;
    // Directories navigate; anything else transfers to the other pane's
    // current directory (plan veto #4). An
    // explicitly chosen symlink is allowed through: the engine follows a
    // symlinked FILE that the user picked, and refuses only links it meets
    // while walking a directory (T43).
    if (entry.kind === "dir") onNavigate(childPath(entry));
    else onTransfer([entry]);
  };

  const onRowClick = (entry: FileEntry, e: MouseEvent<HTMLElement>) => {
    const name = entry.name;
    if (e.shiftKey && selection.anchor !== null) {
      const order = rows.map((r) => r.name);
      const a = order.indexOf(selection.anchor);
      const b = order.indexOf(name);
      if (a !== -1 && b !== -1) {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        setSelection({ names: new Set(order.slice(lo, hi + 1)), anchor: selection.anchor });
        return;
      }
    }
    if (e.metaKey || e.ctrlKey) {
      const names = new Set(selected);
      if (names.has(name)) names.delete(name);
      else names.add(name);
      setSelection({ names, anchor: name });
      return;
    }
    setSelection({ names: new Set([name]), anchor: name });
  };

  /** Right-clicking outside the selection collapses onto that row first,
   *  so a menu action can only ever target highlighted rows (the
   *  file-manager convention `DeviceTree` also follows). */
  const onRowContextMenu = (entry: FileEntry) => {
    if (!selected.has(entry.name)) {
      setSelection({ names: new Set([entry.name]), anchor: entry.name });
    }
  };

  /**
   * Start a row drag. Dragging a row that ISN'T selected drags just that row
   * (and selects it) — the Finder/Explorer convention; dragging a selected
   * row drags the whole selection.
   *
   * Plain HTML5 DnD on purpose: these rows are not dnd-kit draggables, so
   * they never interact with `TerminalArea`'s tab-drag context (see
   * `lib/fileDnd.ts`).
   */
  const onRowDragStart = (entry: FileEntry, e: DragEvent<HTMLElement>) => {
    let dragged: FileEntry[];
    if (selected.has(entry.name)) {
      dragged = selectedEntries;
    } else {
      dragged = [entry];
      setSelection({ names: new Set([entry.name]), anchor: entry.name });
    }
    const payload: FilesDragPayload = {
      side,
      sessionId,
      paths: dragged.map(childPath),
    };
    e.dataTransfer.effectAllowed = "copy";
    // `setData` is kept only so the OS shows a copy cursor; the transfer is
    // completed from the stashed payload the parent holds, never by reading
    // this back (wry doesn't deliver it to the DOM drop — see FilesPane).
    e.dataTransfer.setData(FILES_DND_MIME, serializeFilesDrag(payload));
    onDragChange(payload);
  };

  const onPaneDragOver = (e: DragEvent<HTMLElement>) => {
    // `canAcceptDrop` is true only while a row drag from the OTHER pane is
    // live, so it alone identifies our drag — no need to sniff
    // `dataTransfer.types` (which some webviews withhold during dragover).
    if (disabled || !canAcceptDrop) return;
    // preventDefault is what marks this element as a drop target at all.
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
    setDropTarget(true);
  };

  const onPaneDragLeave = (e: DragEvent<HTMLElement>) => {
    // Moving between child rows fires `dragleave` on the pane too; only a
    // pointer that actually left the pane should drop the highlight.
    const next = e.relatedTarget;
    if (next instanceof Node && e.currentTarget.contains(next)) return;
    setDropTarget(false);
  };

  const onPaneDrop = (e: DragEvent<HTMLElement>) => {
    setDropTarget(false);
    if (disabled || !canAcceptDrop) return;
    e.preventDefault();
    // The parent transfers the stashed drag to this side; `dataTransfer` is
    // never read (untrusted, and empty under wry).
    onDropRows();
  };

  // Prefer the listing's canonical parent; fall back to computing it from the
  // current path when no listing resolved — crucially after a listing ERROR
  // (permission-denied on a subdir), so the user can still walk back up
  // instead of being trapped (F6). `null` only at the true root.
  const parentTarget = listing?.parent ?? parentDir(listing?.path ?? path);

  const goUp = () => {
    if (disabled || !parentTarget) return;
    onNavigate(parentTarget);
  };

  const submitPath = () => {
    if (disabled) return;
    const trimmed = draft.trim();
    if (trimmed.length === 0) return;
    onNavigate(trimmed);
  };

  const copyPath = () => {
    const target =
      selectedEntries.length > 0
        ? selectedEntries.map(childPath).join("\n")
        : (listing?.path ?? path);
    void navigator.clipboard?.writeText(target).catch(() => {});
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    if (e.key === "Enter") {
      if (selectedEntries.length === 1) {
        e.preventDefault();
        open(selectedEntries[0]);
      }
      return;
    }
    // Cmd/Ctrl+Backspace is the macOS delete gesture; a bare Backspace
    // walks up a directory (the file-manager binding).
    if (e.key === "Backspace") {
      e.preventDefault();
      if (e.metaKey || e.ctrlKey) {
        if (selectedEntries.length > 0) onDelete(selectedEntries);
      } else {
        goUp();
      }
      return;
    }
    if (e.key === "Delete") {
      e.preventDefault();
      if (selectedEntries.length > 0) onDelete(selectedEntries);
      return;
    }
    if (e.key === "F2") {
      e.preventDefault();
      if (selectedEntries.length === 1) onRename(selectedEntries[0]);
    }
  };

  const errorMessage = error ? (error instanceof Error ? error.message : String(error)) : null;

  const showDropRing = (dropTarget || dropRingActive) && canAcceptDrop && !disabled;

  return (
    <div
      className={cn(
        "flex h-full min-h-0 w-full flex-col",
        showDropRing && "ring-2 ring-inset ring-primary",
      )}
      data-testid={`files-pane-${side}`}
      data-drop-target={showDropRing ? "true" : undefined}
      onDragOver={onPaneDragOver}
      onDragLeave={onPaneDragLeave}
      onDrop={onPaneDrop}
    >
      {/* Toolbar: title, path bar, navigation + directory actions. */}
      <div className="flex shrink-0 flex-col gap-1 border-b border-border px-2 py-1.5">
        <div className="flex items-center gap-1">
          <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {title}
          </span>
          <form
            className="flex min-w-0 flex-1 items-center"
            onSubmit={(e) => {
              e.preventDefault();
              submitPath();
            }}
          >
            <input
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              disabled={disabled}
              aria-label={`${title} path`}
              data-testid={`files-${side}-path`}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              className="min-w-0 flex-1 rounded border border-input bg-background px-2 py-0.5 font-mono text-xs outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
            />
          </form>
          <ToolButton
            label="Up one directory"
            testId={`files-${side}-up`}
            disabled={disabled || !parentTarget}
            onClick={goUp}
          >
            <ArrowUp className="h-3.5 w-3.5" />
          </ToolButton>
          <ToolButton
            label="Home directory"
            testId={`files-${side}-home`}
            disabled={disabled}
            onClick={onHome}
          >
            <Home className="h-3.5 w-3.5" />
          </ToolButton>
          {roots && roots.length > 0 && (
            <Popover>
              <PopoverTrigger asChild>
                <button
                  type="button"
                  aria-label="Filesystem roots"
                  title="Filesystem roots"
                  data-testid={`files-${side}-roots`}
                  className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                >
                  <HardDrive className="h-3.5 w-3.5" />
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-56 p-1">
                {roots.map((r) => (
                  <button
                    key={r.path}
                    type="button"
                    onClick={() => onNavigate(r.path)}
                    className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-accent"
                  >
                    <HardDrive className="h-3 w-3 shrink-0 text-muted-foreground" />
                    <span className="truncate">{r.label}</span>
                    <span className="ml-auto shrink-0 truncate pl-2 font-mono text-[10px] text-muted-foreground">
                      {r.path}
                    </span>
                  </button>
                ))}
              </PopoverContent>
            </Popover>
          )}
          <ToolButton label="Refresh listing" testId={`files-${side}-refresh`} onClick={onRefresh}>
            <RefreshCw className="h-3.5 w-3.5" />
          </ToolButton>
          {/* Direction is the pane's geometry: the local pane is on the left,
              so its transfer arrow points right (and vice versa). */}
          <ToolButton
            label={`${transferVerb} selected`}
            testId={`files-${side}-transfer`}
            disabled={disabled || transferDisabled || selectedEntries.length === 0}
            onClick={() => onTransfer(selectedEntries)}
          >
            {isRemote ? (
              <ArrowLeft className="h-3.5 w-3.5" />
            ) : (
              <ArrowRight className="h-3.5 w-3.5" />
            )}
          </ToolButton>
          <ToolButton
            label="New folder"
            testId={`files-${side}-mkdir`}
            disabled={disabled}
            onClick={onNewFolder}
          >
            <FolderPlus className="h-3.5 w-3.5" />
          </ToolButton>
          <button
            type="button"
            onClick={onToggleHidden}
            aria-pressed={showHidden}
            title="Show hidden files"
            data-testid={`files-${side}-hidden`}
            className={cn(
              "shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium",
              showHidden
                ? "bg-accent text-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground",
            )}
          >
            .hidden
          </button>
        </div>
      </div>

      {/* Column headers double as the sort control (dirs always first). */}
      <div className="flex shrink-0 items-center gap-2 border-b border-border bg-muted/30 px-2 py-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        <SortHeader
          className="min-w-0 flex-1"
          label="Name"
          sortKey="name"
          sort={sort}
          side={side}
          onSort={onSort}
        />
        <SortHeader
          className="w-20 text-right"
          label="Size"
          sortKey="size"
          sort={sort}
          side={side}
          onSort={onSort}
        />
        <SortHeader
          className="w-32 text-right"
          label="Modified"
          sortKey="mtime"
          sort={sort}
          side={side}
          onSort={onSort}
        />
        {isRemote && <span className="w-20 text-right">Perms</span>}
      </div>

      <ContextMenu>
        <ContextMenuTrigger asChild>
          <div className="flex min-h-0 flex-1 flex-col">
            {/* Truncation notice ABOVE the scroller as a sticky bar. It used
                to render at the BOTTOM of the scroll container — i.e. below
                the virtualizer's full-height spacer (hundreds of thousands of
                px), so it was off-screen in the exact 20k-cap case it exists
                for (F5). */}
            {listing?.truncated && (
              <div
                className="shrink-0 border-b border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-400"
                data-testid={`files-${side}-truncated`}
              >
                Listing truncated — this folder holds more entries than Transit shows.
              </div>
            )}
            <div
              ref={scrollRef}
              // A multi-select list of options, which is what the selection +
              // keyboard model actually is — and it gives the rows an
              // interactive role (a plain div with onClick is neither
              // announced nor keyboard-reachable).
              role="listbox"
              aria-multiselectable
              tabIndex={0}
              onKeyDown={onKeyDown}
              data-testid={`files-${side}-list`}
              aria-label={`${title} files`}
              className="min-h-0 flex-1 overflow-auto outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring"
            >
              {errorMessage ? (
                <div
                  className="m-2 rounded border border-destructive/40 bg-destructive/10 px-2 py-1.5 text-xs text-destructive"
                  role="alert"
                >
                  {errorMessage}
                </div>
              ) : isLoading ? (
                <div className="px-3 py-6 text-center text-xs text-muted-foreground">Loading…</div>
              ) : disabled && !listing ? (
                // The session died before this pane ever listed anything. (If it
                // HAD listed, the cached rows stay on screen so the user can
                // still see where they were — no need for a notice.)
                <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                  Disconnected — reconnect to browse this device.
                </div>
              ) : rows.length === 0 ? (
                <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                  {(listing?.entries.length ?? 0) > 0
                    ? "Only hidden entries here — toggle .hidden to show them."
                    : "This folder is empty."}
                </div>
              ) : (
                // The virtualizer's spacer sits between the listbox and its
                // options; `presentation` keeps it out of the a11y tree so the
                // option/listbox relationship still reads correctly.
                <div
                  role="presentation"
                  style={{ height: virtualizer.getTotalSize(), position: "relative" }}
                >
                  {virtualizer.getVirtualItems().map((item) => {
                    const entry = rows[item.index];
                    if (!entry) return null;
                    return (
                      <Row
                        key={entry.name}
                        entry={entry}
                        isRemote={isRemote}
                        selected={selected.has(entry.name)}
                        style={{
                          position: "absolute",
                          top: 0,
                          left: 0,
                          width: "100%",
                          height: `${ROW_HEIGHT}px`,
                          transform: `translateY(${item.start}px)`,
                        }}
                        onClick={(e) => onRowClick(entry, e)}
                        onContextMenu={() => onRowContextMenu(entry)}
                        onDoubleClick={() => open(entry)}
                        draggable={!disabled}
                        onDragStart={(e) => onRowDragStart(entry, e)}
                        onDragEnd={() => onDragChange(null)}
                      />
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem
            disabled={disabled || transferDisabled || selectedEntries.length === 0}
            onSelect={() => selectedEntries.length > 0 && onTransfer(selectedEntries)}
            data-testid={`files-${side}-ctx-transfer`}
          >
            {transferVerb}
          </ContextMenuItem>
          <ContextMenuSeparator />
          {selectedEntries.length === 1 && selectedEntries[0].kind === "dir" && (
            <>
              <ContextMenuItem disabled={disabled} onSelect={() => open(selectedEntries[0])}>
                Open
              </ContextMenuItem>
              <ContextMenuSeparator />
            </>
          )}
          <ContextMenuItem disabled={disabled} onSelect={onNewFolder}>
            New folder...
          </ContextMenuItem>
          <ContextMenuItem
            disabled={disabled || selectedEntries.length !== 1}
            onSelect={() => selectedEntries.length === 1 && onRename(selectedEntries[0])}
          >
            Rename...
          </ContextMenuItem>
          <ContextMenuItem
            disabled={disabled || selectedEntries.length === 0}
            className="text-destructive focus:text-destructive"
            onSelect={() => selectedEntries.length > 0 && onDelete(selectedEntries)}
          >
            Delete...
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem onSelect={onRefresh}>Refresh</ContextMenuItem>
          <ContextMenuItem onSelect={copyPath}>Copy path</ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
    </div>
  );
}

function ToolButton({
  label,
  testId,
  disabled,
  onClick,
  children,
}: {
  label: string;
  testId: string;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      data-testid={testId}
      className="shrink-0 rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {children}
    </button>
  );
}

function SortHeader({
  label,
  sortKey,
  sort,
  side,
  className,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  sort: PaneSort;
  side: PaneSide;
  className?: string;
  onSort: (key: SortKey) => void;
}) {
  const activeKey = sort.key === sortKey;
  return (
    <button
      type="button"
      onClick={() => onSort(sortKey)}
      data-testid={`files-${side}-sort-${sortKey}`}
      className={cn(
        "truncate uppercase hover:text-foreground",
        activeKey && "text-foreground",
        className,
      )}
    >
      {label}
      {activeKey ? (sort.asc ? " ▲" : " ▼") : ""}
    </button>
  );
}

function Row({
  entry,
  isRemote,
  selected,
  style,
  onClick,
  onContextMenu,
  onDoubleClick,
  draggable,
  onDragStart,
  onDragEnd,
}: {
  entry: FileEntry;
  isRemote: boolean;
  selected: boolean;
  style: React.CSSProperties;
  onClick: (e: MouseEvent<HTMLElement>) => void;
  onContextMenu: () => void;
  onDoubleClick: () => void;
  draggable: boolean;
  onDragStart: (e: DragEvent<HTMLElement>) => void;
  onDragEnd: () => void;
}) {
  const Icon = entry.kind === "dir" ? Folder : entry.kind === "symlink" ? Link2 : FileIcon;
  return (
    <div
      role="option"
      aria-selected={selected}
      style={style}
      onClick={onClick}
      onContextMenu={onContextMenu}
      onDoubleClick={onDoubleClick}
      draggable={draggable}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      data-selected={selected ? "true" : undefined}
      className={cn(
        "flex cursor-default items-center gap-2 px-2 text-xs hover:bg-accent",
        selected && "bg-primary/15",
      )}
    >
      <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      {/* Remote-supplied names render as React text nodes — never markup
          (T43: a hostile server can't inject anything through a filename). */}
      <span className="min-w-0 flex-1 truncate font-mono" title={entry.name}>
        {entry.name}
      </span>
      <span className="w-20 shrink-0 text-right tabular-nums text-muted-foreground">
        {entry.kind === "dir" ? "—" : formatBytes(entry.size)}
      </span>
      <span className="w-32 shrink-0 text-right tabular-nums text-muted-foreground">
        {formatMtime(entry.mtime)}
      </span>
      {isRemote && (
        <span className="w-20 shrink-0 truncate text-right font-mono text-muted-foreground">
          {entry.perms ?? "—"}
        </span>
      )}
    </div>
  );
}
