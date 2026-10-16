import { useMemo, useState } from "react";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronDown,
  ChevronRight,
  Folder,
  PanelLeft,
  PanelLeftClose,
  Pencil,
  Plus,
  RefreshCw,
  Send,
  Trash2,
} from "lucide-react";

import { EditionChip, SettingsButton } from "@/components/SettingsButton";
import { EndpointFolderView } from "@/components/api/EndpointFolderView";
import { ApiUserCollections } from "@/components/ApiUserCollections";
import { AddApiSessionDialog } from "@/components/dialogs/AddApiSessionDialog";
import { DeleteConfirmDialog } from "@/components/dialogs/DeleteConfirmDialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SidebarResizeHandle, useSidebarWidth } from "@/components/SidebarResizeHandle";
import { listApiSessions, type ApiSessionMeta } from "@/lib/api";
import { type ApiRequestTemplate } from "@/lib/apiCollections";
import { bundledCollectionFor } from "@/lib/bundledCollections";
import { useDeleteApiSession } from "@/lib/mutations";
import { useUiStore } from "@/stores/uiStore";

const KIND_LABEL: Record<ApiSessionMeta["kind"], string> = {
  site_manager: "Cloud",
  network_local: "Self-hosted",
  connector_proxy: "Proxy",
  generic: "Custom",
};

type DialogState =
  | { kind: "none" }
  | { kind: "add" }
  | { kind: "edit"; session: ApiSessionMeta }
  | { kind: "delete"; session: ApiSessionMeta };

/** A folder node in the API-controller tree. `sessions` are controllers
 *  directly in this group; `children` are nested subgroups. */
type ApiTreeNode = {
  name: string;
  path: string;
  children: ApiTreeNode[];
  sessions: ApiSessionMeta[];
};

/** Build a nested tree from controllers' slash-path `group` fields, so
 *  `group = "MSP/ClientA"` renders root → MSP → ClientA → controller.
 *  Ungrouped controllers sit at the root. Mirrors the SSH DeviceTree. */
function buildApiTree(sessions: ApiSessionMeta[]): ApiTreeNode {
  const root: ApiTreeNode = { name: "", path: "", children: [], sessions: [] };
  for (const s of sessions) {
    const segs = (s.group ?? "")
      .split("/")
      .map((x) => x.trim())
      .filter(Boolean);
    let node = root;
    let acc = "";
    for (const seg of segs) {
      acc = acc === "" ? seg : `${acc}/${seg}`;
      let child = node.children.find((c) => c.name === seg);
      if (!child) {
        child = { name: seg, path: acc, children: [], sessions: [] };
        node.children.push(child);
      }
      node = child;
    }
    node.sessions.push(s);
  }
  return root;
}

type RowHandlers = {
  onLaunch: (s: ApiSessionMeta) => void;
  onEdit: (s: ApiSessionMeta) => void;
  onDelete: (s: ApiSessionMeta) => void;
  /** Load an endpoint template into the controller's pane (opens/focuses
   *  its tab). Fired by clicking an endpoint nested under the controller. */
  onLoadRequest: (s: ApiSessionMeta, t: ApiRequestTemplate) => void;
};

/** One controller row: a disclosure chevron (its endpoint collection,
 *  collapsed by default), launch (name), and edit/delete (hover). When
 *  expanded, the bundled endpoint tree renders nested beneath it. */
function ControllerRow({
  session: s,
  depth,
  expanded,
  onToggleExpand,
  onLaunch,
  onEdit,
  onDelete,
  onLoadRequest,
}: {
  session: ApiSessionMeta;
  depth: number;
  expanded: boolean;
  onToggleExpand: () => void;
} & RowHandlers) {
  const collection = useMemo(() => bundledCollectionFor(s.vendor, s.kind), [s.vendor, s.kind]);
  const [folderCollapsed, setFolderCollapsed] = useState<Set<string>>(new Set());
  const toggleFolder = (id: string) =>
    setFolderCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div>
      <div
        className="group flex items-center gap-1 py-1.5 pr-3 hover:bg-accent"
        style={{ paddingLeft: 6 + depth * 14 }}
      >
        {/* Always expandable: even a controller with no bundled collection
            can host the user's own saved/imported collections. */}
        <button
          type="button"
          onClick={onToggleExpand}
          className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-foreground"
          aria-label={expanded ? `Collapse ${s.name} endpoints` : `Show ${s.name} endpoints`}
        >
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5" />
          )}
        </button>
        <button
          type="button"
          onClick={() => onLaunch(s)}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
          title={`Launch ${s.name}`}
        >
          <Send className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-sm">{s.name}</span>
            <span className="block truncate text-[11px] text-muted-foreground">
              {s.vendor} · {KIND_LABEL[s.kind]}
              {s.host ? ` · ${s.host}` : ""}
            </span>
          </span>
        </button>
        <div className="flex shrink-0 items-center gap-0.5 opacity-0 group-hover:opacity-100">
          <button
            type="button"
            onClick={() => onEdit(s)}
            className="rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
            aria-label={`Edit ${s.name}`}
            title="Edit"
          >
            <Pencil className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => onDelete(s)}
            className="rounded p-1 text-muted-foreground hover:bg-background hover:text-destructive"
            aria-label={`Delete ${s.name}`}
            title="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      {expanded && (
        <>
          {collection && (
            <EndpointFolderView
              folder={collection.root}
              depth={depth + 1}
              collapsed={folderCollapsed}
              onToggle={toggleFolder}
              onPick={(t) => onLoadRequest(s, t)}
            />
          )}
          <ApiUserCollections
            apiSessionId={s.id}
            depth={depth + 1}
            onPick={(t) => onLoadRequest(s, t)}
          />
        </>
      )}
    </div>
  );
}

/** Recursively render a tree node: its controllers, then its subfolders
 *  (each a collapsible header). */
function ApiGroupView({
  node,
  depth,
  collapsed,
  onToggle,
  expandedControllers,
  onToggleExpand,
  ...handlers
}: {
  node: ApiTreeNode;
  depth: number;
  collapsed: Set<string>;
  onToggle: (path: string) => void;
  expandedControllers: Set<string>;
  onToggleExpand: (id: string) => void;
} & RowHandlers) {
  return (
    <>
      {node.sessions.map((s) => (
        <ControllerRow
          key={s.id}
          session={s}
          depth={depth}
          expanded={expandedControllers.has(s.id)}
          onToggleExpand={() => onToggleExpand(s.id)}
          {...handlers}
        />
      ))}
      {node.children.map((child) => {
        const isCollapsed = collapsed.has(child.path);
        return (
          <div key={child.path}>
            <button
              type="button"
              onClick={() => onToggle(child.path)}
              className="flex w-full items-center gap-1 py-1 pr-3 text-xs font-medium text-muted-foreground hover:bg-accent"
              style={{ paddingLeft: 8 + depth * 14 }}
            >
              {isCollapsed ? (
                <ChevronRight className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5 shrink-0" />
              )}
              <Folder className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate">{child.name}</span>
            </button>
            {!isCollapsed && (
              <ApiGroupView
                node={child}
                depth={depth + 1}
                collapsed={collapsed}
                onToggle={onToggle}
                expandedControllers={expandedControllers}
                onToggleExpand={onToggleExpand}
                {...handlers}
              />
            )}
          </div>
        );
      })}
    </>
  );
}

/**
 * v4.0.0 — the "APIs" sidebar, shown when the left-rail PanelSwitcher is
 * on `apis`. The HTTP-world sibling of the device `Sidebar`: lists
 * `[[api_session]]` controllers, launches them into the Postman pane
 * (wired next), and manages add/edit/delete. Server state lives in
 * TanStack Query (`["apiSessions"]`), never the store.
 */
export function ApiSidebar() {
  const [search, setSearch] = useState("");
  const [dialog, setDialog] = useState<DialogState>({ kind: "none" });
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const openApiTab = useUiStore((s) => s.openApiTab);
  const queryClient = useQueryClient();

  const { data, error, isLoading, isRefetching } = useQuery({
    queryKey: ["apiSessions"],
    queryFn: listApiSessions,
  });
  const deleteMutation = useDeleteApiSession();

  const filtered = useMemo<ApiSessionMeta[]>(() => {
    if (!data) return [];
    const needle = search.trim().toLowerCase();
    if (!needle) return data;
    return data.filter(
      (s) =>
        s.id.toLowerCase().includes(needle) ||
        s.name.toLowerCase().includes(needle) ||
        (s.host ?? "").toLowerCase().includes(needle),
    );
  }, [data, search]);

  // Group-folder collapse state (ephemeral, per mount). Distinct from the
  // sidebar-wide `collapsed` above.
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const toggleGroup = (path: string) =>
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  const tree = useMemo(() => buildApiTree(filtered), [filtered]);
  const searching = search.trim() !== "";

  // Which controllers have their endpoint collection expanded (collapsed
  // by default). Ephemeral, per mount.
  const [expandedControllers, setExpandedControllers] = useState<Set<string>>(new Set());
  const toggleController = (id: string) =>
    setExpandedControllers((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const launchApiRequest = useUiStore((s) => s.launchApiRequest);

  const rowHandlers: RowHandlers = {
    onLaunch: (s) => openApiTab(s.id, s.name),
    onEdit: (s) => setDialog({ kind: "edit", session: s }),
    onDelete: (s) => setDialog({ kind: "delete", session: s }),
    onLoadRequest: (s, t) => launchApiRequest(s.id, s.name, t),
  };

  // v6.5.2 — shared, user-draggable rail width.
  const sidebarWidth = useSidebarWidth();

  if (collapsed) {
    return (
      <aside
        data-testid="api-sidebar-collapsed"
        className="flex h-full w-10 flex-col items-center border-r border-border bg-background py-2"
        aria-label="API controllers (collapsed)"
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
        <h1 className="flex-1 text-sm font-semibold tracking-wide">APIs</h1>
        <button
          type="button"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["apiSessions"] })}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Refresh controllers"
          title="Refresh"
        >
          <RefreshCw className={isRefetching ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
        </button>
        <button
          type="button"
          onClick={() => setDialog({ kind: "add" })}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Add controller"
          title="New API controller"
        >
          <Plus className="h-4 w-4" />
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
          placeholder="Search controllers..."
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

      <ScrollArea className="flex-1">
        <div className="min-h-full">
          {isLoading ? (
            <div className="px-4 py-8 text-center text-xs text-muted-foreground">Loading...</div>
          ) : filtered.length === 0 ? (
            <EmptyState hasSearch={search.length > 0} onAdd={() => setDialog({ kind: "add" })} />
          ) : searching ? (
            // Search flattens (folders can't hide a match behind a collapse).
            <div className="py-1">
              {filtered.map((s) => (
                <ControllerRow
                  key={s.id}
                  session={s}
                  depth={0}
                  expanded={expandedControllers.has(s.id)}
                  onToggleExpand={() => toggleController(s.id)}
                  {...rowHandlers}
                />
              ))}
            </div>
          ) : (
            <div className="py-1">
              <ApiGroupView
                node={tree}
                depth={0}
                collapsed={collapsedGroups}
                onToggle={toggleGroup}
                expandedControllers={expandedControllers}
                onToggleExpand={toggleController}
                {...rowHandlers}
              />
            </div>
          )}
        </div>
      </ScrollArea>

      <footer className="border-t border-border p-2">
        <div className="flex items-center gap-1.5">
          <div className="min-w-0 flex-1">
            <EditionChip />
          </div>
          <SettingsButton />
        </div>
      </footer>

      <AddApiSessionDialog
        open={dialog.kind === "add"}
        onOpenChange={(o) => !o && setDialog({ kind: "none" })}
      />
      {dialog.kind === "edit" && (
        <AddApiSessionDialog
          open
          onOpenChange={(o) => !o && setDialog({ kind: "none" })}
          session={dialog.session}
        />
      )}
      {dialog.kind === "delete" && (
        <DeleteConfirmDialog
          open
          onOpenChange={(o) => !o && setDialog({ kind: "none" })}
          title={`Delete ${dialog.session.name}?`}
          description="Removes the controller from inventory. The stored API key is left in its backend."
          onConfirm={() => deleteMutation.mutateAsync(dialog.session.id)}
        />
      )}
    </aside>
  );
}

function EmptyState({ hasSearch, onAdd }: { hasSearch: boolean; onAdd: () => void }) {
  if (hasSearch) {
    return (
      <div className="px-4 py-8 text-center text-xs text-muted-foreground">
        No controllers match your search.
      </div>
    );
  }
  return (
    <div className="px-4 py-8 text-center text-xs text-muted-foreground">
      <p>No API controllers yet.</p>
      <p className="mt-2">
        Click <span className="font-medium">+ New API controller</span> to connect a UniFi
        controller.
      </p>
      <button
        type="button"
        onClick={onAdd}
        className="mt-4 rounded-md border border-input bg-background px-3 py-1.5 text-xs hover:bg-accent"
      >
        + New API controller
      </button>
    </div>
  );
}
