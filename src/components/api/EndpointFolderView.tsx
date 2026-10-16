import { ChevronDown, ChevronRight, Trash2 } from "lucide-react";

import { methodColor, type ApiFolder, type ApiRequestTemplate } from "@/lib/apiCollections";

/** The endpoint catalog nested under a controller or user collection:
 *  color-coded requests + collapsible subfolders. Click a request to load it
 *  into the controller's request pane. Shared by the bundled tree (read-only)
 *  and the user's own collections (which pass `onDeleteRequest` to show a
 *  per-request delete affordance). */
export function EndpointFolderView({
  folder,
  depth,
  collapsed,
  onToggle,
  onPick,
  onDeleteRequest,
}: {
  folder: ApiFolder;
  depth: number;
  collapsed: Set<string>;
  onToggle: (id: string) => void;
  onPick: (t: ApiRequestTemplate) => void;
  /** When present, each request shows a hover delete button (user
   *  collections). Omit for read-only bundled trees. */
  onDeleteRequest?: (t: ApiRequestTemplate) => void;
}) {
  return (
    <>
      {folder.requests.map((r) => (
        <div key={r.id} className="group/req flex items-center hover:bg-accent">
          <button
            type="button"
            onClick={() => onPick(r)}
            className="flex min-w-0 flex-1 items-center gap-2 py-1 pr-1 text-left"
            style={{ paddingLeft: 12 + depth * 14 }}
            title={r.description ?? r.name}
          >
            <span
              className={`w-10 shrink-0 text-right font-mono text-[10px] font-bold ${methodColor(r.method)}`}
            >
              {r.method}
            </span>
            <span className="min-w-0 flex-1 truncate text-xs">{r.name}</span>
          </button>
          {onDeleteRequest && (
            <button
              type="button"
              onClick={() => onDeleteRequest(r)}
              className="mr-2 shrink-0 rounded p-1 text-muted-foreground opacity-0 hover:bg-background hover:text-destructive group-hover/req:opacity-100"
              aria-label={`Delete request ${r.name}`}
              title="Delete request"
            >
              <Trash2 className="h-3 w-3" />
            </button>
          )}
        </div>
      ))}
      {folder.folders.map((sub) => {
        const open = !collapsed.has(sub.id);
        return (
          <div key={sub.id}>
            <button
              type="button"
              onClick={() => onToggle(sub.id)}
              className="flex w-full items-center gap-1 py-1 pr-3 text-left text-[11px] font-medium text-muted-foreground hover:bg-accent"
              style={{ paddingLeft: 12 + depth * 14 }}
            >
              {open ? (
                <ChevronDown className="h-3 w-3 shrink-0" />
              ) : (
                <ChevronRight className="h-3 w-3 shrink-0" />
              )}
              <span className="truncate">{sub.name}</span>
            </button>
            {open && (
              <EndpointFolderView
                folder={sub}
                depth={depth + 1}
                collapsed={collapsed}
                onToggle={onToggle}
                onPick={onPick}
                onDeleteRequest={onDeleteRequest}
              />
            )}
          </div>
        );
      })}
    </>
  );
}
