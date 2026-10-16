import { useRef, useState } from "react";

import { Check, ChevronDown, ChevronRight, Download, FolderPlus, Trash2, X } from "lucide-react";

import { EndpointFolderView } from "@/components/api/EndpointFolderView";
import { Input } from "@/components/ui/input";
import {
  importPostmanCollection,
  type ApiCollection,
  type ApiRequestTemplate,
} from "@/lib/apiCollections";
import { toastError, toastInfo, toastSuccess } from "@/lib/toast";
import { useApiCollectionsStore } from "@/stores/apiCollectionsStore";

/** Stable empty reference so the zustand selector doesn't return a fresh
 *  array (and force a re-render) on every store change for other controllers. */
const EMPTY: ApiCollection[] = [];

/** Count requests in a folder tree (for the collapsed header hint). */
function countRequests(f: ApiCollection["root"]): number {
  return f.requests.length + f.folders.reduce((n, sub) => n + countRequests(sub), 0);
}

/**
 * The USER's own collections for one controller, rendered beneath the bundled
 * endpoint tree in the sidebar. Create an empty collection, import a Postman
 * v2.1 export, delete a collection (two-click confirm), or delete a saved
 * request. All human-side — nothing here is agent-reachable (the gate never
 * consults a template; the agent path is GET-only regardless of what a
 * template holds).
 */
export function ApiUserCollections({
  apiSessionId,
  depth,
  onPick,
}: {
  apiSessionId: string;
  depth: number;
  /** Load a saved request into the controller's request pane. */
  onPick: (t: ApiRequestTemplate) => void;
}) {
  const collections = useApiCollectionsStore((s) => s.byController[apiSessionId] ?? EMPTY);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const toggle = (id: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const submitNew = () => {
    const name = newName.trim();
    if (name) useApiCollectionsStore.getState().createCollection(apiSessionId, name);
    setNewName("");
    setCreating(false);
  };

  const onImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = ""; // let the same file be re-picked later
    if (!file) return;
    // Guard the whole-file read: a real Postman export is well under a MB, so
    // reject anything huge before `text()` pulls it into memory (the importer's
    // request-count bound only kicks in after parse).
    if (file.size > 20 * 1024 * 1024) {
      toastError("Postman import failed", { description: "File is too large (max 20 MB)." });
      return;
    }
    try {
      const parsed: unknown = JSON.parse(await file.text());
      const { collection, warnings } = importPostmanCollection(parsed);
      useApiCollectionsStore.getState().addCollection(apiSessionId, collection);
      const total = countRequests(collection.root);
      if (warnings.length) {
        toastInfo(`Imported “${collection.name}” (${total} requests, ${warnings.length} note(s))`, {
          description: warnings.slice(0, 3).join(" · "),
        });
      } else {
        toastSuccess(`Imported “${collection.name}” (${total} requests)`);
      }
    } catch (err) {
      toastError("Postman import failed", {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  };

  const pad = 12 + depth * 14;

  return (
    <div data-testid="api-user-collections">
      {collections.map((col) => {
        const open = !collapsed.has(col.id);
        const count = countRequests(col.root);
        const confirming = confirmingDelete === col.id;
        return (
          <div key={col.id}>
            <div
              className="group/col flex items-center hover:bg-accent"
              style={{ paddingLeft: pad }}
            >
              <button
                type="button"
                onClick={() => toggle(col.id)}
                className="flex min-w-0 flex-1 items-center gap-1 py-1 pr-1 text-left text-[11px] font-medium"
                aria-label={open ? `Collapse ${col.name}` : `Expand ${col.name}`}
              >
                {open ? (
                  <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" />
                ) : (
                  <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />
                )}
                <span className="min-w-0 flex-1 truncate">{col.name}</span>
                <span className="shrink-0 text-[10px] text-muted-foreground">{count}</span>
              </button>
              {confirming ? (
                <div className="mr-2 flex shrink-0 items-center gap-0.5">
                  <button
                    type="button"
                    onClick={() => {
                      useApiCollectionsStore.getState().deleteCollection(apiSessionId, col.id);
                      setConfirmingDelete(null);
                    }}
                    className="rounded p-1 text-destructive hover:bg-background"
                    aria-label={`Confirm delete ${col.name}`}
                    title="Confirm delete"
                  >
                    <Check className="h-3 w-3" />
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmingDelete(null)}
                    className="rounded p-1 text-muted-foreground hover:bg-background"
                    aria-label="Cancel delete"
                    title="Cancel"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmingDelete(col.id)}
                  className="mr-2 shrink-0 rounded p-1 text-muted-foreground opacity-0 hover:bg-background hover:text-destructive group-hover/col:opacity-100"
                  aria-label={`Delete collection ${col.name}`}
                  title="Delete collection"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              )}
            </div>
            {open &&
              (count === 0 ? (
                <p
                  className="py-1 text-[11px] italic text-muted-foreground"
                  style={{ paddingLeft: pad + 18 }}
                >
                  No saved requests yet — Save from the request builder.
                </p>
              ) : (
                <EndpointFolderView
                  folder={col.root}
                  depth={depth + 1}
                  collapsed={collapsed}
                  onToggle={toggle}
                  onPick={onPick}
                  onDeleteRequest={(t) =>
                    useApiCollectionsStore.getState().deleteRequest(apiSessionId, col.id, t.id)
                  }
                />
              ))}
          </div>
        );
      })}

      {/* New-collection inline input / action row */}
      {creating ? (
        <div className="flex items-center gap-1 py-1 pr-2" style={{ paddingLeft: pad }}>
          <Input
            autoFocus
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitNew();
              else if (e.key === "Escape") {
                setNewName("");
                setCreating(false);
              }
            }}
            placeholder="Collection name"
            className="h-6 flex-1 text-xs"
            aria-label="New collection name"
          />
          <button
            type="button"
            onClick={submitNew}
            className="rounded p-1 text-muted-foreground hover:bg-background hover:text-foreground"
            aria-label="Create collection"
            title="Create"
          >
            <Check className="h-3.5 w-3.5" />
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-3 py-1 pr-3" style={{ paddingLeft: pad }}>
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
          >
            <FolderPlus className="h-3 w-3" /> New collection
          </button>
          <button
            type="button"
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"
          >
            <Download className="h-3 w-3" /> Import Postman
          </button>
          <input
            ref={fileRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={onImportFile}
            data-testid="postman-import-input"
          />
        </div>
      )}
    </div>
  );
}
