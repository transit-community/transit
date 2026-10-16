import { useState } from "react";

import { Check, Save } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  isDestructiveMethod,
  isStrippedHeader,
  scrubCredentialsFromBody,
  methodColor,
  type ApiCollection,
} from "@/lib/apiCollections";
import { toastInfo, toastSuccess } from "@/lib/toast";
import { useApiCollectionsStore } from "@/stores/apiCollectionsStore";

const NEW = "__new__";
const EMPTY: ApiCollection[] = [];

/** The current request-builder state to snapshot into a saved template. */
export interface SaveableRequest {
  method: string;
  path: string;
  headers: { key: string; value: string }[];
  body: string | null;
}

/**
 * v4.0.0 — save the request currently in the builder into one of the user's
 * collections (or a brand-new one). Human-only affordance; the saved template
 * carries no secret (the `X-API-KEY` is injected server-side, never stored).
 */
export function SaveRequestPopover({
  apiSessionId,
  request,
}: {
  apiSessionId: string;
  request: SaveableRequest;
}) {
  const collections = useApiCollectionsStore((s) => s.byController[apiSessionId] ?? EMPTY);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState<string>(NEW);
  const [newColName, setNewColName] = useState("");

  const nothingToSave = request.path.trim() === "" && (request.body ?? "").trim() === "";

  // Seed the form when the popover opens (avoids an effect + its deps churn).
  const onOpenChange = (next: boolean) => {
    if (next) {
      setName(request.path.trim() || `${request.method} request`);
      setTargetId(collections[0]?.id ?? NEW);
      setNewColName("");
    }
    setOpen(next);
  };

  const canSave = name.trim() !== "" && (targetId !== NEW || newColName.trim() !== "");

  const save = () => {
    if (!canSave) return;
    const store = useApiCollectionsStore.getState();
    const colId = targetId === NEW ? store.createCollection(apiSessionId, newColName) : targetId;
    // A saved template is persisted to localStorage, so a literal credential
    // typed into the body box must not ride along — rewrite it to a
    // {{variable}}, which is masked and memory-only. (Auth HEADERS are
    // stripped just below; bodies were the blind spot.)
    const { body, scrubbed } = scrubCredentialsFromBody(request.body);
    store.saveRequest(apiSessionId, colId, {
      name: name.trim(),
      method: request.method,
      path: request.path,
      // Never persist an auth header — the API key is injected server-side.
      headers: request.headers.filter((h) => h.key.trim() !== "" && !isStrippedHeader(h.key)),
      body,
      destructive: isDestructiveMethod(request.method),
    });
    if (scrubbed.length > 0) {
      toastInfo(
        `Saved with ${[...new Set(scrubbed)].join(", ")} replaced by a {{variable}} — credentials are never saved to disk.`,
      );
    }
    toastSuccess(`Saved “${name.trim()}”`);
    setOpen(false);
  };

  return (
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          disabled={nothingToSave}
          className="shrink-0 gap-1.5"
          title="Save this request to a collection"
          aria-label="Save request to a collection"
        >
          <Save className="h-3.5 w-3.5" />
          Save
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-72 space-y-3">
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground" htmlFor="save-req-name">
            Request name
          </label>
          <div className="flex items-center gap-1.5">
            <span
              className={`shrink-0 font-mono text-[10px] font-bold ${methodColor(request.method)}`}
            >
              {request.method}
            </span>
            <Input
              id="save-req-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") save();
              }}
              placeholder="List offline APs"
              className="h-8 text-sm"
              autoFocus
            />
          </div>
        </div>

        <div className="space-y-1">
          <span className="text-xs font-medium text-muted-foreground">Collection</span>
          <div className="grid max-h-40 gap-0.5 overflow-auto">
            {collections.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setTargetId(c.id)}
                className={`flex items-center justify-between rounded px-2 py-1 text-left text-sm hover:bg-accent ${
                  targetId === c.id ? "bg-accent font-medium" : ""
                }`}
              >
                <span className="min-w-0 flex-1 truncate">{c.name}</span>
                {targetId === c.id && <Check className="h-3.5 w-3.5 shrink-0 text-primary" />}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setTargetId(NEW)}
              className={`rounded px-2 py-1 text-left text-sm text-muted-foreground hover:bg-accent ${
                targetId === NEW ? "bg-accent font-medium text-foreground" : ""
              }`}
            >
              + New collection
            </button>
          </div>
          {targetId === NEW && (
            <Input
              value={newColName}
              onChange={(e) => setNewColName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") save();
              }}
              placeholder="Collection name"
              className="mt-1 h-8 text-sm"
              aria-label="New collection name"
            />
          )}
        </div>

        <Button onClick={save} disabled={!canSave} className="w-full gap-1.5">
          <Save className="h-3.5 w-3.5" />
          Save request
        </Button>
      </PopoverContent>
    </Popover>
  );
}
