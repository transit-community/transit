import { memo } from "react";

import { AlertTriangle } from "lucide-react";

import { GroupCombobox } from "@/components/dialogs/GroupCombobox";
import { VendorCombobox } from "@/components/dialogs/VendorCombobox";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { AuthProfileMeta } from "@/lib/api";
import { cn } from "@/lib/utils";

import type { ImportAction, ImportRow, ImportState } from "./importReducer";

const ROW_GRID =
  "grid grid-cols-[2.25rem_1.75rem_minmax(6rem,1fr)_minmax(6rem,1fr)_4rem_minmax(7rem,1.1fr)_minmax(7rem,1.1fr)_minmax(8rem,1.3fr)_4.5rem] items-center gap-2 px-3";

export function PreviewGridStep({
  state,
  dispatch,
  errors,
  existingIds,
  existingGroups,
  profiles,
}: {
  state: ImportState;
  dispatch: React.Dispatch<ImportAction>;
  errors: Map<string, string[]>;
  existingIds: Set<string>;
  existingGroups: string[];
  profiles: AuthProfileMeta[];
}) {
  const includedCount = state.rows.filter((r) => r.include).length;
  const conflictCount = state.rows.filter((r) => existingIds.has(r.id)).length;
  const errorCount = errors.size;
  const allKeys = state.rows.map((r) => r.key);
  const allSelected = state.selected.size === state.rows.length && state.rows.length > 0;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border px-4 py-2 text-xs">
        <span className="text-muted-foreground">
          <span className="font-medium text-foreground">{includedCount}</span> to import
        </span>
        {conflictCount > 0 && (
          <span className="text-amber-600 dark:text-amber-500">
            {conflictCount} name conflict(s) skipped
          </span>
        )}
        {errorCount > 0 && <span className="text-destructive">{errorCount} with errors</span>}
        {state.warnings.length > 0 && (
          <details className="ml-auto">
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
              {state.warnings.length} note(s)
            </summary>
            <ul className="absolute right-4 z-10 mt-1 max-w-md rounded-md border border-border bg-popover p-2 text-xs shadow-md">
              {state.warnings.map((w, i) => (
                <li key={i} className="text-muted-foreground">
                  {w}
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>

      {state.selected.size > 0 && (
        <BulkBar
          dispatch={dispatch}
          count={state.selected.size}
          existingGroups={existingGroups}
          profiles={profiles}
        />
      )}

      <div
        className={cn(
          ROW_GRID,
          "border-b border-border py-2 text-xs font-medium text-muted-foreground",
        )}
      >
        <span title="Include in import">✓</span>
        <input
          type="checkbox"
          aria-label="Select all rows"
          checked={allSelected}
          onChange={(e) =>
            dispatch(
              e.target.checked ? { type: "SELECT_KEYS", keys: allKeys } : { type: "CLEAR_SELECT" },
            )
          }
          className="h-3.5 w-3.5 accent-primary"
        />
        <span>Name</span>
        <span>Host</span>
        <span>Port</span>
        <span>Vendor</span>
        <span>Group</span>
        <span>Auth</span>
        <span>Status</span>
      </div>

      <ScrollArea className="flex-1">
        <div className="py-1">
          {state.rows.map((row) => (
            <GridRow
              key={row.key}
              row={row}
              dispatch={dispatch}
              error={errors.get(row.key)}
              selected={state.selected.has(row.key)}
              conflict={existingIds.has(row.id)}
              existingGroups={existingGroups}
              profiles={profiles}
            />
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

const GridRow = memo(function GridRow({
  row,
  dispatch,
  error,
  selected,
  conflict,
  existingGroups,
  profiles,
}: {
  row: ImportRow;
  dispatch: React.Dispatch<ImportAction>;
  error: string[] | undefined;
  selected: boolean;
  conflict: boolean;
  existingGroups: string[];
  profiles: AuthProfileMeta[];
}) {
  return (
    <div
      className={cn(
        ROW_GRID,
        "py-1.5",
        !row.include && "opacity-50",
        conflict && row.include && "bg-amber-500/5",
      )}
    >
      <input
        type="checkbox"
        aria-label={`Include ${row.id}`}
        checked={row.include}
        onChange={() => dispatch({ type: "TOGGLE_INCLUDE", key: row.key })}
        className="h-3.5 w-3.5 accent-primary"
      />
      <input
        type="checkbox"
        aria-label={`Select ${row.id}`}
        checked={selected}
        onChange={() => dispatch({ type: "TOGGLE_SELECT", key: row.key })}
        className="h-3.5 w-3.5 accent-primary"
      />
      <Input
        value={row.id}
        aria-label={`Name for ${row.host}`}
        onChange={(e) =>
          dispatch({ type: "PATCH_ROW", key: row.key, patch: { id: e.target.value } })
        }
        className="h-8 font-mono text-xs"
      />
      <Input
        value={row.host}
        aria-label={`Host for ${row.id}`}
        onChange={(e) =>
          dispatch({ type: "PATCH_ROW", key: row.key, patch: { host: e.target.value } })
        }
        className="h-8 font-mono text-xs"
      />
      <Input
        type="number"
        value={row.port}
        aria-label={`Port for ${row.id}`}
        onChange={(e) =>
          dispatch({ type: "PATCH_ROW", key: row.key, patch: { port: Number(e.target.value) } })
        }
        className="h-8 text-xs"
      />
      <VendorCombobox
        value={row.vendor}
        onChange={(v) => dispatch({ type: "PATCH_ROW", key: row.key, patch: { vendor: v } })}
      />
      <GroupCombobox
        value={row.group}
        existingGroups={existingGroups}
        onChange={(v) => dispatch({ type: "PATCH_ROW", key: row.key, patch: { group: v } })}
      />
      <Select
        value={row.auth}
        onValueChange={(v) => dispatch({ type: "PATCH_ROW", key: row.key, patch: { auth: v } })}
      >
        <SelectTrigger className="h-8 text-xs">
          <SelectValue placeholder="Auth…" />
        </SelectTrigger>
        <SelectContent>
          {profiles.map((p) => (
            <SelectItem key={p.name} value={p.name}>
              <span className="font-mono">{p.name}</span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <StatusCell include={row.include} error={error} conflict={conflict} />
    </div>
  );
});

function StatusCell({
  include,
  error,
  conflict,
}: {
  include: boolean;
  error: string[] | undefined;
  conflict: boolean;
}) {
  if (!include) return <span className="text-xs text-muted-foreground">skipped</span>;
  if (error && error.length > 0) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs text-destructive"
        title={error.join("\n")}
      >
        <AlertTriangle className="h-3.5 w-3.5" />
        {error.length}
      </span>
    );
  }
  if (conflict) return <span className="text-xs text-amber-600 dark:text-amber-500">exists</span>;
  return <span className="text-xs text-emerald-600 dark:text-emerald-500">ok</span>;
}

function BulkBar({
  dispatch,
  count,
  existingGroups,
  profiles,
}: {
  dispatch: React.Dispatch<ImportAction>;
  count: number;
  existingGroups: string[];
  profiles: AuthProfileMeta[];
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border bg-muted/40 px-4 py-2 text-xs">
      <span className="font-medium">{count} selected</span>
      <span className="text-muted-foreground">·</span>
      <span className="text-muted-foreground">Set</span>
      <div className="w-40">
        <VendorCombobox
          value=""
          onChange={(v) => dispatch({ type: "BULK_SET", field: "vendor", value: v })}
        />
      </div>
      <div className="w-40">
        <GroupCombobox
          value=""
          existingGroups={existingGroups}
          onChange={(v) => dispatch({ type: "BULK_SET", field: "group", value: v })}
        />
      </div>
      <Select onValueChange={(v) => dispatch({ type: "BULK_SET", field: "auth", value: v })}>
        <SelectTrigger className="h-8 w-40 text-xs">
          <SelectValue placeholder="Auth profile…" />
        </SelectTrigger>
        <SelectContent>
          {profiles.map((p) => (
            <SelectItem key={p.name} value={p.name}>
              <span className="font-mono">{p.name}</span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <span className="text-muted-foreground">·</span>
      <button
        type="button"
        onClick={() => dispatch({ type: "BULK_INCLUDE", include: true })}
        className="rounded border border-input bg-background px-2 py-1 hover:bg-accent"
      >
        Include
      </button>
      <button
        type="button"
        onClick={() => dispatch({ type: "BULK_INCLUDE", include: false })}
        className="rounded border border-input bg-background px-2 py-1 hover:bg-accent"
      >
        Exclude
      </button>
      <button
        type="button"
        onClick={() => dispatch({ type: "CLEAR_SELECT" })}
        className="ml-auto text-muted-foreground hover:text-foreground"
      >
        Clear selection
      </button>
    </div>
  );
}
