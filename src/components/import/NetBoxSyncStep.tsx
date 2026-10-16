import { useMemo } from "react";

import { useQuery } from "@tanstack/react-query";
import { Boxes, Loader2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  listApiSessions,
  previewNetboxSync,
  type ApiSessionMeta,
  type AuthProfileMeta,
  type NetBoxSyncPreviewWire,
} from "@/lib/api";
import type { StaleAction } from "@/lib/netboxSync";
import { cn } from "@/lib/utils";

import type { ImportAction, ImportState, NetBoxState } from "./importReducer";
import { PreviewGridStep } from "./PreviewGridStep";

const STALE_ACTIONS: { value: StaleAction; label: string }[] = [
  { value: "keep", label: "Keep" },
  { value: "unlink", label: "Unlink" },
  { value: "delete", label: "Delete" },
];

/**
 * The NetBox live-sync step (v6.2.0): pick the NetBox API session, fetch
 * the diff against the current inventory, and review the three buckets.
 * The New tab IS the standard import grid (`PreviewGridStep` over
 * `state.rows`); Changed and Stale are sync-specific. Commit lives in the
 * wizard footer (`ImportConnectionsView`), like every other step.
 */
export function NetBoxSyncStep({
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
  const nb = state.netbox;
  const sessionsQuery = useQuery({ queryKey: ["apiSessions"], queryFn: listApiSessions });
  const netboxSessions = useMemo(
    () => (sessionsQuery.data ?? []).filter((s) => s.vendor === "netbox"),
    [sessionsQuery.data],
  );

  const fetchPreview = async (activeOnly: boolean) => {
    if (!nb.sessionId) return;
    dispatch({ type: "NETBOX_FETCH_START" });
    try {
      const preview = await previewNetboxSync(nb.sessionId, activeOnly);
      dispatch({ type: "NETBOX_FETCH_OK", preview });
    } catch (e) {
      dispatch({
        type: "NETBOX_FETCH_ERR",
        message: e instanceof Error ? e.message : String(e),
      });
    }
  };

  if (!nb.preview) {
    return (
      <PickSessionScreen
        nb={nb}
        sessions={netboxSessions}
        dispatch={dispatch}
        onFetch={fetchPreview}
      />
    );
  }

  const p = nb.preview;
  const deleteCount = Object.values(nb.staleActions).filter((a) => a === "delete").length;
  return (
    <div className="flex h-full flex-col">
      <SummaryBar preview={p} fetching={nb.fetching} onRefetch={() => void fetchPreview(true)} />

      <Tabs defaultValue="new" className="flex min-h-0 flex-1 flex-col">
        <TabsList className="mx-4 mt-2 w-fit">
          <TabsTrigger value="new" data-testid="netbox-tab-new">
            New ({p.new.length})
          </TabsTrigger>
          <TabsTrigger value="changed" data-testid="netbox-tab-changed">
            Changed ({p.changed.length})
          </TabsTrigger>
          <TabsTrigger value="stale" data-testid="netbox-tab-stale">
            Stale ({p.stale.length}){deleteCount > 0 ? ` · ${deleteCount} to delete` : ""}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="new" className="mt-0 min-h-0 flex-1">
          {p.new.length === 0 ? (
            <Empty>Nothing new: every NetBox device is already in this inventory.</Empty>
          ) : (
            <div className="flex h-full flex-col">
              <div className="flex items-center gap-2 border-b border-border px-4 py-2">
                <label className="text-xs font-medium" htmlFor="netbox-default-auth">
                  Auth profile for imported devices
                </label>
                <select
                  id="netbox-default-auth"
                  data-testid="netbox-default-auth"
                  className="h-7 rounded-md border border-input bg-background px-2 text-xs text-foreground"
                  value={nb.defaultAuth}
                  onChange={(e) =>
                    dispatch({ type: "NETBOX_SEED_AUTH", profileName: e.target.value })
                  }
                >
                  <option value="">Pick per row…</option>
                  {profiles.map((pr) => (
                    <option key={pr.name} value={pr.name}>
                      {pr.name} ({pr.username})
                    </option>
                  ))}
                </select>
                <span className="text-xs text-muted-foreground">
                  NetBox holds no device credentials, so pick which saved profile these use.
                </span>
              </div>
              <div className="min-h-0 flex-1">
                <PreviewGridStep
                  state={state}
                  dispatch={dispatch}
                  errors={errors}
                  existingIds={existingIds}
                  existingGroups={existingGroups}
                  profiles={profiles}
                />
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="changed" className="mt-0 min-h-0 flex-1">
          <ChangedTab preview={p} nb={nb} dispatch={dispatch} />
        </TabsContent>

        <TabsContent value="stale" className="mt-0 min-h-0 flex-1">
          <StaleTab preview={p} nb={nb} dispatch={dispatch} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Pre-fetch screen: session picker + fetch buttons (or the empty-state
 *  pointer at the APIs rail). */
function PickSessionScreen({
  nb,
  sessions,
  dispatch,
  onFetch,
}: {
  nb: NetBoxState;
  sessions: ApiSessionMeta[];
  dispatch: React.Dispatch<ImportAction>;
  onFetch: (activeOnly: boolean) => Promise<void>;
}) {
  return (
    <div className="mx-auto flex h-full max-w-lg flex-col justify-center px-6 py-10">
      <h2 className="inline-flex items-center gap-2 text-xl font-semibold tracking-tight">
        <Boxes className="size-5 text-primary" />
        Sync from NetBox
      </h2>
      <p className="mt-2 text-sm text-muted-foreground">
        Pulls the device list from your NetBox and diffs it against this inventory: new devices to
        import, drifted fields to accept, and stale entries to review. Nothing is written until you
        commit, and NetBox is never written at all.
      </p>

      {sessions.length === 0 ? (
        <p className="mt-6 rounded-md border border-border bg-muted/40 p-3 text-sm text-muted-foreground">
          No NetBox API session yet. Add one in the <span className="font-medium">APIs</span> rail
          (New API controller → Vendor: NetBox), then come back here.
        </p>
      ) : (
        <div className="mt-6 grid gap-4">
          <div className="grid gap-1">
            <label className="text-sm font-medium" htmlFor="netbox-session-select">
              NetBox session
            </label>
            <Select
              value={nb.sessionId ?? ""}
              onValueChange={(v) => dispatch({ type: "NETBOX_SET_SESSION", sessionId: v })}
            >
              <SelectTrigger id="netbox-session-select" data-testid="netbox-session-select">
                <SelectValue placeholder="Pick the NetBox controller" />
              </SelectTrigger>
              <SelectContent>
                {sessions.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {s.name} · {s.base_url ?? s.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-3">
            <Button
              type="button"
              disabled={!nb.sessionId || nb.fetching}
              onClick={() => void onFetch(true)}
              data-testid="netbox-fetch"
            >
              {nb.fetching ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : null}
              Fetch active devices
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={!nb.sessionId || nb.fetching}
              onClick={() => void onFetch(false)}
              data-testid="netbox-fetch-all"
            >
              Fetch all statuses
            </Button>
          </div>
        </div>
      )}

      {nb.fetchError && (
        <p
          role="alert"
          className="mt-4 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          {nb.fetchError}
        </p>
      )}
    </div>
  );
}

function SummaryBar({
  preview: p,
  fetching,
  onRefetch,
}: {
  preview: NetBoxSyncPreviewWire;
  fetching: boolean;
  onRefetch: () => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2 text-xs">
      <span className="text-muted-foreground">
        Fetched <span className="font-medium text-foreground">{p.fetched}</span> from NetBox:{" "}
        <span className="font-medium text-foreground">{p.new.length}</span> new,{" "}
        <span className="font-medium text-foreground">{p.changed.length}</span> changed,{" "}
        <span className="font-medium text-foreground">{p.stale.length}</span> stale, {p.unchanged}{" "}
        unchanged
      </span>
      {p.skipped.length > 0 && (
        <details>
          <summary className="cursor-pointer text-amber-600 hover:text-foreground dark:text-amber-500">
            {p.skipped.length} not importable
          </summary>
          <ul className="absolute z-10 mt-1 max-w-md rounded-md border border-border bg-popover p-2 text-xs shadow-md">
            {p.skipped.map((w) => (
              <li key={w} className="text-muted-foreground">
                {w}
              </li>
            ))}
          </ul>
        </details>
      )}
      <button
        type="button"
        className="ml-auto inline-flex items-center gap-1 text-muted-foreground hover:text-foreground"
        onClick={onRefetch}
        disabled={fetching}
        data-testid="netbox-refetch"
      >
        {fetching ? (
          <Loader2 className="size-3.5 animate-spin" />
        ) : (
          <RefreshCw className="size-3.5" />
        )}
        Re-fetch
      </button>
    </div>
  );
}

function ChangedTab({
  preview: p,
  nb,
  dispatch,
}: {
  preview: NetBoxSyncPreviewWire;
  nb: NetBoxState;
  dispatch: React.Dispatch<ImportAction>;
}) {
  if (p.changed.length === 0) {
    return <Empty>No drift: every matched device agrees with NetBox.</Empty>;
  }
  return (
    <ScrollArea className="h-full">
      <div className="grid gap-3 p-4">
        {p.changed.map((c) => (
          <div key={c.device_id} className="rounded-lg border border-border p-3">
            <div className="text-sm font-medium">{c.device_id}</div>
            <div className="mt-2 grid gap-1.5">
              {c.changes.map((f) => (
                <label key={f.field} className="flex cursor-pointer items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={nb.changeAccepts[c.device_id]?.[f.field] ?? false}
                    onChange={() =>
                      dispatch({
                        type: "NETBOX_TOGGLE_CHANGE",
                        deviceId: c.device_id,
                        field: f.field,
                      })
                    }
                    data-testid={`netbox-change-${c.device_id}-${f.field}`}
                  />
                  <span className="w-14 font-medium">{f.field}</span>
                  <span className="text-muted-foreground line-through">
                    {f.current === "" ? "(none)" : f.current}
                  </span>
                  <span aria-hidden>→</span>
                  <span className="text-foreground">{f.incoming}</span>
                </label>
              ))}
            </div>
          </div>
        ))}
      </div>
    </ScrollArea>
  );
}

function StaleTab({
  preview: p,
  nb,
  dispatch,
}: {
  preview: NetBoxSyncPreviewWire;
  nb: NetBoxState;
  dispatch: React.Dispatch<ImportAction>;
}) {
  if (p.stale.length === 0) {
    return <Empty>Nothing stale: every synced device still exists in NetBox.</Empty>;
  }
  return (
    <ScrollArea className="h-full">
      <div className="grid gap-2 p-4">
        <p className="text-xs text-muted-foreground">
          These devices carry a NetBox link that no longer matches anything in the pull.
          <span className="font-medium"> Keep</span> leaves them untouched,
          <span className="font-medium"> Unlink</span> clears the NetBox link,
          <span className="font-medium"> Delete</span> removes the device from this inventory
          (confirmed before commit).
        </p>
        {p.stale.map((s) => {
          const current = nb.staleActions[s.device_id] ?? "keep";
          return (
            <div
              key={s.device_id}
              className="flex items-center gap-3 rounded-lg border border-border px-3 py-2"
            >
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium">{s.device_id}</div>
                <div className="truncate text-xs text-muted-foreground">
                  {s.host} · NetBox id {s.netbox_id}
                </div>
              </div>
              <div className="flex gap-1" role="radiogroup" aria-label={s.device_id}>
                {STALE_ACTIONS.map((a) => (
                  <Button
                    key={a.value}
                    type="button"
                    size="sm"
                    variant={current === a.value ? "default" : "outline"}
                    className={cn(
                      "h-7 px-2 text-xs",
                      a.value === "delete" &&
                        current === "delete" &&
                        "bg-destructive text-destructive-foreground hover:bg-destructive/90",
                    )}
                    onClick={() =>
                      dispatch({
                        type: "NETBOX_SET_STALE",
                        deviceId: s.device_id,
                        action: a.value,
                      })
                    }
                    data-testid={`netbox-stale-${s.device_id}-${a.value}`}
                  >
                    {a.label}
                  </Button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </ScrollArea>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full items-center justify-center p-8 text-sm text-muted-foreground">
      {children}
    </div>
  );
}
