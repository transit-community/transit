import { useMemo, useReducer, useState } from "react";

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Download, X } from "lucide-react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { listAuthProfiles, listDevices, listGroups, type DeviceInput } from "@/lib/api";
import { useApplyNetboxSync, useImportConnections } from "@/lib/mutations";
import { buildApplyPayload, payloadOpCount } from "@/lib/netboxSync";
import { toastInfo } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

import { CredentialMapStep } from "./CredentialMapStep";
import { importReducer, initialImportState, validateRows } from "./importReducer";
import { pruneJumpRefs, resolveJumpHost, type JumpCandidate } from "./resolveJumpHost";
import { NetBoxSyncStep } from "./NetBoxSyncStep";
import { PreviewGridStep } from "./PreviewGridStep";
import { SourcePickStep } from "./SourcePickStep";

const STEP_LABELS: Record<string, string> = {
  source: "1 · Source",
  credentials: "2 · Credentials",
  preview: "3 · Review & import",
  netbox: "NetBox sync",
};

/**
 * Full-pane bulk-import wizard, mounted as a `MainArea` branch (the app
 * has no router; `MainArea` already swaps in full-pane states). Owns a
 * `useReducer` draft that evaporates on close — the desired discard-on-
 * cancel semantics. The NetBox branch (v6.2.0) is a single self-contained
 * step whose New bucket reuses the standard review grid.
 */
export function ImportConnectionsView() {
  const closeImport = useUiStore((s) => s.closeImport);
  const expandGroups = useUiStore((s) => s.expandGroups);
  const setActiveDeviceId = useUiStore((s) => s.setActiveDeviceId);

  const [state, dispatch] = useReducer(importReducer, initialImportState);
  const [confirmDeletes, setConfirmDeletes] = useState(false);
  const importMutation = useImportConnections();
  const netboxMutation = useApplyNetboxSync();

  const devicesQuery = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  const groupsQuery = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const profilesQuery = useQuery({ queryKey: ["authProfiles"], queryFn: listAuthProfiles });

  const profiles = useMemo(() => profilesQuery.data ?? [], [profilesQuery.data]);
  const existingIds = useMemo(
    () => new Set((devicesQuery.data ?? []).map((d) => d.id)),
    [devicesQuery.data],
  );
  const existingGroups = useMemo(() => {
    const set = new Set<string>(groupsQuery.data ?? []);
    for (const d of devicesQuery.data ?? []) if (d.group) set.add(d.group);
    return [...set].sort();
  }, [groupsQuery.data, devicesQuery.data]);

  const errors = useMemo(() => validateRows(state.rows, existingIds), [state.rows, existingIds]);
  const includedValid = useMemo(
    () => state.rows.filter((r) => r.include && !errors.has(r.key)),
    [state.rows, errors],
  );

  const commit = () => {
    dispatch({ type: "COMMIT_START" });
    // v6.5.0 — close the ProxyJump/"Firewall" loop: resolve each row's
    // raw jump-host value to a device id via the never-guess resolver
    // (alias-first, unique-host-only, port-verified, IPv6-safe — see
    // resolveJumpHost.ts). Candidates = the batch itself + existing
    // inventory. Anything unresolved, ambiguous, port-mismatched, or
    // SELF-referential (would self-cycle and abort the import) is
    // dropped and counted for the toast.
    const candidates: JumpCandidate[] = [
      ...includedValid.map((row) => ({ id: row.id, host: row.host.trim(), port: row.port })),
      ...(devicesQuery.data ?? []).map((d) => ({ id: d.id, host: d.host, port: d.port })),
    ];
    const resolvedJumps = new Map<string, string | null>();
    let droppedJumps = 0;
    for (const r of includedValid) {
      const raw = (r.jumpHost ?? "").trim();
      if (raw === "") {
        resolvedJumps.set(r.key, null);
        continue;
      }
      const hit = resolveJumpHost(raw, candidates);
      const jump = hit === r.id ? null : hit;
      if (jump === null) droppedJumps += 1;
      resolvedJumps.set(r.key, jump);
    }
    // Sweep the RESOLVED graph for cycles (a mutual ProxyJump pair in
    // one file) and over-deep chains — either would abort the whole
    // atomic import with a raw loader error. Dropped refs join the toast.
    const idJumps = new Map<string, string>();
    for (const r of includedValid) {
      const jump = resolvedJumps.get(r.key);
      if (jump) idJumps.set(r.id, jump);
    }
    const existingJumpOf = new Map<string, string>(
      (devicesQuery.data ?? []).filter((d) => d.jump_via).map((d) => [d.id, d.jump_via as string]),
    );
    const pruned = pruneJumpRefs(idJumps, existingJumpOf);
    if (pruned.size > 0) {
      for (const r of includedValid) {
        if (pruned.has(r.id) && resolvedJumps.get(r.key)) {
          resolvedJumps.set(r.key, null);
          droppedJumps += 1;
        }
      }
    }
    const devices: DeviceInput[] = includedValid.map((r) => ({
      id: r.id,
      host: r.host.trim(),
      port: r.port,
      vendor: r.vendor,
      group: r.group.trim() === "" ? null : r.group.trim(),
      color: null,
      tags: [],
      auth: r.auth,
      syntax_highlighting: null,
      quick_copy_paste: null,
      jump_via: resolvedJumps.get(r.key) ?? null,
    }));
    importMutation.mutate(devices, {
      onSuccess: () => {
        if (droppedJumps > 0) {
          toastInfo(
            `${droppedJumps} jump-host reference${droppedJumps === 1 ? "" : "s"} couldn't be matched unambiguously to an imported or existing device and ${droppedJumps === 1 ? "was" : "were"} left unset`,
          );
        }
        const groups = [...new Set(devices.map((d) => d.group).filter((g): g is string => !!g))];
        expandGroups(groups);
        if (devices[0]) setActiveDeviceId(devices[0].id);
        closeImport();
      },
      onError: (err) =>
        dispatch({ type: "COMMIT_ERR", message: err instanceof Error ? err.message : String(err) }),
    });
  };

  // The NetBox payload is derived live so the footer button can count ops
  // and gate the destructive confirm on the actual delete decisions.
  const netboxPayload = useMemo(() => {
    if (!state.netbox.preview) return null;
    return buildApplyPayload({
      rows: state.rows,
      errors,
      preview: state.netbox.preview,
      changeAccepts: state.netbox.changeAccepts,
      staleActions: state.netbox.staleActions,
      devices: devicesQuery.data ?? [],
    });
  }, [state.netbox, state.rows, errors, devicesQuery.data]);
  const netboxOps = netboxPayload ? payloadOpCount(netboxPayload) : 0;

  const commitNetbox = () => {
    if (!netboxPayload) return;
    setConfirmDeletes(false);
    dispatch({ type: "COMMIT_START" });
    netboxMutation.mutate(netboxPayload, {
      onSuccess: () => {
        const groups = [
          ...new Set(netboxPayload.adds.map((d) => d.group).filter((g): g is string => !!g)),
        ];
        expandGroups(groups);
        if (netboxPayload.adds[0]) setActiveDeviceId(netboxPayload.adds[0].id);
        closeImport();
      },
      onError: (err) =>
        dispatch({ type: "COMMIT_ERR", message: err instanceof Error ? err.message : String(err) }),
    });
  };

  return (
    <div className="flex h-full w-full flex-col" data-testid="import-view">
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-border px-4">
        <Download className="h-4 w-4 text-primary" />
        <h1 className="text-sm font-semibold">Import connections</h1>
        <span className="ml-2 text-xs text-muted-foreground">{STEP_LABELS[state.step]}</span>
        <button
          type="button"
          onClick={closeImport}
          className="ml-auto rounded-md p-1.5 text-muted-foreground hover:bg-accent"
          aria-label="Cancel import"
          title="Cancel"
        >
          <X className="h-4 w-4" />
        </button>
      </header>

      <div className="min-h-0 flex-1">
        {state.step === "source" && <SourcePickStep state={state} dispatch={dispatch} />}
        {state.step === "credentials" && (
          <CredentialMapStep state={state} dispatch={dispatch} profiles={profiles} />
        )}
        {state.step === "preview" && (
          <PreviewGridStep
            state={state}
            dispatch={dispatch}
            errors={errors}
            existingIds={existingIds}
            existingGroups={existingGroups}
            profiles={profiles}
          />
        )}
        {state.step === "netbox" && (
          <NetBoxSyncStep
            state={state}
            dispatch={dispatch}
            errors={errors}
            existingIds={existingIds}
            existingGroups={existingGroups}
            profiles={profiles}
          />
        )}
      </div>

      {state.commitError && (
        <div
          role="alert"
          className="shrink-0 border-t border-destructive/40 bg-destructive/10 px-4 py-2 text-xs text-destructive"
        >
          Import failed — nothing was written. {state.commitError}
        </div>
      )}

      {state.step !== "source" && (
        <footer className="flex h-14 shrink-0 items-center justify-between border-t border-border px-4">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="gap-1.5"
            onClick={() =>
              dispatch({
                type: "GOTO",
                step:
                  state.step === "preview"
                    ? "credentials"
                    : state.step === "netbox"
                      ? "source"
                      : "source",
              })
            }
          >
            <ArrowLeft className="h-4 w-4" />
            Back
          </Button>
          {state.step === "credentials" ? (
            <Button type="button" onClick={() => dispatch({ type: "SEED_AUTH_DEFAULTS" })}>
              Continue to review
            </Button>
          ) : state.step === "netbox" ? (
            <Button
              type="button"
              disabled={netboxOps === 0 || netboxMutation.isPending || state.netbox.fetching}
              onClick={() => {
                if ((netboxPayload?.deletes.length ?? 0) > 0) setConfirmDeletes(true);
                else commitNetbox();
              }}
              data-testid="netbox-commit"
            >
              {netboxMutation.isPending
                ? "Applying…"
                : `Apply ${netboxOps} change${netboxOps === 1 ? "" : "s"}`}
            </Button>
          ) : (
            <Button
              type="button"
              disabled={includedValid.length === 0 || importMutation.isPending}
              onClick={commit}
              data-testid="import-commit"
            >
              {importMutation.isPending ? "Importing…" : `Import ${includedValid.length}`}
            </Button>
          )}
        </footer>
      )}

      {/* Opt-in Stale deletes get one explicit destructive confirm naming
          the count — never a default, never silent (threat model T49). */}
      <AlertDialog open={confirmDeletes} onOpenChange={setConfirmDeletes}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Delete {netboxPayload?.deletes.length ?? 0} device
              {(netboxPayload?.deletes.length ?? 0) === 1 ? "" : "s"} from the inventory?
            </AlertDialogTitle>
            <AlertDialogDescription>
              These devices are marked Delete in the Stale tab:{" "}
              {(netboxPayload?.deletes ?? []).join(", ")}. This removes them from Transit only;
              NetBox is never written, and saved credentials in your keychain are untouched.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={commitNetbox}
              data-testid="netbox-confirm-deletes"
            >
              Delete and apply
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
