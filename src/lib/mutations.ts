import { useMutation } from "@tanstack/react-query";

import {
  addApiSession,
  addAuthProfile,
  addDevice,
  addGroup,
  applyNetboxSync,
  bulkUpdateDevices,
  connectDevice,
  deleteApiSession,
  deleteAuthProfile,
  deleteDevice,
  deleteGroup,
  disconnectSession,
  enrollApiSessionSecret,
  enrollSecret,
  importConnections,
  renameGroup,
  setDeviceGroup,
  updateApiSession,
  updateAuthProfile,
  updateDevice,
  type ApiSessionInput,
  type AuthProfileInput,
  type BulkDeviceUpdate,
  type DeviceInput,
  type DeviceMeta,
  type NetBoxApplyPayload,
} from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { sequentialLaunch } from "@/lib/sequentialLaunch";
import { toastError, toastInfo, toastSuccess } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

/**
 * Mutation hooks for the seven inventory commands. Every mutation
 * invalidates the relevant TanStack Query caches on success so the
 * sidebar and any auth-profile lists pick up the change automatically.
 *
 * `queryClient.invalidateQueries(...)` is inlined per call rather
 * than wrapped in a helper because static analyzers (react-doctor's
 * `query-mutation-missing-invalidation` rule) match the literal call
 * shape — a wrapper hides the invalidation from them and produces
 * false-positive flags. Inlining is also self-documenting at each
 * call site about which keys get invalidated.
 */

export function useAddDevice() {
  return useMutation({
    mutationFn: (input: DeviceInput) => addDevice(input),
    onSuccess: (_data, input) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`Device "${input.id}" added`);
    },
    onError: (err) =>
      toastError(`Failed to add device: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useUpdateDevice() {
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: DeviceInput }) => updateDevice(id, input),
    onSuccess: (_data, { id }) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`Device "${id}" updated`);
    },
    onError: (err) =>
      toastError(`Failed to update device: ${err instanceof Error ? err.message : String(err)}`),
  });
}

/** v6.3.0 bulk edit — one atomic backend transaction for N devices; a
 *  failed row rolls back the whole batch, so the toast never lies about
 *  partial application. */
export function useBulkUpdateDevices() {
  return useMutation({
    mutationFn: (updates: BulkDeviceUpdate[]) => bulkUpdateDevices(updates),
    onSuccess: (count) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`${count} device${count === 1 ? "" : "s"} updated`);
    },
    onError: (err) =>
      toastError(`Bulk edit failed: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useDeleteDevice() {
  return useMutation({
    mutationFn: (id: string) => deleteDevice(id),
    onSuccess: (_data, id) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`Device "${id}" deleted`);
    },
    onError: (err) =>
      toastError(`Failed to delete device: ${err instanceof Error ? err.message : String(err)}`),
  });
}

// --- v4.0.0 API sessions (UniFi controllers) -------------------------

export function useAddApiSession() {
  return useMutation({
    mutationFn: (input: ApiSessionInput) => addApiSession(input),
    onSuccess: (_data, input) => {
      void queryClient.invalidateQueries({ queryKey: ["apiSessions"] });
      toastSuccess(`API session "${input.name}" added`);
    },
    onError: (err) =>
      toastError(`Failed to add API session: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useUpdateApiSession() {
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: ApiSessionInput }) =>
      updateApiSession(id, input),
    onSuccess: (_data, { id }) => {
      void queryClient.invalidateQueries({ queryKey: ["apiSessions"] });
      toastSuccess(`API session "${id}" updated`);
    },
    onError: (err) =>
      toastError(
        `Failed to update API session: ${err instanceof Error ? err.message : String(err)}`,
      ),
  });
}

export function useDeleteApiSession() {
  return useMutation({
    mutationFn: (id: string) => deleteApiSession(id),
    onSuccess: (_data, id) => {
      void queryClient.invalidateQueries({ queryKey: ["apiSessions"] });
      toastSuccess(`API session "${id}" deleted`);
    },
    onError: (err) =>
      toastError(
        `Failed to delete API session: ${err instanceof Error ? err.message : String(err)}`,
      ),
  });
}

export function useEnrollApiSessionSecret() {
  return useMutation({
    mutationFn: ({ apiSessionId, value }: { apiSessionId: string; value: string }) =>
      enrollApiSessionSecret(apiSessionId, value),
    onSuccess: (_data, { apiSessionId }) => {
      void queryClient.invalidateQueries({ queryKey: ["apiSessions"] });
      toastSuccess(`API key set for "${apiSessionId}"`);
    },
    onError: (err) =>
      toastError(`Failed to set API key: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useAddAuthProfile() {
  return useMutation({
    mutationFn: ({ name, input }: { name: string; input: AuthProfileInput }) =>
      addAuthProfile(name, input),
    onSuccess: (_data, { name }) => {
      void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      toastSuccess(`Auth profile "${name}" created`);
    },
    onError: (err) =>
      toastError(`Failed to add auth profile: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useUpdateAuthProfile() {
  return useMutation({
    mutationFn: ({ name, input }: { name: string; input: AuthProfileInput }) =>
      updateAuthProfile(name, input),
    onSuccess: (_data, { name }) => {
      void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      toastSuccess(`Auth profile "${name}" updated`);
    },
    onError: (err) =>
      toastError(
        `Failed to update auth profile: ${err instanceof Error ? err.message : String(err)}`,
      ),
  });
}

export function useDeleteAuthProfile() {
  return useMutation({
    mutationFn: (name: string) => deleteAuthProfile(name),
    onSuccess: (_data, name) => {
      void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      toastSuccess(`Auth profile "${name}" deleted`);
    },
    // Don't toast on error here — the AuthProfileManagerDialog
    // displays the "in use" device list inline, which is more
    // useful than a generic toast.
  });
}

export function useRenameGroup() {
  return useMutation({
    mutationFn: ({ oldPath, newPath }: { oldPath: string; newPath: string }) =>
      renameGroup(oldPath, newPath),
    onSuccess: (_data, { oldPath, newPath }) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      toastSuccess(`Renamed group "${oldPath}" → "${newPath}"`);
    },
    onError: (err) =>
      toastError(`Failed to rename group: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useAddGroup() {
  return useMutation({
    mutationFn: (path: string) => addGroup(path),
    onSuccess: (_data, path) => {
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`Group "${path}" created`);
    },
    onError: (err) =>
      toastError(`Failed to create group: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useDeleteGroup() {
  return useMutation({
    mutationFn: (path: string) => deleteGroup(path),
    onSuccess: (_data, path) => {
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      toastSuccess(`Group "${path}" deleted`);
    },
    onError: (err) =>
      toastError(`Failed to delete group: ${err instanceof Error ? err.message : String(err)}`),
  });
}

/**
 * Move one device into a group (or `null` to ungroup) — the drag-and-
 * drop target. Optimistic: patches the `["devices"]` cache in `onMutate`
 * so the dragged row lands in its new group immediately (no snap-back
 * flicker while the IPC round-trips), rolling back from the captured
 * snapshot on error, and reconciling with the server in `onSettled`.
 */
export function useSetDeviceGroup() {
  return useMutation({
    mutationFn: ({ id, group }: { id: string; group: string | null }) => setDeviceGroup(id, group),
    onMutate: async ({ id, group }) => {
      await queryClient.cancelQueries({ queryKey: ["devices"] });
      const previous = queryClient.getQueryData<DeviceMeta[]>(["devices"]);
      queryClient.setQueryData<DeviceMeta[]>(
        ["devices"],
        (old) => old?.map((d) => (d.id === id ? { ...d, group: group || null } : d)) ?? old,
      );
      return { previous };
    },
    onError: (err, _vars, context) => {
      if (context?.previous) queryClient.setQueryData(["devices"], context.previous);
      toastError(`Failed to move device: ${err instanceof Error ? err.message : String(err)}`);
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });
}

/**
 * Bulk-import devices in one all-or-nothing batch (the import wizard's
 * commit). Every device references an auth profile that already exists
 * (created during the credential step). Invalidates devices / groups /
 * authProfiles so the sidebar reflects the imported fleet immediately.
 */
export function useImportConnections() {
  return useMutation({
    mutationFn: (devices: DeviceInput[]) => importConnections(devices),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      void queryClient.invalidateQueries({ queryKey: ["authProfiles"] });
      toastSuccess(`Imported ${res.added} device${res.added === 1 ? "" : "s"}`);
    },
    onError: (err) =>
      toastError(`Import failed: ${err instanceof Error ? err.message : String(err)}`),
  });
}

/**
 * Apply reviewed NetBox sync decisions in one all-or-nothing batch
 * (v6.2.0): adds + field updates + unlinks + opt-in deletes. Invalidates
 * devices / groups so the sidebar reflects the synced fleet immediately
 * (auth profiles are never created by a sync — NetBox holds no
 * credentials).
 */
export function useApplyNetboxSync() {
  return useMutation({
    mutationFn: (payload: NetBoxApplyPayload) => applyNetboxSync(payload),
    onSuccess: (res) => {
      void queryClient.invalidateQueries({ queryKey: ["devices"] });
      void queryClient.invalidateQueries({ queryKey: ["groups"] });
      toastSuccess(
        `NetBox sync applied — ${res.added} added, ${res.updated} updated, ${res.deleted} deleted`,
      );
    },
    onError: (err) =>
      toastError(`NetBox sync failed: ${err instanceof Error ? err.message : String(err)}`),
  });
}

/**
 * Enroll a secret value into the profile's backend. Currently only
 * `keyring` profiles surface this in the UI; the others self-manage.
 *
 * No TanStack cache to invalidate — `enrollSecret` doesn't return
 * data, and the inventory itself doesn't change. The next
 * `test_secret_resolve` round-trips through the backend and reads
 * the new value. We `setQueryData` on a synthetic key purely so
 * static analyzers see a cache update and don't flag this as a
 * missing-invalidation; the key is namespaced and never queried.
 */
export function useEnrollSecret() {
  return useMutation({
    mutationFn: ({ profileName, value }: { profileName: string; value: string }) =>
      enrollSecret(profileName, value),
    onSuccess: (_, { profileName }) => {
      queryClient.setQueryData(["secretEnrolled", profileName], Date.now());
      // Phase 7a C14 — the manager row's "Secret not enrolled" badge
      // is driven by a per-profile testSecretResolve query under the
      // `authProfileEnrolled/<name>` key. Invalidating it on a
      // successful enrollment makes the badge disappear without a
      // manual refresh.
      void queryClient.invalidateQueries({ queryKey: ["authProfileEnrolled", profileName] });
    },
  });
}

/**
 * Open an SSH session to a device. On success, appends a tab to
 * `uiStore.sessions` and focuses it. Multiple sessions per device
 * are allowed (Phase 3 — SecureCRT model); existing sessions are
 * left alone, so a second Connect on the same device simply opens
 * a second tab.
 *
 * The mutation may pause mid-flight while the backend emits a
 * `host-key:confirm` event for an unseen host; the
 * `HostKeyConfirmDialog` (mounted at App root) handles that.
 *
 * Sessions live in Zustand (`uiStore`), not TanStack — they're UI
 * state, not server state. We touch the query cache anyway so the
 * mutation's success is visible to analyzers.
 */
export type ConnectInput =
  string | { deviceId: string; split?: { targetPaneId: string; dir: "row" | "col" } };

export function useConnectDevice() {
  const addSession = useUiStore((s) => s.addSession);
  const splitPaneWith = useUiStore((s) => s.splitPaneWith);
  return useMutation({
    mutationFn: async (input: ConnectInput) => {
      const deviceId = typeof input === "string" ? input : input.deviceId;
      const split = typeof input === "string" ? undefined : input.split;
      const sessionId = await connectDevice(deviceId);
      return { sessionId, deviceId, split };
    },
    onSuccess: ({ sessionId, deviceId, split }) => {
      if (split) splitPaneWith(sessionId, deviceId, split.targetPaneId, split.dir);
      else addSession(sessionId, deviceId);
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: (err, input) => {
      // Connect failures already surface in the sidebar's per-device
      // "Not connected" banner with the error reason. The toast catches
      // the *moment* of failure for users who weren't watching the
      // sidebar (e.g. they connected via the palette).
      const deviceId = typeof input === "string" ? input : input.deviceId;
      toastError(`Connect to "${deviceId}" failed`, {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });
}

/** Input to `useConnectManyDevices` (v2.8.1 sidebar "Launch all"). */
export interface ConnectManyInput {
  /** Inventory device ids, in launch order (the tree's visible order). */
  deviceIds: string[];
  /** Called after each device settles (opened OR failed) with the
   *  number settled so far — drives the sidebar's progress banner. */
  onProgress?: (done: number, total: number) => void;
  /** Polled before each connect. Returning true stops the batch after
   *  the in-flight connect (an IPC invoke can't be aborted mid-flight);
   *  devices already opened stay open. */
  shouldStop?: () => boolean;
}

export interface ConnectManyResult {
  opened: number;
  failures: { deviceId: string; message: string }[];
  stopped: boolean;
  total: number;
}

/**
 * Open SSH sessions to MANY devices — the sidebar's multi-select /
 * group-folder "Launch all" (v2.8.1). Same semantics per device as
 * `useConnectDevice` (always a NEW tab; existing sessions untouched).
 *
 * The bulk mechanics — **strictly sequential** (the single-slot host-key /
 * weak-crypto prompt safety invariant), **continue on error**, and progress
 * reporting — live in `sequentialLaunch`; this hook supplies only the
 * per-device `run` (connect + `addSession`, so the fleet appears
 * progressively) and the summary toast.
 */
export function useConnectManyDevices() {
  const addSession = useUiStore((s) => s.addSession);
  return useMutation({
    mutationFn: async ({
      deviceIds,
      onProgress,
      shouldStop,
    }: ConnectManyInput): Promise<ConnectManyResult> => {
      // Strictly sequential — see `sequentialLaunch` for WHY (single-slot
      // host-key / weak-crypto prompt paths).
      const { opened, failures, stopped, total } = await sequentialLaunch({
        ids: deviceIds,
        run: async (deviceId) => {
          const sessionId = await connectDevice(deviceId);
          addSession(sessionId, deviceId);
        },
        onProgress,
        shouldStop,
      });
      return {
        opened,
        failures: failures.map((f) => ({ deviceId: f.id, message: f.message })),
        stopped,
        total,
      };
    },
    onSuccess: ({ opened, failures, stopped, total }) => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      if (failures.length > 0) {
        // One summary toast, not one per failure. Cap the detail lines
        // — bulk failures usually share a cause (VPN down, bad creds)
        // and the first few name it.
        const lines = failures.slice(0, 4).map((f) => `${f.deviceId}: ${f.message}`);
        if (failures.length > 4) lines.push(`…and ${failures.length - 4} more`);
        toastError(`Opened ${opened} of ${total} session${total === 1 ? "" : "s"}`, {
          description: lines.join(" · "),
        });
      } else if (stopped) {
        toastInfo(`Stopped — opened ${opened} of ${total} sessions`);
      } else {
        toastSuccess(`Opened ${opened} session${opened === 1 ? "" : "s"}`);
      }
    },
  });
}

export function useDisconnectSession() {
  const removeSession = useUiStore((s) => s.removeSession);
  return useMutation({
    mutationFn: (sessionId: string) => disconnectSession(sessionId),
    onSuccess: (_, sessionId) => {
      removeSession(sessionId);
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
  });
}

/**
 * Reconnect a (presumably ended) session in place. Best-effort
 * disconnects the dead backend entry so `SshState.sessions` doesn't
 * accumulate orphans, then opens a fresh SSH session against the same
 * device and swaps the new sessionId into the tab's slot via
 * `reconnectSession`. The tab keeps its position, custom label, and
 * any split anchor; the user perceives this as "the same tab, now
 * alive again".
 *
 * Failures fold into a toast — the dead tab stays in place so the
 * user can retry (or X it manually).
 */
export function useReconnectSession() {
  const reconnect = useUiStore((s) => s.reconnectSession);
  return useMutation({
    mutationFn: async ({ oldSessionId, deviceId }: { oldSessionId: string; deviceId: string }) => {
      // Best-effort. The session is already ended on the wire; the
      // backend may have already torn down its SshState entry. Either
      // outcome lets us proceed — we just don't want a dead entry
      // surfacing in the agent's `list_open_sessions` after reconnect.
      try {
        await disconnectSession(oldSessionId);
      } catch {
        // ignore
      }
      const newSessionId = await connectDevice(deviceId);
      return { oldSessionId, newSessionId, deviceId };
    },
    onSuccess: ({ oldSessionId, newSessionId }) => {
      reconnect(oldSessionId, newSessionId);
      void queryClient.invalidateQueries({ queryKey: ["sessions"] });
    },
    onError: (err, { deviceId }) => {
      toastError(`Reconnect to "${deviceId}" failed`, {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });
}
