import { useMutation, useQuery } from "@tanstack/react-query";

import {
  filesConnect,
  filesDelete,
  filesDisconnect,
  filesEnabled,
  filesListDir,
  filesLocalDelete,
  filesLocalListDir,
  filesLocalMkdir,
  filesLocalRename,
  filesLocalRoots,
  filesMkdir,
  filesReconnect,
  filesRename,
  type DirListing,
  type LocalRoot,
} from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { sequentialLaunch } from "@/lib/sequentialLaunch";
import { toastError, toastInfo, toastSuccess } from "@/lib/toast";
import { clearFilesPaneState, useFilesStore } from "@/stores/filesStore";
import { useUiStore } from "@/stores/uiStore";

/**
 * v5.0.0 Files surface — the Query/mutation layer over the `files_*` IPC.
 *
 * Listings are server state → TanStack Query. Pane cwds / sort / hidden
 * toggles are UI state → `filesStore`. Every mutation's
 * `queryClient.invalidateQueries(...)` call is **inlined in its
 * `onSuccess`**: react-doctor's `query-mutation-missing-invalidation` rule
 * matches the literal call shape and is a hard CI gate, so factoring these
 * into a helper would both hide them from the analyzer and hide from the
 * reader which directory actually refreshes (`mutations.ts:33-44`).
 */

const FILES_ENABLED_KEY = ["filesEnabled"] as const;
const LOCAL_ROOTS_KEY = ["filesLocalRoots"] as const;

/** Query key for one remote directory listing. */
export function remoteDirKey(sessionId: string, path: string) {
  return ["filesRemoteDir", sessionId, path] as const;
}

/** Query key for one local directory listing. `null` = the backend
 *  default (home), which is a distinct cache entry from any concrete
 *  path — the first listing's response tells us what that path is. */
export function localDirKey(path: string | null) {
  return ["filesLocalDir", path] as const;
}

/**
 * Whether the Files surface is enabled. Mirrors the Terminal rail's gate:
 * `staleTime: Infinity` + an optimistic placeholder so the rail entry
 * doesn't flicker in on every mount of a locked-down deployment.
 */
export function useFilesEnabled() {
  return useQuery({
    queryKey: FILES_ENABLED_KEY,
    queryFn: filesEnabled,
    staleTime: Infinity,
    placeholderData: true,
  });
}

/** One remote (SFTP) directory. Disabled while the session is dead — a
 *  refetch over a closed channel would only produce an error banner on
 *  top of the reconnect banner. */
export function useRemoteDir(sessionId: string, path: string, enabled: boolean) {
  return useQuery<DirListing>({
    queryKey: remoteDirKey(sessionId, path),
    queryFn: () => filesListDir(sessionId, path),
    enabled: enabled && sessionId.length > 0 && path.length > 0,
    // A remote directory can change under us (another admin, a transfer);
    // never serve it from cache without a refetch on remount.
    staleTime: 0,
  });
}

/** One local directory. `null` asks the backend for the user's home. */
export function useLocalDir(path: string | null) {
  return useQuery<DirListing>({
    queryKey: localDirKey(path),
    queryFn: () => filesLocalListDir(path),
    staleTime: 0,
  });
}

/** Local filesystem roots (home + `/`, plus drive letters on Windows). */
export function useLocalRoots() {
  return useQuery<LocalRoot[]>({
    queryKey: LOCAL_ROOTS_KEY,
    queryFn: filesLocalRoots,
    staleTime: 5 * 60_000,
  });
}

/**
 * Open a Files session against an inventory device and append its tab.
 * The backend hands back the server's canonical login directory, which
 * seeds the pane's remote cwd before `FilesPane` ever mounts — so the
 * first listing is already the right directory.
 */
export function useOpenFilesSession() {
  const openFilesTab = useUiStore((s) => s.openFilesTab);
  const ensurePane = useFilesStore((s) => s.ensurePane);

  return useMutation({
    mutationFn: (deviceId: string) => filesConnect(deviceId),
    onSuccess: ({ session_id, home }, deviceId) => {
      ensurePane(session_id, home);
      openFilesTab(session_id, deviceId);
    },
    onError: (err, deviceId) => {
      toastError(`Couldn't open file transfer to "${deviceId}"`, {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });
}

/** Input to `useOpenFilesSessions` (the sidebar's "Launch all"). */
export interface OpenFilesManyInput {
  deviceIds: string[];
  /** Called after each device settles (opened OR failed). */
  onProgress?: (done: number, total: number) => void;
  /** Polled before each connect; true stops the batch after the
   *  in-flight one (an IPC invoke can't be aborted mid-flight). */
  shouldStop?: () => boolean;
}

export interface OpenFilesManyResult {
  opened: number;
  failures: { deviceId: string; message: string }[];
  stopped: boolean;
  total: number;
}

/**
 * Open Files sessions to MANY devices — the sidebar's multi-select /
 * group-folder "Launch all".
 *
 * The bulk mechanics — **strictly sequential** (a Files connect runs the same
 * single-slot host-key / weak-crypto handshake as SSH, so it must never
 * parallelize either), continue-on-error, and progress — live in the shared
 * `sequentialLaunch`; this hook supplies only the per-device `run` (connect +
 * seed the pane + open the tab) and the summary toast.
 */
export function useOpenFilesSessions() {
  const openFilesTab = useUiStore((s) => s.openFilesTab);
  const ensurePane = useFilesStore((s) => s.ensurePane);

  return useMutation({
    mutationFn: async ({
      deviceIds,
      onProgress,
      shouldStop,
    }: OpenFilesManyInput): Promise<OpenFilesManyResult> => {
      const { opened, failures, stopped, total } = await sequentialLaunch({
        ids: deviceIds,
        run: async (deviceId) => {
          const result = await filesConnect(deviceId);
          ensurePane(result.session_id, result.home);
          openFilesTab(result.session_id, deviceId);
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
      if (failures.length > 0) {
        const lines = failures.slice(0, 4).map((f) => `${f.deviceId}: ${f.message}`);
        if (failures.length > 4) lines.push(`…and ${failures.length - 4} more`);
        toastError(`Opened ${opened} of ${total} file transfer${total === 1 ? "" : "s"}`, {
          description: lines.join(" · "),
        });
      } else if (stopped) {
        toastInfo(`Stopped — opened ${opened} of ${total} file transfers`);
      } else {
        toastSuccess(`Opened ${opened} file transfer${opened === 1 ? "" : "s"}`);
      }
    },
  });
}

/**
 * Re-establish a dead session in place. The backend keeps the SAME
 * session id, so the tab, its `files:{id}:*` topics, and both pane cwds
 * survive; we only need to un-end the tab and drop the stale listings.
 * A failure leaves the tab ended so the banner stays and the user can
 * retry.
 */
export function useFilesReconnectSession() {
  const markSessionReconnected = useUiStore((s) => s.markSessionReconnected);
  const setRemoteHome = useFilesStore((s) => s.setRemoteHome);

  return useMutation({
    mutationFn: (sessionId: string) => filesReconnect(sessionId),
    onSuccess: ({ home }, sessionId) => {
      setRemoteHome(sessionId, home);
      markSessionReconnected(sessionId);
      // Prefix key: drop every cached directory for THIS session (they
      // were read over the dead channel), leaving other sessions alone.
      void queryClient.invalidateQueries({ queryKey: ["filesRemoteDir", sessionId] });
    },
    onError: (err) => {
      toastError("Reconnect failed", {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });
}

/**
 * Close a Files session from somewhere other than the tab strip's ✕
 * (the session-info panel). Drops the tab and its pane state too, so no
 * orphan state outlives the backend session.
 */
export function useFilesDisconnectSession() {
  const removeSession = useUiStore((s) => s.removeSession);

  return useMutation({
    mutationFn: (sessionId: string) => filesDisconnect(sessionId),
    onSuccess: (_data, sessionId) => {
      clearFilesPaneState(sessionId);
      removeSession(sessionId);
      void queryClient.invalidateQueries({ queryKey: ["filesRemoteDir", sessionId] });
    },
    onError: (err) => {
      toastError("Couldn't close the file transfer session", {
        description: err instanceof Error ? err.message : String(err),
      });
    },
  });
}

// ---------------------------------------------------------------------
// Mutations. Each carries the affected DIRECTORY so `onSuccess` knows
// precisely which listing to invalidate.
// ---------------------------------------------------------------------

/** Rename variables — `fromDir`/`toDir` are the listings to refresh. */
interface RenameVars {
  from: string;
  to: string;
  fromDir: string;
  toDir: string;
}

interface DeleteVars {
  path: string;
  dir: string;
  recursive: boolean;
}

/** Local variants carry `null` dirs (the un-navigated "home" listing). */
interface LocalRenameVars {
  from: string;
  to: string;
  fromDir: string | null;
  toDir: string | null;
}

interface LocalDeleteVars {
  path: string;
  dir: string | null;
  recursive: boolean;
}

export function useRemoteMkdir() {
  return useMutation({
    mutationFn: ({ sessionId, path }: { sessionId: string; dir: string; path: string }) =>
      filesMkdir(sessionId, path),
    onSuccess: (_data, { sessionId, dir }) => {
      void queryClient.invalidateQueries({ queryKey: remoteDirKey(sessionId, dir) });
    },
    onError: (err) =>
      toastError(`Couldn't create the folder: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useRemoteRename() {
  return useMutation({
    mutationFn: ({ sessionId, from, to }: RenameVars & { sessionId: string }) =>
      filesRename(sessionId, from, to),
    onSuccess: (_data, { sessionId, fromDir, toDir }) => {
      void queryClient.invalidateQueries({ queryKey: remoteDirKey(sessionId, fromDir) });
      // A rename that MOVES an entry changes two listings; the second
      // invalidation is a cheap no-op for an in-place rename.
      void queryClient.invalidateQueries({ queryKey: remoteDirKey(sessionId, toDir) });
    },
    onError: (err) =>
      toastError(`Couldn't rename: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useRemoteDelete() {
  return useMutation({
    mutationFn: ({ sessionId, path, recursive }: DeleteVars & { sessionId: string }) =>
      filesDelete(sessionId, path, recursive),
    onSuccess: (_data, { sessionId, dir }) => {
      void queryClient.invalidateQueries({ queryKey: remoteDirKey(sessionId, dir) });
    },
    onError: (err) =>
      toastError(`Couldn't delete: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useLocalMkdir() {
  return useMutation({
    mutationFn: ({ path }: { dir: string | null; path: string }) => filesLocalMkdir(path),
    onSuccess: (_data, { dir }) => {
      void queryClient.invalidateQueries({ queryKey: localDirKey(dir) });
    },
    onError: (err) =>
      toastError(`Couldn't create the folder: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useLocalRename() {
  return useMutation({
    mutationFn: ({ from, to }: LocalRenameVars) => filesLocalRename(from, to),
    onSuccess: (_data, { fromDir, toDir }) => {
      void queryClient.invalidateQueries({ queryKey: localDirKey(fromDir) });
      void queryClient.invalidateQueries({ queryKey: localDirKey(toDir) });
    },
    onError: (err) =>
      toastError(`Couldn't rename: ${err instanceof Error ? err.message : String(err)}`),
  });
}

export function useLocalDelete() {
  return useMutation({
    mutationFn: ({ path, recursive }: LocalDeleteVars) => filesLocalDelete(path, recursive),
    onSuccess: (_data, { dir }) => {
      void queryClient.invalidateQueries({ queryKey: localDirKey(dir) });
    },
    onError: (err) =>
      toastError(`Couldn't delete: ${err instanceof Error ? err.message : String(err)}`),
  });
}
