import { useMutation, useQuery } from "@tanstack/react-query";

import {
  listAvailableShells,
  openLocalShell,
  restartLocalShell,
  type LocalShellResult,
  type OpenShellParams,
  type ShellInfo,
} from "@/lib/api";
import { toastError } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

const SHELLS_KEY = ["availableShells"] as const;

/**
 * Discovered local shells + versions (the "look under the hood" list).
 * Installed shells rarely change within a session, so a long stale time
 * keeps this off the subprocess-probing path on every sidebar mount.
 */
export function useAvailableShells() {
  // No `placeholderData` on purpose: a placeholder makes the query report
  // `success` before the FIRST fetch resolves, so `isLoading`/`isPending`
  // would be permanently false and the launcher's "Scanning…" state could
  // never render — during the (real, subprocess-probing) initial discovery
  // it would instead flash "No shells found." Letting `data` be undefined
  // until the first resolve keeps `isLoading` meaningful; callers default it.
  return useQuery<ShellInfo[]>({
    queryKey: SHELLS_KEY,
    queryFn: listAvailableShells,
    staleTime: 5 * 60_000,
  });
}

/**
 * Spawn a local shell in a PTY and append its tab. A local shell has a
 * REAL backend session (unlike an API tab), so on success we push a
 * `kind: "local"` tab keyed by the backend-assigned session id — the
 * standard tab-close X (`disconnectSession`) tears it down via the
 * shared command's local fall-through.
 */
export function useOpenLocalShell() {
  const openShellTab = useUiStore((s) => s.openShellTab);

  return useMutation<LocalShellResult, Error, OpenShellParams>({
    mutationFn: openLocalShell,
    onSuccess: ({ session_id, label }) => {
      openShellTab(session_id, label);
    },
    onError: (err) => {
      toastError("Failed to open local shell", { description: err.message });
    },
  });
}

/**
 * Restart a dead local shell in place ("process exited — press Enter for a
 * new shell"). Re-spawns under the SAME backend session id; on success we
 * flip the tab back to live so the pane un-ends — the exact mechanism the
 * console reconnect uses (`markSessionReconnected`).
 */
export function useRestartLocalShell() {
  const markSessionReconnected = useUiStore((s) => s.markSessionReconnected);

  return useMutation<void, Error, string>({
    mutationFn: restartLocalShell,
    onSuccess: (_result, sessionId) => {
      markSessionReconnected(sessionId);
    },
    onError: (err) => {
      toastError("Failed to restart shell", { description: err.message });
    },
  });
}
