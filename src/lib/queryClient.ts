import { QueryClient } from "@tanstack/react-query";

/**
 * Single QueryClient for the app. Defaults are tuned for the
 * Tauri-IPC-as-server-state pattern:
 *
 *   - `refetchOnWindowFocus: false` — the IPC backend is local; no
 *     network state to be stale against.
 *   - `staleTime: 30_000` — most fetches (device list, settings) don't
 *     change during a session; 30s avoids re-running them on every
 *     component re-mount.
 *   - `retry: 1` — IPC failures are usually backend bugs (not flakes);
 *     one retry is enough to absorb cold-start jitters.
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: 1,
    },
  },
});
