import { useQuery } from "@tanstack/react-query";

import { secretBackendAvailability, type BackendAvailability } from "@/lib/api";

/**
 * Per-backend availability snapshot. Cached app-wide via TanStack
 * Query — the registry's snapshot is taken once at startup and we
 * don't re-probe on every dialog open.
 *
 * The `staleTime: Infinity` means we trust the startup snapshot for
 * the lifetime of the session. If the user installs `op` mid-session
 * they restart the app to pick it up — that's fine for the first
 * version of this UX.
 */
export function useBackendAvailability() {
  return useQuery({
    queryKey: ["backendAvailability"],
    queryFn: secretBackendAvailability,
    staleTime: Infinity,
  });
}

/**
 * Convenience: pull a single backend's availability with a sensible
 * default for the still-loading case ("Ready" — don't render an
 * install banner before we know).
 */
export function useBackendAvailabilityFor(kind: string): BackendAvailability {
  const { data } = useBackendAvailability();
  return data?.[kind] ?? { status: "ready" };
}
