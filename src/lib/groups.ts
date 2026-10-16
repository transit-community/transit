import { useMemo } from "react";

import { useQuery } from "@tanstack/react-query";

import { listDevices } from "@/lib/api";

/**
 * Sorted, unique group paths derived from the current inventory —
 * including every prefix. If the inventory has `Lab/Junos/Sandbox`,
 * the dropdown should also offer `Lab` and `Lab/Junos` so the user
 * can pick a parent without retyping it.
 *
 * Empty inventories return `[]`. Reads from the same `["devices"]`
 * cache as the sidebar so no extra IPC traffic.
 */
export function useExistingGroups(): string[] {
  const { data } = useQuery({ queryKey: ["devices"], queryFn: listDevices });
  return useMemo(() => {
    if (!data) return [];
    const set = new Set<string>();
    for (const d of data) {
      if (!d.group) continue;
      const segments = d.group.split("/").filter((s) => s.length > 0);
      for (let i = 1; i <= segments.length; i++) {
        set.add(segments.slice(0, i).join("/"));
      }
    }
    return [...set].sort();
  }, [data]);
}
