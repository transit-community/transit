import { useMemo } from "react";

import { useQuery } from "@tanstack/react-query";

import {
  getLocalModelsSettings,
  localEndpointsStatus,
  localModelsStatus,
  type LocalEndpointStatus,
  type LocalModelsSettings,
  type LocalModelsStatus,
} from "@/lib/api";

/**
 * BYOM local-models hooks (v3.0.0). Server-state only — TanStack Query
 * owns all of it (CLAUDE.md §11); nothing here lands in Zustand.
 *
 * The status queries are `enabled`-gated on the feature toggle so
 * Transit never probes localhost ports the user didn't opt into
 * (mirrors the Rust-side short-circuit).
 */

export const LOCAL_SETTINGS_QUERY_KEY = ["local-models", "settings"] as const;
export const LOCAL_STATUS_QUERY_KEY = ["local-models", "status"] as const;
export const LOCAL_ENDPOINTS_STATUS_QUERY_KEY = ["local-models", "endpoints-status"] as const;
export const LOCAL_ENDPOINTS_LIST_QUERY_KEY = ["local-models", "endpoints"] as const;

/**
 * Mirrors `transit_agent::llm::is_local_model` — keep the two in sync
 * (the Rust side is the enforcement predicate; this one only drives
 * UI branching like reconcile + labels).
 */
export function isLocalModelId(id: string): boolean {
  return id.startsWith("ollama:") || id.startsWith("endpoint:");
}

export function useLocalModelsSettings() {
  return useQuery<LocalModelsSettings>({
    queryKey: LOCAL_SETTINGS_QUERY_KEY,
    queryFn: getLocalModelsSettings,
    staleTime: 15_000,
    retry: false,
  });
}

export function useLocalModelsStatus(enabled: boolean) {
  return useQuery<LocalModelsStatus>({
    queryKey: LOCAL_STATUS_QUERY_KEY,
    queryFn: localModelsStatus,
    enabled,
    staleTime: 15_000,
    // Ollama starting/stopping is a thing users do mid-session; a
    // slow background refresh keeps the picker honest without
    // hammering localhost.
    refetchInterval: 60_000,
    retry: false,
  });
}

export function useLocalEndpointsStatus(enabled: boolean) {
  return useQuery<LocalEndpointStatus[]>({
    queryKey: LOCAL_ENDPOINTS_STATUS_QUERY_KEY,
    queryFn: localEndpointsStatus,
    enabled,
    staleTime: 15_000,
    refetchInterval: 60_000,
    retry: false,
  });
}

/** One picker-ready local model. */
export interface LocalPickerModel {
  /** Namespaced id the chat factory routes on. */
  id: string;
  /** Picker label, e.g. `qwen3:8b · local` / `qwen3:8b · Lab vLLM`. */
  label: string;
  /** False for OpenAI-compat endpoint models — that wire exposes no
   *  capability metadata, so tool support is unverified. */
  toolsVerified: boolean;
}

/**
 * Merge the zero-config Ollama models + custom-endpoint models into
 * one selectable list. Filters: Ollama models must report the `tools`
 * capability (the agent loop requires tool calling); endpoint models
 * are excluded only when tool support is known-absent (`false`) —
 * `null` (unverifiable, OpenAI-compat) stays in, labeled unverified.
 * `:cloud` tags never appear here — both probes exclude them (T33).
 */
export function mergeLocalPickerModels(
  status: LocalModelsStatus | undefined,
  endpoints: LocalEndpointStatus[] | undefined,
): LocalPickerModel[] {
  const out: LocalPickerModel[] = [];
  if (status?.reachable) {
    for (const m of status.models) {
      if (m.tools_capable) {
        out.push({ id: m.id, label: `${m.name} · local`, toolsVerified: true });
      }
    }
  }
  for (const ep of endpoints ?? []) {
    if (!ep.reachable) continue;
    for (const m of ep.models) {
      if (m.tools_capable === false) continue;
      out.push({
        id: m.id,
        label: `${m.name} · ${ep.name}`,
        toolsVerified: m.tools_capable === true,
      });
    }
  }
  return out;
}

/**
 * The selectable local models, plus whether the lists have actually
 * LOADED (the model-reconcile effect must never thrash a selection on
 * a transient fetch state).
 */
export function useLocalToolModels(enabled: boolean): {
  models: LocalPickerModel[];
  statusLoaded: boolean;
} {
  const status = useLocalModelsStatus(enabled);
  const endpoints = useLocalEndpointsStatus(enabled);
  const models = useMemo(
    () => mergeLocalPickerModels(status.data, endpoints.data),
    [status.data, endpoints.data],
  );
  return {
    models,
    statusLoaded: enabled && status.isSuccess && endpoints.isSuccess,
  };
}
