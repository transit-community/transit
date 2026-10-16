import { useEffect } from "react";

import { useQuery } from "@tanstack/react-query";

import {
  providerForModel,
  providerModelsList,
  type Provider,
  type ProviderKeysStatus,
  type ProviderModel,
} from "@/lib/api";
import { isLocalModelId } from "@/lib/localModels";
import { useUiStore } from "@/stores/uiStore";

/**
 * Live model discovery for the two direct providers. Server state lives in
 * TanStack Query (CLAUDE.md §11); the last successful list is mirrored into
 * `preferences.cachedModels` so the picker is populated at launch and keeps
 * working offline. The provider's own catalogue is the source of truth —
 * nothing here hard-codes a model that exists today.
 */

export const PROVIDER_MODELS_QUERY_KEY = (provider: Provider) =>
  ["provider-models", provider] as const;

/** One day: a new model is rare, a Settings → Refresh is one click away. */
const MODELS_STALE_MS = 24 * 60 * 60_000;

export function useProviderModels(provider: Provider, enabled: boolean) {
  const setCachedModels = useUiStore((s) => s.setCachedModels);
  const query = useQuery<ProviderModel[]>({
    queryKey: PROVIDER_MODELS_QUERY_KEY(provider),
    queryFn: () => providerModelsList(provider),
    enabled,
    staleTime: MODELS_STALE_MS,
    refetchOnWindowFocus: false,
    retry: false,
  });
  // Mirror a successful fetch into the persisted cache. Store-driven
  // (not an event handler): the query resolves on its own schedule.
  // react-doctor-disable-next-line react-doctor/no-effect-event-handler
  const data = query.data;
  useEffect(() => {
    if (data) setCachedModels(provider, data);
  }, [data, provider, setCachedModels]);
  return query;
}

/** Level the picker groups under; `other` is for user-typed custom ids. */
export type PickerLevel = ProviderModel["level"] | "other";

export interface PickerModel {
  id: string;
  displayName: string;
  level: PickerLevel;
  created: number | null;
}

/**
 * Last-resort list for a key with no discovery result and no cache yet
 * (first run, offline). Deliberately short and bland: it exists so the
 * picker is never empty while a key is enrolled, not to be current.
 */
export const FALLBACK_MODELS: Readonly<Record<Provider, ReadonlyArray<PickerModel>>> = {
  anthropic: [
    { id: "claude-sonnet-5-5", displayName: "Sonnet 5.5", level: "medium", created: null },
    { id: "claude-opus-5-5", displayName: "Opus 5.5", level: "advanced", created: null },
    { id: "claude-haiku-4-5", displayName: "Haiku 4.5", level: "easy", created: null },
  ],
  openai: [
    { id: "gpt-5.6-terra", displayName: "GPT-5.6 Terra", level: "medium", created: null },
    { id: "gpt-5.6-sol", displayName: "GPT-5.6 Sol", level: "advanced", created: null },
    { id: "gpt-5.6-luna", displayName: "GPT-5.6 Luna", level: "easy", created: null },
  ],
};

/**
 * Preferred defaults for a NEW chat, in order. The first id present in
 * the offered list wins; this is the only place a model id is written
 * down for the picker, and it only steers the default — it never gates
 * what is shown.
 */
export const PREFERRED_DEFAULTS: ReadonlyArray<string> = [
  "claude-sonnet-5-5",
  "gpt-5.6-terra",
  "claude-sonnet-5",
  "claude-sonnet-4-6",
];

/** Picker display: the provider's name minus a leading family word the
 *  narrow trigger would truncate to ("Claude Sonnet 5.5" → "Sonnet 5.5"). */
export function pickerDisplayName(m: ProviderModel): string {
  return m.display_name.replace(/^Claude /, "");
}

function toPicker(m: ProviderModel): PickerModel {
  return { id: m.id, displayName: pickerDisplayName(m), level: m.level, created: m.created };
}

/**
 * The provider models the enrolled keys can serve: per provider, the
 * discovered list (else the persisted cache, else the fallback), then the
 * user's custom ids under `other`. Pure — unit-tested without rendering.
 */
export function offeredProviderModels(
  keys: ProviderKeysStatus | undefined,
  discovered: Partial<Record<Provider, ProviderModel[] | undefined>>,
  cached: Partial<Record<Provider, ProviderModel[] | undefined>>,
  customIds: ReadonlyArray<string>,
): PickerModel[] {
  if (!keys) return [];
  const out: PickerModel[] = [];
  const seen = new Set<string>();
  const push = (m: PickerModel) => {
    if (isLocalModelId(m.id) || seen.has(m.id)) return;
    seen.add(m.id);
    out.push(m);
  };
  for (const provider of ["anthropic", "openai"] as const) {
    if (!keys[provider]) continue;
    const live = discovered[provider];
    const stored = cached[provider];
    const list: ReadonlyArray<PickerModel> =
      live && live.length > 0
        ? live.map(toPicker)
        : stored && stored.length > 0
          ? stored.map(toPicker)
          : FALLBACK_MODELS[provider];
    for (const m of list) push(m);
  }
  for (const id of customIds) {
    const provider = providerForModel(id);
    if (!keys[provider]) continue;
    push({ id, displayName: id, level: "other", created: null });
  }
  return out;
}

/**
 * Default model for a new chat: first preferred id present → newest
 * medium → newest of anything. `null` when nothing is offered (the caller
 * falls through to a local model).
 */
export function pickDefaultModel(offered: ReadonlyArray<PickerModel>): string | null {
  if (offered.length === 0) return null;
  for (const id of PREFERRED_DEFAULTS) {
    if (offered.some((m) => m.id === id)) return id;
  }
  const newest = (list: ReadonlyArray<PickerModel>) =>
    [...list].sort((a, b) => (b.created ?? -1) - (a.created ?? -1))[0];
  const medium = offered.filter((m) => m.level === "medium");
  return (medium.length > 0 ? newest(medium) : newest(offered)).id;
}
