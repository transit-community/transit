import { useMemo } from "react";

import { useQuery } from "@tanstack/react-query";

import { listAuthProfiles, type AuthProfileMeta, type DeviceMeta } from "@/lib/api";

/**
 * The `SecretRef` backend that means "ask the human at connect time"
 * (v6.1.0). Mirrors `secret_backend_label`'s string in commands.rs.
 */
export const PROMPT_BACKEND = "prompt";

/**
 * Split a launch selection into devices that can be opened unattended
 * and devices that need a human at the keyboard.
 *
 * **Why this exists at all.** Bulk "Launch all" is strictly sequential
 * because the host-key and weak-crypto responder maps are single-slot per
 * `(host, port)` — and interactive auth lands in the same machinery. So a
 * 30-device launch containing prompt-auth devices wouldn't fail, it would
 * *queue thirty credential dialogs*. That is precisely the modal-fatigue
 * path that trains people to type without reading (the T18 lesson applied
 * to credentials rather than commands), so these devices are held back
 * and reported instead of being asked for in a stream.
 *
 * A device whose auth profile is missing from `profiles` is treated as
 * launchable: an unknown profile is the backend's error to raise with a
 * real message, not something to silently drop from a batch.
 */
export function partitionInteractiveAuth(
  devices: DeviceMeta[],
  profiles: AuthProfileMeta[] | undefined,
): { launchable: DeviceMeta[]; interactive: DeviceMeta[] } {
  if (!profiles || profiles.length === 0) {
    return { launchable: devices, interactive: [] };
  }
  const promptProfiles = new Set(
    profiles.reduce<string[]>((acc, p) => {
      if (p.backend === PROMPT_BACKEND) acc.push(p.name);
      return acc;
    }, []),
  );
  if (promptProfiles.size === 0) {
    return { launchable: devices, interactive: [] };
  }
  const launchable: DeviceMeta[] = [];
  const interactive: DeviceMeta[] = [];
  for (const d of devices) {
    (promptProfiles.has(d.auth) ? interactive : launchable).push(d);
  }
  return { launchable, interactive };
}

/** Human-readable note for the devices held back from a bulk launch. */
export function interactiveSkipMessage(skipped: DeviceMeta[]): string {
  if (skipped.length === 1) {
    return `${skipped[0].id} needs interactive sign-in — open it on its own.`;
  }
  const names = skipped
    .slice(0, 3)
    .map((d) => d.id)
    .join(", ");
  const more = skipped.length > 3 ? ` and ${skipped.length - 3} more` : "";
  return `${skipped.length} devices need interactive sign-in (${names}${more}) — open them individually.`;
}

/**
 * Names of auth profiles that ask for a credential at connect time.
 *
 * Shared by the launch-count labels so "Launch all (N)" promises what it
 * will actually do: a device that needs an attended prompt is held back,
 * and counting it would make the menu lie by one.
 */
export function usePromptAuthProfileNames(): Set<string> {
  const { data } = useQuery({ queryKey: ["authProfiles"], queryFn: listAuthProfiles });
  // Memoized on the query data: returning a fresh Set every render
  // changes identity every render, which silently defeats any useMemo
  // keyed on the result (DeviceTree's selection-count memo re-filtered
  // the whole device list on every render because of exactly this).
  return useMemo(() => {
    const names = new Set<string>();
    for (const p of data ?? []) {
      if (p.backend === PROMPT_BACKEND) names.add(p.name);
    }
    return names;
  }, [data]);
}

/** How many of `devices` a bulk launch will actually open. */
export function countLaunchable(devices: DeviceMeta[], promptProfiles: Set<string>): number {
  if (promptProfiles.size === 0) return devices.length;
  let n = 0;
  for (const d of devices) {
    if (!promptProfiles.has(d.auth)) n += 1;
  }
  return n;
}
