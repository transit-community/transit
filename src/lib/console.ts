import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect } from "react";

import {
  connectConsoleCable,
  listConsoleCables,
  listConsoleDriverStatus,
  type ConsoleConnectArgs,
  type ConsoleConnectResult,
  type ConsoleDriverStatus,
  type HotplugEvent,
  type SerialPortInfo,
} from "@/lib/api";
import { queryClient } from "@/lib/queryClient";
import { toastError } from "@/lib/toast";
import { useUiStore } from "@/stores/uiStore";

const CABLES_KEY = ["consoleCables"] as const;
const DRIVER_STATUS_KEY = ["consoleDriverStatus"] as const;

/**
 * Reactive list of attached console cables.
 *
 * Seeded from `list_console_cables()` and invalidated on every
 * `console:plug` event so the sidebar's hidden-when-empty section
 * appears within ~1s of a cable being plugged in (the hot-plug
 * watcher's poll interval).
 */
export function useConsoleCables() {
  // Subscribe to plug events once per app lifetime; on every event
  // we just refetch — the event payload itself is ignored. Keeping
  // the TanStack cache authoritative means we don't need to think
  // about the snapshot vs event race window.
  useEffect(() => {
    let mounted = true;
    let unlisten: UnlistenFn | undefined;
    listen<HotplugEvent>("console:plug", () => {
      if (!mounted) return;
      void queryClient.invalidateQueries({ queryKey: CABLES_KEY });
    })
      .then((fn) => {
        if (!mounted) {
          fn();
          return;
        }
        unlisten = fn;
      })
      .catch(() => {
        // Not a hard failure — the cable list will still seed once
        // from the initial query; the user just won't see live
        // updates until the next manual invalidation. Fold silently,
        // same trade-off as `useConsoleDriverStatus` below.
      });
    return () => {
      mounted = false;
      unlisten?.();
    };
  }, []);

  return useQuery<SerialPortInfo[]>({
    queryKey: CABLES_KEY,
    queryFn: listConsoleCables,
    // Hot-plug events drive freshness — no polling fallback. The
    // 30s staleTime is just an optimization for re-mounts.
    staleTime: 30_000,
    // Default to an empty array so consumers don't have to guard
    // against `undefined`. The sidebar's hidden-when-empty test
    // becomes `data.length === 0`.
    placeholderData: [],
  });
}

/**
 * Open a console session against `args.port_path`. On success,
 * appends a tab to `uiStore.sessions` using the backend-supplied
 * label as the SessionTab's deviceId (synthetic — there's no
 * inventory device for a console cable).
 */
export function useConnectConsoleCable() {
  const addSession = useUiStore((s) => s.addSession);
  const setSessionLabel = useUiStore((s) => s.setSessionLabel);

  return useMutation<ConsoleConnectResult, Error, ConsoleConnectArgs>({
    mutationFn: connectConsoleCable,
    onSuccess: ({ session_id, label }) => {
      // The SessionTab's `deviceId` field is a string we display on
      // the tab — for SSH it's the inventory id, for console it's a
      // synthetic "console-<chip>-<serial>" prefix so a future
      // sidebar render can tell which transport the tab belongs to.
      // The user-visible text comes from `customLabel` (set right
      // after via setSessionLabel). The AGENT, however, sees the bare
      // `label` as this session's device_id (ConsoleScrollbackSource),
      // so it rides along as `agentDeviceId` — the chat scope popover
      // must speak the backend's vocabulary or console sessions could
      // never be brought into a chat's scope (v2.7.0, T31).
      addSession(session_id, `console-${label}`, label);
      setSessionLabel(session_id, label);
    },
    onError: (err) => {
      toastError("Failed to open console session", {
        description: err.message,
      });
    },
  });
}

/**
 * Reactive USB-driver status. Reads on mount, then re-fetches on every
 * `console:plug` event (since plugging a new chip in might surface a
 * new missing-driver banner). Result is `{ missing_drivers: [] }` on
 * non-macOS platforms.
 */
export function useConsoleDriverStatus() {
  // We piggyback on `useConsoleCables`'s hot-plug listener to invalidate
  // this query too — register a listener here so the hook works in
  // isolation (e.g. if a future caller renders the banner without the
  // cable list).
  useEffect(() => {
    let mounted = true;
    let unlisten: UnlistenFn | undefined;
    listen<HotplugEvent>("console:plug", () => {
      if (!mounted) return;
      void queryClient.invalidateQueries({ queryKey: DRIVER_STATUS_KEY });
    })
      .then((fn) => {
        if (!mounted) {
          fn();
          return;
        }
        unlisten = fn;
      })
      .catch(() => {
        // Same trade-off as `useConsoleCables` — listener attach
        // failure means we just won't refresh on plug events; the
        // 60s staleTime still picks up driver changes eventually.
      });
    return () => {
      mounted = false;
      unlisten?.();
    };
  }, []);

  return useQuery<ConsoleDriverStatus>({
    queryKey: DRIVER_STATUS_KEY,
    queryFn: listConsoleDriverStatus,
    staleTime: 60_000,
    placeholderData: { missing_drivers: [] },
  });
}

/** Build the user-visible row label for a cable. Falls back to the
 *  bare path when the OS didn't classify the device as USB. */
export function cableLabel(info: SerialPortInfo): string {
  if (info.usb) {
    const { manufacturer, product, serial_number } = info.usb;
    const chip =
      manufacturer && product
        ? `${manufacturer} ${product}`
        : product || manufacturer || "USB serial";
    return serial_number ? `${chip} (${serial_number})` : chip;
  }
  return info.port_path;
}
