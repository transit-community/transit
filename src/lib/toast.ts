import { toast as sonner } from "sonner";

/**
 * Phase 7a C3 — toast surface (Decision A1: Sonner).
 *
 * Every async success/error in the UI that the user could miss
 * otherwise should land here. Sites wired in v1:
 *   - provider key saved / cleared
 *   - Connect failure (the sidebar's persistent banner is still the
 *     primary surface, but a toast catches the *moment* of failure)
 *   - Inventory edit succeeded (Add/Edit/Delete device, Add/Edit/
 *     Delete auth profile, rename group)
 *   - Weak-crypto "Remember" persisted
 *   - Chat completed / aborted via Stop button
 *   - Update available (C12)
 *
 * Keep the API tight — `toastSuccess` / `toastError` / `toastInfo`
 * for synchronous emissions, `toastPromise` for promise-shaped
 * async work. If you need the full Sonner surface (rich actions,
 * custom IDs, etc.) for a one-off site, import `toast` from
 * `sonner` directly.
 *
 * Defaults baked in:
 *   - Errors persist until dismissed (`duration: Infinity`). The
 *     user might be away from the keyboard when the failure fires
 *     and shouldn't lose the message.
 *   - Successes auto-dismiss at 4s.
 *   - Info auto-dismisses at 5s.
 *   - Hover pauses the dismiss timer.
 */

export interface ToastOpts {
  /** Optional Sonner id — pass when you want to dedupe or update an
   *  in-flight toast (e.g. replace "Saving..." with "Saved"). */
  id?: string | number;
  /** Optional millisecond duration override. */
  duration?: number;
  /** Optional description shown below the main message. */
  description?: string;
}

export function toastSuccess(message: string, opts: ToastOpts = {}) {
  return sonner.success(message, { duration: 4000, ...opts });
}

export function toastError(message: string, opts: ToastOpts = {}) {
  return sonner.error(message, { duration: Infinity, ...opts });
}

export function toastInfo(message: string, opts: ToastOpts = {}) {
  return sonner(message, { duration: 5000, ...opts });
}

/**
 * Wrap a Promise in a toast that flips through loading → success /
 * error labels automatically. Thin pass-through over `sonner.promise`
 * — the helper exists for consistency with the other named exports
 * and to keep `import { toastPromise } from "@/lib/toast"` as the
 * one-stop import for callers. Returns the same promise so callers
 * can still await or chain it.
 */
export function toastPromise<T>(
  promise: Promise<T>,
  labels: {
    loading: string;
    success: string | ((data: T) => string);
    error: string | ((err: unknown) => string);
  },
): Promise<T> {
  sonner.promise(promise, labels);
  return promise;
}
