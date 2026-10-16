import { useEffect } from "react";

import { listen } from "@tauri-apps/api/event";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { chatgptStatus, type ChatGptStatus } from "@/lib/api";
import { PROVIDER_MODELS_QUERY_KEY } from "@/lib/providerModels";

/**
 * Sign in with ChatGPT (preview) — status plumbing. Booleans + the
 * display email only ever reach the webview (Rule 1); the OAuth flow, the
 * tokens and the refresh live in `src-tauri/src/chatgpt_auth.rs`.
 *
 * The Rust side emits `chatgpt:signin-success` / `chatgpt:signin-error`
 * when the browser round-trip finishes; this hook turns those into a
 * status refetch and an OpenAI model-list refetch (the plan token lists a
 * different catalogue than a key does).
 */

export const CHATGPT_STATUS_QUERY_KEY = ["chatgpt", "status"] as const;

export interface SigninErrorPayload {
  reason: string;
}

export function useChatGptStatus(opts: { onError?: (reason: string) => void } = {}) {
  const queryClient = useQueryClient();
  const onError = opts.onError;

  useEffect(() => {
    // `listen` reaches into `window.__TAURI_INTERNALS__`; in jsdom that
    // throws synchronously — swallow it, the query still works.
    const unlisteners: Array<() => void> = [];
    const invalidate = () => {
      void queryClient.invalidateQueries({ queryKey: CHATGPT_STATUS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: PROVIDER_MODELS_QUERY_KEY("openai") });
    };
    try {
      void listen("chatgpt:signin-success", invalidate)
        .then((fn) => unlisteners.push(fn))
        .catch(() => {});
      void listen<SigninErrorPayload>("chatgpt:signin-error", (e) => {
        invalidate();
        onError?.(e.payload.reason);
      })
        .then((fn) => unlisteners.push(fn))
        .catch(() => {});
    } catch {
      // Tauri runtime not available (tests).
    }
    return () => {
      for (const u of unlisteners) u();
    };
  }, [queryClient, onError]);

  return useQuery<ChatGptStatus>({
    queryKey: CHATGPT_STATUS_QUERY_KEY,
    queryFn: chatgptStatus,
    staleTime: 0,
    retry: false,
  });
}
