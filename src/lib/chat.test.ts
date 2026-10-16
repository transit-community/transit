import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The chat lifecycle thunks keep TWO mirrors truthful: the uiStore tab
// strip and the never-stale BACKEND_CHATS_QUERY_KEY cache. These tests
// pin the review findings: a closed chat must leave the cache (or a
// panel remount inside gcTime resurrects it as a ghost tab over a
// destroyed session), a created chat must enter it, and the restore
// sync is add-only.

vi.mock("@/lib/api", () => ({
  chatCancel: vi.fn(async () => {}),
  chatCreate: vi.fn(async () => "new-chat-id"),
  chatDestroy: vi.fn(async () => {}),
  chatMessages: vi.fn(async () => []),
  chatSendMessage: vi.fn(async () => {}),
  chatSetModel: vi.fn(async () => {}),
  chatSetScope: vi.fn(async () => {}),
}));

vi.mock("@/lib/toast", () => ({
  toastError: vi.fn(),
  toastInfo: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

// A REAL QueryClient (fresh per test via resetModules) so setQueryData /
// getQueryData behave exactly as they do in the app.
vi.mock("@/lib/queryClient", async () => {
  const { QueryClient } = await import("@tanstack/react-query");
  return { queryClient: new QueryClient() };
});

async function load() {
  const api = await import("@/lib/api");
  const chat = await import("@/lib/chat");
  const { queryClient } = await import("@/lib/queryClient");
  const { useUiStore, CHAT_TABS_MAX } = await import("@/stores/uiStore");
  return { api, chat, queryClient, useUiStore, CHAT_TABS_MAX };
}

describe("chat lifecycle thunks (v6.3.0 backend-cache truthfulness)", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
  });
  afterEach(() => localStorage.clear());

  it("closeChat removes the tab, filters the backend cache, and destroys the session", async () => {
    const { api, chat, queryClient, useUiStore } = await load();
    const s = () => useUiStore.getState();
    s().addChat("a", "m");
    s().addChat("b", "m");
    queryClient.setQueryData(chat.BACKEND_CHATS_QUERY_KEY, [
      { chat_id: "a", model: "m" },
      { chat_id: "b", model: "m" },
    ]);

    chat.closeChat("a");

    expect(s().chats.map((c) => c.chatId)).toEqual(["b"]);
    expect(queryClient.getQueryData(chat.BACKEND_CHATS_QUERY_KEY)).toEqual([
      { chat_id: "b", model: "m" },
    ]);
    expect(vi.mocked(api.chatDestroy)).toHaveBeenCalledWith("a");
  });

  it("createChat adds the tab and mirrors it into the backend cache", async () => {
    const { chat, queryClient, useUiStore } = await load();
    queryClient.setQueryData(chat.BACKEND_CHATS_QUERY_KEY, []);

    await chat.createChat("m");

    expect(useUiStore.getState().chats.map((c) => c.chatId)).toEqual(["new-chat-id"]);
    expect(queryClient.getQueryData(chat.BACKEND_CHATS_QUERY_KEY)).toEqual([
      { chat_id: "new-chat-id", model: "m" },
    ]);
  });

  it("createChat destroys the orphan and skips the cache when the cap fills mid-await", async () => {
    const { api, chat, queryClient, useUiStore, CHAT_TABS_MAX } = await load();
    const s = () => useUiStore.getState();
    for (let i = 0; i < CHAT_TABS_MAX - 1; i++) s().addChat(`pre-${i}`, "m");
    queryClient.setQueryData(chat.BACKEND_CHATS_QUERY_KEY, []);
    // The last slot fills while chat_create is in flight: addChat no-ops
    // at the cap, so the backend session is an orphan — it must be
    // destroyed AND stay out of the cache (the early-return fix).
    vi.mocked(api.chatCreate).mockImplementationOnce(async () => {
      s().addChat("filler", "m");
      return "orphan-id";
    });

    await chat.createChat("m");

    expect(s().chats.some((c) => c.chatId === "orphan-id")).toBe(false);
    expect(vi.mocked(api.chatDestroy)).toHaveBeenCalledWith("orphan-id");
    expect(queryClient.getQueryData(chat.BACKEND_CHATS_QUERY_KEY)).toEqual([]);
  });

  it("applyBackendChats is add-only and reports how many tabs it added", async () => {
    const { chat, useUiStore } = await load();
    const s = () => useUiStore.getState();
    s().addChat("a", "live-model");

    const added = chat.applyBackendChats([
      { chat_id: "a", model: "stale-model" },
      { chat_id: "restored", model: "m" },
    ]);

    expect(added).toBe(1);
    const byId = Object.fromEntries(s().chats.map((c) => [c.chatId, c.model]));
    // The live tab's model is never clobbered by the backend list.
    expect(byId).toEqual({ a: "live-model", restored: "m" });
  });
});
