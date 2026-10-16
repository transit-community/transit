import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ChatNotificationCenter } from "@/components/ChatNotificationCenter";
import { useUiStore } from "@/stores/uiStore";

type Handler = (event: { payload: unknown }) => void;
const registered: Record<string, Handler[]> = {};

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: Handler) => {
    (registered[name] ??= []).push(handler);
    return () => {
      registered[name] = (registered[name] ?? []).filter((h) => h !== handler);
    };
  }),
}));

function fire(name: string, payload: unknown) {
  act(() => {
    [...(registered[name] ?? [])].forEach((h) => h({ payload }));
  });
}

/** Two chats, `a` active. */
function seedChats() {
  useUiStore.setState({
    chats: [
      { chatId: "a", model: "m", seq: 1, scopedDeviceIds: null },
      { chatId: "b", model: "m", seq: 2, scopedDeviceIds: null },
    ],
    activeChatId: "a",
    pendingApprovalByChat: {},
    completedUnfocusedByChat: {},
    chatPanelOpen: true,
  });
}

const approval = (chatId: string) => ({
  request_id: `r-${chatId}`,
  chat_id: chatId,
  session_id: "s",
  command: "show version",
  gate_decision: "allow",
  allow_auto_approve: true,
});

beforeEach(() => {
  for (const k of Object.keys(registered)) registered[k] = [];
  useUiStore.setState({
    chats: [],
    activeChatId: null,
    pendingApprovalByChat: {},
    completedUnfocusedByChat: {},
    chatPanelOpen: false,
    preferences: { ...useUiStore.getState().preferences, notifyOnUnfocusedComplete: true },
  });
});

afterEach(() => vi.clearAllMocks());

describe("ChatNotificationCenter", () => {
  it("renders nothing when there's no cross-chat attention", () => {
    seedChats();
    render(<ChatNotificationCenter />);
    expect(screen.queryByTestId("chat-notification-center")).not.toBeInTheDocument();
  });

  it("a background chat's approval shows a card; the ACTIVE chat's does not (that's the modal's job)", async () => {
    seedChats();
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["propose-command:request"]?.length).toBeGreaterThan(0));

    fire("propose-command:request", approval("b"));
    expect(await screen.findByTestId("chat-notif-approval-b")).toBeInTheDocument();

    // The active chat (a) routes to the modal, never a card.
    fire("propose-command:request", approval("a"));
    expect(screen.queryByTestId("chat-notif-approval-a")).not.toBeInTheDocument();
  });

  it("switching to the pending chat drops its card (the modal takes over)", async () => {
    seedChats();
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["propose-command:request"]?.length).toBeGreaterThan(0));
    fire("propose-command:request", approval("b"));
    await screen.findByTestId("chat-notif-approval-b");

    act(() => useUiStore.getState().setActiveChat("b"));
    await waitFor(() =>
      expect(screen.queryByTestId("chat-notif-approval-b")).not.toBeInTheDocument(),
    );
  });

  it("a chat-scoped cancel clears only that chat's card", async () => {
    seedChats();
    // Add a third chat so we can prove the cancel is scoped.
    act(() =>
      useUiStore.setState((s) => ({
        chats: [...s.chats, { chatId: "c", model: "m", seq: 3, scopedDeviceIds: null }],
      })),
    );
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["propose-command:request"]?.length).toBeGreaterThan(0));
    fire("propose-command:request", approval("b"));
    fire("propose-command:request", approval("c"));
    await screen.findByTestId("chat-notif-approval-b");
    await screen.findByTestId("chat-notif-approval-c");

    fire("propose-command:cancel", { request_id: "r-b", chat_id: "b" });
    await waitFor(() =>
      expect(screen.queryByTestId("chat-notif-approval-b")).not.toBeInTheDocument(),
    );
    // c's card survives.
    expect(screen.getByTestId("chat-notif-approval-c")).toBeInTheDocument();
  });

  it("an unfocused completion shows a green card when the notify pref is on", async () => {
    seedChats();
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["chat:b:completed"]?.length).toBeGreaterThan(0));
    fire("chat:b:completed", { stop_reason: "end_turn" });
    expect(await screen.findByTestId("chat-notif-complete-b")).toBeInTheDocument();
  });

  it("no completion card when the notify pref is off (but the store dot still flips)", async () => {
    useUiStore.setState({
      preferences: { ...useUiStore.getState().preferences, notifyOnUnfocusedComplete: false },
    });
    seedChats();
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["chat:b:completed"]?.length).toBeGreaterThan(0));
    fire("chat:b:completed", { stop_reason: "end_turn" });
    await new Promise((r) => setTimeout(r, 0));
    expect(screen.queryByTestId("chat-notif-complete-b")).not.toBeInTheDocument();
    // The green dot is still recorded (the tab shows it); only the card is pref-gated.
    expect(useUiStore.getState().completedUnfocusedByChat.b).toBe(true);
  });

  it("clicking a card focuses the chat and opens a collapsed panel", async () => {
    seedChats();
    act(() => useUiStore.setState({ chatPanelOpen: false }));
    render(<ChatNotificationCenter />);
    await waitFor(() => expect(registered["propose-command:request"]?.length).toBeGreaterThan(0));
    fire("propose-command:request", approval("b"));

    await userEvent.click(await screen.findByTestId("chat-notif-approval-b"));
    expect(useUiStore.getState().activeChatId).toBe("b");
    expect(useUiStore.getState().chatPanelOpen).toBe(true);
  });
});
