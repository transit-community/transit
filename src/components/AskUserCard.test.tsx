import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AskUserCard } from "@/components/AskUserCard";

// ---- Tauri event listener capture ----
type Handler = (event: { payload: unknown }) => void;
const handlers = new Map<string, Set<Handler>>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: Handler) => {
    if (!handlers.has(eventName)) handlers.set(eventName, new Set());
    handlers.get(eventName)!.add(handler);
    return () => {
      handlers.get(eventName)?.delete(handler);
    };
  }),
}));

// ---- respondAskUser mock ----
vi.mock("@/lib/api", async (orig) => {
  // Keep the type re-exports working; only override the function.
  const actual = await orig<typeof import("@/lib/api")>();
  return {
    ...actual,
    respondAskUser: vi.fn(async (_id: string, _answer: string) => undefined),
  };
});

function fireEvent(name: string, payload: unknown): void {
  act(() => {
    handlers.get(name)?.forEach((h) => h({ payload }));
  });
}

beforeEach(() => {
  handlers.clear();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("AskUserCard — initial state", () => {
  it("renders nothing when no request is pending", () => {
    render(<AskUserCard chatId="chat-1" />);
    expect(screen.queryByTestId("ask-user-card")).not.toBeInTheDocument();
  });

  it("does not subscribe when chatId is null", async () => {
    const { listen } = await import("@tauri-apps/api/event");
    render(<AskUserCard chatId={null} />);
    expect(listen).not.toHaveBeenCalled();
  });
});

describe("AskUserCard — on ask-user:request", () => {
  it("renders the question and the secret-warning banner", async () => {
    render(<AskUserCard chatId="chat-1" />);
    // wait for the listen() registrations to land
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device did you mean — vEX1 or vEX2?",
    });

    expect(await screen.findByTestId("ask-user-card")).toBeInTheDocument();
    expect(screen.getByText(/which device did you mean/i)).toBeInTheDocument();

    // The warning is the load-bearing part of this card.
    const warning = screen.getByTestId("ask-user-secret-warning");
    expect(warning).toBeInTheDocument();
    expect(warning).toHaveTextContent(/secrets/i);
    expect(warning).toHaveTextContent(/sent to the ai/i);
  });

  it("warning appears ABOVE the input — users see it before typing", async () => {
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "What's the BGP neighbor MD5 key for vEX1?",
    });

    await screen.findByTestId("ask-user-card");
    const warning = screen.getByTestId("ask-user-secret-warning");
    const input = screen.getByTestId("ask-user-input");

    // DOCUMENT_POSITION_FOLLOWING (4) means `input` comes AFTER
    // `warning` in document order. If a refactor moves the warning
    // below the input, this fails — the entire defensive purpose
    // of the banner is that the user sees it BEFORE they start
    // typing.
    const position = warning.compareDocumentPosition(input);
    expect(position & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("ignores requests for a different chat_id", async () => {
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-OTHER",
      question: "Stale event from another chat — should be ignored.",
    });

    // Card never mounts for the wrong chat.
    expect(screen.queryByTestId("ask-user-card")).not.toBeInTheDocument();
  });
});

describe("AskUserCard — send key contract (v6.3.0)", () => {
  // The card MUST share the main composer's send-key rules: it renders in
  // the same thread, autofocused, right after a placeholder that said
  // "↵ to send" — a diverging binding left the agent loop looking hung.
  it("plain Enter sends the answer when Enter-to-send is on (the default)", async () => {
    const { useUiStore } = await import("@/stores/uiStore");
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    const { respondAskUser } = await import("@/lib/api");
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device?",
    });

    await screen.findByTestId("ask-user-card");
    const input = screen.getByTestId("ask-user-input");
    expect(input).toHaveAttribute("placeholder", expect.stringContaining("↵ to send"));
    await userEvent.type(input, "vEX1{Enter}");

    expect(respondAskUser).toHaveBeenCalledWith("req-1", "vEX1");
    expect(screen.queryByTestId("ask-user-card")).not.toBeInTheDocument();
  });

  it("Enter on an empty answer falls through to a newline (never swallowed)", async () => {
    const { useUiStore } = await import("@/stores/uiStore");
    act(() => useUiStore.getState().setChatSendOnEnter(true));
    const { respondAskUser } = await import("@/lib/api");
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device?",
    });

    await screen.findByTestId("ask-user-card");
    const input = screen.getByTestId("ask-user-input");
    await userEvent.type(input, "{Enter}after");
    expect(respondAskUser).not.toHaveBeenCalled();
    expect((input as HTMLTextAreaElement).value).toBe("\nafter");
  });

  it("with Enter-to-send off, Cmd+Enter sends and plain Enter newlines (legacy)", async () => {
    const { useUiStore } = await import("@/stores/uiStore");
    act(() => useUiStore.getState().setChatSendOnEnter(false));
    try {
      const { respondAskUser } = await import("@/lib/api");
      render(<AskUserCard chatId="chat-1" />);
      await new Promise((r) => setTimeout(r, 0));

      fireEvent("ask-user:request", {
        request_id: "req-1",
        chat_id: "chat-1",
        question: "Which device?",
      });

      await screen.findByTestId("ask-user-card");
      const input = screen.getByTestId("ask-user-input");
      await userEvent.type(input, "line one{Enter}line two");
      expect(respondAskUser).not.toHaveBeenCalled();
      await userEvent.keyboard("{Meta>}{Enter}{/Meta}");
      expect(respondAskUser).toHaveBeenCalledWith("req-1", "line one\nline two");
    } finally {
      const { useUiStore } = await import("@/stores/uiStore");
      act(() => useUiStore.getState().setChatSendOnEnter(true));
    }
  });
});

describe("AskUserCard — submit + dismiss", () => {
  it("Send button calls respondAskUser with the request_id + typed answer, then dismisses", async () => {
    const { respondAskUser } = await import("@/lib/api");
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device?",
    });

    await screen.findByTestId("ask-user-card");
    await userEvent.type(screen.getByTestId("ask-user-input"), "vEX1");
    await userEvent.click(screen.getByTestId("ask-user-send"));

    expect(respondAskUser).toHaveBeenCalledWith("req-1", "vEX1");
    // Card dismisses after a successful send.
    expect(screen.queryByTestId("ask-user-card")).not.toBeInTheDocument();
  });

  it("Send button is disabled when the answer is empty / whitespace-only", async () => {
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device?",
    });

    await screen.findByTestId("ask-user-card");
    const send = screen.getByTestId("ask-user-send");
    expect(send).toBeDisabled();

    await userEvent.type(screen.getByTestId("ask-user-input"), "   ");
    // Trimming makes "   " empty — still disabled.
    expect(send).toBeDisabled();

    await userEvent.type(screen.getByTestId("ask-user-input"), "vEX1");
    expect(send).not.toBeDisabled();
  });

  it("chat:{id}:completed dismisses an open card silently", async () => {
    const { respondAskUser } = await import("@/lib/api");
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "Which device?",
    });
    await screen.findByTestId("ask-user-card");

    fireEvent("chat:chat-1:completed", {
      usage: { input_uncached: 0, input_cache_write: 0, input_cache_read: 0, output: 0 },
      stop_reason: "user_aborted",
    });

    expect(screen.queryByTestId("ask-user-card")).not.toBeInTheDocument();
    // No respondAskUser call — backend already dropped the responder
    // via cancel_chat_approvals.
    expect(respondAskUser).not.toHaveBeenCalled();
  });

  it("new request replaces prior question's state cleanly", async () => {
    render(<AskUserCard chatId="chat-1" />);
    await new Promise((r) => setTimeout(r, 0));

    fireEvent("ask-user:request", {
      request_id: "req-1",
      chat_id: "chat-1",
      question: "First question?",
    });
    await screen.findByTestId("ask-user-card");
    await userEvent.type(screen.getByTestId("ask-user-input"), "leftover-text");

    fireEvent("ask-user:request", {
      request_id: "req-2",
      chat_id: "chat-1",
      question: "Second question?",
    });

    // Question text swapped to the new one.
    expect(screen.getByText("Second question?")).toBeInTheDocument();
    // Input cleared so the old answer doesn't leak into the new
    // question's response.
    const input = screen.getByTestId("ask-user-input") as HTMLTextAreaElement;
    expect(input.value).toBe("");
  });
});
