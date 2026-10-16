import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProposeCommandDialog } from "@/components/dialogs/ProposeCommandDialog";
import { useUiStore } from "@/stores/uiStore";

type Handler = (event: { payload: unknown }) => void;
const registered: Record<string, Handler[]> = {};

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: Handler) => {
    (registered[eventName] ??= []).push(handler);
    return () => {
      registered[eventName] = (registered[eventName] ?? []).filter((h) => h !== handler);
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  respondProposeCommand: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => {
  for (const k of Object.keys(registered)) registered[k] = [];
  vi.clearAllMocks();
  // Reset the shared UI store so a session seeded by one test (for the
  // friendly-name lookup) or a chat's pending approval doesn't leak.
  useUiStore.setState({
    sessions: [],
    activeTabId: null,
    activeChatId: null,
    pendingApprovalByChat: {},
    completedUnfocusedByChat: {},
  });
});

// v2.5.0: the dialog is store-driven (ChatNotificationCenter owns the raw
// events and writes them to the store). These helpers drive that seam
// directly — set the payload's chat as the active chat + its pending
// approval, exactly what the center does on `propose-command:request`.
function fireRequest(payload: {
  request_id: string;
  chat_id: string;
  session_id: string;
  command: string;
  gate_decision?: string;
  allow_auto_approve?: boolean;
  unrestricted?: boolean;
}) {
  // Default to a gated vendor with the auto-approve affordance available;
  // individual tests override allow_auto_approve: false to exercise the
  // unrestricted/custom-vendor hidden path.
  const full = { gate_decision: "allow", allow_auto_approve: true, ...payload };
  act(() => {
    useUiStore.getState().setChatPendingApproval(full.chat_id, full);
    useUiStore.setState({ activeChatId: full.chat_id });
  });
}

function fireCancel(request_id: string) {
  // Clear whichever chat's pending entry carries this request_id — the
  // store effect of a chat-scoped `propose-command:cancel`.
  act(() => {
    const st = useUiStore.getState();
    const entry = Object.entries(st.pendingApprovalByChat).find(
      ([, p]) => p.request_id === request_id,
    );
    if (entry) st.setChatPendingApproval(entry[0], null);
  });
}

describe("ProposeCommandDialog", () => {
  it("renders nothing when no event has fired", () => {
    render(<ProposeCommandDialog />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens with the command + session when the request event fires", async () => {
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-1",
      chat_id: "chat-1",
      session_id: "s-vEX1",
      command: "show bgp summary",
    });
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("show bgp summary")).toBeInTheDocument();
    // No matching tab in the store → falls back to the raw id.
    expect(screen.getByText("s-vEX1")).toBeInTheDocument();
  });

  it("shows the session's friendly tab name (not the raw UUID) when it's a known tab", async () => {
    // Seed the open-sessions store the way TerminalArea does, then fire a
    // request carrying that session's backend UUID.
    act(() => {
      useUiStore.setState({
        sessions: [
          { sessionId: "fff01105-0656-4e89-b4cf-92fcf4048d15", deviceId: "vEX1", ended: false },
        ],
      });
    });
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-name",
      chat_id: "c",
      session_id: "fff01105-0656-4e89-b4cf-92fcf4048d15",
      command: "show version",
    });
    await screen.findByRole("dialog");
    // The friendly tab name is shown...
    expect(screen.getByText("vEX1")).toBeInTheDocument();
    // ...and the opaque UUID is NOT visible text (it lives only in the
    // title attribute for reference on hover).
    expect(screen.queryByText("fff01105-0656-4e89-b4cf-92fcf4048d15")).not.toBeInTheDocument();
  });

  it("Approve calls respondProposeCommand with kind:approve", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-2",
      chat_id: "c",
      session_id: "s",
      command: "show version",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-command-approve"));
    expect(mocked).toHaveBeenCalledWith({
      request_id: "req-2",
      verdict: { kind: "approve" },
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Deny calls respondProposeCommand with kind:deny", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-3",
      chat_id: "c",
      session_id: "s",
      command: "configure",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-command-deny"));
    expect(mocked).toHaveBeenCalledWith({
      request_id: "req-3",
      verdict: { kind: "deny" },
    });
  });

  it("Approve and remember sends always_allow_regex with the typed pattern", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-4",
      chat_id: "c",
      session_id: "s",
      command: "show interfaces",
    });
    await screen.findByRole("dialog");
    // Auto-approve is behind a collapsed disclosure — expand it, then
    // edit the pre-filled regex and approve-and-remember.
    await userEvent.click(screen.getByText(/Expand here/i));
    const input = screen.getByTestId("propose-command-regex-input");
    await userEvent.clear(input);
    await userEvent.type(input, "^show bgp");
    await userEvent.click(screen.getByTestId("propose-command-approve-remember"));
    expect(mocked).toHaveBeenCalledWith({
      request_id: "req-4",
      verdict: { kind: "always_allow_regex", regex: "^show bgp" },
    });
  });

  it("pre-fills the regex with ^show and sends it unedited", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-prefill",
      chat_id: "c",
      session_id: "s",
      command: "show ip bgp summary",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByText(/Expand here/i));
    // Pre-filled with the read-only default so a single click arms ^show.
    const input = screen.getByTestId("propose-command-regex-input") as HTMLInputElement;
    expect(input.value).toBe("^show");
    await userEvent.click(screen.getByTestId("propose-command-approve-remember"));
    expect(mocked).toHaveBeenCalledWith({
      request_id: "req-prefill",
      verdict: { kind: "always_allow_regex", regex: "^show" },
    });
  });

  it("hides the auto-approve affordance entirely when allow_auto_approve is false", async () => {
    // Unrestricted (Linux) and custom (BYOP) vendors have no shipped
    // read-only floor, so the backend sends allow_auto_approve=false and
    // the regex field + "Auto-approve matching" button must not render —
    // every command needs an explicit per-command click.
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-noaa",
      chat_id: "c",
      session_id: "s",
      command: "ls -la",
      allow_auto_approve: false,
    });
    await screen.findByRole("dialog");
    expect(screen.queryByTestId("propose-command-auto-approve")).not.toBeInTheDocument();
    expect(screen.queryByTestId("propose-command-regex-input")).not.toBeInTheDocument();
    expect(screen.queryByTestId("propose-command-approve-remember")).not.toBeInTheDocument();
    // Plain Approve / Deny are still the only way out.
    expect(screen.getByTestId("propose-command-approve")).toBeInTheDocument();
    expect(screen.getByTestId("propose-command-deny")).toBeInTheDocument();
  });

  it("invalid regex shows inline error and does not call IPC", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-5",
      chat_id: "c",
      session_id: "s",
      command: "show ip route",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByText(/Expand here/i));
    const input = screen.getByTestId("propose-command-regex-input");
    await userEvent.clear(input);
    // Invalid regex — unmatched paren.
    await userEvent.type(input, "(unclosed");
    await userEvent.click(screen.getByTestId("propose-command-approve-remember"));
    // No IPC call — input compile-failed first.
    expect(mocked).not.toHaveBeenCalled();
    // Inline error visible (role="alert").
    expect(screen.getByRole("alert")).toBeInTheDocument();
  });

  it("propose-command:cancel for matching request_id dismisses the dialog", () => {
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-6",
      chat_id: "c",
      session_id: "s",
      command: "show",
    });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireCancel("req-6");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("propose-command:cancel for non-matching request_id leaves dialog open", () => {
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-7",
      chat_id: "c",
      session_id: "s",
      command: "show",
    });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireCancel("req-different");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("renders a command containing \\n faithfully across two lines (whitespace-pre-wrap)", async () => {
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-nl",
      chat_id: "c",
      session_id: "s",
      command: "show version\nshow arp",
    });
    const dialog = await screen.findByRole("dialog");
    // The command box must preserve the embedded newline — a modal
    // that collapses `\n` to a space is approving something other
    // than what it displays.
    const box = dialog.querySelector(".whitespace-pre-wrap.break-all");
    expect(box).not.toBeNull();
    expect(box!.className).toContain("font-mono");
    expect(box!.textContent).toBe("show version\nshow arp");
  });

  it("backend-rejected regex (JS-valid, Rust-invalid) keeps the dialog open with an inline error; Approve still works", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    // Tauri rejects with the Rust command's raw error string. The
    // backend validates the regex BEFORE consuming the pending
    // approval, so the modal stays answerable.
    mocked.mockRejectedValueOnce(
      "invalid regex: look-around, including look-ahead and look-behind, is not supported",
    );
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-8",
      chat_id: "c",
      session_id: "s",
      command: "show version",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByText(/Expand here/i));
    const input = screen.getByTestId("propose-command-regex-input");
    await userEvent.clear(input);
    // Lookahead: compiles in JS (so the client-side gate passes) but
    // Rust's regex crate refuses it.
    await userEvent.type(input, "^show (?=ver)");
    await userEvent.click(screen.getByTestId("propose-command-approve-remember"));

    // Inline error shown, dialog still open, pending NOT cleared.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/invalid regex/i);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("show version")).toBeInTheDocument();

    // The approval is still answerable: plain Approve goes through
    // (the mock's rejection was one-shot; default resolves).
    await userEvent.click(screen.getByTestId("propose-command-approve"));
    expect(mocked).toHaveBeenLastCalledWith({
      request_id: "req-8",
      verdict: { kind: "approve" },
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });

  it("'responder consumed' rejection still dismisses silently (chat cancelled mid-flight)", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    vi.mocked(respondProposeCommand).mockRejectedValueOnce("responder consumed");
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-9",
      chat_id: "c",
      session_id: "s",
      command: "show",
    });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-command-approve"));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });

  it("renders no close X; Escape and outside-click do not dismiss and never send a verdict", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeCommandDialog />);
    fireRequest({
      request_id: "req-x",
      chat_id: "c",
      session_id: "s",
      command: "show version",
    });
    await screen.findByRole("dialog");

    // No close X anywhere in the rendered tree (hideClose).
    expect(screen.queryByRole("button", { name: /^close$/i })).not.toBeInTheDocument();

    await userEvent.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    fireEvent.pointerDown(document.body);
    fireEvent.mouseDown(document.body);
    fireEvent.click(document.body);
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    // No dismissal path ever produced a verdict.
    expect(mocked).not.toHaveBeenCalled();
  });
});
