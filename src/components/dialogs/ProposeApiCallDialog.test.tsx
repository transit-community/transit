import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProposeApiCallDialog } from "@/components/dialogs/ProposeApiCallDialog";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => {}),
}));

// The API-call dialog replies through the SHARED respond_propose_command,
// and (opt-in) sets the chat's auto-approve-GET flag via chatSetAutoApproveGets.
vi.mock("@/lib/api", () => ({
  respondProposeCommand: vi.fn().mockResolvedValue(undefined),
  chatSetAutoApproveGets: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => {
  vi.clearAllMocks();
  useUiStore.setState({
    sessions: [],
    activeTabId: null,
    activeChatId: null,
    pendingApiCallByChat: {},
    pendingApprovalByChat: {},
    completedUnfocusedByChat: {},
  });
});

// The dialog is store-driven — ChatNotificationCenter owns the raw
// `propose-api-call:request` event and writes it here. These helpers drive
// that seam directly.
function fireRequest(payload: {
  request_id: string;
  chat_id: string;
  session_id: string;
  path: string;
  gate_decision?: string;
}) {
  const full = { gate_decision: "allow (GET)", ...payload };
  act(() => {
    useUiStore.getState().setChatPendingApiCall(full.chat_id, full);
    useUiStore.setState({ activeChatId: full.chat_id });
  });
}

function fireCancel(request_id: string) {
  act(() => {
    const st = useUiStore.getState();
    const entry = Object.entries(st.pendingApiCallByChat).find(
      ([, p]) => p.request_id === request_id,
    );
    if (entry) st.setChatPendingApiCall(entry[0], null);
  });
}

describe("ProposeApiCallDialog", () => {
  it("renders nothing when no request is pending", () => {
    render(<ProposeApiCallDialog />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens with the GET path + controller when a request fires", async () => {
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a1", chat_id: "c", session_id: "office-unifi", path: "/v1/sites" });
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("/v1/sites")).toBeInTheDocument();
    // No matching tab in the store → falls back to the raw controller id.
    expect(screen.getByText("office-unifi")).toBeInTheDocument();
    // The GET method is shown (in the description sentence + the badge).
    expect(screen.getAllByText("GET").length).toBeGreaterThanOrEqual(1);
  });

  it("Approve replies kind:approve via the shared IPC and clears the dialog", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a2", chat_id: "c", session_id: "s", path: "/v1/devices" });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-api-call-approve"));
    expect(mocked).toHaveBeenCalledWith({ request_id: "a2", verdict: { kind: "approve" } });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Deny replies kind:deny", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a3", chat_id: "c", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-api-call-deny"));
    expect(mocked).toHaveBeenCalledWith({ request_id: "a3", verdict: { kind: "deny" } });
  });

  it("offers a GET auto-approve checkbox but NOT the command-style regex affordance", async () => {
    // A controller auto-approve is a single GET-only checkbox (safe: a GET
    // can't mutate) — NOT the command dialog's regex allowlist.
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a4", chat_id: "c", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");
    expect(screen.getByTestId("propose-api-call-auto-approve")).toBeInTheDocument();
    expect(screen.queryByTestId("propose-command-auto-approve")).not.toBeInTheDocument();
    expect(screen.queryByTestId("propose-command-regex-input")).not.toBeInTheDocument();
    expect(screen.getByTestId("propose-api-call-approve")).toBeInTheDocument();
    expect(screen.getByTestId("propose-api-call-deny")).toBeInTheDocument();
  });

  it("checking auto-approve then Approve opts the chat into auto-approving GETs", async () => {
    const { respondProposeCommand, chatSetAutoApproveGets } = await import("@/lib/api");
    const mockedResp = vi.mocked(respondProposeCommand);
    const mockedAuto = vi.mocked(chatSetAutoApproveGets);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "aa", chat_id: "chatX", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-api-call-auto-approve"));
    await userEvent.click(screen.getByTestId("propose-api-call-approve"));
    // Flag set for this chat BEFORE the approve reply.
    expect(mockedAuto).toHaveBeenCalledWith("chatX", true);
    expect(mockedResp).toHaveBeenCalledWith({ request_id: "aa", verdict: { kind: "approve" } });
  });

  it("Approve WITHOUT checking auto-approve does not opt in", async () => {
    const { chatSetAutoApproveGets } = await import("@/lib/api");
    const mockedAuto = vi.mocked(chatSetAutoApproveGets);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "ab", chat_id: "c", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-api-call-approve"));
    expect(mockedAuto).not.toHaveBeenCalled();
  });

  it("Deny does not opt into auto-approve even if the box is checked", async () => {
    const { chatSetAutoApproveGets } = await import("@/lib/api");
    const mockedAuto = vi.mocked(chatSetAutoApproveGets);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "ac", chat_id: "c", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("propose-api-call-auto-approve"));
    await userEvent.click(screen.getByTestId("propose-api-call-deny"));
    expect(mockedAuto).not.toHaveBeenCalled();
  });

  it("a cleared pending slot (cancel) dismisses the dialog", () => {
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a5", chat_id: "c", session_id: "s", path: "/v1/sites" });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireCancel("a5");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders the path faithfully in a mono, pre-wrapped box", async () => {
    render(<ProposeApiCallDialog />);
    fireRequest({
      request_id: "a-path",
      chat_id: "c",
      session_id: "s",
      path: "/v1/sites/default/wlans",
    });
    const dialog = await screen.findByRole("dialog");
    const box = dialog.querySelector(".whitespace-pre-wrap.break-all");
    expect(box).not.toBeNull();
    expect(box!.className).toContain("font-mono");
    expect(box!.textContent).toBe("/v1/sites/default/wlans");
  });

  it("renders no close X; Escape and outside-click do not dismiss and never reply", async () => {
    const { respondProposeCommand } = await import("@/lib/api");
    const mocked = vi.mocked(respondProposeCommand);
    render(<ProposeApiCallDialog />);
    fireRequest({ request_id: "a6", chat_id: "c", session_id: "s", path: "/v1/sites" });
    await screen.findByRole("dialog");

    // No close X anywhere (hideClose).
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
