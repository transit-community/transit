import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/chat", () => ({
  setChatScope: vi.fn().mockResolvedValue(undefined),
}));

import { ChatScopePopover } from "@/components/ChatScopePopover";
import type { ChatTab } from "@/stores/uiStore";
import { useUiStore } from "@/stores/uiStore";

// Radix Popover needs ResizeObserver; happy-dom lacks it.
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

const chat: ChatTab = { chatId: "c1", model: "opus", seq: 1, scopedDeviceIds: null };

beforeEach(() => {
  useUiStore.setState({ sessions: [], activeTabId: null });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("ChatScopePopover", () => {
  it("lists live SSH/console devices the agent can actually see", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "s2", deviceId: "console-ttyUSB0", ended: false, agentDeviceId: "ttyUSB0" },
        { sessionId: "s3", deviceId: "vEX-dead", ended: true },
      ],
    });
    render(<ChatScopePopover chat={chat} />);
    await userEvent.click(screen.getByTestId("chat-scope-trigger"));

    expect(await screen.findByTestId("chat-scope-device-vEX1")).toBeInTheDocument();
    // Console tabs are listed under the BACKEND's vocabulary.
    expect(screen.getByTestId("chat-scope-device-ttyUSB0")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-scope-device-vEX-dead")).toBeNull();
  });

  it("excludes agent-BLIND surfaces: local shells (T42) and Files sessions (T43)", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "vEX1", ended: false },
        { sessionId: "l1", deviceId: "zsh", ended: false, kind: "local" },
        // A Files session is unreachable from both agent composition points
        // and `transit_files` is banned outside `transit_app` — the picker
        // must not claim the AI can see it.
        { sessionId: "f1", deviceId: "vEX2", ended: false, kind: "files" },
      ],
    });
    render(<ChatScopePopover chat={chat} />);
    await userEvent.click(screen.getByTestId("chat-scope-trigger"));

    expect(await screen.findByTestId("chat-scope-device-vEX1")).toBeInTheDocument();
    expect(screen.queryByTestId("chat-scope-device-zsh")).toBeNull();
    expect(screen.queryByTestId("chat-scope-device-vEX2")).toBeNull();
    // The trigger's count reflects the same universe.
    expect(screen.getByTestId("chat-scope-trigger")).toHaveTextContent("All devices");
  });

  it("a Files-only workspace shows the empty universe, not a phantom device", async () => {
    useUiStore.setState({
      sessions: [{ sessionId: "f1", deviceId: "vEX1", ended: false, kind: "files" }],
    });
    render(<ChatScopePopover chat={chat} />);
    await userEvent.click(screen.getByTestId("chat-scope-trigger"));
    expect(await screen.findByText(/No connected devices/)).toBeInTheDocument();
  });
});
