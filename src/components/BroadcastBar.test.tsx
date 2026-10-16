import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BroadcastBar } from "@/components/BroadcastBar";
import { decodeBase64ToBytes } from "@/lib/terminal/bytes";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  sendInput: vi.fn().mockResolvedValue(undefined),
}));

// Radix Popover uses ResizeObserver; happy-dom lacks it.
class StubResizeObserver {
  observe() {}
  disconnect() {}
  unobserve() {}
}
(globalThis as unknown as { ResizeObserver: typeof StubResizeObserver }).ResizeObserver =
  StubResizeObserver;

function setShown(shown: boolean) {
  useUiStore.setState((s) => ({
    preferences: { ...s.preferences, showBroadcastBar: shown },
  }));
}

function decode(b64: string): string {
  return new TextDecoder().decode(decodeBase64ToBytes(b64));
}

beforeEach(() => {
  useUiStore.setState({ sessions: [], activeTabId: null });
  setShown(false);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("BroadcastBar", () => {
  it("renders nothing when the bar is hidden", () => {
    render(<BroadcastBar />);
    expect(screen.queryByTestId("broadcast-bar")).not.toBeInTheDocument();
  });

  it("shows the live device count (targets of live sessions)", () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "R1", ended: false },
        { sessionId: "s2", deviceId: "R2", ended: false },
        { sessionId: "s3", deviceId: "R3", ended: true }, // ended → not live
      ],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);
    // 2 live of 2 live (ended excluded from BOTH numerator and the live total).
    expect(screen.getByTestId("broadcast-targets")).toHaveTextContent("Sending to 2 of 2");
  });

  it("Enter broadcasts the line + CR to every LIVE session, skipping ended", async () => {
    const { sendInput } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "R1", ended: false },
        { sessionId: "s2", deviceId: "R2", ended: false },
        { sessionId: "s3", deviceId: "R3", ended: true },
      ],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);

    await userEvent.type(screen.getByTestId("broadcast-input"), "show version{Enter}");

    await waitFor(() => expect(sendInput).toHaveBeenCalledTimes(2));
    const calls = vi.mocked(sendInput).mock.calls;
    const byId = Object.fromEntries(calls.map(([id, b64]) => [id, decode(b64 as string)]));
    expect(byId).toEqual({ s1: "show version\r", s2: "show version\r" });
    expect(byId).not.toHaveProperty("s3"); // ended session never targeted
    // Input cleared after send.
    expect(screen.getByTestId("broadcast-input")).toHaveValue("");
  });

  it("excluding a session drops it from the broadcast and updates the count", async () => {
    const { sendInput } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "R1", ended: false },
        { sessionId: "s2", deviceId: "R2", ended: false },
      ],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);

    await userEvent.click(screen.getByTestId("broadcast-targets"));
    await userEvent.click(await screen.findByTestId("broadcast-target-s2"));

    await waitFor(() =>
      expect(screen.getByTestId("broadcast-targets")).toHaveTextContent("Sending to 1 of 2"),
    );

    await userEvent.type(screen.getByTestId("broadcast-input"), "wr mem{Enter}");
    await waitFor(() => expect(sendInput).toHaveBeenCalledTimes(1));
    expect(vi.mocked(sendInput).mock.calls[0][0]).toBe("s1");
  });

  it("Interrupt-all sends Ctrl-C (0x03) to every target", async () => {
    const { sendInput } = await import("@/lib/api");
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "R1", ended: false },
        { sessionId: "s2", deviceId: "R2", ended: false },
      ],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);

    await userEvent.click(screen.getByTestId("broadcast-interrupt-all"));

    await waitFor(() => expect(sendInput).toHaveBeenCalledTimes(2));
    for (const [, b64] of vi.mocked(sendInput).mock.calls) {
      expect(decode(b64 as string)).toBe("\x03");
    }
  });

  it("disables input + interrupt when there are no live sessions", () => {
    useUiStore.setState({
      sessions: [{ sessionId: "s1", deviceId: "R1", ended: true }],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);
    expect(screen.getByTestId("broadcast-input")).toBeDisabled();
    expect(screen.getByTestId("broadcast-interrupt-all")).toBeDisabled();
    expect(screen.getByTestId("broadcast-targets")).toHaveTextContent("Sending to 0 of 0");
  });

  it("the close button turns the bar off", async () => {
    setShown(true);
    render(<BroadcastBar />);
    await userEvent.click(screen.getByRole("button", { name: /close broadcast bar/i }));
    expect(useUiStore.getState().preferences.showBroadcastBar).toBe(false);
  });

  it("excludes every non-PTY tab from the targets AND the M count (v5.0.0)", async () => {
    useUiStore.setState({
      sessions: [
        { sessionId: "s1", deviceId: "R1", ended: false },
        // No PTY: an API tab (a latent bug before v5.0.0 — it was counted
        // and `send_input`-ed) and a Files/SFTP tab.
        { sessionId: "a1", deviceId: "HQ Controller", ended: false, kind: "api" },
        { sessionId: "f1", deviceId: "R9", ended: false, kind: "files" },
        // A local shell HAS a PTY but is excluded by policy (fleet tool).
        { sessionId: "l1", deviceId: "zsh", ended: false, kind: "local" },
      ],
      activeTabId: "s1",
    });
    setShown(true);
    render(<BroadcastBar />);

    // Only the one real device counts, in BOTH numbers.
    expect(screen.getByTestId("broadcast-targets")).toHaveTextContent("Sending to 1 of 1");

    const input = screen.getByTestId("broadcast-input");
    await userEvent.type(input, "show version{Enter}");
    const { sendInput } = await import("@/lib/api");
    await waitFor(() => expect(sendInput).toHaveBeenCalledTimes(1));
    expect(vi.mocked(sendInput).mock.calls[0][0]).toBe("s1");
  });
});
