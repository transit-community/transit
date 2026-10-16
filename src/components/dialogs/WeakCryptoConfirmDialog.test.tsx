import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { WeakCryptoConfirmDialog } from "@/components/dialogs/WeakCryptoConfirmDialog";
import type { WeakCryptoConfirmPayload } from "@/lib/api";

// Capture the registered Tauri event handler so each test can fire
// synthetic events into the dialog without rounding through real
// IPC. Mirrors HostKeyConfirmDialog.test.tsx.
type ConfirmHandler = (event: { payload: unknown }) => void;
let registeredHandlers: ConfirmHandler[] = [];

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: ConfirmHandler) => {
    if (eventName === "weak-crypto:confirm") {
      registeredHandlers.push(handler);
    }
    return () => {
      registeredHandlers = registeredHandlers.filter((h) => h !== handler);
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  weakCryptoDecision: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => {
  registeredHandlers = [];
  vi.clearAllMocks();
});

const SAMPLE: WeakCryptoConfirmPayload = {
  host: "192.0.2.86",
  port: 22,
  device_id: "csr1000v",
  kind: "Kex",
  offered: ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"],
};

function fireConfirmEvent(payload: WeakCryptoConfirmPayload) {
  const handlers = [...registeredHandlers];
  act(() => {
    handlers.forEach((h) => h({ payload }));
  });
}

describe("WeakCryptoConfirmDialog", () => {
  it("renders nothing without an event", () => {
    render(<WeakCryptoConfirmDialog />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens with the host + offered algorithms when the event fires", async () => {
    render(<WeakCryptoConfirmDialog />);
    fireConfirmEvent(SAMPLE);

    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    // Host appears twice (data row + remember-checkbox label); just
    // assert at least one match.
    expect(screen.getAllByText(/192\.0\.2\.86:22/).length).toBeGreaterThan(0);
    expect(screen.getByTestId("weak-crypto-offered")).toHaveTextContent(
      "diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha1",
    );
  });

  it("Connect anyway calls weakCryptoDecision(accept=true, remember=false)", async () => {
    const { weakCryptoDecision } = await import("@/lib/api");
    const mocked = vi.mocked(weakCryptoDecision);

    render(<WeakCryptoConfirmDialog />);
    fireConfirmEvent(SAMPLE);
    await screen.findByRole("dialog");

    await userEvent.click(screen.getByTestId("weak-crypto-accept"));

    expect(mocked).toHaveBeenCalledWith("192.0.2.86", 22, true, false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Cancel calls weakCryptoDecision(accept=false) regardless of remember", async () => {
    const { weakCryptoDecision } = await import("@/lib/api");
    const mocked = vi.mocked(weakCryptoDecision);

    render(<WeakCryptoConfirmDialog />);
    fireConfirmEvent(SAMPLE);
    await screen.findByRole("dialog");

    // Even if the user ticked "remember" first, Cancel must not
    // persist the opt-in.
    await userEvent.click(screen.getByTestId("weak-crypto-remember"));
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(mocked).toHaveBeenCalledWith("192.0.2.86", 22, false, false);
  });

  it("Connect anyway + remember persists the opt-in", async () => {
    const { weakCryptoDecision } = await import("@/lib/api");
    const mocked = vi.mocked(weakCryptoDecision);

    render(<WeakCryptoConfirmDialog />);
    fireConfirmEvent(SAMPLE);
    await screen.findByRole("dialog");

    await userEvent.click(screen.getByTestId("weak-crypto-remember"));
    await userEvent.click(screen.getByTestId("weak-crypto-accept"));

    expect(mocked).toHaveBeenCalledWith("192.0.2.86", 22, true, true);
  });

  it("remember resets between modal openings", async () => {
    const { weakCryptoDecision } = await import("@/lib/api");
    const mocked = vi.mocked(weakCryptoDecision);

    render(<WeakCryptoConfirmDialog />);
    // First modal: tick remember + accept.
    fireConfirmEvent(SAMPLE);
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("weak-crypto-remember"));
    await userEvent.click(screen.getByTestId("weak-crypto-accept"));
    expect(mocked).toHaveBeenLastCalledWith("192.0.2.86", 22, true, true);

    // Second modal — same host, different attempt. The remember
    // checkbox must start unchecked; the user must consciously
    // re-tick to grant a remembered downgrade.
    fireConfirmEvent({ ...SAMPLE, port: 2222 });
    await screen.findByRole("dialog");
    await userEvent.click(screen.getByTestId("weak-crypto-accept"));
    expect(mocked).toHaveBeenLastCalledWith("192.0.2.86", 2222, true, false);
  });

  it("renders no close X; Escape and outside-click do not dismiss and never reply to the backend", async () => {
    const { weakCryptoDecision } = await import("@/lib/api");
    const mocked = vi.mocked(weakCryptoDecision);

    render(<WeakCryptoConfirmDialog />);
    fireConfirmEvent(SAMPLE);
    await screen.findByRole("dialog");

    // No close X in the rendered tree (`hideClose`) — previously the
    // unconditional Radix X acted as a silent Cancel path.
    expect(screen.queryByRole("button", { name: /^close$/i })).not.toBeInTheDocument();

    await userEvent.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    fireEvent.pointerDown(document.body);
    fireEvent.mouseDown(document.body);
    fireEvent.click(document.body);
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    // Neither path produced a decision IPC — only the explicit
    // Cancel / Connect-anyway buttons may reply.
    expect(mocked).not.toHaveBeenCalled();
  });
});
