import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HostKeyConfirmDialog } from "@/components/dialogs/HostKeyConfirmDialog";

// Tauri event listen() lives behind a stable global hook; the
// dialog's useEffect calls `listen("host-key:confirm", ...)`. We
// capture the registered handler so each test can fire synthetic
// events directly.
type ConfirmHandler = (event: { payload: unknown }) => void;
let registeredHandlers: ConfirmHandler[] = [];

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (eventName: string, handler: ConfirmHandler) => {
    if (eventName === "host-key:confirm") {
      registeredHandlers.push(handler);
    }
    return () => {
      registeredHandlers = registeredHandlers.filter((h) => h !== handler);
    };
  }),
}));

vi.mock("@/lib/api", () => ({
  verifyHostKey: vi.fn().mockResolvedValue(undefined),
}));

afterEach(() => {
  registeredHandlers = [];
  vi.clearAllMocks();
});

function fireConfirmEvent(payload: {
  device_id: string;
  host: string;
  port: number;
  fingerprint: string;
  algorithm: string;
  previous_fingerprint?: string | null;
}) {
  // act() wraps the synchronous state update so React knows to flush
  // before the next assertion — silences the "update not wrapped in
  // act(...)" warning that test runs cleanly otherwise.
  const handlers = [...registeredHandlers];
  act(() => {
    handlers.forEach((h) => h({ payload }));
  });
}

describe("HostKeyConfirmDialog", () => {
  it("renders nothing when no host-key:confirm event has fired", () => {
    render(<HostKeyConfirmDialog />);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens with the fingerprint when the event fires", async () => {
    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "gw-172-20-1-35",
      host: "192.0.2.35",
      port: 22,
      fingerprint: "SHA256:TB9yfs7U9suPXvdMryrKA/UG1ZJrp3DXaZWulMipLoM",
      algorithm: "ssh-ed25519",
    });

    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/192\.0\.2\.35:22/)).toBeInTheDocument();
    expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
    expect(
      screen.getByText("SHA256:TB9yfs7U9suPXvdMryrKA/UG1ZJrp3DXaZWulMipLoM"),
    ).toBeInTheDocument();
  });

  it("Trust calls verifyHostKey(true)", async () => {
    const { verifyHostKey } = await import("@/lib/api");
    const mocked = vi.mocked(verifyHostKey);

    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "gw-host-example",
      host: "host.example",
      port: 2222,
      fingerprint: "SHA256:abc",
      algorithm: "ssh-ed25519",
    });

    await screen.findByRole("dialog");
    await userEvent.click(screen.getByRole("button", { name: /trust/i }));

    expect(mocked).toHaveBeenCalledWith("gw-host-example", "host.example", 2222, true);
    // Dialog clears after the responder resolves.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("Cancel calls verifyHostKey(false)", async () => {
    const { verifyHostKey } = await import("@/lib/api");
    const mocked = vi.mocked(verifyHostKey);

    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "gw-host-example",
      host: "host.example",
      port: 22,
      fingerprint: "SHA256:abc",
      algorithm: "ssh-ed25519",
    });

    await screen.findByRole("dialog");
    await userEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(mocked).toHaveBeenCalledWith("gw-host-example", "host.example", 22, false);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("renders no close X; Escape and outside-click do not dismiss and never call verifyHostKey", async () => {
    const { verifyHostKey } = await import("@/lib/api");
    const mocked = vi.mocked(verifyHostKey);

    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "gw-host-example",
      host: "host.example",
      port: 22,
      fingerprint: "SHA256:abc",
      algorithm: "ssh-ed25519",
    });
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

    // Neither path replied to the TOFU prompt — only the explicit
    // Trust / Cancel buttons may.
    expect(mocked).not.toHaveBeenCalled();
  });

  it("names the DEVICE, not just the address", async () => {
    // The overlapping-address case (two MSP sites both on
    // 192.168.1.1) is exactly when the address alone is ambiguous, so
    // the prompt has to say which inventory entry is being trusted.
    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "customerB-gw",
      host: "192.168.1.1",
      port: 22,
      fingerprint: "SHA256:5fwp/g/qDnZinruCPYMCo2xdBeoapGAcWrWrdET/Ad0",
      algorithm: "ssh-ed25519",
    });

    expect(await screen.findByTestId("host-key-device")).toHaveTextContent("customerB-gw");
    expect(screen.getByText(/192\.168\.1\.1:22/)).toBeInTheDocument();
  });

  it("echoes the device id back so the verdict routes to the right prompt", async () => {
    // The responder map is keyed by device id; replying with only the
    // address would hand one device's Trust click to another's prompt.
    render(<HostKeyConfirmDialog />);
    fireConfirmEvent({
      device_id: "customerA-gw",
      host: "192.168.1.1",
      port: 22,
      fingerprint: "SHA256:5fwp/g/qDnZinruCPYMCo2xdBeoapGAcWrWrdET/Ad0",
      algorithm: "ssh-ed25519",
    });

    await userEvent.click(await screen.findByRole("button", { name: /^trust$/i }));
    const { verifyHostKey } = await import("@/lib/api");
    expect(vi.mocked(verifyHostKey)).toHaveBeenCalledWith("customerA-gw", "192.168.1.1", 22, true);
  });

  describe("changed-key warning variant", () => {
    const changedPayload = {
      device_id: "gw-192-168-139-33",
      host: "192.168.139.33",
      port: 2211,
      fingerprint: "SHA256:5fwp/g/qDnZinruCPYMCo2xdBeoapGAcWrWrdET/Ad0",
      algorithm: "ssh-ed25519",
      previous_fingerprint: "SHA256:fiXpMHKBeXyLx1rIMyCa5NopkWi+ufHm+ptw58i5orU",
    };

    it("renders the warning with BOTH fingerprints when previous_fingerprint is set", async () => {
      render(<HostKeyConfirmDialog />);
      fireConfirmEvent(changedPayload);

      expect(await screen.findByRole("dialog")).toBeInTheDocument();
      expect(screen.getByText(/host key changed/i)).toBeInTheDocument();
      expect(screen.getByText(changedPayload.previous_fingerprint)).toBeInTheDocument();
      expect(screen.getByText(changedPayload.fingerprint)).toBeInTheDocument();
      // The first-contact affordance is not offered on a key change.
      expect(screen.queryByRole("button", { name: /^trust$/i })).not.toBeInTheDocument();
    });

    it("Replace & connect stays disabled until the verification checkbox is ticked", async () => {
      const { verifyHostKey } = await import("@/lib/api");
      const mocked = vi.mocked(verifyHostKey);

      render(<HostKeyConfirmDialog />);
      fireConfirmEvent(changedPayload);
      await screen.findByRole("dialog");

      const replace = screen.getByRole("button", { name: /replace & connect/i });
      expect(replace).toBeDisabled();

      await userEvent.click(screen.getByRole("checkbox"));
      expect(replace).toBeEnabled();

      await userEvent.click(replace);
      expect(mocked).toHaveBeenCalledWith("gw-192-168-139-33", "192.168.139.33", 2211, true);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    it("Don't connect declines without requiring the checkbox", async () => {
      const { verifyHostKey } = await import("@/lib/api");
      const mocked = vi.mocked(verifyHostKey);

      render(<HostKeyConfirmDialog />);
      fireConfirmEvent(changedPayload);
      await screen.findByRole("dialog");

      await userEvent.click(screen.getByRole("button", { name: /don.t connect/i }));
      expect(mocked).toHaveBeenCalledWith("gw-192-168-139-33", "192.168.139.33", 2211, false);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    it("resets the verification checkbox for each new prompt", async () => {
      render(<HostKeyConfirmDialog />);
      fireConfirmEvent(changedPayload);
      await screen.findByRole("dialog");

      await userEvent.click(screen.getByRole("checkbox"));
      await userEvent.click(screen.getByRole("button", { name: /replace & connect/i }));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

      // A later key change must demand a fresh verification — the
      // previous tick never carries over.
      fireConfirmEvent(changedPayload);
      await screen.findByRole("dialog");
      expect(screen.getByRole("checkbox")).not.toBeChecked();
      expect(screen.getByRole("button", { name: /replace & connect/i })).toBeDisabled();
    });

    it("Escape and outside-click do not dismiss the warning and never reply", async () => {
      const { verifyHostKey } = await import("@/lib/api");
      const mocked = vi.mocked(verifyHostKey);

      render(<HostKeyConfirmDialog />);
      fireConfirmEvent(changedPayload);
      await screen.findByRole("dialog");

      expect(screen.queryByRole("button", { name: /^close$/i })).not.toBeInTheDocument();

      await userEvent.keyboard("{Escape}");
      expect(screen.getByRole("dialog")).toBeInTheDocument();

      fireEvent.pointerDown(document.body);
      fireEvent.mouseDown(document.body);
      fireEvent.click(document.body);
      expect(screen.getByRole("dialog")).toBeInTheDocument();

      expect(mocked).not.toHaveBeenCalled();
    });
  });
});
