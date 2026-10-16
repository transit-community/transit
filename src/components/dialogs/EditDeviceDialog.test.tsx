import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listAuthProfiles: vi.fn(),
  addDevice: vi.fn(),
  updateDevice: vi.fn(),
  deleteDevice: vi.fn(),
  addAuthProfile: vi.fn(),
  updateAuthProfile: vi.fn(),
  deleteAuthProfile: vi.fn(),
  renameGroup: vi.fn(),
  secretBackendAvailability: vi.fn().mockResolvedValue({}),
  testSecretResolve: vi.fn(),
  enrollSecret: vi.fn(),
  listMonospaceFonts: vi.fn().mockResolvedValue(["JetBrains Mono", "Menlo"]),
}));

import { listAuthProfiles, listDevices, updateDevice, type DeviceMeta } from "@/lib/api";

import { EditDeviceDialog } from "./EditDeviceDialog";

const mockedUpdateDevice = vi.mocked(updateDevice);
const mockedListAuthProfiles = vi.mocked(listAuthProfiles);
const mockedListDevices = vi.mocked(listDevices);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

function makeDevice(overrides: Partial<DeviceMeta> = {}): DeviceMeta {
  return {
    id: "vEX1",
    host: "192.0.2.35",
    port: 22,
    vendor: "junos",
    group: null,
    auth: "lab-pw",
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    color: null,
    tags: [],
    allow_weak_crypto: null,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
    ...overrides,
  };
}

beforeEach(() => {
  mockedListAuthProfiles.mockResolvedValue([
    { name: "lab-pw", username: "alice", backend: "keyring", key_path: null },
  ]);
  mockedListDevices.mockResolvedValue([]);
  mockedUpdateDevice.mockResolvedValue();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("EditDeviceDialog", () => {
  // The dialog renders no control for allow_weak_crypto (only the
  // WeakCryptoConfirmDialog's "remember" checkbox writes it), but
  // `update_device` is a whole-record replace — omitting the field
  // from the payload deserializes to `None` on the Rust side and
  // silently wipes a remembered opt-in.
  it("round-trips jump_via and forward_agent through an untouched save (v6.5.0)", async () => {
    renderWithQuery(
      <EditDeviceDialog
        open
        onOpenChange={vi.fn()}
        device={makeDevice({ jump_via: "work-laptop", forward_agent: true })}
      />,
    );

    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(mockedUpdateDevice).toHaveBeenCalledTimes(1);
    });
    const [, input] = mockedUpdateDevice.mock.calls[0];
    // `update_device` is a whole-record replace: an untouched save must
    // carry the jump path and the forwarding opt-in through verbatim.
    expect(input.jump_via).toBe("work-laptop");
    expect(input.forward_agent).toBe(true);
  });

  it("collapses a cleared jump host and unchecked forwarding to null (v6.5.0)", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);

    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(mockedUpdateDevice).toHaveBeenCalledTimes(1);
    });
    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.jump_via).toBeNull();
    expect(input.forward_agent).toBeNull();
  });

  it("one-click reset takes a jumped device back to direct (v6.5.0 smoke finding)", async () => {
    renderWithQuery(
      <EditDeviceDialog
        open
        onOpenChange={vi.fn()}
        device={makeDevice({ jump_via: "work-laptop" })}
      />,
    );
    // The reset control appears only while a jump is set, so its presence
    // confirms the prefilled state; clicking it must null the field on save.
    await userEvent.click(await screen.findByTestId("jump-via-clear"));
    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));

    await waitFor(() => expect(mockedUpdateDevice).toHaveBeenCalledTimes(1));
    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.jump_via).toBeNull();
  });

  it("jump-host picker filters a large inventory by name or host (v6.5.0 smoke finding)", async () => {
    mockedListDevices.mockResolvedValue([
      makeDevice({ id: "lab-bastion", host: "192.0.2.66" }),
      makeDevice({ id: "Synology", host: "198.51.100.221" }),
      makeDevice({ id: "walrus-mn", host: "69.2.42.119" }),
    ]);
    renderWithQuery(
      <EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice({ id: "R2" })} />,
    );

    await userEvent.click(await screen.findByTestId("jump-via-trigger"));
    // Search by HOST octet — operators know bastions by address too.
    await userEvent.type(
      await screen.findByPlaceholderText(/search by name or host/i),
      "192.0.2.66",
    );
    expect(await screen.findByRole("option", { name: /lab-bastion/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /walrus-mn/ })).toBeNull();

    await userEvent.click(screen.getByRole("option", { name: /lab-bastion/ }));
    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(mockedUpdateDevice).toHaveBeenCalledTimes(1));
    expect(mockedUpdateDevice.mock.calls[0][1].jump_via).toBe("lab-bastion");
  });

  it("preserves allow_weak_crypto=true in the update payload", async () => {
    renderWithQuery(
      <EditDeviceDialog
        open
        onOpenChange={vi.fn()}
        device={makeDevice({ allow_weak_crypto: true })}
      />,
    );

    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(mockedUpdateDevice).toHaveBeenCalledTimes(1);
    });
    const [id, input] = mockedUpdateDevice.mock.calls[0];
    expect(id).toBe("vEX1");
    expect(input.allow_weak_crypto).toBe(true);
    // The rest of the record round-trips unchanged.
    expect(input).toMatchObject({
      id: "vEX1",
      host: "192.0.2.35",
      port: 22,
      vendor: "junos",
      auth: "lab-pw",
    });
  });

  it("passes an unset (null) allow_weak_crypto through without inventing a value", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);

    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(mockedUpdateDevice).toHaveBeenCalledTimes(1);
    });
    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.allow_weak_crypto).toBeNull();
  });

  // v4.1.0 left-nav shell.
  it("renders the section rail and lazy-switches panes", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);

    // Connection is the default section — its field is visible.
    expect(await screen.findByLabelText("Friendly Name")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /connection/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /appearance/i })).toBeInTheDocument();

    // Switching to Appearance mounts its pane and unmounts Connection's.
    await userEvent.click(screen.getByRole("tab", { name: /appearance/i }));
    expect(await screen.findByText("Accent color")).toBeInTheDocument();
    expect(screen.queryByLabelText("Friendly Name")).not.toBeInTheDocument();
  });

  it("jumps the rail to the section holding a validation error on Save", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);

    // Make a Connection field invalid, then navigate AWAY so the error
    // would otherwise be stranded on a hidden pane.
    await userEvent.clear(await screen.findByLabelText("Host"));
    await userEvent.click(screen.getByRole("tab", { name: /appearance/i }));
    await screen.findByText("Accent color");

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    // The rail jumped back to Connection and surfaced the error; nothing saved.
    expect(await screen.findByLabelText("Host")).toBeInTheDocument();
    expect(await screen.findByText("Host is required")).toBeInTheDocument();
    expect(mockedUpdateDevice).not.toHaveBeenCalled();
  });

  it("saves per-device appearance overrides (font family + size + bold accent)", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);
    await userEvent.click(screen.getByRole("tab", { name: /appearance/i }));

    await userEvent.type(await screen.findByLabelText("Terminal font"), "JetBrains Mono");
    const size = screen.getByLabelText("Font size");
    await userEvent.clear(size);
    await userEvent.type(size, "16");
    await userEvent.click(screen.getByLabelText("Bold accent"));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(mockedUpdateDevice).toHaveBeenCalledTimes(1));

    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.font_family).toBe("JetBrains Mono");
    expect(input.font_size).toBe(16);
    expect(input.bold_color).toBe(true);
  });

  it("saves a custom #rrggbb accent picked via the Custom swatch (v6.3.0)", async () => {
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);
    await userEvent.click(screen.getByRole("tab", { name: /appearance/i }));

    // The swatch button proxies into the hidden native input; fire the
    // change there (type=color only ever emits strict #rrggbb).
    fireEvent.change(await screen.findByTestId("device-color-custom-input"), {
      target: { value: "#FFAA00" },
    });
    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(mockedUpdateDevice).toHaveBeenCalledTimes(1));

    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.color).toBe("#ffaa00");
  });

  it("collapses unset appearance overrides to null on the wire", async () => {
    // A device with no font/bold set must send null (not "" / 0 / false),
    // so the TOML stays clean — same discipline as color/highlighting.
    renderWithQuery(<EditDeviceDialog open onOpenChange={vi.fn()} device={makeDevice()} />);
    await userEvent.click(await screen.findByRole("button", { name: /^save$/i }));
    await waitFor(() => expect(mockedUpdateDevice).toHaveBeenCalledTimes(1));

    const [, input] = mockedUpdateDevice.mock.calls[0];
    expect(input.font_family).toBeNull();
    expect(input.font_size).toBeNull();
    expect(input.bold_color).toBeNull();
  });
});
