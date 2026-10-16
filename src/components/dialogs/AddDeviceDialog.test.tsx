import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
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
}));

import { addDevice, listAuthProfiles, listDevices, type DeviceInput } from "@/lib/api";

import { AddDeviceDialog } from "./AddDeviceDialog";

const mockedAddDevice = vi.mocked(addDevice);
const mockedListAuthProfiles = vi.mocked(listAuthProfiles);
const mockedListDevices = vi.mocked(listDevices);

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  mockedListAuthProfiles.mockResolvedValue([
    { name: "lab-pw", username: "alice", backend: "keyring", key_path: null },
  ]);
  mockedListDevices.mockResolvedValue([]);
  mockedAddDevice.mockResolvedValue();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("AddDeviceDialog", () => {
  it("submits a valid device through addDevice and closes on success", async () => {
    const onOpenChange = vi.fn();
    renderWithQuery(<AddDeviceDialog open onOpenChange={onOpenChange} />);

    await userEvent.type(screen.getByLabelText("Friendly Name"), "vEX1");
    await userEvent.type(screen.getByLabelText("Host"), "192.0.2.35");
    // Default port 22 is pre-filled; default vendor "junos" pre-selected.

    // Group is a combobox: open it, type a new path, click the
    // "Create..." item.
    const groupTrigger = screen.getByRole("combobox", { name: /group/i });
    await userEvent.click(groupTrigger);
    const groupSearch = await screen.findByPlaceholderText(/search or type to create new/i);
    await userEvent.type(groupSearch, "Lab/Junos");
    // The "Create Lab/Junos" row is a cmdk option (role="option").
    await userEvent.click(await screen.findByRole("option", { name: /Create Lab\/Junos/ }));

    // Open the auth select; click the only profile.
    const authTrigger = screen.getByRole("combobox", { name: /auth profile/i });
    await userEvent.click(authTrigger);
    await userEvent.click(await screen.findByText("lab-pw"));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    await waitFor(() => {
      expect(mockedAddDevice).toHaveBeenCalledTimes(1);
    });
    const expected: DeviceInput = {
      id: "vEX1",
      host: "192.0.2.35",
      port: 22,
      vendor: "junos",
      group: "Lab/Junos",
      color: null,
      tags: [],
      auth: "lab-pw",
      // Per-device syntax highlighting + quick copy/paste — unchecked,
      // so the dialog sends `null` to keep the TOML clean (no
      // explicit "false").
      syntax_highlighting: null,
      quick_copy_paste: null,
      // v4.1.0 appearance overrides — unset, so also null on the wire.
      font_family: null,
      font_size: null,
      bold_color: null,
      // v6.5.0 — untouched jump-host select ("" = direct) and unchecked
      // agent forwarding both collapse to null on the wire.
      jump_via: null,
      forward_agent: null,
    };
    expect(mockedAddDevice).toHaveBeenCalledWith(expected);

    await waitFor(() => {
      expect(onOpenChange).toHaveBeenCalledWith(false);
    });
  });

  it("shows the inline error when the backend rejects", async () => {
    mockedAddDevice.mockRejectedValue(new Error("device id 'vEX1' is already in use"));

    renderWithQuery(<AddDeviceDialog open onOpenChange={vi.fn()} />);

    await userEvent.type(screen.getByLabelText("Friendly Name"), "vEX1");
    await userEvent.type(screen.getByLabelText("Host"), "192.0.2.35");
    const authTrigger = screen.getByRole("combobox", { name: /auth profile/i });
    await userEvent.click(authTrigger);
    await userEvent.click(await screen.findByText("lab-pw"));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/already in use/);
  });

  it("rejects an invalid id with the inline schema error", async () => {
    renderWithQuery(<AddDeviceDialog open onOpenChange={vi.fn()} />);

    await userEvent.type(screen.getByLabelText("Friendly Name"), "has spaces");
    await userEvent.type(screen.getByLabelText("Host"), "h");
    const authTrigger = screen.getByRole("combobox", { name: /auth profile/i });
    await userEvent.click(authTrigger);
    await userEvent.click(await screen.findByText("lab-pw"));

    await userEvent.click(screen.getByRole("button", { name: /^save$/i }));

    expect(await screen.findByText(/letters, digits, underscore/i)).toBeInTheDocument();
    expect(mockedAddDevice).not.toHaveBeenCalled();
  });

  it("pre-fills the group field when defaultGroup is provided", () => {
    renderWithQuery(<AddDeviceDialog open onOpenChange={vi.fn()} defaultGroup="Prod/Routers" />);
    // Combobox renders the current value as the trigger button's text.
    const groupTrigger = screen.getByRole("combobox", { name: /group/i });
    expect(groupTrigger).toHaveTextContent("Prod/Routers");
  });

  // Regression (v1.4.1): the dialog stays mounted (Sidebar toggles `open`),
  // so a defaultGroup arriving on a later open — the "New device in this
  // group" path — must still pre-fill. Before the reset-on-open fix the
  // group stayed empty because useForm read defaultValues only at mount.
  it("pre-fills the group when reopened in a group after mounting closed", async () => {
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: 0 } },
    });
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <AddDeviceDialog open={false} onOpenChange={vi.fn()} />
      </QueryClientProvider>,
    );
    rerender(
      <QueryClientProvider client={client}>
        <AddDeviceDialog open onOpenChange={vi.fn()} defaultGroup="Prod/Routers" />
      </QueryClientProvider>,
    );
    const groupTrigger = await screen.findByRole("combobox", { name: /group/i });
    expect(groupTrigger).toHaveTextContent("Prod/Routers");
  });
});
