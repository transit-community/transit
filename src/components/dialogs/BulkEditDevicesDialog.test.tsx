import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  listAuthProfiles: vi.fn(),
  bulkUpdateDevices: vi.fn(),
  // The font-family datalist rides @/lib/fonts, which reads this IPC.
  listMonospaceFonts: vi.fn(async () => []),
  // v6.5.0 — the jump-host row's target list.
  listDevices: vi.fn(async () => []),
}));

import { bulkUpdateDevices, listAuthProfiles, type DeviceMeta } from "@/lib/api";

import { BulkEditDevicesDialog } from "./BulkEditDevicesDialog";

const mockedBulk = vi.mocked(bulkUpdateDevices);
const mockedProfiles = vi.mocked(listAuthProfiles);

function renderWithQuery(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

function makeDevice(overrides: Partial<DeviceMeta> = {}): DeviceMeta {
  return {
    id: "sw-a",
    host: "10.0.0.1",
    port: 22,
    vendor: "junos",
    group: null,
    color: null,
    tags: [],
    auth: "lab-pw",
    syntax_highlighting: null,
    quick_copy_paste: null,
    font_family: null,
    font_size: null,
    bold_color: null,
    allow_weak_crypto: null,
    netbox_id: null,
    jump_via: null,
    forward_agent: null,
    ...overrides,
  };
}

beforeEach(() => {
  mockedProfiles.mockResolvedValue([]);
  mockedBulk.mockResolvedValue(2);
});
afterEach(() => {
  vi.clearAllMocks();
});

describe("BulkEditDevicesDialog (v6.3.0)", () => {
  const devices = [
    makeDevice({
      id: "sw-a",
      allow_weak_crypto: true,
      netbox_id: "77",
      // v6.5.0 — non-null on purpose: the passthrough test proves the
      // whole-record replace carries these (null==null would pass even
      // if the mapper dropped the fields).
      jump_via: "jb-1",
      forward_agent: true,
      quick_copy_paste: true,
    }),
    makeDevice({
      id: "sw-b",
      host: "10.0.0.2",
      vendor: "cisco_ios",
      auth: "core-pw",
      group: "Lab",
      tags: ["edge"],
      font_size: 14,
    }),
  ];

  it("Apply is disabled while every row is Leave as is (no-op by default)", () => {
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();
  });

  it("resolves tri-state changes into complete per-device inputs with passthrough", async () => {
    const onOpenChange = vi.fn();
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={onOpenChange} devices={devices} />);

    // Color → Set → custom hex via the picker's hidden native input.
    await userEvent.click(screen.getByTestId("bulk-color-mode-set"));
    fireEvent.change(screen.getByTestId("device-color-custom-input"), {
      target: { value: "#FFAA00" },
    });
    // Bold accent → On; syntax highlighting → Off (== clear on the wire).
    await userEvent.click(screen.getByTestId("bulk-bold-mode-on"));
    await userEvent.click(screen.getByTestId("bulk-syntax-mode-off"));

    await userEvent.click(screen.getByTestId("bulk-apply"));
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));

    const updates = mockedBulk.mock.calls[0][0];
    expect(updates).toHaveLength(2);
    const [a, b] = updates;
    expect(a.id).toBe("sw-a");
    expect(b.id).toBe("sw-b");
    // Patched fields land on BOTH devices.
    expect(a.input.color).toBe("#ffaa00");
    expect(b.input.color).toBe("#ffaa00");
    expect(a.input.bold_color).toBe(true);
    expect(b.input.bold_color).toBe(true);
    expect(a.input.syntax_highlighting).toBeNull();
    expect(b.input.syntax_highlighting).toBeNull();
    // Untouched fields are preserved PER DEVICE — a whole-record replace
    // must not homogenize or drop them across the batch.
    expect(a.input.vendor).toBe("junos");
    expect(b.input.vendor).toBe("cisco_ios");
    expect(a.input.auth).toBe("lab-pw");
    expect(b.input.auth).toBe("core-pw");
    expect(a.input.quick_copy_paste).toBe(true);
    expect(b.input.quick_copy_paste).toBeNull();
    expect(b.input.group).toBe("Lab");
    expect(b.input.tags).toEqual(["edge"]);
    expect(b.input.font_size).toBe(14);
    // The load-bearing passthroughs (same discipline the single-edit
    // dialog pins): losing them would strip a weak-crypto opt-in, a
    // NetBox link, a jump-host path, or an agent-forwarding opt-in as a
    // silent side effect of a color change.
    expect(a.input.allow_weak_crypto).toBe(true);
    expect(a.input.netbox_id).toBe("77");
    expect(a.input.jump_via).toBe("jb-1");
    expect(a.input.forward_agent).toBe(true);
    expect(b.input.allow_weak_crypto).toBeNull();
    expect(b.input.netbox_id).toBeNull();
    expect(b.input.jump_via).toBeNull();
    expect(b.input.forward_agent).toBeNull();
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("jump host (v6.5.0): Set applies one jump to the batch; Clear nulls it; forward_agent never bulk-edits", async () => {
    const { listDevices } = await import("@/lib/api");
    // apply() resolves each row against the FRESHEST ["devices"] cache,
    // which this mock populates — so it must mirror the prop fixtures
    // (a divergent sw-a here would be "fresher" and win).
    vi.mocked(listDevices).mockResolvedValue([
      makeDevice({ id: "jb-2", host: "10.0.0.254" }),
      ...devices,
    ]);

    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    await userEvent.click(screen.getByTestId("bulk-jump-mode-set"));
    // Set with nothing picked is invalid, not destructive.
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();

    await userEvent.click(screen.getByTestId("bulk-jump-select"));
    const option = await screen.findByRole("option", { name: /jb-2/ });
    // The selected device never appears as its own jump target.
    expect(screen.queryByRole("option", { name: /sw-a/ })).toBeNull();
    await userEvent.click(option);

    await userEvent.click(screen.getByTestId("bulk-apply"));
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
    const updates = mockedBulk.mock.calls[0][0];
    expect(updates[0].input.jump_via).toBe("jb-2");
    expect(updates[1].input.jump_via).toBe("jb-2");
    // The security opt-in is NOT a bulk field: per-device values ride
    // through exactly as stored.
    expect(updates[0].input.forward_agent).toBe(true);
    expect(updates[1].input.forward_agent).toBeNull();

    // Clear mode nulls the jump on every selected device.
    vi.clearAllMocks();
    mockedProfiles.mockResolvedValue([]);
    mockedBulk.mockResolvedValue(2);
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    const clears = screen.getAllByTestId("bulk-jump-mode-clear");
    await userEvent.click(clears[clears.length - 1]);
    const applies = screen.getAllByTestId("bulk-apply");
    await userEvent.click(applies[applies.length - 1]);
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
    const cleared = mockedBulk.mock.calls[0][0];
    expect(cleared[0].input.jump_via).toBeNull();
    expect(cleared[1].input.jump_via).toBeNull();
  });

  it("Clear mode nulls the font family; Set with an empty field just disables Apply", async () => {
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    // Set + empty is invalid, NOT a destructive clear — an earlier draft
    // made the freshly-clicked Set mode's default state wipe the field
    // across the selection.
    await userEvent.click(screen.getByTestId("bulk-font-family-mode-set"));
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();

    await userEvent.click(screen.getByTestId("bulk-font-family-mode-clear"));
    await userEvent.click(screen.getByTestId("bulk-apply"));
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
    const updates = mockedBulk.mock.calls[0][0];
    expect(updates[0].input.font_family).toBeNull();
    // An untouched numeric pref still rides through per device.
    expect(updates[1].input.font_size).toBe(14);
  });

  it("a non-integer font size disables Apply (wire type is u16)", async () => {
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    await userEvent.click(screen.getByTestId("bulk-font-size-mode-set"));
    const input = screen.getByLabelText("Terminal font size");
    await userEvent.clear(input);
    await userEvent.type(input, "12.5");
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();
  });

  it("Leave as is preserves an explicitly-stored false verbatim", async () => {
    const withFalse = [
      makeDevice({ id: "sw-a", syntax_highlighting: false }),
      makeDevice({ id: "sw-b", host: "10.0.0.2" }),
    ];
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={withFalse} />);
    await userEvent.click(screen.getByTestId("bulk-bold-mode-on"));
    await userEvent.click(screen.getByTestId("bulk-apply"));
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
    const updates = mockedBulk.mock.calls[0][0];
    // The row the user left alone passes the stored value through —
    // a hand-written `= false` is NOT collapsed to key-removal.
    expect(updates[0].input.syntax_highlighting).toBe(false);
    expect(updates[1].input.syntax_highlighting).toBeNull();
  });

  it("apply resolves against the freshest device cache, not the open-time snapshot", async () => {
    const { queryClient } = await import("@/lib/queryClient");
    try {
      // Simulate a write landing while the dialog sat open: the cache's
      // sw-b gained a NetBox link the snapshot doesn't have.
      queryClient.setQueryData(["devices"], [devices[0], { ...devices[1], netbox_id: "99" }]);
      renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
      await userEvent.click(screen.getByTestId("bulk-bold-mode-on"));
      await userEvent.click(screen.getByTestId("bulk-apply"));
      await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
      const updates = mockedBulk.mock.calls[0][0];
      expect(updates[1].input.netbox_id).toBe("99");
    } finally {
      queryClient.clear();
    }
  });

  it("a failed batch keeps the dialog open (choices survive a retry)", async () => {
    mockedBulk.mockRejectedValue(new Error("device not found: ghost"));
    const onOpenChange = vi.fn();
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={onOpenChange} devices={devices} />);
    await userEvent.click(screen.getByTestId("bulk-bold-mode-on"));
    await userEvent.click(screen.getByTestId("bulk-apply"));
    await waitFor(() => expect(mockedBulk).toHaveBeenCalledTimes(1));
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("an out-of-range font size disables Apply", async () => {
    renderWithQuery(<BulkEditDevicesDialog open onOpenChange={vi.fn()} devices={devices} />);
    await userEvent.click(screen.getByTestId("bulk-font-size-mode-set"));
    const input = screen.getByLabelText("Terminal font size");
    await userEvent.clear(input);
    await userEvent.type(input, "5");
    expect(screen.getByTestId("bulk-apply")).toBeDisabled();
  });
});
