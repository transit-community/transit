import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useReducer, type ReactElement } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    listApiSessions: vi.fn(),
    previewNetboxSync: vi.fn(),
  };
});

import {
  listApiSessions,
  previewNetboxSync,
  type ApiSessionMeta,
  type NetBoxSyncPreviewWire,
} from "@/lib/api";

import { importReducer, initialImportState, validateRows } from "./importReducer";
import { NetBoxSyncStep } from "./NetBoxSyncStep";

const mockedSessions = vi.mocked(listApiSessions);
const mockedPreview = vi.mocked(previewNetboxSync);

const NETBOX_SESSION: ApiSessionMeta = {
  id: "netbox",
  name: "NetBox (lab)",
  vendor: "netbox",
  kind: "generic",
  host: null,
  console_id: null,
  base_url: "http://netbox.lab:8000/api",
  group: null,
  color: null,
  tags: [],
  backend: "keyring",
  auth: { scheme: "api_key", header: "Authorization", value_prefix: "Token " },
};

const PREVIEW: NetBoxSyncPreviewWire = {
  new: [
    {
      netbox_id: "30",
      proposed_device_id: "vQFX1",
      host: "10.140.0.30",
      name: "vQFX1",
      status: "active",
      vendor_tag: "junos",
      group: "Springfield HQ",
      tags: ["lab"],
      collides: false,
    },
  ],
  changed: [
    {
      device_id: "vEX2",
      netbox_id: "21",
      changes: [{ field: "host", current: "10.140.0.12", incoming: "10.140.0.99" }],
    },
  ],
  stale: [{ device_id: "old-box", netbox_id: "99", host: "10.9.9.9" }],
  unchanged: 3,
  skipped: [],
  warnings: [],
  fetched: 5,
};

/** Host harness: real reducer + live errors, like ImportConnectionsView. */
function Harness() {
  const [state, dispatch] = useReducer(importReducer, {
    ...initialImportState,
    step: "netbox" as const,
  });
  return (
    <NetBoxSyncStep
      state={state}
      dispatch={dispatch}
      errors={validateRows(state.rows, new Set())}
      existingIds={new Set()}
      existingGroups={[]}
      profiles={[{ name: "lab-pw", username: "alice", backend: "keyring", key_path: null }]}
    />
  );
}

function renderWithQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("NetBoxSyncStep (v6.2.0)", () => {
  it("with no NetBox session, points at the APIs rail instead of a picker", async () => {
    mockedSessions.mockResolvedValue([{ ...NETBOX_SESSION, vendor: "meraki", id: "mx" }]);
    renderWithQuery(<Harness />);
    expect(await screen.findByText(/No NetBox API session yet/)).toBeInTheDocument();
    expect(screen.queryByTestId("netbox-session-select")).not.toBeInTheDocument();
  });

  it("fetches the diff and renders the three buckets with decision controls", async () => {
    mockedSessions.mockResolvedValue([NETBOX_SESSION]);
    mockedPreview.mockResolvedValue(PREVIEW);
    renderWithQuery(<Harness />);

    // Pick the session (Radix Select) and fetch active devices.
    await userEvent.click(await screen.findByTestId("netbox-session-select"));
    await userEvent.click(await screen.findByText(/NetBox \(lab\)/));
    await userEvent.click(screen.getByTestId("netbox-fetch"));

    await waitFor(() => expect(mockedPreview).toHaveBeenCalledWith("netbox", true));

    // Tabs render with per-bucket counts once the preview lands.
    expect(await screen.findByTestId("netbox-tab-new")).toHaveTextContent("New (1)");
    expect(screen.getByTestId("netbox-tab-changed")).toHaveTextContent("Changed (1)");
    expect(screen.getByTestId("netbox-tab-stale")).toHaveTextContent("Stale (1)");

    // New tab: the standard grid renders the candidate + the default-auth
    // seeder fills its profile.
    expect(screen.getByDisplayValue("vQFX1")).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByTestId("netbox-default-auth"), "lab-pw");

    // Changed tab: the accepted-by-default checkbox toggles.
    await userEvent.click(screen.getByTestId("netbox-tab-changed"));
    const change = screen.getByTestId("netbox-change-vEX2-host");
    expect(change).toBeChecked();
    await userEvent.click(change);
    expect(change).not.toBeChecked();

    // Stale tab: Keep is the default; Delete is an explicit opt-in and
    // surfaces in the tab label.
    await userEvent.click(screen.getByTestId("netbox-tab-stale"));
    await userEvent.click(screen.getByTestId("netbox-stale-old-box-delete"));
    expect(screen.getByTestId("netbox-tab-stale")).toHaveTextContent("1 to delete");
  });

  it("surfaces a fetch error inline", async () => {
    mockedSessions.mockResolvedValue([NETBOX_SESSION]);
    mockedPreview.mockRejectedValue(new Error("NetBox returned HTTP 403 on page 1"));
    renderWithQuery(<Harness />);

    await userEvent.click(await screen.findByTestId("netbox-session-select"));
    await userEvent.click(await screen.findByText(/NetBox \(lab\)/));
    await userEvent.click(screen.getByTestId("netbox-fetch"));

    expect(await screen.findByRole("alert")).toHaveTextContent(/HTTP 403/);
  });
});
