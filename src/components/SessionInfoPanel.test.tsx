import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SessionInfoPanel, relativeTime } from "@/components/SessionInfoPanel";
import { useUiStore } from "@/stores/uiStore";

vi.mock("@/lib/api", () => ({
  listDevices: vi.fn(),
  listOpenSessions: vi.fn(),
  connectDevice: vi.fn(),
  disconnectSession: vi.fn(),
  // v5.0.0 — the Files card's own teardown IPC.
  filesDisconnect: vi.fn().mockResolvedValue(undefined),
}));

import {
  connectDevice,
  disconnectSession,
  filesDisconnect,
  listDevices,
  listOpenSessions,
} from "@/lib/api";

const mockedListDevices = vi.mocked(listDevices);
const mockedListOpenSessions = vi.mocked(listOpenSessions);
const mockedDisconnect = vi.mocked(disconnectSession);

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return render(
    <QueryClientProvider client={client}>
      <SessionInfoPanel />
    </QueryClientProvider>,
  );
}

const VEX1 = {
  id: "vEX1",
  host: "192.0.2.35",
  port: 22,
  vendor: "junos",
  group: "Lab/Junos",
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
};

beforeEach(() => {
  act(() => {
    useUiStore.setState({
      sessionInfoPanelOpen: false,
      activeDeviceId: null,
      sessions: [],
      activeTabId: null,
    });
  });
  mockedListDevices.mockResolvedValue([VEX1]);
  mockedListOpenSessions.mockResolvedValue([]);
  vi.mocked(connectDevice).mockResolvedValue("new-session-id");
  mockedDisconnect.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("SessionInfoPanel", () => {
  it("renders the collapsed rail when sessionInfoPanelOpen is false", () => {
    renderPanel();
    expect(screen.getByTestId("session-info-panel-closed")).toBeInTheDocument();
    expect(screen.queryByTestId("session-info-panel")).not.toBeInTheDocument();
  });

  it("expands when the store flag flips", async () => {
    renderPanel();
    act(() => useUiStore.getState().toggleSessionInfoPanel());
    expect(await screen.findByTestId("session-info-panel")).toBeInTheDocument();
    expect(screen.queryByTestId("session-info-panel-closed")).not.toBeInTheDocument();
  });

  it("shows the empty state when no tab is active", async () => {
    renderPanel();
    act(() => useUiStore.getState().toggleSessionInfoPanel());
    await screen.findByTestId("session-info-panel");
    expect(screen.getByTestId("session-info-empty")).toBeInTheDocument();
  });

  it("renders device + session metadata for the active tab", async () => {
    mockedListOpenSessions.mockResolvedValue([
      {
        session_id: "sess-abcd-1234",
        host: "192.0.2.35",
        port: 22,
        username: "alice",
        opened_at: new Date(Date.now() - 90_000).toISOString(),
      },
    ]);
    renderPanel();
    act(() => {
      useUiStore.setState({
        sessionInfoPanelOpen: true,
        sessions: [{ sessionId: "sess-abcd-1234", deviceId: "vEX1", ended: false }],
        activeTabId: "sess-abcd-1234",
      });
    });
    expect(await screen.findByText("vEX1")).toBeInTheDocument();
    expect(screen.getByTestId("session-info-state")).toHaveTextContent("Connected");
    expect(await screen.findByText("192.0.2.35:22")).toBeInTheDocument();
    expect(screen.getByText("junos")).toBeInTheDocument();
    expect(screen.getByText("Lab/Junos")).toBeInTheDocument();
    expect(screen.getByText("lab-pw")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByTestId("session-info-opened-at")).toHaveTextContent(/m ago|s ago/),
    );
    expect(screen.getByText("alice")).toBeInTheDocument();
  });

  it("flips the state pill + disables disconnect when the remote ended", async () => {
    renderPanel();
    act(() => {
      useUiStore.setState({
        sessionInfoPanelOpen: true,
        sessions: [{ sessionId: "ses-1", deviceId: "vEX1", ended: true }],
        activeTabId: "ses-1",
      });
    });
    await screen.findByTestId("session-info-panel");
    expect(screen.getByTestId("session-info-state")).toHaveTextContent("Ended");
    expect(screen.getByTestId("session-info-disconnect")).toBeDisabled();
  });

  it("calls disconnectSession when Disconnect is clicked", async () => {
    renderPanel();
    act(() => {
      useUiStore.setState({
        sessionInfoPanelOpen: true,
        sessions: [{ sessionId: "ses-2", deviceId: "vEX1", ended: false }],
        activeTabId: "ses-2",
      });
    });
    await screen.findByTestId("session-info-panel");
    await userEvent.click(screen.getByTestId("session-info-disconnect"));
    await waitFor(() => expect(mockedDisconnect).toHaveBeenCalledWith("ses-2"));
  });

  it("survives an active-tab switch — re-renders for the new session", async () => {
    mockedListOpenSessions.mockResolvedValue([
      {
        session_id: "ses-a",
        host: "192.0.2.35",
        port: 22,
        username: "alice",
        opened_at: new Date().toISOString(),
      },
    ]);
    renderPanel();
    act(() => {
      useUiStore.setState({
        sessionInfoPanelOpen: true,
        sessions: [
          { sessionId: "ses-a", deviceId: "vEX1", ended: false },
          { sessionId: "ses-b", deviceId: "vEX1", ended: false },
        ],
        activeTabId: "ses-a",
      });
    });
    await screen.findByTestId("session-info-panel");
    expect(screen.getByText(/ses-a/i)).toBeInTheDocument();

    act(() => useUiStore.getState().setActiveTab("ses-b"));
    await waitFor(() => expect(screen.getByText(/ses-b/i)).toBeInTheDocument());
  });
});

describe("relativeTime", () => {
  const now = Date.parse("2026-05-11T12:00:00Z");

  it("renders seconds", () => {
    expect(relativeTime("2026-05-11T11:59:30Z", now)).toBe("30s ago");
  });

  it("renders minutes", () => {
    expect(relativeTime("2026-05-11T11:55:00Z", now)).toBe("5m ago");
  });

  it("renders hours", () => {
    expect(relativeTime("2026-05-11T09:00:00Z", now)).toBe("3h ago");
  });

  it("renders days", () => {
    expect(relativeTime("2026-05-09T12:00:00Z", now)).toBe("2d ago");
  });

  it("falls back to a date past a week", () => {
    expect(relativeTime("2026-04-15T12:00:00Z", now)).toBe("2026-04-15");
  });

  it("returns the raw string for unparseable input", () => {
    expect(relativeTime("garbage", now)).toBe("garbage");
  });
});

describe("SessionInfoPanel — Files tabs (v5.0.0)", () => {
  const filesTab = {
    sessionId: "f1-abcdef12",
    deviceId: "vEX1",
    ended: false,
    kind: "files" as const,
  };

  beforeEach(() => {
    mockedListDevices.mockResolvedValue([VEX1]);
    mockedListOpenSessions.mockResolvedValue([]);
    useUiStore.setState({
      sessionInfoPanelOpen: true,
      sessions: [filesTab],
      activeTabId: filesTab.sessionId,
    });
  });

  it("renders the minimal SFTP card with host:port from the inventory", async () => {
    renderPanel();
    expect(await screen.findByTestId("session-info-files")).toBeInTheDocument();
    expect(screen.getByText("SFTP file transfer")).toBeInTheDocument();
    // The devices query resolves after the card's first paint.
    expect(await screen.findByText("192.0.2.35:22")).toBeInTheDocument();
    expect(screen.getByTestId("session-info-state")).toHaveTextContent("Connected");
    // Never the SSH-only affordances (a Files session isn't in
    // list_open_sessions and can't be reconnected via connect_device).
    expect(screen.queryByText("Open another session")).toBeNull();
    expect(screen.queryByText("Username")).toBeNull();
    expect(screen.queryByText("Opened")).toBeNull();
  });

  it("Disconnect routes to files_disconnect, never disconnect_session", async () => {
    renderPanel();
    await userEvent.click(await screen.findByTestId("session-info-files-disconnect"));
    await waitFor(() =>
      expect(vi.mocked(filesDisconnect)).toHaveBeenCalledWith(filesTab.sessionId),
    );
    expect(mockedDisconnect).not.toHaveBeenCalled();
    // The tab goes with it.
    await waitFor(() => expect(useUiStore.getState().sessions).toHaveLength(0));
  });

  it("never queries the SSH session list for a Files tab", async () => {
    renderPanel();
    await screen.findByTestId("session-info-files");
    expect(mockedListOpenSessions).not.toHaveBeenCalled();
  });
});
