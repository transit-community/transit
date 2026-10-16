import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The PCaps surface, tested at the seam that broke it.
 *
 * A capture that opens with no id is indistinguishable from a working one
 * until you look at the pane: the tab renders (its label comes from a
 * different field), the sidebar row renders, and the only complaint is a
 * React key warning. So the assertions here are deliberately about
 * **identity** — that the id the backend sent is the id the tab carries —
 * rather than about anything being on screen.
 *
 * Every fixture below is shaped like the real IPC payload: snake_case,
 * mirroring the Rust structs in `src-tauri/src/pcap.rs`, which are pinned
 * by `wire_structs_serialize_the_keys_the_frontend_reads` on that side.
 */

const pcapOpenFile = vi.fn();
const pcapCaptureStart = vi.fn();
const pcapCaptureStop = vi.fn();
const NICS = [{ name: "en0", description: "Wi-Fi", up: true, loopback: false }];
/** What `pcap_list_open` returns; the sidebar renders this, not local state. */
let openCapturesFixture: unknown[] = [];

vi.mock("@/lib/pcap", async () => {
  const actual = await vi.importActual<typeof import("@/lib/pcap")>("@/lib/pcap");
  return {
    ...actual,
    pcapOpenFile: (...a: unknown[]) => pcapOpenFile(...a),
    pcapCaptureStart: (...a: unknown[]) => pcapCaptureStart(...a),
    pcapCaptureStop: (...a: unknown[]) => pcapCaptureStop(...a),
    // Overridden wholesale rather than by mocking `pcapListInterfaces`:
    // the real hook closes over the real module's binding, which an
    // `importActual` spread does not rebind. Mocking the fetcher would
    // leave the hook calling `invoke` for real.
    useCaptureInterfaces: () => ({ data: NICS, isLoading: false }),
    usePcapOpenCaptures: () => ({ data: openCapturesFixture }),
    pcapClose: vi.fn().mockResolvedValue(undefined),
    OPEN_CAPTURES_KEY: ["pcapOpenCaptures"],
    pcapRows: vi.fn().mockResolvedValue({ rows: [], total_matched: 0, offset: 0 }),
    pcapPacketDetail: vi.fn().mockResolvedValue([]),
    pcapPacketBytes: vi.fn().mockResolvedValue([]),
    pcapConversations: vi.fn().mockResolvedValue([]),
    pcapFindings: vi.fn().mockResolvedValue([]),
    pcapProtocolTree: vi.fn().mockResolvedValue([]),
    pcapOverview: vi.fn().mockResolvedValue("OVERVIEW"),
    pcapValidateFilter: vi.fn().mockResolvedValue(undefined),
  };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn().mockResolvedValue("/tmp/lab.pcap"),
  save: vi.fn().mockResolvedValue(null),
}));

type Handler = (event: { payload: unknown }) => void;
const listeners = new Map<string, Handler[]>();

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (topic: string, handler: Handler) => {
    listeners.set(topic, [...(listeners.get(topic) ?? []), handler]);
    return () => {
      listeners.set(
        topic,
        (listeners.get(topic) ?? []).filter((h) => h !== handler),
      );
    };
  }),
  emit: vi.fn().mockResolvedValue(undefined),
}));

function fireCaptureUpdate(payload: unknown) {
  for (const h of listeners.get("pcap:capture:update") ?? []) h({ payload });
}

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}));

import { toast } from "sonner";

import { PcapPane } from "@/components/PcapPane";
import { PcapSidebar } from "@/components/PcapSidebar";
import { type CaptureSummary } from "@/lib/pcap";
import { useUiStore } from "@/stores/uiStore";

/** Exactly what `pcap_open_file` puts on the wire. */
const WIRE_SUMMARY: CaptureSummary = {
  capture_id: "cap-7f3a",
  name: "lab-uplink.pcap",
  packets: 595,
  bytes: 120_330,
  duration_us: 14_000_000,
  first_ts: 1_770_000_000,
  last_ts: 1_770_000_014,
  link_type: "EN10MB",
  snaplen: 262_144,
  live: false,
  index_truncated: false,
  flows: 12,
  findings: 1,
};

function withQuery(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  listeners.clear();
  openCapturesFixture = [];
  useUiStore.setState({ sessions: [], activeTabId: null, sidebarCollapsed: false });
  pcapOpenFile.mockResolvedValue(WIRE_SUMMARY);
  pcapCaptureStart.mockResolvedValue("cap-live-1");
  pcapCaptureStop.mockResolvedValue({ ...WIRE_SUMMARY, capture_id: "cap-live-1" });
});

afterEach(() => vi.clearAllMocks());

describe("PcapSidebar → tab identity", () => {
  it("opens a tab carrying the backend's capture id", async () => {
    withQuery(<PcapSidebar />);
    await userEvent.click(screen.getByRole("button", { name: /open capture file/i }));

    await waitFor(() => {
      const { sessions, activeTabId } = useUiStore.getState();
      expect(sessions).toHaveLength(1);
      // The whole bug in one assertion: this was `undefined`, which is a
      // perfectly valid object key and a perfectly invalid tab id.
      expect(sessions[0].sessionId).toBe("cap-7f3a");
      expect(sessions[0].kind).toBe("pcap");
      // Radix selects content by matching this against the tab's value.
      // `undefined` here is what left the pane blank.
      expect(activeTabId).toBe("cap-7f3a");
    });
  });

  it("lands a stopped capture in a tab with the id it was recorded under", async () => {
    withQuery(<PcapSidebar />);
    const select = await screen.findByLabelText(/interface/i);
    await userEvent.selectOptions(select, "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));
    await userEvent.click(await screen.findByRole("button", { name: /stop capture/i }));

    await waitFor(() => {
      expect(useUiStore.getState().activeTabId).toBe("cap-live-1");
    });
  });

  it("sends the start request under the field names the backend deserializes", async () => {
    withQuery(<PcapSidebar />);
    const select = await screen.findByLabelText(/interface/i);
    await userEvent.selectOptions(select, "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));

    await waitFor(() => expect(pcapCaptureStart).toHaveBeenCalled());
    // A camelCase key here fails serde's Deserialize outright, so the
    // capture never starts — the loud half of the same mismatch.
    expect(pcapCaptureStart.mock.calls[0][0]).toEqual({
      interface: "en0",
      bpf: null,
      snaplen: 262_144,
      max_file_mb: 256,
      max_files: 8,
      max_duration_secs: 3600,
    });
  });

  it("shows live progress while recording, and flags a capture writing nothing", async () => {
    withQuery(<PcapSidebar />);
    await userEvent.selectOptions(await screen.findByLabelText(/interface/i), "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));
    const status = await screen.findByTestId("pcap-recording-status");

    await act(async () => {
      fireCaptureUpdate({
        capture_id: "cap-live-1",
        state: "running",
        file_bytes: 2_400_000,
        elapsed_secs: 6,
        packets: null,
        error: null,
      });
    });
    await waitFor(() => expect(status.textContent).toContain("2.40 MB"));
    expect(status.textContent).toContain("6s");

    // Ten seconds in with an empty file is the shape of every failed
    // capture so far — a permission error, a filter matching nothing, a
    // dead interface. Silence there is what made those look like success.
    await act(async () => {
      fireCaptureUpdate({
        capture_id: "cap-live-1",
        state: "running",
        file_bytes: 0,
        elapsed_secs: 12,
        packets: null,
        error: null,
      });
    });
    await waitFor(() => expect(screen.getByText(/nothing written yet/i)).toBeTruthy());
  });

  it("ignores progress for a capture it is not recording", async () => {
    withQuery(<PcapSidebar />);
    await userEvent.selectOptions(await screen.findByLabelText(/interface/i), "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));
    const status = await screen.findByTestId("pcap-recording-status");

    await act(async () => {
      fireCaptureUpdate({
        capture_id: "some-other-capture",
        state: "running",
        file_bytes: 999_000_000,
        elapsed_secs: 900,
        packets: null,
        error: null,
      });
    });
    expect(status.textContent).not.toContain("999");
  });

  it("warns when the backend reports a partially-indexed capture", async () => {
    pcapOpenFile.mockResolvedValue({ ...WIRE_SUMMARY, index_truncated: true });
    withQuery(<PcapSidebar />);
    await userEvent.click(screen.getByRole("button", { name: /open capture file/i }));
    // Reading the wrong field name makes this branch unreachable, and a
    // half-indexed capture then reads as a complete one.
    await waitFor(() => expect(toast.warning).toHaveBeenCalled());
  });
});

describe("PcapPane", () => {
  it("renders and reports the matched-packet count from the wire field", async () => {
    const { pcapRows } = await import("@/lib/pcap");
    vi.mocked(pcapRows).mockResolvedValue({ rows: [], total_matched: 595, offset: 0 });

    withQuery(<PcapPane captureId="cap-7f3a" active />);
    expect(screen.getByTestId("pcap-pane")).toBeTruthy();
    // `totalMatched` read `undefined` → `?? 0` → "0 packets", which reads
    // as an empty capture rather than a naming mistake.
    await waitFor(() => expect(screen.getByText("595 packets")).toBeTruthy());
  });

  it("renders a conversation row without throwing on its numeric fields", async () => {
    const { pcapConversations } = await import("@/lib/pcap");
    vi.mocked(pcapConversations).mockResolvedValue([
      {
        flow_id: 41,
        endpoints: "10.0.0.1:52344 → 93.184.216.34:443",
        protocol: "tcp",
        packets: 210,
        bytes: 240_100,
        duration_us: 9_000_000,
        retransmit_pct: 0.4,
        resets: 0,
        rtt_p50_us: 11_200,
      },
    ]);

    withQuery(<PcapPane captureId="cap-7f3a" active />);
    // `mouseDown`, not `userEvent.click`: a Radix tab activates on mousedown,
    // and user-event's pointer sequence leaves the drawer on "Findings" under
    // happy-dom. Clicking and asserting nothing rendered would look like a
    // data bug rather than an inert click.
    fireEvent.mouseDown(screen.getByRole("tab", { name: /conversations/i }));

    // `retransmit_pct.toFixed(1)` on an undefined field is a TypeError that
    // takes the whole pane down, so this row rendering at all is the test.
    const cell = await screen.findByText(/10\.0\.0\.1:52344/);
    const row = cell.closest("tr");
    expect(row?.textContent).toContain("0.4%");
    expect(row?.textContent).toContain("11.2ms");
  });
});

describe("PcapSidebar → captures list", () => {
  it("renders the backend's open captures, not an ever-growing local list", async () => {
    openCapturesFixture = [
      WIRE_SUMMARY,
      { ...WIRE_SUMMARY, capture_id: "cap-2", name: "bgp.pcap" },
    ];
    withQuery(<PcapSidebar />);
    expect(await screen.findByText("lab-uplink.pcap")).toBeTruthy();
    expect(screen.getByText("bgp.pcap")).toBeTruthy();
  });

  it("closes a capture from the list — backend, tab and row together", async () => {
    openCapturesFixture = [WIRE_SUMMARY];
    useUiStore.setState({
      sessions: [
        { sessionId: "cap-7f3a", deviceId: "lab-uplink.pcap", ended: false, kind: "pcap" },
      ],
      activeTabId: "cap-7f3a",
    });
    const { pcapClose } = await import("@/lib/pcap");

    withQuery(<PcapSidebar />);
    await userEvent.click(await screen.findByRole("button", { name: /close lab-uplink\.pcap/i }));

    // The index is freed backend-side, and the tab goes with it — a row
    // that outlives its capture reopens a tab onto an id the backend has
    // forgotten, which is what the old local-state list did.
    await waitFor(() => expect(vi.mocked(pcapClose)).toHaveBeenCalledWith("cap-7f3a"));
    await waitFor(() => expect(useUiStore.getState().sessions).toHaveLength(0));
  });
});

describe("protocolClass", () => {
  it("groups protocols by what they are for, and leaves unknowns unstyled", async () => {
    const { protocolClass } = await import("@/components/PcapPane");
    // Same family, same colour — the point is bands of activity, not 30
    // individually memorable hues.
    expect(protocolClass("dns")).toBe(protocolClass("mdns"));
    expect(protocolClass("bgp")).toBe(protocolClass("ospf"));
    expect(protocolClass("arp")).toBe(protocolClass("lldp"));
    // Different families must be distinguishable.
    expect(protocolClass("tls")).not.toBe(protocolClass("http"));
    expect(protocolClass("dns")).not.toBe(protocolClass("bgp"));
    // Case-insensitive, since the row renders uppercase.
    expect(protocolClass("TLS")).toBe(protocolClass("tls"));
    // An unrecognized protocol inherits rather than guessing a colour.
    expect(protocolClass("wireguard")).toBe("");
  });
});

describe("PcapSidebar → chrome and feedback", () => {
  it("carries the account footer every other rail view has", async () => {
    withQuery(<PcapSidebar />);
    // It went missing here and only here, because this sidebar scrolled
    // its whole aside instead of pinning a footer under scrolling content.
    expect(await screen.findByTestId("pcap-sidebar")).toBeTruthy();
    expect(document.querySelector("footer")).not.toBeNull();
  });

  it("collapses with the shared sidebarCollapsed state (⌘/Ctrl+B)", async () => {
    useUiStore.setState({ sidebarCollapsed: true });
    withQuery(<PcapSidebar />);
    expect(await screen.findByTestId("pcap-sidebar-collapsed")).toBeTruthy();
    expect(screen.queryByTestId("pcap-sidebar")).toBeNull();
    // Nothing is recording, so no Stop affordance is needed.
    expect(screen.queryByTestId("pcap-collapsed-stop")).toBeNull();
  });

  it("keeps Stop reachable while collapsed AND recording", async () => {
    withQuery(<PcapSidebar />);
    await userEvent.selectOptions(await screen.findByLabelText(/interface/i), "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));
    await screen.findByTestId("pcap-recording-status");

    act(() => useUiStore.setState({ sidebarCollapsed: true }));

    // Collapsing away the only Stop button would leave quitting the app as
    // the sole way to stop recording a network.
    const stop = await screen.findByTestId("pcap-collapsed-stop");
    await userEvent.click(stop);
    await waitFor(() => expect(pcapCaptureStop).toHaveBeenCalledWith("cap-live-1"));
  });

  it("says Stopping while the capture flushes, so the click reads as landed", async () => {
    // Hold the stop open so the in-flight state is observable.
    let release: (v: unknown) => void = () => {};
    pcapCaptureStop.mockReturnValue(new Promise((r) => (release = r)));

    withQuery(<PcapSidebar />);
    await userEvent.selectOptions(await screen.findByLabelText(/interface/i), "en0");
    await userEvent.click(screen.getByRole("button", { name: /start capture/i }));
    await userEvent.click(await screen.findByRole("button", { name: /stop capture/i }));

    expect(await screen.findByRole("button", { name: /stopping/i })).toBeTruthy();
    const status = screen.getByTestId("pcap-recording-status");
    expect(status.textContent).toContain("Stopping");
    expect(status.textContent).not.toContain("Recording");

    await act(async () => {
      release({ ...WIRE_SUMMARY, capture_id: "cap-live-1" });
    });
  });
});
