import { useQuery } from "@tanstack/react-query";
import { invoke } from "@tauri-apps/api/core";

/**
 * IPC wrappers for the PCaps surface (v6.0.0).
 *
 * Every command lives in the `pcap_*` namespace, which is disjoint from
 * every transport dispatch by design — a capture is never reachable
 * through `send_input` / `disconnect_session` / `list_open_sessions`, and
 * a session is never reachable through these.
 *
 * ⚠️ **Wire field names are snake_case, matching the Rust structs
 * verbatim.** Serde serializes Rust field names as written and nothing in
 * `src-tauri/src/` renames them, so a camelCase field here compiles fine
 * and reads `undefined` at runtime — TypeScript is a declaration, not a
 * check on what the backend actually sends. That is exactly the bug that
 * shipped a dead capture tab: `captureId` was `undefined`, so the tab's
 * id was `undefined`, so it never matched the active tab and its pane
 * stayed blank. Mirror the Rust struct field-for-field.
 */

export interface CaptureSummary {
  capture_id: string;
  name: string;
  packets: number;
  bytes: number;
  duration_us: number;
  first_ts: number;
  last_ts: number;
  link_type: string;
  snaplen: number;
  live: boolean;
  index_truncated: boolean;
  flows: number;
  findings: number;
}

export interface PacketRow {
  number: number;
  ts_us: number;
  time: string;
  src: string;
  dst: string;
  protocol: string;
  length: number;
  info: string;
  /** `ANALYSIS_*` bits from the TCP tracker; see ANALYSIS below. */
  analysis: number;
}

/** Per-packet analysis bits, mirroring `transit_pcap::analysis::flow`. */
export const ANALYSIS = {
  RETRANSMIT: 0x01,
  DUP_ACK: 0x02,
  OUT_OF_ORDER: 0x04,
  ZERO_WINDOW: 0x08,
  RESET: 0x10,
} as const;

export interface RowPage {
  rows: PacketRow[];
  total_matched: number;
  offset: number;
}

export interface DetailField {
  name: string;
  label: string;
  value: string;
}

export interface DetailLayer {
  protocol: string;
  label: string;
  fields: DetailField[];
}

export interface FlowRow {
  flow_id: number;
  endpoints: string;
  protocol: string;
  packets: number;
  bytes: number;
  duration_us: number;
  retransmit_pct: number;
  resets: number;
  rtt_p50_us: number | null;
}

export interface FindingRow {
  severity: "info" | "low" | "med" | "high";
  rule: string;
  detail: string;
  filter: string | null;
}

export interface Nic {
  name: string;
  description: string;
  up: boolean;
  loopback: boolean;
}

export interface CaptureStartRequest {
  interface: string;
  bpf: string | null;
  snaplen: number;
  max_file_mb: number;
  max_files: number;
  max_duration_secs: number;
}

/** Event topic for live capture progress. */
export const CAPTURE_UPDATE_EVENT = "pcap:capture:update";

/** `pcap:capture:update` payload — progress for a recording capture.
 *
 *  `file_bytes` is what is on disk across the whole rotation set, and it
 *  lags the wire by whatever the capture tool has yet to flush. `packets`
 *  is null while recording: counting would mean re-scanning a growing
 *  file every tick, and a confident `0` would make a failed capture look
 *  exactly like a quiet interface. */
export interface CaptureStats {
  capture_id: string;
  /** `running` while recording, `stopped` once the file is closed. */
  state: string;
  file_bytes: number;
  elapsed_secs: number;
  packets: number | null;
  error: string | null;
}

/** Snaplen presets. "Headers only" is offered prominently because it is
 *  the one-click answer for a shop that wants flow analysis without
 *  recording payload at all. */
export const SNAPLEN_FULL = 262144;
export const SNAPLEN_HEADERS_ONLY = 128;

export const pcapEnabled = () => invoke<boolean>("pcap_enabled");
export const pcapAgentAccessEnabled = () => invoke<boolean>("pcap_agent_access_enabled");

export const pcapOpenFile = (path: string) => invoke<CaptureSummary>("pcap_open_file", { path });
export const pcapListOpen = () => invoke<CaptureSummary[]>("pcap_list_open");
export const pcapClose = (captureId: string) => invoke<void>("pcap_close", { captureId });

export const pcapRows = (captureId: string, filter: string | null, offset: number, limit: number) =>
  invoke<RowPage>("pcap_rows", { captureId, filter, offset, limit });

export const pcapPacketDetail = (captureId: string, number: number) =>
  invoke<DetailLayer[]>("pcap_packet_detail", { captureId, number });

/** ⚑ Human-only. Raw packet bytes for the hex pane — deliberately absent
 *  from the assistant's `CaptureSource`, so `query_capture` has no path
 *  to wire payload (threat model T45). */
export const pcapPacketBytes = (captureId: string, number: number) =>
  invoke<number[]>("pcap_packet_bytes", { captureId, number });

export const pcapConversations = (captureId: string, by: string, limit: number) =>
  invoke<FlowRow[]>("pcap_conversations", { captureId, by, limit });

export const pcapFindings = (captureId: string) =>
  invoke<FindingRow[]>("pcap_findings", { captureId });

export const pcapProtocolTree = (captureId: string) =>
  invoke<[string, number, number][]>("pcap_protocol_tree", { captureId });

export const pcapOverview = (captureId: string) => invoke<string>("pcap_overview", { captureId });

export const pcapValidateFilter = (expr: string) => invoke<void>("pcap_validate_filter", { expr });

export const pcapFilterFields = () => invoke<[string, string][]>("pcap_filter_fields");

export const pcapListInterfaces = () => invoke<Nic[]>("pcap_list_interfaces");

/** Reveal the capture folder in the OS file manager.
 *
 *  A dedicated command rather than the opener plugin's `openPath`: that
 *  capability would let the webview hand ANY path to the OS, while this
 *  resolves the one app-owned folder backend-side. */
export const pcapOpenCapturesDir = () => invoke<void>("pcap_open_captures_dir");

/** The folder captures are written to, resolved (configured or default). */
export const pcapCapturesDir = () => invoke<string>("pcap_captures_dir");

/** The CONFIGURED folder, or null when the default is in use. */
export const pcapConfiguredDir = () => invoke<string | null>("pcap_configured_dir");

/** Choose where captures are written; null restores the default. */
export const setPcapDir = (dir: string | null) => invoke<void>("set_pcap_dir", { dir });

/** The resolved capture folder, for display beside the reveal link. */
export function useCapturesDir() {
  return useQuery({
    queryKey: ["pcapCapturesDir"],
    queryFn: pcapCapturesDir,
    staleTime: 30_000,
  });
}

export const pcapCaptureStart = (request: CaptureStartRequest) =>
  invoke<string>("pcap_capture_start", { request });

/** Stop a recording capture and open what it captured. */
export const pcapCaptureStop = (captureId: string) =>
  invoke<CaptureSummary>("pcap_capture_stop", { captureId });

/**
 * Whether the PCaps rail entry shows.
 *
 * Hiding the entry is convenience only — the backend refuses every
 * `pcap_*` command independently, and re-reads the flag per call so a
 * DLP-locked deployment cannot be circumvented through a tab that was
 * already open.
 */
export function usePcapEnabled() {
  return useQuery({
    queryKey: ["pcapEnabled"],
    queryFn: pcapEnabled,
    staleTime: Infinity,
    placeholderData: true,
  });
}

/** Whether the assistant may query captures (`[pcap] agent_access`). */
export function usePcapAgentAccess() {
  return useQuery({
    queryKey: ["pcapAgentAccess"],
    queryFn: pcapAgentAccessEnabled,
    staleTime: Infinity,
    placeholderData: true,
  });
}

/** Query key for the open-capture list, so every mutation site can
 *  invalidate it without duplicating the string. */
export const OPEN_CAPTURES_KEY = ["pcapOpenCaptures"] as const;

/**
 * The captures currently open in the backend.
 *
 * Server state, so it lives in TanStack Query rather than component state
 * (§11). That is not bookkeeping pedantry here: the sidebar list used to
 * be a local array that only ever grew, so closing a capture's TAB — which
 * really does close it in the backend — left a row behind that produced
 * "no capture is open with id …" when clicked. Asking the backend what is
 * open makes the list correct by construction.
 */
export function usePcapOpenCaptures(enabled: boolean) {
  return useQuery({
    queryKey: OPEN_CAPTURES_KEY,
    queryFn: pcapListOpen,
    enabled,
    staleTime: Infinity,
  });
}

export function useCaptureInterfaces(enabled: boolean) {
  return useQuery({
    queryKey: ["pcapInterfaces"],
    queryFn: pcapListInterfaces,
    enabled,
    staleTime: 30_000,
  });
}

/** Format bytes the way the digest does, so the UI and the assistant
 *  never disagree about how big something is. */
export function bytesHuman(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2)} GB`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(2)} KB`;
  return `${n} B`;
}

export function durationHuman(us: number): string {
  const totalMs = Math.max(0, Math.floor(us / 1000));
  const ms = totalMs % 1000;
  const totalS = Math.floor(totalMs / 1000);
  const s = totalS % 60;
  const m = Math.floor(totalS / 60) % 60;
  const h = Math.floor(totalS / 3600);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(h)}:${pad(m)}:${pad(s)}.${pad(ms, 3)}`;
}
