//! The PCaps surface: state, IPC, and the agent seam.
//!
//! Owns `transit_pcap` and exposes it two ways that are deliberately
//! different sizes:
//!
//! - **To the user**, the full `pcap_*` IPC namespace, including the
//!   three capabilities the assistant does not get: raw packet bytes for
//!   the hex pane, flow reassembly, and export.
//! - **To the assistant**, [`PcapCaptureSource`] — an implementation of
//!   `transit_agent::CaptureSource` carrying only what
//!   `query_capture` can ask for. The three above are simply not on that
//!   trait, which is what makes "metadata only" an absence rather than a
//!   policy (threat model T45).
//!
//! The `pcap_*` namespace is disjoint from every transport dispatch:
//! `send_input`, `resize_pty`, `clear_scrollback`, `disconnect_session`
//! and `list_open_sessions` have no pcap arm, so nothing terminal-shaped
//! can reach a capture and nothing capture-shaped can reach a session.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use transit_agent::{CaptureAnswer, CaptureMeta, CaptureQueryError, CaptureQueryKind};
use transit_pcap::analysis::digest::{bytes_human, duration_human, thousands, ts_human};
use transit_pcap::analysis::findings::{Finding, Severity};
use transit_pcap::analysis::{evaluate_findings, render_digest, DigestOptions};
use transit_pcap::dissect::{dissect, Detail, Dissection, FieldValue};
use transit_pcap::filter::Filter;
use transit_pcap::index::{build as build_index, CaptureIndex, FlowSort, IndexLimits};
use transit_pcap::live::{self, CaptureRequest, Nic};
use transit_pcap::reader::CaptureFile;

use crate::commands::{resolve_pcap_agent_access, resolve_pcap_enabled};

/// One topic for every capture's live statistics — the frontend keeps an
/// event-built mirror keyed by capture id, the same shape the Files
/// transfer queue uses.
const CAPTURE_TOPIC: &str = "pcap:capture:update";

/// Rows returned in one page. The agent's ceiling; the UI asks for what
/// fits on screen.
const MAX_ROWS: u32 = 500;

/// How many captures may be open at once.
///
/// Each holds its whole index resident — up to ~320 MB at the
/// five-million-packet ceiling — so without a bound here eight large
/// captures can reach a couple of gigabytes with nothing having gone
/// wrong anywhere. Refusing is better than evicting: a tab vanishing
/// under the user is worse than being told to close one.
const MAX_OPEN_CAPTURES: usize = 8;

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

/// An opened capture: the file, its index, and its findings.
pub struct OpenCapture {
    pub id: String,
    pub file: CaptureFile,
    pub index: CaptureIndex,
    pub findings: Vec<Finding>,
    /// Set while a live capture is still being written to this file.
    pub live_pid: Option<u32>,
}

impl OpenCapture {
    fn meta(&self) -> CaptureMeta {
        CaptureMeta {
            capture_id: self.id.clone(),
            // The FILE name, never the path: a path carries a username
            // and a directory layout, and neither helps the model.
            name: self.index.meta.name.clone(),
            packets: self.index.packet_count(),
            bytes: self.index.total_bytes,
            duration: duration_human(self.index.duration_us()),
            live: self.live_pid.is_some(),
        }
    }
}

#[derive(Default)]
pub struct PcapState {
    pub captures: Mutex<HashMap<String, Arc<OpenCapture>>>,
    /// Open order, so listings are stable rather than hash-ordered.
    pub order: Mutex<Vec<String>>,
    /// Captures currently recording, keyed by capture id.
    ///
    /// Holding the `Child` is the whole point of this map: dropping it
    /// orphans the capture process, which then keeps recording after
    /// Transit exits — the one outcome T44 promises cannot happen.
    pub live: Mutex<HashMap<String, LiveCapture>>,
}

/// A capture currently being recorded.
pub struct LiveCapture {
    pub child: tokio::process::Child,
    pub path: PathBuf,
    /// The supervisor polls for this file and stops the capture when it
    /// disappears. On the elevated path that means Stop is an
    /// unprivileged file delete rather than a second password prompt.
    pub sentinel: PathBuf,
    /// Touched every few seconds for as long as Transit lives. The
    /// supervisor stops the capture when it goes stale — the backstop for
    /// a Transit that dies WITHOUT a clean exit.
    pub heartbeat: PathBuf,
    /// The task doing the touching. Aborted on stop.
    pub ticker: tauri::async_runtime::JoinHandle<()>,
}

impl PcapState {
    pub fn new() -> Self {
        Self::default()
    }

    fn open_in_order(&self) -> Vec<Arc<OpenCapture>> {
        let captures = self.captures.lock().expect("pcap state poisoned");
        let order = self.order.lock().expect("pcap order poisoned");
        order
            .iter()
            .filter_map(|id| captures.get(id).cloned())
            .collect()
    }

    fn get(&self, id: &str) -> Option<Arc<OpenCapture>> {
        self.captures
            .lock()
            .expect("pcap state poisoned")
            .get(id)
            .cloned()
    }

    fn insert(&self, capture: OpenCapture) {
        let id = capture.id.clone();
        self.captures
            .lock()
            .expect("pcap state poisoned")
            .insert(id.clone(), Arc::new(capture));
        self.order.lock().expect("pcap order poisoned").push(id);
    }

    fn remove(&self, id: &str) {
        self.captures
            .lock()
            .expect("pcap state poisoned")
            .remove(id);
        self.order
            .lock()
            .expect("pcap order poisoned")
            .retain(|x| x != id);
    }
}

/// Stash the state on the app.
pub fn install(app: &AppHandle) {
    app.manage(Arc::new(PcapState::new()));
}

/// Stop every running capture. Called on app exit.
///
/// Without this, quitting Transit while a capture runs leaves a
/// root-privileged capture process recording the network indefinitely,
/// with no UI left to stop it. Best-effort by design: we would far rather
/// over-try to stop than leave one running.
pub async fn stop_all(state: &PcapState) {
    let ids: Vec<String> = state
        .live
        .lock()
        .expect("pcap live state poisoned")
        .keys()
        .cloned()
        .collect();
    for id in ids {
        let _ = stop_capture(state, &id).await;
    }
}

/// Refuse every capture operation when the surface is disabled.
///
/// Checked per call, not at startup, so flipping `[pcap] enabled = false`
/// takes effect on already-open captures — a DLP-locked deployment cannot
/// be circumvented through a tab that was already open. `pcap_close` is
/// deliberately left ungated so teardown always succeeds.
fn ensure_enabled() -> Result<(), String> {
    if resolve_pcap_enabled() {
        Ok(())
    } else {
        Err("packet capture is disabled on this installation".into())
    }
}

// ---------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct CaptureSummary {
    pub capture_id: String,
    pub name: String,
    pub packets: u64,
    pub bytes: u64,
    pub duration_us: i64,
    pub first_ts: i64,
    pub last_ts: i64,
    pub link_type: String,
    pub snaplen: u32,
    pub live: bool,
    pub index_truncated: bool,
    pub flows: usize,
    pub findings: usize,
}

#[derive(Debug, Serialize)]
pub struct PacketRow {
    pub number: u64,
    pub ts_us: i64,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    /// `ANALYSIS_*` bits, so the list can colour a retransmission.
    pub analysis: u8,
}

#[derive(Debug, Serialize)]
pub struct RowPage {
    pub rows: Vec<PacketRow>,
    pub total_matched: u64,
    pub offset: u32,
}

#[derive(Debug, Serialize)]
pub struct DetailField {
    pub name: String,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct DetailLayer {
    pub protocol: String,
    pub label: String,
    pub fields: Vec<DetailField>,
}

#[derive(Debug, Serialize)]
pub struct FlowRow {
    pub flow_id: u32,
    pub endpoints: String,
    pub protocol: String,
    pub packets: u64,
    pub bytes: u64,
    pub duration_us: i64,
    pub retransmit_pct: f64,
    pub resets: u32,
    pub rtt_p50_us: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FindingRow {
    pub severity: String,
    pub rule: String,
    pub detail: String,
    pub filter: Option<String>,
}

/// `pcap:capture:update` — progress for a capture that is recording.
///
/// Only what can be known cheaply and truthfully while the capture tool
/// owns the file. Bytes on disk is a `stat` per rotation file; a packet
/// COUNT would mean re-scanning a growing file on every tick, so it stays
/// `None` until Stop indexes the result. Reporting a confident `0` there
/// (the first cut did) is worse than reporting nothing: an interface that
/// is genuinely seeing no traffic and a capture that failed to start look
/// identical, and the whole point of this event is telling them apart.
#[derive(Debug, Serialize, Clone)]
pub struct CaptureStats {
    pub capture_id: String,
    /// `running` while recording, `stopped` once the file is closed.
    pub state: String,
    /// Summed across every rotation file `-C`/`-W` has produced so far.
    pub file_bytes: u64,
    /// Whole seconds since Start — so a stalled capture reads as "30s and
    /// still 0 bytes" rather than just "0 bytes".
    pub elapsed_secs: u64,
    /// Known only after Stop has indexed the capture.
    pub packets: Option<u64>,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------
// Opening and closing
// ---------------------------------------------------------------------

/// Open a capture file and index it.
#[tauri::command]
pub async fn pcap_open_file(
    state: State<'_, Arc<PcapState>>,
    path: String,
) -> Result<CaptureSummary, String> {
    ensure_enabled()?;
    ensure_room(&state)?;
    let path = PathBuf::from(path);
    // Indexing is CPU-bound and can take seconds on a large capture, so
    // it runs off the async runtime rather than stalling every other IPC
    // call behind it.
    let opened = tauri::async_runtime::spawn_blocking(move || open_and_index(&path))
        .await
        .map_err(|e| format!("indexing task failed: {e}"))??;
    let summary = summarize(&opened);
    state.insert(opened);
    Ok(summary)
}

/// Refuse to open past the ceiling, naming what to do about it.
fn ensure_room(state: &PcapState) -> Result<(), String> {
    let open = state.captures.lock().expect("pcap state poisoned").len();
    if open >= MAX_OPEN_CAPTURES {
        return Err(format!(
            "{open} captures are already open, which is the limit — each one keeps its index in \
             memory. Close a capture tab and try again."
        ));
    }
    Ok(())
}

fn open_and_index(path: &std::path::Path) -> Result<OpenCapture, String> {
    let file = CaptureFile::open(path).map_err(|e| e.to_string())?;
    let index = build_index(&file, IndexLimits::default()).map_err(|e| e.to_string())?;
    let findings = evaluate_findings(&index);
    Ok(OpenCapture {
        id: uuid::Uuid::new_v4().to_string(),
        file,
        index,
        findings,
        live_pid: None,
    })
}

fn summarize(c: &OpenCapture) -> CaptureSummary {
    CaptureSummary {
        capture_id: c.id.clone(),
        name: c.index.meta.name.clone(),
        packets: c.index.packet_count(),
        bytes: c.index.total_bytes,
        duration_us: c.index.duration_us(),
        first_ts: c.index.first_ts,
        last_ts: c.index.last_ts,
        link_type: c.index.meta.link_type.as_str().to_string(),
        snaplen: c.index.meta.snaplen,
        live: c.live_pid.is_some(),
        index_truncated: c.index.limits_hit.any(),
        flows: c.index.flows.len(),
        findings: c.findings.len(),
    }
}

#[tauri::command]
pub fn pcap_list_open(state: State<'_, Arc<PcapState>>) -> Vec<CaptureSummary> {
    state.open_in_order().iter().map(|c| summarize(c)).collect()
}

/// Close a capture. Deliberately NOT gated on `[pcap] enabled` — teardown
/// must always succeed, or turning the surface off would strand state.
#[tauri::command]
pub fn pcap_close(state: State<'_, Arc<PcapState>>, capture_id: String) {
    state.remove(&capture_id);
}

// ---------------------------------------------------------------------
// Browsing
// ---------------------------------------------------------------------

/// A window of packet rows.
///
/// The virtualized list asks for what is on screen and no more. Rows are
/// built by re-dissecting only those packets, seeking to the offsets the
/// index recorded — which is why the index holds no strings and a
/// 1.5-million-packet capture still scrolls.
#[tauri::command]
pub async fn pcap_rows(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
    filter: Option<String>,
    offset: u32,
    limit: u32,
) -> Result<RowPage, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    // Off the IPC thread. A filter naming an application field takes the
    // slow path — re-reading and re-dissecting every packet — which on a
    // multi-million-packet capture is seconds of work. Run synchronously
    // it blocks an IPC worker and the filter bar simply appears frozen,
    // which reads as a hang rather than as work in progress.
    let limit = limit.min(MAX_ROWS);
    tauri::async_runtime::spawn_blocking(move || rows_page(&c, filter.as_deref(), offset, limit))
        .await
        .map_err(|e| format!("row query failed: {e}"))?
}

fn rows_page(
    c: &OpenCapture,
    filter: Option<&str>,
    offset: u32,
    limit: u32,
) -> Result<RowPage, String> {
    let matched = matching_indices(c, filter)?;
    let total = matched.len() as u64;
    let start = offset as usize;
    let slice: Vec<usize> = matched
        .into_iter()
        .skip(start)
        .take(limit as usize)
        .collect();

    let mut fetcher = c
        .file
        .fetcher(c.index.interfaces.clone())
        .map_err(|e| e.to_string())?;
    let mut rows = Vec::with_capacity(slice.len());
    for i in slice {
        let rec = &c.index.records[i];
        let Ok(owned) = fetcher.fetch(i as u64 + 1, rec.offset) else {
            continue;
        };
        let d = dissect(&owned.as_raw(), Detail::Full);
        rows.push(PacketRow {
            number: i as u64 + 1,
            ts_us: rec.ts_us,
            time: ts_human(rec.ts_us),
            src: c
                .index
                .src_ip(rec)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| mac_or_blank(&d, "eth.src")),
            dst: c
                .index
                .dst_ip(rec)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| mac_or_blank(&d, "eth.dst")),
            protocol: d.summary.top.as_str().to_string(),
            length: rec.orig_len,
            info: d.info.clone(),
            analysis: rec.analysis,
        });
    }
    Ok(RowPage {
        rows,
        total_matched: total,
        offset,
    })
}

fn mac_or_blank(d: &Dissection, field: &str) -> String {
    match d.field(field) {
        Some(v) => v.render(),
        None => String::new(),
    }
}

/// Packet indices matching a filter, in file order.
///
/// Takes the index-only fast path when the filter allows it — no file
/// access at all — and re-dissects only when an application field is
/// named. That distinction is decided once when the filter compiles.
fn matching_indices(c: &OpenCapture, filter: Option<&str>) -> Result<Vec<usize>, String> {
    let Some(expr) = filter.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok((0..c.index.records.len()).collect());
    };
    let f = Filter::compile(expr).map_err(|e| e.to_string())?;

    if !f.needs_dissection {
        return Ok((0..c.index.records.len())
            .filter(|i| f.matches_index(&c.index, *i))
            .collect());
    }

    let mut fetcher = c
        .file
        .fetcher(c.index.interfaces.clone())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for i in 0..c.index.records.len() {
        let rec = &c.index.records[i];
        let Ok(owned) = fetcher.fetch(i as u64 + 1, rec.offset) else {
            continue;
        };
        let d = dissect(&owned.as_raw(), Detail::Full);
        if f.matches(&c.index, i, Some(&d)) {
            out.push(i);
        }
    }
    Ok(out)
}

/// One packet's dissected field tree.
#[tauri::command]
pub async fn pcap_packet_detail(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
    number: u64,
) -> Result<Vec<DetailLayer>, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    let d = tauri::async_runtime::spawn_blocking(move || dissect_one(&c, number))
        .await
        .map_err(|e| format!("dissection failed: {e}"))??;
    Ok(d.layers
        .iter()
        .map(|l| DetailLayer {
            protocol: l.proto.as_str().to_string(),
            label: l.label.clone(),
            fields: l
                .fields
                .iter()
                .map(|f| DetailField {
                    name: f.name.to_string(),
                    label: f.label.to_string(),
                    value: f.value.render(),
                })
                .collect(),
        })
        .collect())
}

fn dissect_one(c: &OpenCapture, number: u64) -> Result<Dissection, String> {
    let i = (number as usize)
        .checked_sub(1)
        .filter(|i| *i < c.index.records.len())
        .ok_or_else(|| format!("packet {number} is not in this capture"))?;
    let rec = &c.index.records[i];
    let mut fetcher = c
        .file
        .fetcher(c.index.interfaces.clone())
        .map_err(|e| e.to_string())?;
    let owned = fetcher
        .fetch(number, rec.offset)
        .map_err(|e| e.to_string())?;
    Ok(dissect(&owned.as_raw(), Detail::Full))
}

/// ⚑ HUMAN ONLY. Raw packet bytes for the hex pane.
///
/// This is one of the three capabilities deliberately absent from
/// `CaptureSource`, and therefore from `query_capture`. Wire payload is
/// the densest credential surface a capture holds; a human looking at
/// their own capture is a different proposition from that payload
/// entering a model's context and, from there, a provider's logs.
#[tauri::command]
pub fn pcap_packet_bytes(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
    number: u64,
) -> Result<Vec<u8>, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    let i = (number as usize)
        .checked_sub(1)
        .filter(|i| *i < c.index.records.len())
        .ok_or_else(|| format!("packet {number} is not in this capture"))?;
    let rec = &c.index.records[i];
    let mut fetcher = c
        .file
        .fetcher(c.index.interfaces.clone())
        .map_err(|e| e.to_string())?;
    let owned = fetcher
        .fetch(number, rec.offset)
        .map_err(|e| e.to_string())?;
    Ok(owned.data)
}

#[tauri::command]
pub fn pcap_conversations(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
    by: String,
    limit: u32,
) -> Result<Vec<FlowRow>, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    let sort = FlowSort::from_tag(&by).unwrap_or(FlowSort::Bytes);
    Ok(c.index
        .top_flows(sort, limit.min(MAX_ROWS) as usize)
        .into_iter()
        .map(flow_row)
        .collect())
}

fn flow_row(f: &transit_pcap::analysis::Flow) -> FlowRow {
    FlowRow {
        flow_id: f.id,
        endpoints: f.key.render(),
        protocol: f.key.proto.as_str().to_string(),
        packets: f.packets(),
        bytes: f.bytes(),
        duration_us: f.duration_us(),
        retransmit_pct: f.retransmit_pct(),
        resets: f.resets,
        rtt_p50_us: f.rtt_percentile(0.5).or(f.handshake_rtt_us),
    }
}

#[tauri::command]
pub fn pcap_findings(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
) -> Result<Vec<FindingRow>, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    Ok(c.findings.iter().map(finding_row).collect())
}

fn finding_row(f: &Finding) -> FindingRow {
    FindingRow {
        severity: f.severity.as_str().to_string(),
        rule: f.rule.to_string(),
        detail: f.detail.clone(),
        filter: f.filter.clone(),
    }
}

/// Protocol histogram for the analysis drawer.
#[tauri::command]
pub fn pcap_protocol_tree(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
) -> Result<Vec<(String, u64, u64)>, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    let mut rows: Vec<(String, u64, u64)> = c
        .index
        .proto_counts
        .iter()
        .map(|(p, (pk, by))| (p.as_str().to_string(), *pk, *by))
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.2));
    Ok(rows)
}

/// The digest, as the Overview tab shows it. Same text the assistant
/// gets, which is deliberate: what the user reads and what the model
/// reads should not diverge.
#[tauri::command]
pub async fn pcap_overview(
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
) -> Result<String, String> {
    ensure_enabled()?;
    let c = state
        .get(&capture_id)
        .ok_or_else(|| format!("no capture is open with id {capture_id}"))?;
    // Cheap relative to a filtered scan, but it walks every flow and
    // talker, so a wide capture is still real work.
    tauri::async_runtime::spawn_blocking(move || {
        render_digest(&c.index, &c.findings, &DigestOptions::default())
    })
    .await
    .map_err(|e| format!("digest failed: {e}"))
}

/// Validate a filter without running it, so the filter bar can show a
/// caret-positioned error as the user types.
#[tauri::command]
pub fn pcap_validate_filter(expr: String) -> Result<(), String> {
    if expr.trim().is_empty() {
        return Ok(());
    }
    Filter::compile(&expr)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Field names and descriptions for the filter bar's completion list.
#[tauri::command]
pub fn pcap_filter_fields() -> Vec<(String, String)> {
    transit_pcap::filter::REGISTRY
        .iter()
        .map(|f| (f.name.to_string(), f.description.to_string()))
        .collect()
}

// ---------------------------------------------------------------------
// Live capture
// ---------------------------------------------------------------------

#[tauri::command]
pub async fn pcap_list_interfaces() -> Result<Vec<Nic>, String> {
    ensure_enabled()?;
    live::list_interfaces().await.map_err(|e| e.to_string())
}

/// What the frontend sends to start a capture.
///
/// One struct rather than eight positional arguments: the settings travel
/// together, they are what the sidebar form produces, and adding the next
/// one (a rotation policy, a ring-buffer mode) should not re-shape the
/// command signature.
// No `rename_all`: every wire struct in `src-tauri/src/` serializes its
// Rust field names verbatim, and the TypeScript mirrors them. This struct
// briefly disagreed, which made the surface half camelCase and half
// snake_case — and the half nobody had exercised end-to-end silently read
// `undefined` in the webview.
#[derive(Debug, serde::Deserialize)]
pub struct CaptureStartRequest {
    pub interface: String,
    #[serde(default)]
    pub bpf: Option<String>,
    pub snaplen: u32,
    pub max_file_mb: u32,
    pub max_files: u32,
    pub max_duration_secs: u64,
}

/// Start a capture.
///
/// Preflight refuses an interface we did not enumerate, an invalid
/// filter, a capture with no rotation ceiling, or a disk with no room —
/// all before the user is prompted for anything.
#[tauri::command]
pub async fn pcap_capture_start(
    app: AppHandle,
    state: State<'_, Arc<PcapState>>,
    request: CaptureStartRequest,
) -> Result<String, String> {
    let CaptureStartRequest {
        interface,
        bpf,
        snaplen,
        max_file_mb,
        max_files,
        max_duration_secs,
    } = request;
    ensure_enabled()?;
    let dir = capture_dir()?;
    let nics = live::list_interfaces().await.map_err(|e| e.to_string())?;
    let req = CaptureRequest {
        interface,
        bpf: bpf.filter(|b| !b.trim().is_empty()),
        snaplen,
        max_file_mb,
        max_files,
        max_duration_secs,
    };
    live::preflight(&req, &nics, &dir).map_err(|e| e.to_string())?;
    // On Windows the capture filter is not BPF, so a filter that cannot
    // be translated must be refused HERE — before the user is prompted
    // for anything, and long before a capture could start recording more
    // than they asked for.
    #[cfg(not(unix))]
    if let Some(bpf) = &req.bpf {
        // BOTH halves, because they refuse different things. Translation
        // rejects a term pktmon cannot express at all (`not`, direction);
        // combination rejects a set it cannot express EXACTLY (three
        // hosts, contradictory transports). Either one silently
        // approximated would widen the capture, so both run here — before
        // anything spawns and long before a capture could record more than
        // was asked for.
        let filters = live::bpf_to_pktmon(bpf)?;
        live::pktmon_filter_args(&filters)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let stamp = ts_human(now_us())
        .replace([' ', ':', '-'], "")
        .replace('.', "");
    let out = live::capture_path(&dir, &stamp, &id[..8]);

    // Create both control files BEFORE spawning: the supervisor checks
    // them on its first iteration, and a missing heartbeat would read as
    // "Transit is already gone" and stop the capture instantly.
    let sentinel = out.with_extension("running");
    let heartbeat = out.with_extension("beat");
    std::fs::write(&sentinel, b"1").map_err(|e| format!("could not create stop sentinel: {e}"))?;
    std::fs::write(&heartbeat, b"1").map_err(|e| format!("could not create heartbeat: {e}"))?;

    // The capture path emitted NOTHING to tracing, so a diagnostic log
    // recorded nothing about the one operation people turn diagnostics on
    // for. These are facts rather than values (§10): what was attempted,
    // on which interface, whether it needed elevation, what came back.
    tracing::info!(
        interface = %req.interface,
        snaplen = req.snaplen,
        filtered = req.bpf.is_some(),
        max_file_mb = req.max_file_mb,
        max_files = req.max_files,
        "pcap: starting capture"
    );

    let (child, elevated) = match spawn_capture(&req, &out, &sentinel, &heartbeat).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "pcap: capture failed to start");
            let _ = std::fs::remove_file(&sentinel);
            let _ = std::fs::remove_file(&heartbeat);
            return Err(e);
        }
    };
    tracing::info!(elevated, pid = child.id(), "pcap: capture process spawned");

    // One task, two jobs on different cadences.
    //
    // The heartbeat is a SAFETY mechanism: the supervisor stops the
    // capture when it goes stale, which is the backstop for a Transit that
    // dies WITHOUT a clean exit — a crash, a force-quit, or a dev rebuild.
    // (`stop_all` covers the graceful case; this covers the one that
    // actually bit us on the first smoke test.)
    //
    // The progress event is a UI concern, and it wants a faster tick than
    // the heartbeat should have. They share a task rather than getting one
    // each because every task here needs aborting on Stop, and a second
    // handle is a second chance to leak one.
    let beat_path = heartbeat.clone();
    let progress_base = out.clone();
    let progress_id = id.clone();
    let progress_app = app.clone();
    let ticker = tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut elapsed: u64 = 0;
        loop {
            tick.tick().await;
            elapsed = elapsed.saturating_add(1);

            if elapsed.is_multiple_of(live::HEARTBEAT_INTERVAL_SECS)
                && std::fs::write(&beat_path, b"1").is_err()
            {
                break;
            }

            // Measure the file the platform is ACTUALLY writing right now,
            // which is not the same on each OS — and getting this wrong is
            // half of why Windows capture looked broken.
            //
            // Unix: tcpdump streams straight into the pcap (rotation
            // suffixes and all), so summing `written_files` tracks it live.
            //
            // Windows: pktmon writes an ETL while recording and only
            // produces the pcapng at Stop (stop-then-convert, plan §3a).
            // The pcapng the Unix-shaped `written_files` looks for does not
            // exist yet, so it reported 0 bytes for the whole capture — and
            // the sidebar's "nothing written after 10s" warning fired over
            // a capture that was filling the ETL the entire time. Measure
            // the ETL here so the byte counter climbs and that warning
            // means what it says.
            #[cfg(windows)]
            let file_bytes = std::fs::metadata(progress_base.with_extension("etl"))
                .map(|m| m.len())
                .unwrap_or(0);
            #[cfg(not(windows))]
            let file_bytes = live::written_files(&progress_base)
                .iter()
                .filter_map(|p| std::fs::metadata(p).ok())
                .map(|m| m.len())
                .sum();

            let _ = progress_app.emit(
                CAPTURE_TOPIC,
                CaptureStats {
                    capture_id: progress_id.clone(),
                    state: "running".into(),
                    file_bytes,
                    elapsed_secs: elapsed,
                    packets: None,
                    error: None,
                },
            );
        }
    });

    // The handle is STORED, not dropped. Dropping it orphans the capture
    // process: it keeps recording, as root, after Transit exits, with no
    // UI left to stop it. That is exactly the outcome T44 promises cannot
    // happen, so the handle lives here until Stop or app exit.
    state.live.lock().expect("pcap live state poisoned").insert(
        id.clone(),
        LiveCapture {
            child,
            path: out.clone(),
            sentinel,
            heartbeat,
            ticker,
        },
    );

    let _ = app.emit(
        CAPTURE_TOPIC,
        CaptureStats {
            capture_id: id.clone(),
            state: "running".into(),
            file_bytes: 0,
            elapsed_secs: 0,
            packets: None,
            error: None,
        },
    );
    Ok(id)
}

/// Stop a running capture and open what it recorded.
///
/// Indexing on the way out lands the user in the explorer looking at what
/// they just captured, rather than at an empty pane and a file path.
#[tauri::command]
pub async fn pcap_capture_stop(
    app: AppHandle,
    state: State<'_, Arc<PcapState>>,
    capture_id: String,
) -> Result<CaptureSummary, String> {
    let base = stop_capture(&state, &capture_id).await?;

    // What the capture actually wrote, asked of the filesystem rather than
    // assumed. tcpdump's `-W` appends a rotation number to every file
    // (`capture.pcap0`), so Unix uses `written_files`; pktmon honours
    // `--out` verbatim, so Windows uses the id-stem resolver.
    //
    // Windows POLLS for the output, and that is the actual fix for the
    // real-machine failure. `Start-Process -Verb RunAs -Wait` returns
    // early — the launcher exits seconds after spawning instead of waiting
    // for the elevated script — so by the time `stop_capture` returns, the
    // elevated `pktmon stop` + `etl2pcap` may not have run yet. Reading the
    // directory once, immediately, found nothing and reported "wrote no
    // packets" over a capture that appeared a second later. The sentinel we
    // just deleted is what tells the elevated script to convert; waiting
    // for the artifact it then produces is how the app stays in step with a
    // process it cannot join. Bounded, because a real failure must still
    // surface — a capture that never appears is reported with the log tail.
    #[cfg(windows)]
    let written = {
        let mut found = live::windows_capture_outputs(&base);
        // etl2pcap on a bounded (≤ file-size) capture is seconds; 30 is
        // generous headroom, not an expected wait.
        for _ in 0..60 {
            if !found.is_empty() {
                break;
            }
            // Bail early if the elevated script recorded a failure rather
            // than making us wait out the whole budget for a file that is
            // never coming.
            if supervisor_log_failed(&base) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            found = live::windows_capture_outputs(&base);
        }
        found
    };
    #[cfg(not(windows))]
    let written = live::written_files(&base);
    tracing::info!(
        files = written.len(),
        bytes = written
            .iter()
            .filter_map(|p| std::fs::metadata(p).ok())
            .map(|m| m.len())
            .sum::<u64>(),
        "pcap: capture wrote"
    );
    let Some(path) = written.first().cloned() else {
        // Self-diagnosis: list what IS in the capture directory. When the
        // resolver finds nothing, the answer is almost always a file named
        // other than expected — so record the names at debug, and the log
        // shows the mismatch directly instead of leaving it to be guessed.
        if let Some(dir) = base.parent() {
            let listing: Vec<String> = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    let len = e.metadata().ok()?.len();
                    Some(format!("{n} ({len} B)"))
                })
                .collect();
            tracing::debug!(
                dir = %dir.display(),
                entries = listing.len(),
                files = %listing.join(", "),
                "pcap: capture directory contents after a no-output stop"
            );
        }
        // "Nothing matched the filter" is ONE explanation, and offering it
        // alone is how a broken capture reads as a quiet network. On
        // Windows the elevated supervisor keeps a log precisely for this
        // moment: it ran hidden, so this file is the only account of what
        // it actually did.
        let mut msg = format!(
            "the capture stopped but wrote no packets to {}. Nothing matched the capture filter, \
             the interface saw no traffic, or the capture failed to start.",
            base.parent().unwrap_or(&base).display()
        );
        if let Some(tail) = supervisor_log_tail(&base) {
            msg.push_str("\n\nThe capture process reported:\n");
            msg.push_str(&tail);
        }
        return Err(msg);
    };
    let extra = written.len().saturating_sub(1);

    let _ = app.emit(
        CAPTURE_TOPIC,
        CaptureStats {
            capture_id: capture_id.clone(),
            state: "stopped".into(),
            file_bytes: written
                .iter()
                .filter_map(|p| std::fs::metadata(p).ok())
                .map(|m| m.len())
                .sum(),
            elapsed_secs: 0,
            packets: None,
            error: None,
        },
    );

    let opened = tauri::async_runtime::spawn_blocking(move || open_and_index(&path))
        .await
        .map_err(|e| format!("indexing task failed: {e}"))??;
    let summary = summarize(&opened);
    state.insert(opened);
    if extra > 0 {
        // Rotation split the capture. Say so: opening the newest segment
        // silently would present part of a capture as the whole of it.
        tracing::info!(
            capture = %capture_id,
            segments = extra + 1,
            "capture rotated across multiple files; opened the most recent"
        );
    }
    Ok(summary)
}

/// Bring a capture process down and return the base path it was told to
/// write. The file(s) actually created are resolved by the caller — see
/// `live::written_files` for why those differ.
///
/// Graceful first. The elevated path stops by deleting the sentinel its
/// privileged runner polls — an unprivileged file delete, deliberately
/// NOT a second password prompt, because a prompt the user could dismiss
/// would leave the machine recording. The unprivileged path stops by
/// SIGINT so `tcpdump` flushes and closes the file cleanly. Only if
/// neither lands within the grace period do we kill; `-U` means a killed
/// capture still has its packets, but a clean stop closes the file.
async fn stop_capture(state: &PcapState, capture_id: &str) -> Result<PathBuf, String> {
    let mut entry = state
        .live
        .lock()
        .expect("pcap live state poisoned")
        .remove(capture_id)
        .ok_or_else(|| format!("no capture is recording with id {capture_id}"))?;

    // Every capture, privileged or not, runs under the supervisor, so
    // deleting the sentinel is the one stop mechanism — no branch on
    // whether we elevated.
    tracing::info!(capture = %capture_id, "pcap: stopping capture");
    entry.ticker.abort();
    let _ = std::fs::remove_file(&entry.sentinel);

    // Bounded wait, then force. A capture process that ignores its stop
    // signal must not be able to wedge app exit.
    //
    // The bound is DERIVED from the supervisor's own escalation budget
    // rather than picked: the supervisor needs up to a second to notice
    // the sentinel, then sends TERM and waits `STOP_GRACE_SECS` before
    // SIGKILL. A shorter wait here would time out mid-escalation and kill
    // the wrapper instead — the supervisor is a separate root process, so
    // it would finish the job anyway, but Transit would meanwhile start
    // indexing a file still being written.
    let stop_budget = std::time::Duration::from_secs(live::STOP_GRACE_SECS + 8);
    if tokio::time::timeout(stop_budget, entry.child.wait())
        .await
        .is_err()
    {
        let _ = entry.child.kill().await;
    }
    let _ = std::fs::remove_file(&entry.heartbeat);
    tracing::info!(capture = %capture_id, "pcap: capture process exited");
    Ok(entry.path)
}

/// The tail of the elevated supervisor's log, if it wrote one.
///
/// Only Windows produces this: its supervisor runs `-WindowStyle Hidden`
/// and therefore has no console anyone can read, so without the log a
/// failed capture is completely mute. The Unix path surfaces stderr from
/// the process directly and needs no equivalent.
///
/// Sanitized and capped like any other text from outside the app, and the
/// TAIL rather than the head because the failure is at the end.
fn supervisor_log_tail(base: &std::path::Path) -> Option<String> {
    let log = base.with_extension("supervisor.log");
    let text = std::fs::read_to_string(&log).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let tail: Vec<&str> = text.lines().rev().take(12).collect();
    let joined = tail.into_iter().rev().collect::<Vec<_>>().join("\n");
    Some(transit_pcap::sanitize::long_field(&joined))
}

/// Whether the elevated supervisor recorded a terminal failure.
///
/// Lets the Windows stop-poll give up the moment the script says it failed,
/// rather than waiting out the whole timeout for an output file that is
/// never coming. The script's `catch` writes "FAILED:", and its explicit
/// exits precede a stop — so either marker means "do not keep waiting."
#[cfg(windows)]
fn supervisor_log_failed(base: &std::path::Path) -> bool {
    let log = base.with_extension("supervisor.log");
    match std::fs::read_to_string(&log) {
        Ok(text) => text.contains("FAILED:") || text.contains("failed (exit"),
        Err(_) => false,
    }
}

/// The user `-Z` should hand the capture down to on Linux.
///
/// Returned to [`live::build_tcpdump_args`]; see its doc for why a
/// rotating capture produces nothing without it on Debian/Ubuntu.
/// `None` on macOS, whose tcpdump does not drop privileges at all.
#[cfg(unix)]
fn capture_drop_user() -> Option<String> {
    if cfg!(target_os = "macos") {
        return None;
    }
    let from_env = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    if from_env.is_some() {
        return from_env;
    }
    // A desktop launcher is not obliged to export USER, and passing an
    // empty `-Z` would be worse than passing none, so fall back to the
    // kernel's own answer rather than guessing from $HOME.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .to_string();
    // /etc/passwd misses LDAP/SSSD directories, which is exactly why the
    // environment is consulted first rather than as a fallback.
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let _passwd = f.next()?;
        let id = f.next()?;
        (id == uid && !name.is_empty()).then(|| name.to_string())
    })
}

/// The message for a capture refused on its OUTPUT PATH.
///
/// Deliberately does not offer to retry with administrator rights: the
/// refusal survives elevation, and offering it is how this failure spent
/// a password prompt and still recorded nothing.
#[cfg(unix)]
fn capture_dir_refused(out: &std::path::Path) -> String {
    let dir = out
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "the capture folder".into());
    let mut msg = format!(
        "tcpdump is not allowed to create capture files in {dir}. The refusal is on the output \
         folder, not on the interface, so administrator rights do not lift it — choose a \
         different capture folder in Settings \u{2192} General."
    );
    if !cfg!(target_os = "macos") {
        msg.push_str(
            " On Debian and Ubuntu, AppArmor's tcpdump profile denies creating files anywhere \
             beneath a hidden folder in your home directory, which includes ~/.local/share.",
        );
    }
    msg
}

/// Spawn the capture under the supervisor, elevating only if the OS
/// refuses.
///
/// The ladder in full: try unprivileged; if the OS answers "permission
/// denied", ask once, through the platform's own authentication dialog.
/// A machine with a BPF-group helper installed — which is every machine
/// that already has Wireshark — never sees a prompt at all.
///
/// **Both paths run under `live::supervisor_script`**, not just the
/// elevated one. Spawning `tcpdump` directly means a Transit that dies
/// without a clean exit — a crash, a force-quit, a `tauri dev` rebuild —
/// reparents it to init, where it keeps recording as root until the
/// machine reboots. That is not hypothetical: it happened on the first
/// smoke test, twice, and is the reason the heartbeat exists.
async fn spawn_capture(
    req: &CaptureRequest,
    out: &std::path::Path,
    sentinel: &std::path::Path,
    heartbeat: &std::path::Path,
) -> Result<(tokio::process::Child, bool), String> {
    #[cfg(unix)]
    {
        let args = live::build_tcpdump_args(req, out, capture_drop_user().as_deref());
        let program = if cfg!(target_os = "macos") {
            "/usr/sbin/tcpdump"
        } else {
            "tcpdump"
        };
        let script =
            live::supervisor_script(&live::shell_join(program, &args), sentinel, heartbeat);

        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                format!("could not run {program}: {e}. Packet capture needs tcpdump installed.")
            })?;

        // tcpdump exits immediately on a permission error, and the
        // supervisor's fast-fail check (0.3 s) brings the shell down with
        // it, so this window separates "refused" from "running". A working
        // capture is still running when it elapses.
        //
        // The margin over the supervisor's 0.3 s is deliberate and was
        // earned: an earlier version waited 900 ms while the supervisor
        // used `kill -0`, which succeeds for a zombie — the shell survived
        // ~1015 ms on a capture that had already failed, so the failure
        // read as success, no prompt appeared, and nothing was recorded.
        match tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait()).await {
            Err(_) => Ok((child, false)),
            Ok(status) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use tokio::io::AsyncReadExt as _;
                    let _ = pipe.read_to_string(&mut stderr).await;
                }
                // Checked BEFORE `is_permission_error`, which would
                // otherwise claim this and raise a password prompt that
                // cannot possibly help — see `is_output_permission_error`.
                if live::is_output_permission_error(&stderr, out) {
                    return Err(capture_dir_refused(out));
                }
                if live::is_permission_error(&stderr) {
                    // Give the ELEVATED child the same fast-fail scrutiny the
                    // unprivileged attempt just had. Without it every failure
                    // past this point is attributed to one of the three
                    // guesses in the no-output message ("nothing matched the
                    // filter, no traffic, or it failed to start") — which is
                    // how a supervisor that died on its first loop iteration
                    // read as a quiet network for as long as it did.
                    //
                    // The window is generous on purpose: `pkexec` blocks while
                    // the user authenticates, so a still-running child here
                    // means "prompt is up", not "capture is healthy". Only an
                    // EARLY EXIT is diagnostic, and that is the case this
                    // catches — no agent, policy refusal, a script that cannot
                    // start. A prompt dismissed after the window still falls
                    // through to the no-output path.
                    let mut child = spawn_elevated(&script).await?;
                    match tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait())
                        .await
                    {
                        Err(_) => Ok((child, true)),
                        Ok(status) => {
                            let mut estderr = String::new();
                            if let Some(mut pipe) = child.stderr.take() {
                                use tokio::io::AsyncReadExt as _;
                                let _ = pipe.read_to_string(&mut estderr).await;
                            }
                            let detail = estderr.lines().next().unwrap_or("").trim().to_string();
                            Err(if detail.is_empty() {
                                format!(
                                    "the elevated capture exited immediately ({status:?}). \
                                     Administrator rights may have been declined."
                                )
                            } else {
                                detail
                            })
                        }
                    }
                } else {
                    // Surface tcpdump's own words — a filter syntax error
                    // or "no such device" is worth reading verbatim.
                    let detail = stderr.lines().next().unwrap_or("").trim().to_string();
                    Err(if detail.is_empty() {
                        format!("the capture exited immediately ({status:?})")
                    } else {
                        detail
                    })
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows always elevates: `pktmon` needs administrator rights,
        // full stop, so there is no unprivileged attempt worth making.
        //
        // The capture filter is translated here rather than passed
        // through, and anything untranslatable was already REFUSED by
        // `preflight` — a user who asks for `host 10.0.0.5` and silently
        // records the whole segment has a data-safety incident, not a
        // degraded feature (plan §3a).
        let filters = match &req.bpf {
            Some(bpf) => live::bpf_to_pktmon(bpf)?,
            None => Vec::new(),
        };
        // pktmon writes ETL; the pcapng only exists after conversion, so
        // the file we will eventually index is a sibling of what pktmon
        // is told to write.
        let etl = out.with_extension("etl");
        // `req.interface` is an NDIS interface index on Windows, not a
        // pktmon component id: the dropdown is filled unprivileged by
        // `Get-NetAdapter`, and pktmon — which needs Administrator even to
        // list — is only reachable inside the elevated script, which
        // resolves the index to a component there.
        //
        // The index rather than the MAC because a MAC is not unique: an
        // SR-IOV pair shares one, and would resolve to two components.
        // Combined into ONE `filter add`: separate pktmon filters are
        // OR-ed, so a filter per term would widen the capture.
        let filter_args = live::pktmon_filter_args(&filters)?;
        // Beside the capture, so a user who is told "the log says X" can
        // find X, and so it is cleaned up with the rest of a capture.
        let log = out.with_extension("supervisor.log");
        let script = live::windows_supervisor_script(
            &req.interface,
            &filter_args,
            &live::build_pktmon_args(req, &etl),
            live::WindowsCapturePaths {
                etl: &etl,
                pcapng: out,
                sentinel,
                heartbeat,
                log: &log,
            },
        );

        // Deliver the script as `-EncodedCommand` (base64 UTF-16LE), never
        // inline text and never a staged file.
        //
        // Inline text was the original bug: the multi-line script, full of
        // `$`, quotes and braces, crossed three parsers (this launcher's
        // `-Command`, `Start-Process -ArgumentList` splitting, the elevated
        // process's parsing) and arrived mangled, so the elevated
        // PowerShell wrote nothing at all — an empty directory and a 2 ms
        // exit. Base64 is `[A-Za-z0-9+/=]` and survives every layer intact.
        //
        // A staged `.ps1` + `-File` would also fix the parsing, but it
        // writes a user-writable script and then runs it elevated — a
        // TOCTOU a same-user process could win to execute code as admin,
        // and out of step with the macOS/Linux paths, which stage nothing.
        // `-EncodedCommand` keeps the script off disk. See
        // `live::windows_encoded_command`.
        let encoded = live::windows_encoded_command(&script);

        // One elevated run does everything: status check, filters, start,
        // the stop poll, and the conversion. A second elevated call would
        // mean a second UAC prompt, and a prompt on the way OUT could be
        // dismissed — leaving the machine recording.
        let mut cmd = tokio::process::Command::new("powershell");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden \
                 -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{encoded}'"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

        // CREATE_NO_WINDOW. Without it this launcher — whose entire job is
        // to call `Start-Process -Verb RunAs` and wait — flashes up an
        // empty black console that sits there for the whole capture. The
        // elevated child is already `-WindowStyle Hidden`; the visible
        // window was always the outer one, and it looks like Transit
        // opened a terminal for no reason.
        #[cfg(windows)]
        {
            // `creation_flags` is inherent on tokio's Command for Windows,
            // so no trait import — importing `std::os::windows::process::
            // CommandExt` here is unused and fails `-D warnings`.
            cmd.creation_flags(0x0800_0000);
        }

        let child = cmd.spawn().map_err(|e| {
            format!("could not start pktmon: {e}. Packet capture needs Windows 10 1809 or later.")
        })?;
        Ok((child, true))
    }
}

/// Re-run the same supervisor script under the platform's authentication
/// prompt.
///
/// The elevated process is the supervisor, not `tcpdump` directly, and
/// that shape is load-bearing twice over: killing `osascript` would not
/// kill the root `tcpdump` beneath it, and the supervisor is what honours
/// both the stop sentinel and the heartbeat. Stop therefore costs an
/// unprivileged file delete rather than a second password prompt — and a
/// prompt the user could dismiss would leave the machine recording.
#[cfg(unix)]
async fn spawn_elevated(script: &str) -> Result<tokio::process::Child, String> {
    if cfg!(target_os = "macos") {
        let apple = live::macos_elevated_script("/bin/sh", &["-c".into(), script.to_string()]);
        tokio::process::Command::new("osascript")
            .args(["-e", &apple])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    } else {
        tokio::process::Command::new("pkexec")
            .args(["/bin/sh", "-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    }
    .map_err(|e| format!("could not request administrator rights: {e}"))
}

/// Show the capture folder in the OS file manager.
///
/// A dedicated command rather than a frontend `openPath` permission: the
/// capability would let the webview hand any path to the OS, while this
/// resolves the one app-owned directory itself and the webview cannot name
/// a different one. It is also the only `pcap_*` command whose whole job is
/// outside the app, which is precisely why it should be the narrower shape.
///
/// Gated like the rest of the namespace, so `[pcap] enabled = false` does
/// not leave a route to the capture files behind.
#[tauri::command]
pub fn pcap_open_captures_dir(app: AppHandle) -> Result<(), String> {
    ensure_enabled()?;
    let dir = capture_dir()?;
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_path(dir.to_string_lossy().to_string(), None::<&str>)
        .map_err(|e| format!("could not open the capture folder: {e}"))
}

/// The capture folder's path, for display.
///
/// A path, never a credential (Rule 1) — the same thing the Files pane's
/// local pane surfaces. Shown so the folder is findable by hand on a
/// machine where the file manager will not open.
#[tauri::command]
pub fn pcap_captures_dir() -> Result<String, String> {
    ensure_enabled()?;
    Ok(capture_dir()?.to_string_lossy().to_string())
}

/// Where captures are written.
///
/// The user's configured folder when there is one (`[pcap] dir`, or
/// `TRANSIT_PCAP_DIR`), else the app's own data directory. Resolved per
/// call rather than cached, so changing it in Settings applies to the next
/// capture instead of the next launch.
///
/// A configured path is created if missing but NOT otherwise second-
/// guessed: `set_pcap_dir` already refused anything relative or
/// uncreatable, and re-litigating it here would mean a folder that
/// validated at choosing-time could still fail at capture-time with a
/// different message.
fn capture_dir() -> Result<PathBuf, String> {
    if let Some(dir) = crate::commands::resolve_pcap_dir() {
        // Re-validated here, not only in the setter: `config.toml` can be
        // hand-edited and `TRANSIT_PCAP_DIR` never passes through the
        // setter at all, so this is the only check every source crosses.
        crate::commands::validate_capture_dir(&dir.to_string_lossy())?;
        std::fs::create_dir_all(&dir).map_err(|e| {
            format!(
                "the configured capture folder {} cannot be used: {e}",
                dir.display()
            )
        })?;
        return Ok(dir);
    }
    // Linux deliberately does NOT use `dirs::data_dir()`. It resolves to
    // ~/.local/share, and Debian/Ubuntu confine tcpdump with an AppArmor
    // profile carrying `audit deny @{HOME}/.*/** mrwkl` — an explicit
    // deny, which in AppArmor beats every allow rule — so no file may be
    // created beneath ANY hidden folder in the home directory. That is
    // why live capture never produced a file on Ubuntu: it fails as root
    // exactly as it does unprivileged (`operation="mknod"
    // denied_mask="c" fsuid=0`), so the elevation ladder could not
    // rescue it either. A VISIBLE folder is permitted by the same
    // profile's `owner @{HOME}/** rw` and `/**.[pP][cC][aA][pP][0-9]*`
    // allow rules.
    //
    // No migration is needed, because nothing can have been left behind:
    // a live capture could never write to the old path on a machine with
    // the profile, and captures opened from elsewhere are read in place
    // and never copied here.
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = dirs::home_dir().ok_or("could not locate a directory for captures")?;
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    let base = dirs::data_dir()
        .or_else(dirs::home_dir)
        .ok_or("could not locate a directory for captures")?;
    let dir = base.join("TransitCommunity").join("captures");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------
// The agent seam
// ---------------------------------------------------------------------

/// `transit_agent::CaptureSource` over the open captures.
///
/// **What is on this type is the whole of what the assistant can do with
/// a capture.** Raw packet bytes (`pcap_packet_bytes`), flow reassembly
/// and export exist as IPC commands above and are deliberately not
/// reachable from here — not filtered out, not present.
pub struct PcapCaptureSource {
    state: Arc<PcapState>,
}

impl PcapCaptureSource {
    pub fn new(state: Arc<PcapState>) -> Self {
        Self { state }
    }
}

impl transit_agent::CaptureSource for PcapCaptureSource {
    fn list(&self) -> Vec<CaptureMeta> {
        // The off-switch is honoured here too, so a chat that was mid-turn
        // when the flag flipped stops seeing captures immediately.
        if !resolve_pcap_agent_access() {
            return Vec::new();
        }
        self.state
            .open_in_order()
            .iter()
            .map(|c| c.meta())
            .collect()
    }

    fn query(
        &self,
        capture_id: Option<&str>,
        kind: &CaptureQueryKind,
    ) -> Result<CaptureAnswer, CaptureQueryError> {
        if !resolve_pcap_agent_access() {
            return Err(CaptureQueryError::AccessDisabled);
        }
        let open: Vec<CaptureMeta> = self
            .state
            .open_in_order()
            .iter()
            .map(|c| c.meta())
            .collect();

        // `list` is the one query that does not need a capture chosen —
        // it is how the model discovers what is open.
        if matches!(kind, CaptureQueryKind::List) {
            return Ok(CaptureAnswer::plain(render_capture_list(&open)));
        }

        let id = transit_agent::resolve_capture_id(capture_id, &open)?;
        let c = self
            .state
            .get(&id)
            .ok_or_else(|| CaptureQueryError::UnknownCapture(id.clone()))?;
        answer_query(&c, kind)
    }
}

fn render_capture_list(open: &[CaptureMeta]) -> String {
    if open.is_empty() {
        return "No packet captures are open.".into();
    }
    let mut s = String::from("OPEN CAPTURES\n");
    for c in open {
        s.push_str(&format!(
            "  {}  {}  {} packets  {}  {}{}\n",
            c.capture_id,
            c.name,
            thousands(c.packets),
            bytes_human(c.bytes),
            c.duration,
            if c.live { "  (recording)" } else { "" }
        ));
    }
    s
}

fn answer_query(
    c: &OpenCapture,
    kind: &CaptureQueryKind,
) -> Result<CaptureAnswer, CaptureQueryError> {
    match kind {
        CaptureQueryKind::List => unreachable!("handled before capture resolution"),

        CaptureQueryKind::Overview => Ok(CaptureAnswer::plain(render_digest(
            &c.index,
            &c.findings,
            &DigestOptions::default(),
        ))),

        CaptureQueryKind::Packets {
            filter,
            offset,
            limit,
        } => {
            let limit = (*limit).clamp(1, MAX_ROWS);
            let page = rows_page(c, filter.as_deref(), *offset, limit)
                .map_err(CaptureQueryError::BadFilter)?;
            // Compact fixed-width rows, not JSON: identical information,
            // roughly 40% fewer tokens.
            let mut s = String::from("#      time              source → destination                  proto  bytes  info\n");
            for r in &page.rows {
                s.push_str(&format!(
                    "{:<6} {} {:>21} → {:<21} {:<6} {:>6}  {}\n",
                    r.number,
                    &r.time[11..],
                    r.src,
                    r.dst,
                    r.protocol,
                    r.length,
                    r.info
                ));
            }
            let returned = page.rows.len() as u32;
            if page.total_matched > u64::from(returned) {
                s.push_str(&format!(
                    "\n[showing {} of {} matching packets — raise `offset` to page through]\n",
                    returned,
                    thousands(page.total_matched)
                ));
            }
            Ok(CaptureAnswer {
                text: s,
                total_matched: Some(page.total_matched),
                returned: Some(returned),
                truncated: page.total_matched > u64::from(returned),
            })
        }

        CaptureQueryKind::Conversations { by, limit } => {
            let sort = FlowSort::from_tag(by).unwrap_or(FlowSort::Bytes);
            let limit = (*limit).clamp(1, MAX_ROWS) as usize;
            let flows = c.index.top_flows(sort, limit);
            let mut s = String::from(
                "flow   endpoints                                      proto  bytes    pkts   rtt_p50  retx   rst\n",
            );
            for f in &flows {
                s.push_str(&format!(
                    "f{:<5} {:<45} {:<6} {:>8} {:>7} {:>8} {:>5.1}% {:>5}\n",
                    f.id,
                    f.key.render(),
                    f.key.proto.as_str(),
                    bytes_human(f.bytes()),
                    thousands(f.packets()),
                    f.rtt_percentile(0.5)
                        .or(f.handshake_rtt_us)
                        .map(|us| format!("{:.1}ms", us as f64 / 1000.0))
                        .unwrap_or_else(|| "-".into()),
                    f.retransmit_pct(),
                    f.resets
                ));
            }
            let total = c.index.flows.len() as u64;
            if total > flows.len() as u64 {
                s.push_str(&format!(
                    "\n[showing {} of {} conversations]\n",
                    flows.len(),
                    thousands(total)
                ));
            }
            Ok(CaptureAnswer {
                text: s,
                total_matched: Some(total),
                returned: Some(flows.len() as u32),
                truncated: total > flows.len() as u64,
            })
        }

        CaptureQueryKind::Flow { flow_id } => {
            let f = c
                .index
                .flows
                .iter()
                .find(|f| f.id == *flow_id)
                .ok_or_else(|| {
                    CaptureQueryError::NotFound(format!("no conversation with id f{flow_id}"))
                })?;
            let mut s = format!("FLOW f{}  {}\n", f.id, f.key.render());
            s.push_str(&format!(
                "  proto={}  packets={} ({} → / {} ←)  bytes={} ({} → / {} ←)  duration={}\n",
                f.key.proto.as_str(),
                thousands(f.packets()),
                thousands(f.packets_ab),
                thousands(f.packets_ba),
                bytes_human(f.bytes()),
                bytes_human(f.bytes_ab),
                bytes_human(f.bytes_ba),
                duration_human(f.duration_us())
            ));
            s.push_str(&format!(
                "  handshake={}  syn={} syn_ack={} fin={}\n",
                f.handshake_rtt_us
                    .map(|us| format!("{:.1}ms", us as f64 / 1000.0))
                    .unwrap_or_else(|| "-".into()),
                f.syn_seen,
                f.syn_ack_seen,
                f.fin_seen
            ));
            s.push_str(&format!(
                "  retransmits={} ({:.2}%)  dup_acks={}  out_of_order={}  resets={}  \
                 zero_windows={} (longest stall {})\n",
                f.retransmits,
                f.retransmit_pct(),
                f.dup_acks,
                f.out_of_order,
                f.resets,
                f.zero_windows,
                duration_human(f.max_zero_window_us)
            ));
            if let (Some(p50), Some(p95)) = (f.rtt_percentile(0.5), f.rtt_percentile(0.95)) {
                s.push_str(&format!(
                    "  rtt p50={:.1}ms p95={:.1}ms\n",
                    p50 as f64 / 1000.0,
                    p95 as f64 / 1000.0
                ));
            }
            if f.is_refused() {
                s.push_str("  VERDICT: connection refused — something answered and declined.\n");
            } else if f.is_unanswered() {
                s.push_str("  VERDICT: no reply at all — a dropped SYN, a black-holed route, or a silently-discarding firewall.\n");
            }
            Ok(CaptureAnswer::plain(s))
        }

        CaptureQueryKind::Packet { number } => {
            let d = dissect_one(c, *number).map_err(CaptureQueryError::NotFound)?;
            let mut s = format!("PACKET {number}\n");
            for layer in &d.layers {
                s.push_str(&format!("  {}\n", layer.label));
                for f in &layer.fields {
                    s.push_str(&format!("    {} = {}\n", f.name, f.value.render()));
                }
            }
            // Named explicitly rather than left as an unexplained gap: a
            // model that knows payload is unavailable stops asking and
            // reasons from the fields instead.
            s.push_str("  (packet payload is not available through this tool)\n");
            Ok(CaptureAnswer::plain(s))
        }

        CaptureQueryKind::Findings { severity, limit } => {
            let want = severity.as_deref().and_then(Severity::from_tag);
            let limit = (*limit).clamp(1, MAX_ROWS) as usize;
            let matched: Vec<&Finding> = c
                .findings
                .iter()
                .filter(|f| want.is_none_or(|w| f.severity >= w))
                .collect();
            let total = matched.len() as u64;
            let mut s = String::new();
            if matched.is_empty() {
                s.push_str("No findings at this severity.\n");
            }
            for f in matched.iter().take(limit) {
                s.push_str(&format!("[{}] {}\n", f.severity.as_str(), f.detail));
                if let Some(filter) = &f.filter {
                    s.push_str(&format!("      filter: {filter}\n"));
                }
            }
            let returned = matched.len().min(limit) as u32;
            if total > u64::from(returned) {
                s.push_str(&format!("\n[showing {returned} of {total} findings]\n"));
            }
            Ok(CaptureAnswer {
                text: s,
                total_matched: Some(total),
                returned: Some(returned),
                truncated: total > u64::from(returned),
            })
        }

        CaptureQueryKind::Timeline { bucket_ms, filter } => {
            let matched =
                matching_indices(c, filter.as_deref()).map_err(CaptureQueryError::BadFilter)?;
            let bucket_us = i64::from((*bucket_ms).max(1)) * 1000;
            let mut buckets: std::collections::BTreeMap<i64, (u64, u64)> =
                std::collections::BTreeMap::new();
            for i in matched {
                let rec = &c.index.records[i];
                let slot = (rec.ts_us - c.index.first_ts) / bucket_us;
                let e = buckets.entry(slot).or_insert((0, 0));
                e.0 += 1;
                e.1 += u64::from(rec.orig_len);
            }
            // A timeline with thousands of rows would be the exact
            // opposite of the compression this design exists for.
            const MAX_BUCKETS: usize = 120;
            let total = buckets.len() as u64;
            let mut s = format!("TIMELINE  bucket={bucket_ms}ms\n  offset    packets    bytes\n");
            for (slot, (pk, by)) in buckets.iter().take(MAX_BUCKETS) {
                s.push_str(&format!(
                    "  {:>8}  {:>8}  {:>9}\n",
                    duration_human(slot * bucket_us),
                    thousands(*pk),
                    bytes_human(*by)
                ));
            }
            if total > MAX_BUCKETS as u64 {
                s.push_str(&format!(
                    "\n[showing {MAX_BUCKETS} of {total} buckets — use a larger bucket_ms]\n"
                ));
            }
            Ok(CaptureAnswer {
                text: s,
                total_matched: Some(total),
                returned: Some(total.min(MAX_BUCKETS as u64) as u32),
                truncated: total > MAX_BUCKETS as u64,
            })
        }
    }
}

/// Render a field value for the UI. Kept here so the IPC and the agent
/// answers cannot diverge on formatting.
#[allow(dead_code)]
fn render_field(v: &FieldValue) -> String {
    v.render()
}

/// Raw packet bytes for the hex pane never travel through the capture
/// source; this exists so the compiler proves the module still has no
/// path from `CaptureSource` to them.
#[cfg(test)]
mod tests {
    use super::*;

    /// The seam's shape, asserted rather than assumed: every query kind
    /// the agent can name is handled, and none of them is a byte-returning
    /// one. If someone adds a payload variant to `CaptureQueryKind`, this
    /// stops compiling until they decide what it does here.
    #[test]
    fn the_agent_query_surface_is_metadata_only() {
        fn assert_exhaustive(k: &CaptureQueryKind) -> &'static str {
            match k {
                CaptureQueryKind::List => "list",
                CaptureQueryKind::Overview => "overview",
                CaptureQueryKind::Packets { .. } => "packets",
                CaptureQueryKind::Conversations { .. } => "conversations",
                CaptureQueryKind::Flow { .. } => "flow",
                CaptureQueryKind::Packet { .. } => "packet",
                CaptureQueryKind::Findings { .. } => "findings",
                CaptureQueryKind::Timeline { .. } => "timeline",
            }
        }
        assert_eq!(assert_exhaustive(&CaptureQueryKind::Overview), "overview");
    }

    /// The IPC wire contract, pinned key-for-key.
    ///
    /// This exists because the failure it guards is **silent**. The
    /// TypeScript in `src/lib/pcap.ts` declares the shape it expects; it
    /// does not verify it. When `CaptureSummary` serialized `capture_id`
    /// and the TS read `captureId`, everything compiled, every test
    /// passed, and the capture tab opened with an id of `undefined` — so
    /// it never matched the active tab and its pane rendered as a black
    /// rectangle. The only visible symptom was a React key warning in a
    /// console nobody was watching.
    ///
    /// So: if you rename a field here, add `rename_all`, or add a field,
    /// this test fails and points at `src/lib/pcap.ts`, which must be
    /// updated in the same commit.
    #[test]
    fn wire_structs_serialize_the_keys_the_frontend_reads() {
        fn keys(v: &serde_json::Value) -> Vec<&str> {
            let mut k: Vec<&str> = v
                .as_object()
                .expect("object")
                .keys()
                .map(|s| &**s)
                .collect();
            k.sort_unstable();
            k
        }

        let summary = serde_json::to_value(CaptureSummary {
            capture_id: "c".into(),
            name: "n".into(),
            packets: 1,
            bytes: 2,
            duration_us: 3,
            first_ts: 4,
            last_ts: 5,
            link_type: "EN10MB".into(),
            snaplen: 6,
            live: false,
            index_truncated: false,
            flows: 7,
            findings: 8,
        })
        .expect("serialize");
        assert_eq!(
            keys(&summary),
            [
                "bytes",
                "capture_id",
                "duration_us",
                "findings",
                "first_ts",
                "flows",
                "index_truncated",
                "last_ts",
                "link_type",
                "live",
                "name",
                "packets",
                "snaplen",
            ]
        );

        let row = serde_json::to_value(PacketRow {
            number: 1,
            ts_us: 2,
            time: "t".into(),
            src: "a".into(),
            dst: "b".into(),
            protocol: "tcp".into(),
            length: 3,
            info: "i".into(),
            analysis: 0,
        })
        .expect("serialize");
        assert_eq!(
            keys(&row),
            ["analysis", "dst", "info", "length", "number", "protocol", "src", "time", "ts_us"]
        );

        let page = serde_json::to_value(RowPage {
            rows: vec![],
            total_matched: 0,
            offset: 0,
        })
        .expect("serialize");
        assert_eq!(keys(&page), ["offset", "rows", "total_matched"]);

        let flow = serde_json::to_value(FlowRow {
            flow_id: 1,
            endpoints: "e".into(),
            protocol: "tcp".into(),
            packets: 2,
            bytes: 3,
            duration_us: 4,
            retransmit_pct: 0.0,
            resets: 0,
            rtt_p50_us: None,
        })
        .expect("serialize");
        assert_eq!(
            keys(&flow),
            [
                "bytes",
                "duration_us",
                "endpoints",
                "flow_id",
                "packets",
                "protocol",
                "resets",
                "retransmit_pct",
                "rtt_p50_us",
            ]
        );

        let finding = serde_json::to_value(FindingRow {
            severity: "high".into(),
            rule: "r".into(),
            detail: "d".into(),
            filter: None,
        })
        .expect("serialize");
        assert_eq!(keys(&finding), ["detail", "filter", "rule", "severity"]);

        let layer = serde_json::to_value(DetailLayer {
            protocol: "ip".into(),
            label: "IPv4".into(),
            fields: vec![DetailField {
                name: "ip.src".into(),
                label: "Source".into(),
                value: "10.0.0.1".into(),
            }],
        })
        .expect("serialize");
        assert_eq!(keys(&layer), ["fields", "label", "protocol"]);
        assert_eq!(keys(&layer["fields"][0]), ["label", "name", "value"]);

        let stats = serde_json::to_value(CaptureStats {
            capture_id: "c".into(),
            state: "running".into(),
            file_bytes: 3,
            elapsed_secs: 4,
            packets: None,
            error: None,
        })
        .expect("serialize");
        assert_eq!(
            keys(&stats),
            [
                "capture_id",
                "elapsed_secs",
                "error",
                "file_bytes",
                "packets",
                "state"
            ]
        );
        // `null`, not `0` — the UI distinguishes "not counted yet" from
        // "counted, and there were none".
        assert!(stats["packets"].is_null());
    }

    /// The start request travels the other way, so it is pinned by
    /// DEserializing the exact JSON the sidebar sends.
    #[test]
    fn the_start_request_accepts_the_keys_the_frontend_sends() {
        let req: CaptureStartRequest = serde_json::from_str(
            r#"{"interface":"en0","bpf":null,"snaplen":128,
                "max_file_mb":256,"max_files":8,"max_duration_secs":3600}"#,
        )
        .expect("the sidebar's payload must deserialize");
        assert_eq!(req.interface, "en0");
        assert_eq!(req.max_file_mb, 256);
        assert_eq!(req.max_duration_secs, 3600);

        // And the camelCase spelling is NOT silently accepted — a partial
        // rename would otherwise half-work and leave the caps unset.
        assert!(serde_json::from_str::<CaptureStartRequest>(
            r#"{"interface":"en0","snaplen":128,
                "maxFileMb":256,"maxFiles":8,"maxDurationSecs":3600}"#,
        )
        .is_err());
    }
}
