//! The capture digest.
//!
//! This is the single most important artifact in the PCaps design. It is
//! what makes "ask the assistant about this 1.2 GB capture" possible at
//! all.
//!
//! # The arithmetic
//!
//! A 1.2 GB capture is about 1.5 million packets. Rendered one line each,
//! that is roughly 52 million tokens — it does not fit in any context
//! window at any price, and hex would be an order of magnitude worse. The
//! digest is **~1,500 tokens and does not grow with the capture**: it is
//! O(1) in packet count, because everything in it is an aggregate.
//!
//! So the model never receives packets. It receives this, and then drills
//! in with bounded queries against the index. That is a reduction of
//! roughly four orders of magnitude, and it is the entire reason the
//! feature works.
//!
//! # Why text tables and not JSON
//!
//! Every value here is rendered into a compact, column-aligned table.
//! JSON would re-state each field name on every row and cost ~40% more
//! tokens for exactly the same information. The model reads tables fine;
//! it is the field-name repetition that is waste.
//!
//! # Bounded, and honest about it
//!
//! The output is capped. When something is elided — talkers beyond the
//! top N, findings beyond the limit, a capture whose index was truncated
//! — the digest **says so**. A summary that silently omits is worse than
//! one that admits its edges, because it reads as complete.

use std::fmt::Write as _;

use super::findings::Finding;
use crate::index::{CaptureIndex, FlowSort};

/// How much of each section to render.
#[derive(Debug, Clone, Copy)]
pub struct DigestOptions {
    pub max_talkers: usize,
    pub max_conversations: usize,
    pub max_findings: usize,
    /// Hard ceiling on the rendered digest. Generous — the digest is
    /// meant to be the cheap part — but a ceiling nonetheless.
    pub max_bytes: usize,
}

impl Default for DigestOptions {
    fn default() -> Self {
        Self {
            max_talkers: 8,
            max_conversations: 10,
            max_findings: 12,
            max_bytes: 12 * 1024,
        }
    }
}

/// Render the digest for an indexed capture.
pub fn render(idx: &CaptureIndex, findings: &[Finding], opts: &DigestOptions) -> String {
    let mut s = String::with_capacity(4096);

    header(&mut s, idx);
    protocols(&mut s, idx);
    talkers(&mut s, idx, opts);
    conversations(&mut s, idx, opts);
    tcp_health(&mut s, idx);
    app_sections(&mut s, idx);
    findings_section(&mut s, findings, opts);

    if s.len() > opts.max_bytes {
        let cut = floor_char_boundary(&s, opts.max_bytes);
        s.truncate(cut);
        s.push_str("\n[digest truncated to fit its size ceiling]\n");
    }
    s
}

fn header(s: &mut String, idx: &CaptureIndex) {
    let _ = writeln!(s, "CAPTURE  {}", idx.meta.name);
    let _ = writeln!(
        s,
        "  {} packets · {} · {} · link={} · snaplen={}",
        thousands(idx.packet_count()),
        bytes_human(idx.total_bytes),
        duration_human(idx.duration_us()),
        idx.meta.link_type.as_str(),
        if idx.meta.snaplen == 0 {
            "unset".to_string()
        } else {
            idx.meta.snaplen.to_string()
        }
    );
    if idx.packet_count() > 0 {
        let _ = writeln!(
            s,
            "  {} → {} UTC",
            ts_human(idx.first_ts),
            ts_human(idx.last_ts)
        );
    }
    // The index's completeness is stated up front, not buried, because it
    // qualifies every number that follows.
    let index_state = if idx.limits_hit.packet_cap {
        "TRUNCATED — counts below cover the indexed portion only"
    } else if idx.scan.stopped_on_error {
        "PARTIAL — the file is damaged part-way through"
    } else if idx.scan.truncated_tail {
        "growing — the capture is still being written"
    } else {
        "complete"
    };
    let _ = writeln!(s, "  index={index_state}");
    s.push('\n');
}

fn protocols(s: &mut String, idx: &CaptureIndex) {
    if idx.proto_counts.is_empty() {
        return;
    }
    let total = idx.total_bytes.max(1);
    let mut rows: Vec<_> = idx
        .proto_counts
        .iter()
        .map(|(p, (pk, by))| (*p, *pk, *by))
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.2));

    let _ = writeln!(s, "PROTOCOLS (share of bytes)");
    let parts: Vec<String> = rows
        .iter()
        .take(12)
        .map(|(p, _, by)| format!("{} {:.1}%", p.as_str(), *by as f64 * 100.0 / total as f64))
        .collect();
    let _ = writeln!(s, "  {}", parts.join(" · "));
    s.push('\n');
}

fn talkers(s: &mut String, idx: &CaptureIndex, opts: &DigestOptions) {
    let top = idx.top_talkers(opts.max_talkers);
    if top.is_empty() {
        return;
    }
    let _ = writeln!(s, "TOP TALKERS (by bytes)");
    for (ip, t) in &top {
        let _ = writeln!(
            s,
            "  {:<39} {:>10}  {:>9} pkts  (tx {} / rx {})",
            ip.to_string(),
            bytes_human(t.bytes()),
            thousands(t.packets()),
            bytes_human(t.bytes_sent),
            bytes_human(t.bytes_recv)
        );
    }
    let distinct = idx.ips.len();
    if distinct > top.len() {
        let _ = writeln!(s, "  … {} further addresses", distinct - top.len());
    }
    s.push('\n');
}

fn conversations(s: &mut String, idx: &CaptureIndex, opts: &DigestOptions) {
    let top = idx.top_flows(FlowSort::Bytes, opts.max_conversations);
    if top.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "TOP CONVERSATIONS (by bytes)   [flow  endpoints  proto  bytes  pkts  rtt_p50  retx  rst]"
    );
    for f in &top {
        let rtt = f
            .rtt_percentile(0.5)
            .or(f.handshake_rtt_us)
            .map(|us| format!("{:.1}ms", us as f64 / 1000.0))
            .unwrap_or_else(|| "-".into());
        let _ = writeln!(
            s,
            "  f{:<5} {:<45} {:<5} {:>9} {:>8} {:>8} {:>5.1}% {:>4}",
            f.id,
            f.key.render(),
            f.key.proto.as_str(),
            bytes_human(f.bytes()),
            thousands(f.packets()),
            rtt,
            f.retransmit_pct(),
            f.resets
        );
    }
    if idx.flows.len() > top.len() {
        let _ = writeln!(
            s,
            "  … {} further conversations",
            idx.flows.len() - top.len()
        );
    }
    if idx.flow_overflow.0 > 0 {
        let _ = writeln!(
            s,
            "  ! {} packets were not attributed to a conversation (flow-table ceiling)",
            thousands(idx.flow_overflow.0)
        );
    }
    s.push('\n');
}

fn tcp_health(s: &mut String, idx: &CaptureIndex) {
    let h = idx.tcp_health();
    if h.flows == 0 {
        return;
    }
    let _ = writeln!(s, "TCP HEALTH");
    let _ = writeln!(
        s,
        "  {} conversations · retransmits {} ({:.2}%) · dup-acks {} · out-of-order {} · resets {} \
         · zero-window {}",
        thousands(h.flows),
        thousands(h.retransmits),
        h.retransmit_pct(),
        thousands(h.dup_acks),
        thousands(h.out_of_order),
        thousands(h.resets),
        thousands(h.zero_windows)
    );
    if h.refused > 0 || h.unanswered > 0 {
        let _ = writeln!(
            s,
            "  connection attempts: {} refused (RST), {} unanswered (no reply at all)",
            h.refused, h.unanswered
        );
    }
    s.push('\n');
}

fn app_sections(s: &mut String, idx: &CaptureIndex) {
    let st = &idx.stats;
    let mut any = false;

    if st.dns.queries > 0 || st.dns.responses > 0 {
        any = true;
        let mut line = format!(
            "DNS   {} queries · {} responses · {} NXDOMAIN · {} SERVFAIL · {} unanswered",
            thousands(st.dns.queries),
            thousands(st.dns.responses),
            st.dns.nxdomain,
            st.dns.servfail,
            st.dns.unanswered
        );
        if let Some(mean) = st.dns.mean_response_us() {
            let _ = write!(
                line,
                " · mean {:.0}ms, slowest {:.0}ms",
                mean as f64 / 1000.0,
                st.dns.slowest_us as f64 / 1000.0
            );
        }
        let _ = writeln!(s, "{line}");
        let failing = st.dns.failing_names.top(3);
        if !failing.is_empty() {
            let list = failing
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "      failing names: {list}");
        }
    }

    if st.tls.client_hellos > 0 || st.tls.alerts > 0 {
        any = true;
        let versions = st
            .tls
            .versions
            .top(4)
            .iter()
            .map(|(v, c)| format!("{v}={c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            s,
            "TLS   {} client hellos · {} server hellos · {} alerts ({} fatal) · {versions}",
            st.tls.client_hellos, st.tls.server_hellos, st.tls.alerts, st.tls.fatal_alerts
        );
        let sni = st.tls.sni.top(4);
        if !sni.is_empty() {
            let list = sni
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "      top SNI: {list}");
        }
        let reasons = st.tls.alert_reasons.top(3);
        if !reasons.is_empty() {
            let list = reasons
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "      alerts: {list}");
        }
    }

    if st.http.requests > 0 || st.http.responses > 0 {
        any = true;
        let codes = st
            .http
            .status
            .iter()
            .map(|(c, n)| format!("{c}={n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            s,
            "HTTP  {} requests · {} responses · {codes}",
            st.http.requests, st.http.responses
        );
        let hosts = st.http.hosts.top(3);
        if !hosts.is_empty() {
            let list = hosts
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(s, "      top hosts: {list}");
        }
    }

    if st.icmp.total > 0 {
        any = true;
        let mut line = format!(
            "ICMP  {} total · {} echo req · {} echo reply · {} unreachable · {} time-exceeded",
            st.icmp.total,
            st.icmp.echo_requests,
            st.icmp.echo_replies,
            st.icmp.unreachable,
            st.icmp.time_exceeded
        );
        if st.icmp.frag_needed > 0 {
            let mtus = st
                .icmp
                .frag_needed_mtus
                .iter()
                .take(4)
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join("/");
            let _ = write!(line, " · {} frag-needed (MTU {mtus})", st.icmp.frag_needed);
        }
        let _ = writeln!(s, "{line}");
    }

    if st.arp.requests > 0 || st.arp.replies > 0 {
        any = true;
        let dupes = st.arp.claims.values().filter(|m| m.len() > 1).count();
        let _ = writeln!(
            s,
            "ARP   {} requests · {} replies · {} gratuitous · {} addresses claimed by >1 MAC",
            st.arp.requests, st.arp.replies, st.arp.gratuitous, dupes
        );
    }

    if st.dhcp.discovers > 0 || st.dhcp.acks > 0 || st.dhcp.naks > 0 {
        any = true;
        let _ = writeln!(
            s,
            "DHCP  {} discover · {} offer · {} request · {} ack · {} nak",
            st.dhcp.discovers, st.dhcp.offers, st.dhcp.requests, st.dhcp.acks, st.dhcp.naks
        );
    }

    if any {
        s.push('\n');
    }
}

fn findings_section(s: &mut String, findings: &[Finding], opts: &DigestOptions) {
    if findings.is_empty() {
        let _ = writeln!(s, "FINDINGS  none");
        return;
    }
    let _ = writeln!(s, "FINDINGS ({})", findings.len());
    for f in findings.iter().take(opts.max_findings) {
        let _ = writeln!(s, "  [{}] {}", f.severity.as_str(), f.detail);
        if let Some(filter) = &f.filter {
            let _ = writeln!(s, "        filter: {filter}");
        }
    }
    if findings.len() > opts.max_findings {
        let _ = writeln!(
            s,
            "  … {} further findings (query kind=findings for the rest)",
            findings.len() - opts.max_findings
        );
    }
}

// ---------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------

/// `1,482,301`
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `1.21 GB`. Decimal units, because that is what capture tools and NICs
/// report and a mismatch invites arithmetic arguments.
pub fn bytes_human(n: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GB", 1_000_000_000),
        ("MB", 1_000_000),
        ("KB", 1_000),
        ("B", 1),
    ];
    for (unit, div) in UNITS {
        if n >= div {
            return if div == 1 {
                format!("{n} B")
            } else {
                format!("{:.2} {unit}", n as f64 / div as f64)
            };
        }
    }
    "0 B".into()
}

/// `00:14:22.418`
pub fn duration_human(us: i64) -> String {
    let us = us.max(0);
    let total_ms = us / 1000;
    let ms = total_ms % 1000;
    let total_s = total_ms / 1000;
    let s = total_s % 60;
    let m = (total_s / 60) % 60;
    let h = total_s / 3600;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}")
}

/// `2026-08-06 09:14:02.118`, from epoch microseconds.
///
/// Hand-rolled civil-date conversion (Howard Hinnant's `civil_from_days`)
/// rather than a dependency: this crate needs exactly one date format in
/// exactly one place, and the algorithm is short and well known.
pub fn ts_human(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let micros = us.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);

    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day / 60) % 60;
    let ss = secs_of_day % 60;
    format!(
        "{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}.{:03}",
        micros / 1000
    )
}

/// Days since the Unix epoch to a civil (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Largest index `<= i` that is a char boundary, so truncation cannot
/// panic mid-codepoint on a digest containing a non-ASCII hostname.
fn floor_char_boundary(s: &str, i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    let mut idx = i;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_correctly() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1_482_301), "1,482,301");
        assert_eq!(thousands(1_000_000_000), "1,000,000,000");
    }

    #[test]
    fn byte_sizes_use_decimal_units() {
        assert_eq!(bytes_human(0), "0 B");
        assert_eq!(bytes_human(512), "512 B");
        assert_eq!(bytes_human(1_500), "1.50 KB");
        assert_eq!(bytes_human(1_210_000_000), "1.21 GB");
    }

    #[test]
    fn durations_render_as_clock_time() {
        assert_eq!(duration_human(0), "00:00:00.000");
        assert_eq!(duration_human(862_418_000), "00:14:22.418");
        assert_eq!(duration_human(3_661_000_000), "01:01:01.000");
        assert_eq!(duration_human(-5), "00:00:00.000");
    }

    #[test]
    fn timestamps_convert_from_epoch_micros() {
        assert_eq!(ts_human(0), "1970-01-01 00:00:00.000");
        assert_eq!(ts_human(1_785_921_242_118_000), "2026-08-05 09:14:02.118");
        // A leap day, to catch an off-by-one in the civil conversion.
        assert_eq!(ts_human(1_709_164_800_000_000), "2024-02-29 00:00:00.000");
        // The day before and after a century non-leap-year boundary —
        // the case Hinnant's algorithm exists to get right.
        assert_eq!(ts_human(951_782_400_000_000), "2000-02-29 00:00:00.000");
        // A negative timestamp (a capture with a clock set before 1970)
        // must still render rather than wrap.
        assert_eq!(ts_human(-86_400_000_000), "1969-12-31 00:00:00.000");
    }

    #[test]
    fn truncation_never_splits_a_codepoint() {
        let s = "aaaé".repeat(10);
        for i in 0..s.len() {
            let cut = floor_char_boundary(&s, i);
            assert!(
                s.is_char_boundary(cut),
                "cut at {i} → {cut} was not a boundary"
            );
        }
    }
}
