//! Flow (conversation) table and TCP health tracking.
//!
//! # Why flows are the unit that matters
//!
//! A 1.2 GB capture is ~1.5 M packets and maybe 4,000 conversations, of
//! which the top fifty carry ~90% of the bytes. Every question a capture
//! is opened to answer — who is talking, what is slow, what is
//! retransmitting — is a question about conversations, not packets. So
//! the flow table is both the analyst's main view and the single largest
//! source of compression for the assistant: fifty rows instead of a
//! million.
//!
//! # Direction normalization
//!
//! A flow key is stored with its endpoints sorted, so `A→B` and `B→A`
//! land in the same flow, and per-direction counters keep the asymmetry.
//! Without that, every conversation would appear twice and every
//! byte-total would be half right.
//!
//! # TCP analysis
//!
//! Retransmissions, duplicate ACKs, zero windows, out-of-order segments
//! and round-trip time are computed here, in one pass, from bounded
//! per-direction state. These are the numbers the findings rules and the
//! digest are built on, and they are *computed* rather than inferred —
//! deterministic, exact, and free at query time.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::dissect::{Summary, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};
use crate::types::IpProto;

/// Sentinel for "this packet belongs to no flow" (ARP, STP, and anything
/// without an IP pair).
pub const NO_FLOW: u32 = u32::MAX;

/// Per-flow RTT samples kept for the percentile calculation. A bulk
/// transfer offers hundreds of thousands; a few hundred is plenty for a
/// p50/p95 and keeps a flow's footprint fixed.
const MAX_RTT_SAMPLES: usize = 256;

/// Unacknowledged segments tracked per direction for RTT matching.
const MAX_PENDING_ACKS: usize = 64;

/// Endpoints of a conversation, normalized so either direction maps here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub proto: IpProto,
}

impl FlowKey {
    /// Build a normalized key, returning it plus whether the packet that
    /// produced it runs A→B (`true`) or B→A (`false`).
    pub fn normalized(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        proto: IpProto,
    ) -> (Self, bool) {
        // Sort on (ip, port) so the choice of "A" is stable regardless of
        // which direction's packet arrived first.
        let forward = (src_ip, src_port) <= (dst_ip, dst_port);
        let key = if forward {
            Self {
                a_ip: src_ip,
                b_ip: dst_ip,
                a_port: src_port,
                b_port: dst_port,
                proto,
            }
        } else {
            Self {
                a_ip: dst_ip,
                b_ip: src_ip,
                a_port: dst_port,
                b_port: src_port,
                proto,
            }
        };
        (key, forward)
    }

    /// `10.0.0.1:52344 → 93.184.216.34:443` style rendering.
    pub fn render(&self) -> String {
        if self.a_port == 0 && self.b_port == 0 {
            format!("{} ↔ {}", self.a_ip, self.b_ip)
        } else {
            format!(
                "{}:{} ↔ {}:{}",
                self.a_ip, self.a_port, self.b_ip, self.b_port
            )
        }
    }
}

/// One conversation, with per-direction counters and TCP health.
#[derive(Debug, Clone)]
pub struct Flow {
    pub id: u32,
    pub key: FlowKey,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub first_ts: i64,
    pub last_ts: i64,

    pub retransmits: u32,
    pub dup_acks: u32,
    pub out_of_order: u32,
    pub resets: u32,
    pub zero_windows: u32,
    /// Longest stretch, in microseconds, during which one side advertised
    /// a zero window. This is the number that turns "there were some zero
    /// windows" into "the receiver stalled the sender for 3.2 seconds".
    pub max_zero_window_us: i64,

    pub syn_seen: bool,
    pub syn_ack_seen: bool,
    pub fin_seen: bool,
    /// SYN → SYN/ACK, the cleanest RTT a capture offers.
    pub handshake_rtt_us: Option<i64>,

    rtt_samples: Vec<i64>,
    dirs: [DirState; 2],
}

impl Flow {
    pub fn packets(&self) -> u64 {
        self.packets_ab + self.packets_ba
    }

    pub fn bytes(&self) -> u64 {
        self.bytes_ab + self.bytes_ba
    }

    pub fn duration_us(&self) -> i64 {
        (self.last_ts - self.first_ts).max(0)
    }

    /// Retransmission rate as a percentage of this flow's packets.
    pub fn retransmit_pct(&self) -> f64 {
        let total = self.packets();
        if total == 0 {
            return 0.0;
        }
        f64::from(self.retransmits) * 100.0 / total as f64
    }

    /// Round-trip percentile in microseconds, or `None` with no samples.
    pub fn rtt_percentile(&self, pct: f64) -> Option<i64> {
        if self.rtt_samples.is_empty() {
            return None;
        }
        let mut sorted = self.rtt_samples.clone();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
        sorted.get(idx).copied()
    }

    /// A connection that was attempted and refused: SYN went out, a RST
    /// came back, and no SYN/ACK ever did.
    pub fn is_refused(&self) -> bool {
        self.syn_seen && !self.syn_ack_seen && self.resets > 0
    }

    /// A connection that was attempted and never answered at all.
    pub fn is_unanswered(&self) -> bool {
        self.syn_seen && !self.syn_ack_seen && self.resets == 0 && self.packets_ba == 0
    }
}

/// Per-direction TCP state, all of it bounded.
#[derive(Debug, Clone, Default)]
struct DirState {
    /// Highest `seq + payload_len` seen, i.e. how far this side has sent.
    max_seq_end: u32,
    seen_any: bool,
    last_ack: u32,
    dup_ack_run: u32,
    /// Segments sent but not yet acknowledged: `(seq_end, ts)`.
    pending: Vec<(u32, i64)>,
    /// Timestamp of the first zero-window advertisement in the current
    /// stall, if one is open.
    zero_window_since: Option<i64>,
}

/// Builds the flow table over a scan.
pub struct FlowTable {
    flows: Vec<Flow>,
    lookup: HashMap<FlowKey, u32>,
    /// Ceiling on distinct flows. A scan/DDoS capture can have millions
    /// of one-packet "conversations"; past this we stop creating new
    /// flows and count what we dropped rather than growing without bound.
    max_flows: usize,
    overflow_packets: u64,
    overflow_bytes: u64,
}

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        Self {
            flows: Vec::new(),
            lookup: HashMap::new(),
            max_flows,
            overflow_packets: 0,
            overflow_bytes: 0,
        }
    }

    pub fn flows(&self) -> &[Flow] {
        &self.flows
    }

    pub fn into_flows(self) -> Vec<Flow> {
        self.flows
    }

    /// Packets that arrived after the flow ceiling was hit. Non-zero here
    /// is reported to the user — a silently partial conversation table
    /// would read as "that is all the traffic there was".
    pub fn overflow(&self) -> (u64, u64) {
        (self.overflow_packets, self.overflow_bytes)
    }

    /// Record one packet.
    ///
    /// Returns the flow id (or [`NO_FLOW`]) and the per-packet analysis
    /// flags the index stores, so a filter like
    /// `tcp.analysis.retransmission` answers from the index alone rather
    /// than re-deriving state that only exists during the scan.
    pub fn observe(&mut self, s: &Summary, ts_us: i64, wire_len: u32) -> (u32, u8) {
        let (Some(src_ip), Some(dst_ip)) = (s.src_ip, s.dst_ip) else {
            return (NO_FLOW, 0);
        };
        let proto = s.ip_proto.unwrap_or(IpProto::Other(0));
        let (key, forward) = FlowKey::normalized(
            src_ip,
            dst_ip,
            s.src_port.unwrap_or(0),
            s.dst_port.unwrap_or(0),
            proto,
        );

        let id = match self.lookup.get(&key) {
            Some(id) => *id,
            None => {
                if self.flows.len() >= self.max_flows {
                    self.overflow_packets += 1;
                    self.overflow_bytes += u64::from(wire_len);
                    return (NO_FLOW, 0);
                }
                let id = self.flows.len() as u32;
                self.flows.push(Flow {
                    id,
                    key,
                    packets_ab: 0,
                    packets_ba: 0,
                    bytes_ab: 0,
                    bytes_ba: 0,
                    first_ts: ts_us,
                    last_ts: ts_us,
                    retransmits: 0,
                    dup_acks: 0,
                    out_of_order: 0,
                    resets: 0,
                    zero_windows: 0,
                    max_zero_window_us: 0,
                    syn_seen: false,
                    syn_ack_seen: false,
                    fin_seen: false,
                    handshake_rtt_us: None,
                    rtt_samples: Vec::new(),
                    dirs: [DirState::default(), DirState::default()],
                });
                self.lookup.insert(key, id);
                id
            }
        };

        let flow = &mut self.flows[id as usize];
        if forward {
            flow.packets_ab += 1;
            flow.bytes_ab += u64::from(wire_len);
        } else {
            flow.packets_ba += 1;
            flow.bytes_ba += u64::from(wire_len);
        }
        flow.first_ts = flow.first_ts.min(ts_us);
        flow.last_ts = flow.last_ts.max(ts_us);

        let flags = if proto == IpProto::Tcp {
            tcp_observe(flow, s, ts_us, forward)
        } else {
            0
        };
        (id, flags)
    }
}

/// Analysis flags stored per packet in the index, so a filter like
/// `tcp.analysis.retransmission` answers from the index alone.
pub const ANALYSIS_RETRANSMIT: u8 = 0x01;
pub const ANALYSIS_DUP_ACK: u8 = 0x02;
pub const ANALYSIS_OUT_OF_ORDER: u8 = 0x04;
pub const ANALYSIS_ZERO_WINDOW: u8 = 0x08;
pub const ANALYSIS_RESET: u8 = 0x10;

/// TCP health for one packet. Returns the analysis flags to store on the
/// packet's index record.
///
/// The heuristics are the standard ones and are deliberately
/// conservative — a false "retransmission" inflates the number an
/// engineer is about to make a decision on.
fn tcp_observe(flow: &mut Flow, s: &Summary, ts_us: i64, forward: bool) -> u8 {
    let dir = usize::from(!forward);
    let mut flags = 0u8;

    let syn = s.tcp_flags & TCP_SYN != 0;
    let ack = s.tcp_flags & TCP_ACK != 0;
    let rst = s.tcp_flags & TCP_RST != 0;
    let fin = s.tcp_flags & TCP_FIN != 0;
    let len = s.payload_len;
    let seq = s.tcp_seq;
    let seq_end = seq.wrapping_add(len);

    if syn && !ack {
        flow.syn_seen = true;
        flow.dirs[dir].pending.push((seq.wrapping_add(1), ts_us));
    }
    if syn && ack && !flow.syn_ack_seen {
        {
            flow.syn_ack_seen = true;
            // The handshake RTT: the SYN we recorded on the other side,
            // answered here.
            if let Some((_, syn_ts)) = flow.dirs[1 - dir].pending.first().copied() {
                flow.handshake_rtt_us = Some((ts_us - syn_ts).max(0));
            }
        }
    }
    if rst {
        flow.resets += 1;
        flags |= ANALYSIS_RESET;
    }
    if fin {
        flow.fin_seen = true;
    }

    // Zero window: a receiver telling the sender to stop. Only meaningful
    // on a live connection, so RST/FIN are excluded.
    if s.tcp_window == 0 && !rst && !syn && !fin {
        flow.zero_windows += 1;
        flags |= ANALYSIS_ZERO_WINDOW;
        let since = *flow.dirs[dir].zero_window_since.get_or_insert(ts_us);
        flow.max_zero_window_us = flow.max_zero_window_us.max(ts_us - since);
    } else if s.tcp_window > 0 {
        flow.dirs[dir].zero_window_since = None;
    }

    if len > 0 {
        let d = &mut flow.dirs[dir];
        if d.seen_any {
            // Sequence-space comparison must be wrapping-aware: a long
            // connection wraps the 32-bit space, and a naive `<` would
            // then call every subsequent segment a retransmission.
            let delta = seq_end.wrapping_sub(d.max_seq_end) as i32;
            if delta <= 0 {
                // We have already sent this far — the bytes are a repeat.
                flow.retransmits += 1;
                flags |= ANALYSIS_RETRANSMIT;
            } else if seq.wrapping_sub(d.max_seq_end) as i32 > 0 {
                // A gap: this segment starts beyond where we had got to,
                // so something in between is missing or reordered.
                flow.out_of_order += 1;
                flags |= ANALYSIS_OUT_OF_ORDER;
            }
        }
        if (seq_end.wrapping_sub(d.max_seq_end) as i32) > 0 || !d.seen_any {
            d.max_seq_end = seq_end;
        }
        d.seen_any = true;
        if d.pending.len() < MAX_PENDING_ACKS {
            d.pending.push((seq_end, ts_us));
        }
    }

    if ack {
        // Duplicate ACK: same ack number, carrying no data, on a
        // connection where the peer has sent something. Three in a row is
        // the classic fast-retransmit trigger.
        {
            let peer_has_sent = flow.dirs[1 - dir].seen_any;
            let d = &mut flow.dirs[dir];
            let is_bare_ack = len == 0 && !syn && !fin && !rst;
            let repeats_last = d.last_ack == s.tcp_ack;
            if is_bare_ack {
                if repeats_last && peer_has_sent {
                    d.dup_ack_run += 1;
                    flags |= ANALYSIS_DUP_ACK;
                } else {
                    d.dup_ack_run = 0;
                }
            }
            d.last_ack = s.tcp_ack;
            if flags & ANALYSIS_DUP_ACK != 0 {
                flow.dup_acks += 1;
            }
        }

        // RTT: this ACK covers segments the peer sent. Match the newest
        // fully-covered one and retire everything it acknowledges.
        let peer = &mut flow.dirs[1 - dir];
        let ack_num = s.tcp_ack;
        let mut sample = None;
        peer.pending.retain(|(seq_end, sent_ts)| {
            if (ack_num.wrapping_sub(*seq_end) as i32) >= 0 {
                sample = Some((ts_us - *sent_ts).max(0));
                false
            } else {
                true
            }
        });
        if let Some(rtt) = sample {
            if flow.rtt_samples.len() < MAX_RTT_SAMPLES {
                flow.rtt_samples.push(rtt);
            }
        }
    }

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
    }

    fn tcp_summary(src: u8, dst: u8, sport: u16, dport: u16, flags: u8) -> Summary {
        Summary {
            src_ip: Some(ip(src)),
            dst_ip: Some(ip(dst)),
            src_port: Some(sport),
            dst_port: Some(dport),
            ip_proto: Some(IpProto::Tcp),
            tcp_flags: flags,
            tcp_window: 8192,
            ..Default::default()
        }
    }

    #[test]
    fn both_directions_land_in_one_flow() {
        let mut t = FlowTable::new(1000);
        let (a, _) = t.observe(&tcp_summary(1, 2, 4000, 80, TCP_SYN), 0, 74);
        let (b, _) = t.observe(&tcp_summary(2, 1, 80, 4000, TCP_SYN | TCP_ACK), 1000, 74);
        assert_eq!(a, b, "A→B and B→A must be the same conversation");
        assert_eq!(t.flows().len(), 1);
        let f = &t.flows()[0];
        assert_eq!(f.packets_ab, 1);
        assert_eq!(f.packets_ba, 1);
        assert_eq!(f.bytes(), 148);
    }

    #[test]
    fn the_handshake_rtt_is_the_syn_to_syn_ack_gap() {
        let mut t = FlowTable::new(10);
        t.observe(&tcp_summary(1, 2, 4000, 80, TCP_SYN), 0, 74);
        t.observe(&tcp_summary(2, 1, 80, 4000, TCP_SYN | TCP_ACK), 11_200, 74);
        assert_eq!(t.flows()[0].handshake_rtt_us, Some(11_200));
        assert!(t.flows()[0].syn_ack_seen);
    }

    #[test]
    fn a_repeated_segment_counts_as_a_retransmission() {
        let mut t = FlowTable::new(10);
        let mut s = tcp_summary(1, 2, 4000, 80, TCP_ACK);
        s.tcp_seq = 1000;
        s.payload_len = 100;
        t.observe(&s, 0, 154);
        // The same bytes again.
        t.observe(&s, 200_000, 154);
        assert_eq!(t.flows()[0].retransmits, 1);
        assert_eq!(t.flows()[0].out_of_order, 0);
    }

    #[test]
    fn a_forward_gap_counts_as_out_of_order_not_retransmission() {
        let mut t = FlowTable::new(10);
        let mut s = tcp_summary(1, 2, 4000, 80, TCP_ACK);
        s.tcp_seq = 1000;
        s.payload_len = 100;
        t.observe(&s, 0, 154);
        // Jump forward past a missing segment.
        s.tcp_seq = 1500;
        t.observe(&s, 1000, 154);
        assert_eq!(t.flows()[0].out_of_order, 1);
        assert_eq!(t.flows()[0].retransmits, 0);
    }

    /// A long-lived connection wraps the 32-bit sequence space. A naive
    /// `<` comparison would then call every segment after the wrap a
    /// retransmission and report a 100% retransmit rate on a healthy
    /// transfer.
    #[test]
    fn sequence_wraparound_is_not_a_retransmission_storm() {
        let mut t = FlowTable::new(10);
        let mut s = tcp_summary(1, 2, 4000, 80, TCP_ACK);
        s.payload_len = 100;
        s.tcp_seq = u32::MAX - 50;
        t.observe(&s, 0, 154);
        // Wraps past zero.
        s.tcp_seq = s.tcp_seq.wrapping_add(100);
        t.observe(&s, 1000, 154);
        s.tcp_seq = s.tcp_seq.wrapping_add(100);
        t.observe(&s, 2000, 154);
        assert_eq!(
            t.flows()[0].retransmits,
            0,
            "wrapped sequence numbers must not read as repeats"
        );
    }

    #[test]
    fn duplicate_acks_are_counted() {
        let mut t = FlowTable::new(10);
        let mut data = tcp_summary(1, 2, 4000, 80, TCP_ACK);
        data.tcp_seq = 1000;
        data.payload_len = 100;
        t.observe(&data, 0, 154);

        let mut a = tcp_summary(2, 1, 80, 4000, TCP_ACK);
        a.tcp_ack = 1100;
        t.observe(&a, 1000, 54);
        t.observe(&a, 2000, 54);
        t.observe(&a, 3000, 54);
        assert_eq!(t.flows()[0].dup_acks, 2, "the first ACK is not a duplicate");
    }

    #[test]
    fn a_zero_window_stall_records_its_duration() {
        let mut t = FlowTable::new(10);
        let mut s = tcp_summary(2, 1, 80, 4000, TCP_ACK);
        s.tcp_window = 0;
        t.observe(&s, 1_000_000, 54);
        t.observe(&s, 4_200_000, 54);
        let f = &t.flows()[0];
        assert_eq!(f.zero_windows, 2);
        assert_eq!(
            f.max_zero_window_us, 3_200_000,
            "the stall duration is what makes this actionable"
        );
    }

    #[test]
    fn a_refused_connection_is_distinguishable_from_an_unanswered_one() {
        let mut t = FlowTable::new(10);
        t.observe(&tcp_summary(1, 2, 4000, 80, TCP_SYN), 0, 74);
        t.observe(&tcp_summary(2, 1, 80, 4000, TCP_RST | TCP_ACK), 500, 54);
        assert!(t.flows()[0].is_refused());
        assert!(!t.flows()[0].is_unanswered());

        let mut t2 = FlowTable::new(10);
        t2.observe(&tcp_summary(1, 2, 4001, 80, TCP_SYN), 0, 74);
        assert!(t2.flows()[0].is_unanswered());
        assert!(!t2.flows()[0].is_refused());
    }

    #[test]
    fn rtt_percentiles_come_from_acknowledged_segments() {
        let mut t = FlowTable::new(10);
        let mut data = tcp_summary(1, 2, 4000, 80, TCP_ACK);
        data.payload_len = 100;
        for i in 0..5u32 {
            data.tcp_seq = 1000 + i * 100;
            t.observe(&data, i64::from(i) * 100_000, 154);
            let mut a = tcp_summary(2, 1, 80, 4000, TCP_ACK);
            a.tcp_ack = 1100 + i * 100;
            t.observe(&a, i64::from(i) * 100_000 + 10_000, 54);
        }
        let p50 = t.flows()[0].rtt_percentile(0.5).unwrap();
        assert_eq!(p50, 10_000, "each ACK came 10 ms after its data");
    }

    #[test]
    fn the_flow_ceiling_counts_what_it_drops() {
        let mut t = FlowTable::new(2);
        t.observe(&tcp_summary(1, 2, 1, 80, TCP_SYN), 0, 100);
        t.observe(&tcp_summary(1, 3, 2, 80, TCP_SYN), 0, 100);
        // Third distinct conversation: refused, and counted.
        let (id, _) = t.observe(&tcp_summary(1, 4, 3, 80, TCP_SYN), 0, 100);
        assert_eq!(id, NO_FLOW);
        assert_eq!(t.flows().len(), 2);
        assert_eq!(t.overflow(), (1, 100), "dropped traffic must be reported");
    }

    #[test]
    fn a_packet_with_no_ip_pair_belongs_to_no_flow() {
        let mut t = FlowTable::new(10);
        assert_eq!(t.observe(&Summary::default(), 0, 60).0, NO_FLOW);
        assert!(t.flows().is_empty());
    }

    #[test]
    fn flow_keys_render_readably() {
        let (k, forward) = FlowKey::normalized(ip(1), ip(2), 52344, 443, IpProto::Tcp);
        assert!(forward);
        assert_eq!(k.render(), "10.0.0.1:52344 ↔ 10.0.0.2:443");

        let (k2, forward2) = FlowKey::normalized(ip(2), ip(1), 443, 52344, IpProto::Tcp);
        assert!(!forward2);
        assert_eq!(k, k2, "normalization must be direction-independent");
    }
}
