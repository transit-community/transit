//! The capture index.
//!
//! One pass over the file produces everything every later query is
//! answered from: a fixed-size record per packet, the conversation table,
//! per-protocol counters, and the application-layer statistics the digest
//! reports.
//!
//! # The memory decision
//!
//! [`PacketRecord`] is 64 bytes and holds no heap data. It stores the
//! packet's **byte offset**, so anything needing more than the indexed
//! fields — the detail tree, the bytes pane, an application-layer filter
//! — re-reads and re-dissects that one packet. The alternative, keeping
//! dissections resident, would cost hundreds of bytes per packet and put
//! a 1 GB capture out of reach on a laptop.
//!
//! Concretely: ~96 MB of index for a 1.2 GB / 1.5 M-packet capture. The
//! `max_indexed_packets` ceiling (5 M ≈ 320 MB) is the guard rail for
//! pathological files, not the expected case — and when it is hit, the
//! UI says so. A silently half-indexed capture would read as a complete
//! one, which is worse than refusing.
//!
//! # Two-tier dissection
//!
//! Every packet is dissected with [`Detail::SummaryOnly`], which
//! allocates nothing. Only packets whose summary says they carry an
//! application protocol we collect statistics for get a second,
//! [`Detail::Full`] pass. In a typical capture that is a few percent of
//! packets — bulk TCP data is the bulk of a capture and needs no second
//! look.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::ops::ControlFlow;

use crate::analysis::flow::FlowTable;
use crate::analysis::Flow;
use crate::dissect::{dissect, Detail, Dissection, FieldValue, Proto, ProtoSet, Summary};
use crate::error::Result;
use crate::reader::{CaptureFile, Interface, ScanSummary};
use crate::types::{CaptureFileMeta, IpProto, RawPacket};

// ---------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------

/// Ceilings applied while indexing. Every one of them, when hit, is
/// reported in [`LimitsHit`] and surfaced to the user and the model —
/// the "no silent caps" rule.
#[derive(Debug, Clone, Copy)]
pub struct IndexLimits {
    /// Packets indexed before we stop. 5 M ≈ 320 MB of index.
    pub max_indexed_packets: u64,
    /// Distinct conversations tracked. A scan capture can have millions.
    pub max_flows: usize,
    /// Packets given the second, full-dissection pass for app statistics.
    pub max_app_dissections: u64,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_indexed_packets: 5_000_000,
            max_flows: 500_000,
            max_app_dissections: 500_000,
        }
    }
}

/// Which ceilings a scan actually hit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitsHit {
    pub packet_cap: bool,
    pub flow_cap: bool,
    pub app_cap: bool,
}

impl LimitsHit {
    pub fn any(&self) -> bool {
        self.packet_cap || self.flow_cap || self.app_cap
    }
}

// ---------------------------------------------------------------------
// Per-packet record
// ---------------------------------------------------------------------

/// One packet's indexed fields. 64 bytes, no heap data.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketRecord {
    pub ts_us: i64,
    /// Byte offset of the packet's record in the capture file. The whole
    /// lazy-dissection design rests on this.
    pub offset: u64,
    pub protos: u64,
    pub caplen: u32,
    pub orig_len: u32,
    /// Index into [`CaptureIndex::flows`], or [`NO_FLOW`].
    pub flow_id: u32,
    /// Index into the IP dictionary, or `u32::MAX`.
    pub src_ip: u32,
    pub dst_ip: u32,
    pub payload_len: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan: u16,
    pub top: u8,
    pub tcp_flags: u8,
    pub ip_proto: u8,
    /// `ANALYSIS_*` bit flags from the TCP tracker.
    pub analysis: u8,
    pub ttl: u8,
    pub malformed: u8,
}

impl PacketRecord {
    pub fn protos(&self) -> ProtoSet {
        ProtoSet(self.protos)
    }

    pub fn has_vlan(&self) -> bool {
        self.protos().contains(Proto::Vlan)
    }
}

/// Interns IP addresses so a record stores 4 bytes instead of 17.
///
/// A capture has far fewer distinct addresses than packets — often a few
/// hundred against a few million — so this is both a large saving and
/// what makes the top-talkers roll-up a counter over small integers.
#[derive(Debug, Default)]
pub struct IpDict {
    ips: Vec<IpAddr>,
    lookup: HashMap<IpAddr, u32>,
}

impl IpDict {
    pub const NONE: u32 = u32::MAX;

    pub fn intern(&mut self, ip: IpAddr) -> u32 {
        if let Some(id) = self.lookup.get(&ip) {
            return *id;
        }
        let id = self.ips.len() as u32;
        self.ips.push(ip);
        self.lookup.insert(ip, id);
        id
    }

    pub fn get(&self, id: u32) -> Option<IpAddr> {
        self.ips.get(id as usize).copied()
    }

    pub fn len(&self) -> usize {
        self.ips.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }
}

// ---------------------------------------------------------------------
// Bounded counters
// ---------------------------------------------------------------------

/// A frequency counter with a ceiling on distinct keys.
///
/// Bounded because the keys come off the wire: a capture full of random
/// DNS names (which is what a DGA or a subdomain scan looks like) would
/// otherwise grow one map entry per packet. Past the ceiling, additional
/// distinct keys are counted in `overflow` rather than dropped silently.
#[derive(Debug, Default)]
pub struct TopCounter {
    counts: HashMap<String, u64>,
    max_keys: usize,
    pub overflow: u64,
}

impl TopCounter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            counts: HashMap::new(),
            max_keys,
            overflow: 0,
        }
    }

    pub fn add(&mut self, key: &str) {
        if let Some(c) = self.counts.get_mut(key) {
            *c += 1;
        } else if self.counts.len() < self.max_keys {
            self.counts.insert(key.to_string(), 1);
        } else {
            self.overflow += 1;
        }
    }

    /// Top `n` keys, most frequent first, ties broken by key for
    /// determinism — two runs over the same capture must agree.
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<_> = self.counts.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn distinct(&self) -> usize {
        self.counts.len()
    }
}

// ---------------------------------------------------------------------
// Application statistics
// ---------------------------------------------------------------------

/// Cap on in-flight DNS queries tracked for response matching.
const MAX_PENDING_DNS: usize = 20_000;

/// A DNS query is called unanswered if nothing came back within this.
pub const DNS_UNANSWERED_US: i64 = 2_000_000;

#[derive(Debug, Default)]
pub struct DnsStats {
    pub queries: u64,
    pub responses: u64,
    pub nxdomain: u64,
    pub servfail: u64,
    pub refused: u64,
    pub names: TopCounter,
    /// Names that got a non-zero rcode — the actionable list.
    pub failing_names: TopCounter,
    pub slowest_us: i64,
    pub total_response_us: i64,
    pub matched_responses: u64,
    /// Queries with no response inside [`DNS_UNANSWERED_US`].
    pub unanswered: u64,
    pending: HashMap<(u16, String), i64>,
}

impl DnsStats {
    pub fn mean_response_us(&self) -> Option<i64> {
        (self.matched_responses > 0).then(|| self.total_response_us / self.matched_responses as i64)
    }
}

#[derive(Debug, Default)]
pub struct TlsStats {
    pub client_hellos: u64,
    pub server_hellos: u64,
    pub alerts: u64,
    pub fatal_alerts: u64,
    pub sni: TopCounter,
    pub versions: TopCounter,
    pub alert_reasons: TopCounter,
}

#[derive(Debug, Default)]
pub struct HttpStats {
    pub requests: u64,
    pub responses: u64,
    pub status: BTreeMap<u16, u64>,
    pub hosts: TopCounter,
    pub error_uris: TopCounter,
    pub methods: TopCounter,
    /// Requests carrying a credential header. The value never appears —
    /// the dissector redacted it — but the COUNT is a real finding.
    pub authenticated_requests: u64,
}

impl HttpStats {
    pub fn errors(&self) -> u64 {
        self.status
            .iter()
            .filter(|(code, _)| **code >= 400)
            .map(|(_, n)| *n)
            .sum()
    }
}

#[derive(Debug, Default)]
pub struct IcmpStats {
    pub total: u64,
    pub echo_requests: u64,
    pub echo_replies: u64,
    pub unreachable: u64,
    pub time_exceeded: u64,
    /// Fragmentation-needed with DF — the MTU black-hole signature.
    pub frag_needed: u64,
    pub frag_needed_mtus: Vec<u16>,
    pub by_type: TopCounter,
}

#[derive(Debug, Default)]
pub struct ArpStats {
    pub requests: u64,
    pub replies: u64,
    pub gratuitous: u64,
    /// IPv4 address → the MAC addresses claiming it. More than one is a
    /// duplicate-address conflict, which is a real and commonly-missed
    /// cause of intermittent connectivity.
    pub claims: HashMap<IpAddr, HashSet<[u8; 6]>>,
}

#[derive(Debug, Default)]
pub struct DhcpStats {
    pub discovers: u64,
    pub offers: u64,
    pub requests: u64,
    pub acks: u64,
    pub naks: u64,
}

#[derive(Debug)]
pub struct AppStats {
    pub dns: DnsStats,
    pub tls: TlsStats,
    pub http: HttpStats,
    pub icmp: IcmpStats,
    pub arp: ArpStats,
    pub dhcp: DhcpStats,
}

impl Default for AppStats {
    fn default() -> Self {
        Self {
            dns: DnsStats {
                names: TopCounter::new(4096),
                failing_names: TopCounter::new(1024),
                ..Default::default()
            },
            tls: TlsStats {
                sni: TopCounter::new(4096),
                versions: TopCounter::new(16),
                alert_reasons: TopCounter::new(64),
                ..Default::default()
            },
            http: HttpStats {
                hosts: TopCounter::new(4096),
                error_uris: TopCounter::new(1024),
                methods: TopCounter::new(16),
                ..Default::default()
            },
            icmp: IcmpStats {
                by_type: TopCounter::new(64),
                ..Default::default()
            },
            arp: ArpStats::default(),
            dhcp: DhcpStats::default(),
        }
    }
}

// ---------------------------------------------------------------------
// The index
// ---------------------------------------------------------------------

/// Per-endpoint roll-up for the top-talkers table.
#[derive(Debug, Clone, Copy, Default)]
pub struct Talker {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl Talker {
    pub fn bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_recv
    }

    pub fn packets(&self) -> u64 {
        self.packets_sent + self.packets_recv
    }
}

/// Everything one pass over a capture produced.
pub struct CaptureIndex {
    pub meta: CaptureFileMeta,
    pub records: Vec<PacketRecord>,
    pub flows: Vec<Flow>,
    pub ips: IpDict,
    pub interfaces: Vec<Interface>,
    pub scan: ScanSummary,
    pub limits: IndexLimits,
    pub limits_hit: LimitsHit,
    pub stats: AppStats,
    /// Packets and wire bytes per protocol. `BTreeMap` so the digest's
    /// protocol histogram renders in a stable order.
    pub proto_counts: BTreeMap<Proto, (u64, u64)>,
    pub talkers: HashMap<u32, Talker>,
    pub first_ts: i64,
    pub last_ts: i64,
    pub total_bytes: u64,
    /// Packets whose dissection hit a problem — almost always a snaplen
    /// cutting a header, occasionally a genuinely malformed frame.
    pub malformed: u64,
    /// Packets whose capture length was shorter than their wire length.
    pub snapped: u64,
    /// Conversations dropped after the flow ceiling: (packets, bytes).
    pub flow_overflow: (u64, u64),
}

impl CaptureIndex {
    pub fn packet_count(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn duration_us(&self) -> i64 {
        (self.last_ts - self.first_ts).max(0)
    }

    /// Resolve a record's source address.
    pub fn src_ip(&self, r: &PacketRecord) -> Option<IpAddr> {
        (r.src_ip != IpDict::NONE)
            .then(|| self.ips.get(r.src_ip))
            .flatten()
    }

    pub fn dst_ip(&self, r: &PacketRecord) -> Option<IpAddr> {
        (r.dst_ip != IpDict::NONE)
            .then(|| self.ips.get(r.dst_ip))
            .flatten()
    }

    /// Top talkers by total bytes, most first.
    pub fn top_talkers(&self, n: usize) -> Vec<(IpAddr, Talker)> {
        let mut v: Vec<_> = self
            .talkers
            .iter()
            .filter_map(|(id, t)| self.ips.get(*id).map(|ip| (ip, *t)))
            .collect();
        v.sort_by(|a, b| b.1.bytes().cmp(&a.1.bytes()).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Conversations sorted by a key, most first.
    pub fn top_flows(&self, by: FlowSort, n: usize) -> Vec<&Flow> {
        let mut v: Vec<&Flow> = self.flows.iter().collect();
        match by {
            FlowSort::Bytes => v.sort_by(|a, b| b.bytes().cmp(&a.bytes()).then(a.id.cmp(&b.id))),
            FlowSort::Packets => {
                v.sort_by(|a, b| b.packets().cmp(&a.packets()).then(a.id.cmp(&b.id)))
            }
            FlowSort::Duration => {
                v.sort_by(|a, b| b.duration_us().cmp(&a.duration_us()).then(a.id.cmp(&b.id)))
            }
            FlowSort::Retransmits => {
                v.sort_by(|a, b| b.retransmits.cmp(&a.retransmits).then(a.id.cmp(&b.id)))
            }
            FlowSort::Start => v.sort_by(|a, b| a.first_ts.cmp(&b.first_ts).then(a.id.cmp(&b.id))),
        }
        v.truncate(n);
        v
    }

    /// Aggregate TCP health over every conversation.
    pub fn tcp_health(&self) -> TcpHealth {
        let mut h = TcpHealth::default();
        for f in &self.flows {
            if f.key.proto != IpProto::Tcp {
                continue;
            }
            h.flows += 1;
            h.packets += f.packets();
            h.retransmits += u64::from(f.retransmits);
            h.dup_acks += u64::from(f.dup_acks);
            h.out_of_order += u64::from(f.out_of_order);
            h.resets += u64::from(f.resets);
            h.zero_windows += u64::from(f.zero_windows);
            if f.is_refused() {
                h.refused += 1;
            }
            if f.is_unanswered() {
                h.unanswered += 1;
            }
        }
        h
    }
}

/// Sort keys for the conversations view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSort {
    Bytes,
    Packets,
    Duration,
    Retransmits,
    Start,
}

impl FlowSort {
    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "bytes" => Self::Bytes,
            "packets" => Self::Packets,
            "duration" => Self::Duration,
            "retransmits" => Self::Retransmits,
            "start" => Self::Start,
            _ => return None,
        })
    }
}

/// Capture-wide TCP health.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpHealth {
    pub flows: u64,
    pub packets: u64,
    pub retransmits: u64,
    pub dup_acks: u64,
    pub out_of_order: u64,
    pub resets: u64,
    pub zero_windows: u64,
    pub refused: u64,
    pub unanswered: u64,
}

impl TcpHealth {
    pub fn retransmit_pct(&self) -> f64 {
        if self.packets == 0 {
            return 0.0;
        }
        self.retransmits as f64 * 100.0 / self.packets as f64
    }
}

// ---------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------

/// Index a capture from the beginning.
pub fn build(file: &CaptureFile, limits: IndexLimits) -> Result<CaptureIndex> {
    let mut builder = Builder::new(file.meta.clone(), limits);
    let mut scanner = file.scanner()?;
    let summary = scanner.for_each(|p| builder.observe(p));
    builder.finish(summary, scanner.interfaces.clone())
}

/// Incremental state for one indexing pass.
struct Builder {
    idx: CaptureIndex,
    flows: FlowTable,
    app_dissections: u64,
}

impl Builder {
    fn new(meta: CaptureFileMeta, limits: IndexLimits) -> Self {
        Self {
            idx: CaptureIndex {
                meta,
                records: Vec::new(),
                flows: Vec::new(),
                ips: IpDict::default(),
                interfaces: Vec::new(),
                scan: ScanSummary::default(),
                limits,
                limits_hit: LimitsHit::default(),
                stats: AppStats::default(),
                proto_counts: BTreeMap::new(),
                talkers: HashMap::new(),
                first_ts: i64::MAX,
                last_ts: i64::MIN,
                total_bytes: 0,
                malformed: 0,
                snapped: 0,
                flow_overflow: (0, 0),
            },
            flows: FlowTable::new(limits.max_flows),
            app_dissections: 0,
        }
    }

    fn observe(&mut self, p: &RawPacket<'_>) -> ControlFlow<()> {
        if self.idx.records.len() as u64 >= self.idx.limits.max_indexed_packets {
            self.idx.limits_hit.packet_cap = true;
            return ControlFlow::Break(());
        }

        let d = dissect(p, Detail::SummaryOnly);
        let s = &d.summary;

        self.idx.first_ts = self.idx.first_ts.min(p.ts_us);
        self.idx.last_ts = self.idx.last_ts.max(p.ts_us);
        self.idx.total_bytes += u64::from(p.orig_len);
        if s.malformed {
            self.idx.malformed += 1;
        }
        if p.is_snapped() {
            self.idx.snapped += 1;
        }

        for proto in s.protos.iter() {
            let e = self.idx.proto_counts.entry(proto).or_insert((0, 0));
            e.0 += 1;
            e.1 += u64::from(p.orig_len);
        }

        let src_id = s
            .src_ip
            .map(|ip| self.idx.ips.intern(ip))
            .unwrap_or(IpDict::NONE);
        let dst_id = s
            .dst_ip
            .map(|ip| self.idx.ips.intern(ip))
            .unwrap_or(IpDict::NONE);
        if src_id != IpDict::NONE {
            let t = self.idx.talkers.entry(src_id).or_default();
            t.packets_sent += 1;
            t.bytes_sent += u64::from(p.orig_len);
        }
        if dst_id != IpDict::NONE {
            let t = self.idx.talkers.entry(dst_id).or_default();
            t.packets_recv += 1;
            t.bytes_recv += u64::from(p.orig_len);
        }

        let (flow_id, analysis) = self.flows.observe(s, p.ts_us, p.orig_len);

        self.idx.records.push(PacketRecord {
            ts_us: p.ts_us,
            offset: p.offset,
            protos: s.protos.0,
            caplen: p.caplen,
            orig_len: p.orig_len,
            flow_id,
            src_ip: src_id,
            dst_ip: dst_id,
            payload_len: s.payload_len,
            src_port: s.src_port.unwrap_or(0),
            dst_port: s.dst_port.unwrap_or(0),
            vlan: s.vlan.unwrap_or(0),
            top: s.top as u8,
            tcp_flags: s.tcp_flags,
            ip_proto: s.ip_proto.map(ip_proto_u8).unwrap_or(0),
            analysis,
            ttl: s.ttl.unwrap_or(0),
            malformed: u8::from(s.malformed),
        });

        // Second tier: only packets carrying an application protocol we
        // report on get a full dissection.
        if needs_app_pass(s) {
            if self.app_dissections < self.idx.limits.max_app_dissections {
                self.app_dissections += 1;
                let full = dissect(p, Detail::Full);
                collect_app_stats(&mut self.idx.stats, &full, p.ts_us);
            } else {
                self.idx.limits_hit.app_cap = true;
            }
        }

        ControlFlow::Continue(())
    }

    fn finish(mut self, scan: ScanSummary, interfaces: Vec<Interface>) -> Result<CaptureIndex> {
        self.idx.scan = scan;
        self.idx.interfaces = interfaces;
        self.idx.flow_overflow = self.flows.overflow();
        self.idx.limits_hit.flow_cap = self.idx.flow_overflow.0 > 0;
        self.idx.flows = self.flows.into_flows();

        // Queries still pending at end-of-capture never got an answer.
        // Counting them is the whole point of tracking them: "12 DNS
        // queries went unanswered" is a finding, and its absence would
        // make a broken resolver look healthy.
        self.idx.stats.dns.unanswered = self.idx.stats.dns.pending.len() as u64;
        self.idx.stats.dns.pending.clear();

        if self.idx.records.is_empty() {
            self.idx.first_ts = 0;
            self.idx.last_ts = 0;
        }
        Ok(self.idx)
    }
}

/// Is this packet worth a second, full-dissection pass?
fn needs_app_pass(s: &Summary) -> bool {
    const WANTED: [Proto; 7] = [
        Proto::Dns,
        Proto::Mdns,
        Proto::Tls,
        Proto::Http,
        Proto::Icmp,
        Proto::Arp,
        Proto::Dhcp,
    ];
    WANTED.iter().any(|p| s.protos.contains(*p))
}

fn ip_proto_u8(p: IpProto) -> u8 {
    match p {
        IpProto::Icmp => 1,
        IpProto::Igmp => 2,
        IpProto::Tcp => 6,
        IpProto::Udp => 17,
        IpProto::Gre => 47,
        IpProto::Esp => 50,
        IpProto::Ah => 51,
        IpProto::Ipv6Icmp => 58,
        IpProto::Ospf => 89,
        IpProto::Vrrp => 112,
        IpProto::Sctp => 132,
        IpProto::Other(n) => n,
    }
}

/// Roll one fully-dissected packet into the application statistics.
fn collect_app_stats(stats: &mut AppStats, d: &Dissection, ts_us: i64) {
    let str_field = |name: &str| -> Option<String> {
        match d.field(name) {
            Some(FieldValue::Str(s)) => Some(s.clone()),
            _ => None,
        }
    };
    let u64_field = |name: &str| -> Option<u64> {
        match d.field(name) {
            Some(FieldValue::U64(v)) => Some(*v),
            _ => None,
        }
    };
    let bool_field = |name: &str| -> Option<bool> {
        match d.field(name) {
            Some(FieldValue::Bool(v)) => Some(*v),
            _ => None,
        }
    };

    // DNS ----------------------------------------------------------
    //
    // UNICAST DNS ONLY. mDNS is the same wire format and the same parser,
    // so it emits `dns.id` too — but rolling it in here makes every DNS
    // statistic wrong in the same direction. A multicast query with no
    // answer means "nobody on this segment offers that service", which is
    // the protocol working; a unicast query with no answer means the
    // resolver is broken. Counting them together produced a HIGH finding
    // reading "the resolver is unreachable or dropping requests" on an
    // ordinary laptop capture, where mDNS chatter is constant and mostly
    // unanswered by design — a false positive on the most severe rung,
    // and its "show me" filter (`dns and …`) then matched nothing at all,
    // because `dns` and `mdns` are distinct protocol atoms.
    //
    // That mismatch was the tell, and it is the useful kind: the finding
    // and its own evidence filter disagreed about what DNS means.
    if d.summary.protos.contains(Proto::Mdns) {
        // Counted in the protocol breakdown, filterable as `mdns`, and
        // deliberately absent from resolver health.
    } else if let Some(id) = u64_field("dns.id") {
        let is_response = bool_field("dns.flags.response").unwrap_or(false);
        let name = str_field("dns.qry.name").unwrap_or_default();
        let rcode = u64_field("dns.rcode").unwrap_or(0);
        let key = (id as u16, name.clone());

        if is_response {
            stats.dns.responses += 1;
            match rcode {
                3 => stats.dns.nxdomain += 1,
                2 => stats.dns.servfail += 1,
                5 => stats.dns.refused += 1,
                _ => {}
            }
            if rcode != 0 && !name.is_empty() {
                stats.dns.failing_names.add(&name);
            }
            if let Some(sent) = stats.dns.pending.remove(&key) {
                let rtt = (ts_us - sent).max(0);
                stats.dns.total_response_us += rtt;
                stats.dns.matched_responses += 1;
                stats.dns.slowest_us = stats.dns.slowest_us.max(rtt);
            }
        } else {
            stats.dns.queries += 1;
            if !name.is_empty() {
                stats.dns.names.add(&name);
            }
            if stats.dns.pending.len() < MAX_PENDING_DNS {
                stats.dns.pending.insert(key, ts_us);
            }
        }
    }

    // TLS ----------------------------------------------------------
    if let Some(hs) = u64_field("tls.handshake.type") {
        match hs {
            1 => {
                stats.tls.client_hellos += 1;
                if let Some(sni) = str_field("tls.handshake.extensions_server_name") {
                    stats.tls.sni.add(&sni);
                }
            }
            2 => stats.tls.server_hellos += 1,
            _ => {}
        }
    }
    if let Some(v) = str_field("tls.record.version.name") {
        stats.tls.versions.add(&v);
    }
    if let Some(level) = u64_field("tls.alert.level") {
        stats.tls.alerts += 1;
        if level == 2 {
            stats.tls.fatal_alerts += 1;
        }
        if let Some(reason) = str_field("tls.alert.description.name") {
            stats.tls.alert_reasons.add(&reason);
        }
    }

    // HTTP ---------------------------------------------------------
    if let Some(method) = str_field("http.request.method") {
        stats.http.requests += 1;
        stats.http.methods.add(&method);
        if let Some(host) = str_field("http.host") {
            stats.http.hosts.add(&host);
        }
        // The credential VALUE was already refused by the dissector; the
        // count of authenticated requests is safe and useful.
        if d.field("http.authorization").is_some() || d.field("http.cookie").is_some() {
            stats.http.authenticated_requests += 1;
        }
    }
    if let Some(code) = u64_field("http.response.code") {
        stats.http.responses += 1;
        let code = code.min(u64::from(u16::MAX)) as u16;
        *stats.http.status.entry(code).or_insert(0) += 1;
    }

    // ICMP ---------------------------------------------------------
    if let Some(ty) = u64_field("icmp.type") {
        let code = u64_field("icmp.code").unwrap_or(0);
        stats.icmp.total += 1;
        stats.icmp.by_type.add(&format!("type {ty} code {code}"));
        match ty {
            0 => stats.icmp.echo_replies += 1,
            8 => stats.icmp.echo_requests += 1,
            3 => {
                stats.icmp.unreachable += 1;
                if code == 4 {
                    stats.icmp.frag_needed += 1;
                    if let Some(mtu) = u64_field("icmp.mtu") {
                        let mtu = mtu.min(u64::from(u16::MAX)) as u16;
                        if !stats.icmp.frag_needed_mtus.contains(&mtu) {
                            stats.icmp.frag_needed_mtus.push(mtu);
                        }
                    }
                }
            }
            11 => stats.icmp.time_exceeded += 1,
            _ => {}
        }
    }

    // ARP ----------------------------------------------------------
    if let Some(op) = u64_field("arp.opcode") {
        match op {
            1 => stats.arp.requests += 1,
            2 => stats.arp.replies += 1,
            _ => {}
        }
        if bool_field("arp.isgratuitous").unwrap_or(false) {
            stats.arp.gratuitous += 1;
        }
        // Duplicate-address detection: remember which MACs claim an IP.
        if let (Some(FieldValue::Ip(ip)), Some(FieldValue::Mac(mac))) =
            (d.field("arp.src.proto_ipv4"), d.field("arp.src.hw_mac"))
        {
            // Bounded: a scan sweeping a /16 would otherwise create a
            // map entry per probed address.
            if stats.arp.claims.len() < 65_536 {
                stats.arp.claims.entry(*ip).or_default().insert(*mac);
            }
        }
    }

    // DHCP ---------------------------------------------------------
    if let Some(t) = u64_field("dhcp.type") {
        match t {
            1 => stats.dhcp.discovers += 1,
            2 => stats.dhcp.offers += 1,
            3 => stats.dhcp.requests += 1,
            5 => stats.dhcp.acks += 1,
            6 => stats.dhcp.naks += 1,
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
