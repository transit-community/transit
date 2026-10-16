//! Field registry and filter evaluation.
//!
//! # Two evaluation paths, and why
//!
//! Some fields live in the 64-byte index record; the rest need the packet
//! re-read and re-dissected. A filter that touches only indexed fields
//! (`ip.src`, `tcp.port`, `tcp.flags.syn`, protocol presence) is answered
//! by scanning memory — microseconds per thousand packets. A filter
//! reaching an application field (`dns.qry.name`, `tls.handshake…`) has to
//! visit the file.
//!
//! [`Filter::needs_dissection`] is decided once at compile time from the
//! fields the expression actually names, so the caller can show a progress
//! indicator for the slow path and skip it entirely for the fast one. The
//! alternative — always dissecting — would make `tcp.port == 443` on a
//! million packets take seconds instead of milliseconds.
//!
//! # Unknown fields are refused, not ignored
//!
//! A filter naming a field that does not exist is an error with a
//! suggestion, never a silent "matches nothing". A typo that quietly
//! returns an empty packet list reads as "there is no such traffic",
//! which is exactly the wrong conclusion to hand an engineer.

use std::net::IpAddr;

use super::parse::{CmpOp, Expr, FilterError, Value};
use crate::analysis::flow::{
    ANALYSIS_DUP_ACK, ANALYSIS_OUT_OF_ORDER, ANALYSIS_RETRANSMIT, ANALYSIS_ZERO_WINDOW,
};
use crate::dissect::{
    Dissection, FieldValue, Proto, TCP_ACK, TCP_CWR, TCP_ECE, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
    TCP_URG,
};
use crate::index::{CaptureIndex, PacketRecord};

/// Where a field's value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Answerable from the index record alone — the fast path.
    Index,
    /// Requires re-reading and re-dissecting the packet.
    Dissect,
}

/// One entry in the field registry: the name an engineer types, where its
/// value comes from, and a one-line description for the filter bar's
/// completion list.
pub struct FieldSpec {
    pub name: &'static str,
    pub description: &'static str,
    source: Source,
    /// A boolean field. Written bare — `tcp.analysis.retransmission`,
    /// `arp.isgratuitous` — it means "this is TRUE", not merely "this
    /// field exists".
    ///
    /// The distinction is not pedantic. Without it, bare
    /// `tcp.analysis.retransmission` resolves on every TCP packet (the
    /// field is always computed, its value is usually `0`) and selects
    /// the whole conversation instead of the retransmissions — an answer
    /// that looks plausible and is completely wrong.
    flag: bool,
}

/// Every field a filter may name.
///
/// Names are derived from the RFCs that define the protocols. Fields not
/// listed here but produced by a dissector are still filterable — the
/// evaluator falls through to the dissection's own field tree — but only
/// the ones here are offered as completions and answerable from the index.
pub const REGISTRY: &[FieldSpec] = &[
    // Frame ------------------------------------------------------------
    FieldSpec {
        name: "frame.number",
        description: "Packet number in the capture",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.len",
        description: "Bytes on the wire",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.cap_len",
        description: "Bytes actually captured",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.time_epoch",
        description: "Capture time, microseconds since the epoch",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.time_relative",
        description: "Microseconds since the first packet",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.time_delta",
        description: "Microseconds since the previous packet",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "frame.snapped",
        description: "The capture snaplen truncated this packet",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "frame.malformed",
        description: "A layer could not be dissected",
        source: Source::Index,
        flag: true,
    },
    // Ethernet / VLAN ---------------------------------------------------
    FieldSpec {
        name: "eth.src",
        description: "Source MAC address",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "eth.dst",
        description: "Destination MAC address",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "eth.addr",
        description: "Either MAC address",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "eth.type",
        description: "EtherType",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "vlan.id",
        description: "802.1Q VLAN identifier",
        source: Source::Index,
        flag: false,
    },
    // IP -----------------------------------------------------------------
    FieldSpec {
        name: "ip.src",
        description: "Source address (IPv4 or IPv6)",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "ip.dst",
        description: "Destination address (IPv4 or IPv6)",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "ip.addr",
        description: "Either address",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "ip.ttl",
        description: "Time to live / hop limit",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "ip.proto",
        description: "IP protocol number",
        source: Source::Index,
        flag: false,
    },
    // TCP ----------------------------------------------------------------
    FieldSpec {
        name: "tcp.srcport",
        description: "TCP source port",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "tcp.dstport",
        description: "TCP destination port",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "tcp.port",
        description: "Either TCP port",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "tcp.len",
        description: "TCP payload length",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "tcp.window",
        description: "Advertised receive window",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "tcp.flags.syn",
        description: "SYN flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.ack",
        description: "ACK flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.fin",
        description: "FIN flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.reset",
        description: "RST flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.push",
        description: "PSH flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.urg",
        description: "URG flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.ece",
        description: "ECE flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.flags.cwr",
        description: "CWR flag",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.analysis.retransmission",
        description: "Transit judged this a retransmission",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.analysis.duplicate_ack",
        description: "A duplicate acknowledgement",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.analysis.out_of_order",
        description: "Arrived out of sequence",
        source: Source::Index,
        flag: true,
    },
    FieldSpec {
        name: "tcp.analysis.zero_window",
        description: "Advertised a zero receive window",
        source: Source::Index,
        flag: true,
    },
    // UDP ----------------------------------------------------------------
    FieldSpec {
        name: "udp.srcport",
        description: "UDP source port",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "udp.dstport",
        description: "UDP destination port",
        source: Source::Index,
        flag: false,
    },
    FieldSpec {
        name: "udp.port",
        description: "Either UDP port",
        source: Source::Index,
        flag: false,
    },
    // Application --------------------------------------------------------
    FieldSpec {
        name: "dns.id",
        description: "DNS transaction identifier",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "dns.qry.name",
        description: "Queried name",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "dns.qry.type",
        description: "Query type number",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "dns.rcode",
        description: "Response code (0 = no error)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "dns.flags.response",
        description: "Is a response rather than a query",
        source: Source::Dissect,
        flag: true,
    },
    FieldSpec {
        name: "dns.count.answers",
        description: "Answer record count",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tls.record.content_type",
        description: "TLS record content type",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tls.handshake.type",
        description: "TLS handshake message type",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tls.handshake.extensions_server_name",
        description: "SNI host name",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tls.alert.level",
        description: "TLS alert level (2 = fatal)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tls.alert.description",
        description: "TLS alert code",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "http.request.method",
        description: "HTTP method",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "http.request.uri",
        description: "Request URI",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "http.host",
        description: "HTTP Host header",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "http.user_agent",
        description: "HTTP User-Agent",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "http.response.code",
        description: "HTTP status code",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "icmp.type",
        description: "ICMP type",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "icmp.code",
        description: "ICMP code",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "icmp.mtu",
        description: "Next-hop MTU from a fragmentation-needed message",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "arp.opcode",
        description: "ARP operation (1 request, 2 reply)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "arp.src.proto_ipv4",
        description: "ARP sender IPv4 address",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "arp.isgratuitous",
        description: "Sender and target addresses are the same",
        source: Source::Dissect,
        flag: true,
    },
    FieldSpec {
        name: "dhcp.type",
        description: "DHCP message type",
        source: Source::Dissect,
        flag: false,
    },
    // Batch 2 — routing, L2 discovery, redundancy, infra services.
    FieldSpec {
        name: "bgp.type",
        description: "BGP message type (3 = NOTIFICATION)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "bgp.notify.major_error",
        description: "BGP notification error code",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "bgp.notify.reason",
        description: "Why the BGP session was torn down",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "ospf.msg",
        description: "OSPF packet type (1 = Hello)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "ospf.area_id",
        description: "OSPF area",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "ospf.srcrouter",
        description: "OSPF source router id",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "vrrp.virt_rtr_id",
        description: "VRRP group",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "vrrp.prio",
        description: "VRRP priority (0 = resigning, 255 = address owner)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "hsrp.state",
        description: "HSRP state (16 = Active, 8 = Standby)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "hsrp.group",
        description: "HSRP group",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "hsrp.priority",
        description: "HSRP priority",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "lldp.tlv.system.name",
        description: "LLDP neighbour system name",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "lldp.port.id",
        description: "LLDP neighbour port id",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "cdp.deviceid",
        description: "CDP neighbour device id",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "cdp.portid",
        description: "CDP neighbour port id",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "stp.flags.tc",
        description: "STP topology change",
        source: Source::Dissect,
        flag: true,
    },
    FieldSpec {
        name: "stp.root.hw",
        description: "STP root bridge id",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "stp.root.cost",
        description: "STP root path cost",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "ntp.stratum",
        description: "NTP stratum (16 = unsynchronized)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "ntp.flags.mode",
        description: "NTP mode (3 = client, 4 = server)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "snmp.version",
        description: "SNMP version (0 = v1, 1 = v2c, 3 = v3)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "snmp.pdu_type",
        description: "SNMP PDU type",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "radius.code",
        description: "RADIUS code (3 = Access-Reject)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "radius.username",
        description: "RADIUS user name",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tacplus.type",
        description: "TACACS+ type (1 = Authentication)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "tacplus.flags.unencrypted",
        description: "TACACS+ body sent unencrypted",
        source: Source::Dissect,
        flag: true,
    },
    FieldSpec {
        name: "syslog.severity",
        description: "Syslog severity (0 = emergency, 3 = error)",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "syslog.msg",
        description: "Syslog message text",
        source: Source::Dissect,
        flag: false,
    },
    FieldSpec {
        name: "dhcp.option.hostname",
        description: "Client-supplied host name",
        source: Source::Dissect,
        flag: false,
    },
];

fn spec(name: &str) -> Option<&'static FieldSpec> {
    REGISTRY.iter().find(|f| f.name == name)
}

/// Field names close enough to `name` to be worth suggesting.
///
/// Three heuristics, cheapest first, because the point is to turn "I
/// mistyped" into "here is what you meant" rather than to be clever:
/// prefix (`tcp.flag` → `tcp.flags.syn`), matching last segment
/// (`dns.name` → `dns.qry.name`), and finally a small edit distance
/// (`tcp.prot` → `tcp.port`), which catches transpositions the first two
/// miss entirely.
fn suggest(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    if let Some(f) = REGISTRY
        .iter()
        .find(|f| f.name.starts_with(&lower) || lower.starts_with(f.name))
    {
        return Some(f.name);
    }
    let tail = lower.rsplit('.').next().unwrap_or(&lower);
    if let Some(f) = REGISTRY
        .iter()
        .find(|f| f.name.rsplit('.').next() == Some(tail))
    {
        return Some(f.name);
    }
    REGISTRY
        .iter()
        .map(|f| (f.name, edit_distance(&lower, f.name)))
        .filter(|(_, d)| *d <= 2)
        .min_by_key(|(n, d)| (*d, n.len()))
        .map(|(n, _)| n)
}

/// Levenshtein distance, bounded by the shorter string. Small inputs
/// (field names), so the straightforward two-row version is fine.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// A compiled, ready-to-run filter.
#[derive(Debug)]
pub struct Filter {
    expr: Expr,
    /// True when any named field needs the packet re-dissected.
    pub needs_dissection: bool,
    /// The original text, for echoing back in answers.
    pub source: String,
}

impl Filter {
    /// Parse and validate a filter expression.
    pub fn compile(input: &str) -> Result<Self, FilterError> {
        let expr = super::parse::parse(input)?;
        let mut needs = false;
        validate(&expr, &mut needs)?;
        Ok(Self {
            expr,
            needs_dissection: needs,
            source: input.to_string(),
        })
    }

    /// Evaluate against the index alone.
    ///
    /// Only valid when `needs_dissection` is false; a filter that needs
    /// dissection evaluates its unavailable terms as false here, which is
    /// why [`Filter::matches`] exists and callers should use it.
    pub fn matches_index(&self, idx: &CaptureIndex, i: usize) -> bool {
        let ctx = Ctx {
            idx,
            i,
            dissection: None,
        };
        eval(&self.expr, &ctx)
    }

    /// Evaluate with a dissection available for application fields.
    pub fn matches(&self, idx: &CaptureIndex, i: usize, dissection: Option<&Dissection>) -> bool {
        let ctx = Ctx { idx, i, dissection };
        eval(&self.expr, &ctx)
    }
}

/// Walk the expression, refusing unknown fields and noting whether any
/// term needs the slow path.
fn validate(e: &Expr, needs: &mut bool) -> Result<(), FilterError> {
    match e {
        // A protocol Transit names but does not yet dissect can never be
        // set on a packet, so a filter using it could only ever match
        // nothing — which reads as "there is no such traffic". Refuse it
        // by name, exactly as an unknown field is refused.
        Expr::Protocol(p) => {
            if p.is_dissected() {
                Ok(())
            } else {
                Err(FilterError::new(
                    0,
                    format!(
                        "Transit names `{}` but does not dissect it yet, so this filter could \
                         only ever match nothing. Dissected protocols: {}",
                        p.as_str(),
                        Proto::DISSECTED
                            .iter()
                            .map(|p| p.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ))
            }
        }
        Expr::Present(name) => {
            check_field(name, 0, needs)?;
            Ok(())
        }
        Expr::Compare { field, at, .. } => check_field(field, *at, needs),
        Expr::Not(inner) => validate(inner, needs),
        Expr::And(a, b) | Expr::Or(a, b) => {
            validate(a, needs)?;
            validate(b, needs)
        }
    }
}

fn check_field(name: &str, at: usize, needs: &mut bool) -> Result<(), FilterError> {
    match spec(name) {
        Some(s) => {
            if s.source == Source::Dissect {
                *needs = true;
            }
            Ok(())
        }
        None => {
            let hint = match suggest(name) {
                Some(s) => format!(" — did you mean `{s}`?"),
                None => String::new(),
            };
            Err(FilterError::new(
                at,
                format!("unknown field `{name}`{hint}"),
            ))
        }
    }
}

/// Everything a term can read.
struct Ctx<'a> {
    idx: &'a CaptureIndex,
    i: usize,
    dissection: Option<&'a Dissection>,
}

impl Ctx<'_> {
    fn record(&self) -> &PacketRecord {
        &self.idx.records[self.i]
    }
}

fn eval(e: &Expr, ctx: &Ctx<'_>) -> bool {
    match e {
        Expr::Protocol(p) => ctx.record().protos().contains(*p),
        // A bare field. For a boolean field that means "is true"; for any
        // other field it means "this packet has one".
        Expr::Present(name) => match resolve(name, ctx) {
            None => false,
            Some(v) => {
                if spec(name).is_some_and(|s| s.flag) {
                    compare(&v, CmpOp::Ne, &Value::Num(0))
                } else {
                    true
                }
            }
        },
        Expr::Compare {
            field, op, value, ..
        } => match resolve(field, ctx) {
            Some(actual) => compare(&actual, *op, value),
            // A field that is not in this packet cannot match. `!=`
            // included: `tcp.port != 443` should not match an ARP frame,
            // which has no TCP port at all.
            None => false,
        },
        Expr::Not(inner) => !eval(inner, ctx),
        Expr::And(a, b) => eval(a, ctx) && eval(b, ctx),
        Expr::Or(a, b) => eval(a, ctx) || eval(b, ctx),
    }
}

/// A resolved field value. `Multi` covers the "either side" fields, which
/// match if *any* of their values does.
enum Resolved {
    One(Value),
    Multi(Vec<Value>),
}

fn resolve(name: &str, ctx: &Ctx<'_>) -> Option<Resolved> {
    let r = ctx.record();
    let one = |v: Value| Some(Resolved::One(v));
    let num = |n: i128| Some(Resolved::One(Value::Num(n)));
    let flag = |set: bool| Some(Resolved::One(Value::Num(i128::from(set))));

    match name {
        // Frame ---------------------------------------------------------
        "frame.number" => num(ctx.i as i128 + 1),
        "frame.len" => num(i128::from(r.orig_len)),
        "frame.cap_len" => num(i128::from(r.caplen)),
        "frame.time_epoch" => num(i128::from(r.ts_us)),
        "frame.time_relative" => num(i128::from(r.ts_us - ctx.idx.first_ts)),
        "frame.time_delta" => {
            let prev = ctx.i.checked_sub(1).map(|j| ctx.idx.records[j].ts_us);
            num(i128::from(r.ts_us - prev.unwrap_or(r.ts_us)))
        }
        "frame.snapped" => flag(r.caplen < r.orig_len),
        "frame.malformed" => flag(r.malformed != 0),
        // VLAN ----------------------------------------------------------
        "vlan.id" => r
            .has_vlan()
            .then(|| Resolved::One(Value::Num(i128::from(r.vlan)))),
        // IP ------------------------------------------------------------
        "ip.src" => ctx.idx.src_ip(r).map(|ip| Resolved::One(Value::Ip(ip))),
        "ip.dst" => ctx.idx.dst_ip(r).map(|ip| Resolved::One(Value::Ip(ip))),
        "ip.addr" => {
            let mut v = Vec::new();
            if let Some(ip) = ctx.idx.src_ip(r) {
                v.push(Value::Ip(ip));
            }
            if let Some(ip) = ctx.idx.dst_ip(r) {
                v.push(Value::Ip(ip));
            }
            (!v.is_empty()).then_some(Resolved::Multi(v))
        }
        "ip.ttl" => (r.ttl != 0).then(|| Resolved::One(Value::Num(i128::from(r.ttl)))),
        "ip.proto" => (r.ip_proto != 0).then(|| Resolved::One(Value::Num(i128::from(r.ip_proto)))),
        // TCP -----------------------------------------------------------
        "tcp.srcport" => is_tcp(r).then(|| Resolved::One(Value::Num(i128::from(r.src_port)))),
        "tcp.dstport" => is_tcp(r).then(|| Resolved::One(Value::Num(i128::from(r.dst_port)))),
        "tcp.port" => is_tcp(r).then(|| {
            Resolved::Multi(vec![
                Value::Num(i128::from(r.src_port)),
                Value::Num(i128::from(r.dst_port)),
            ])
        }),
        "tcp.len" => is_tcp(r).then(|| Resolved::One(Value::Num(i128::from(r.payload_len)))),
        "tcp.window" => is_tcp(r).then(|| Resolved::One(Value::Num(i128::from(tcp_window(ctx))))),
        "tcp.flags.syn" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_SYN)),
        "tcp.flags.ack" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_ACK)),
        "tcp.flags.fin" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_FIN)),
        "tcp.flags.reset" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_RST)),
        "tcp.flags.push" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_PSH)),
        "tcp.flags.urg" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_URG)),
        "tcp.flags.ece" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_ECE)),
        "tcp.flags.cwr" => is_tcp(r).then(|| flag_value(r.tcp_flags, TCP_CWR)),
        "tcp.analysis.retransmission" => analysis_flag(r, ANALYSIS_RETRANSMIT),
        "tcp.analysis.duplicate_ack" => analysis_flag(r, ANALYSIS_DUP_ACK),
        "tcp.analysis.out_of_order" => analysis_flag(r, ANALYSIS_OUT_OF_ORDER),
        "tcp.analysis.zero_window" => analysis_flag(r, ANALYSIS_ZERO_WINDOW),
        // UDP -----------------------------------------------------------
        "udp.srcport" => is_udp(r).then(|| Resolved::One(Value::Num(i128::from(r.src_port)))),
        "udp.dstport" => is_udp(r).then(|| Resolved::One(Value::Num(i128::from(r.dst_port)))),
        "udp.port" => is_udp(r).then(|| {
            Resolved::Multi(vec![
                Value::Num(i128::from(r.src_port)),
                Value::Num(i128::from(r.dst_port)),
            ])
        }),
        // "Either MAC" needs the dissection, since the index does not hold
        // MAC addresses (they cost 12 bytes a packet and are rarely the
        // question).
        "eth.addr" => {
            let d = ctx.dissection?;
            let mut v = Vec::new();
            for n in ["eth.src", "eth.dst"] {
                if let Some(FieldValue::Mac(m)) = d.field(n) {
                    v.push(Value::Mac(*m));
                }
            }
            (!v.is_empty()).then_some(Resolved::Multi(v))
        }
        // Everything else comes from the dissection's own field tree.
        other => {
            let d = ctx.dissection?;
            let fv = d.field(other)?;
            one(from_field_value(fv))
        }
    }
}

fn is_tcp(r: &PacketRecord) -> bool {
    r.protos().contains(Proto::Tcp)
}

fn is_udp(r: &PacketRecord) -> bool {
    r.protos().contains(Proto::Udp)
}

fn flag_value(flags: u8, bit: u8) -> Resolved {
    Resolved::One(Value::Num(i128::from(flags & bit != 0)))
}

fn analysis_flag(r: &PacketRecord, bit: u8) -> Option<Resolved> {
    // Present only on packets the analyser actually judged, so
    // `not tcp.analysis.retransmission` does not sweep in every ARP frame.
    is_tcp(r).then(|| Resolved::One(Value::Num(i128::from(r.analysis & bit != 0))))
}

/// The index does not store the TCP window (it is only interesting on the
/// zero-window path, which already has an analysis flag), so read it from
/// the dissection when one is available and treat it as absent otherwise.
fn tcp_window(ctx: &Ctx<'_>) -> u32 {
    match ctx.dissection.and_then(|d| d.field("tcp.window")) {
        Some(FieldValue::U64(v)) => *v as u32,
        _ if ctx.record().analysis & ANALYSIS_ZERO_WINDOW != 0 => 0,
        // Unknown. Reported as a non-zero sentinel so a `== 0` test does
        // not falsely match; a `> N` test on an unknown window is
        // answered by the dissection path.
        _ => u32::MAX,
    }
}

fn from_field_value(fv: &FieldValue) -> Value {
    match fv {
        FieldValue::U64(v) => Value::Num(*v as i128),
        FieldValue::I64(v) => Value::Num(i128::from(*v)),
        FieldValue::F64(v) => Value::Num((*v * 1_000_000.0).round() as i128),
        FieldValue::Bool(v) => Value::Num(i128::from(*v)),
        FieldValue::Str(s) => Value::Str(s.clone()),
        FieldValue::Ip(ip) => Value::Ip(*ip),
        FieldValue::Mac(m) => Value::Mac(*m),
    }
}

fn compare(actual: &Resolved, op: CmpOp, want: &Value) -> bool {
    match actual {
        Resolved::One(v) => compare_one(v, op, want),
        // An "either side" field matches if any of its values does — but
        // `!=` must hold for ALL of them, or `tcp.port != 443` would match
        // a packet on port 443 simply because its other port differs.
        Resolved::Multi(vs) => match op {
            CmpOp::Ne => vs.iter().all(|v| compare_one(v, op, want)),
            _ => vs.iter().any(|v| compare_one(v, op, want)),
        },
    }
}

fn compare_one(actual: &Value, op: CmpOp, want: &Value) -> bool {
    if op == CmpOp::In {
        if let Value::Set(items) = want {
            return items.iter().any(|w| compare_one(actual, CmpOp::Eq, w));
        }
        return false;
    }
    if op == CmpOp::Contains {
        let hay = render_value(actual).to_ascii_lowercase();
        let needle = render_value(want).to_ascii_lowercase();
        return hay.contains(&needle);
    }

    // A CIDR compared for equality means containment.
    if let Value::Cidr(net, bits) = want {
        if let Value::Ip(ip) = actual {
            let inside = in_network(*ip, *net, *bits);
            return match op {
                CmpOp::Eq => inside,
                CmpOp::Ne => !inside,
                _ => false,
            };
        }
        return false;
    }

    let ord = match (actual, want) {
        (Value::Num(a), Value::Num(b)) => a.partial_cmp(b),
        (Value::Ip(a), Value::Ip(b)) => a.partial_cmp(b),
        (Value::Mac(a), Value::Mac(b)) => a.partial_cmp(b),
        (Value::Str(a), Value::Str(b)) => Some(a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase())),
        // A numeric field compared against a bareword, or vice versa:
        // fall back to comparing their rendered forms so
        // `dns.rcode.name == "No such name"` and `http.request.method ==
        // GET` both behave.
        (a, b) => Some(
            render_value(a)
                .to_ascii_lowercase()
                .cmp(&render_value(b).to_ascii_lowercase()),
        ),
    };
    let Some(ord) = ord else { return false };
    match op {
        CmpOp::Eq => ord.is_eq(),
        CmpOp::Ne => ord.is_ne(),
        CmpOp::Gt => ord.is_gt(),
        CmpOp::Ge => ord.is_ge(),
        CmpOp::Lt => ord.is_lt(),
        CmpOp::Le => ord.is_le(),
        CmpOp::Contains | CmpOp::In => false,
    }
}

fn render_value(v: &Value) -> String {
    match v {
        Value::Num(n) => n.to_string(),
        Value::Str(s) => s.clone(),
        Value::Ip(ip) => ip.to_string(),
        Value::Cidr(ip, b) => format!("{ip}/{b}"),
        Value::Mac(m) => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        ),
        Value::Set(_) => String::new(),
    }
}

/// Is `ip` inside `net/bits`? Families must match — `10.0.0.1` is not
/// inside `2001:db8::/32`, and saying so beats a confusing false match.
fn in_network(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "eval_tests.rs"]
mod tests;
