//! Deterministic findings.
//!
//! Every entry here is produced by an explicit rule over numbers the
//! index already computed. Nothing is inferred by a model, which buys
//! three things worth more than cleverness:
//!
//! - **Exactness.** "5,912 retransmissions, 0.4% of packets" is a fact.
//! - **Reproducibility.** Two people asking the same question of the same
//!   capture get the same answer, today and in a year.
//! - **Cost.** The assistant spends its budget on judgement — *what does
//!   this mean for this network* — rather than on arithmetic.
//!
//! # Rule-writing discipline
//!
//! A finding must be **actionable and specific**: it names the flow, the
//! address, or the count that a human can go and check. Thresholds are
//! deliberately conservative, because a findings list that cries wolf
//! gets ignored, and an ignored list is worse than none — it launders
//! inattention as diligence.

use crate::index::{CaptureIndex, DNS_UNANSWERED_US};
use crate::types::IpProto;

/// How much attention a finding deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Context, not a problem. Capture-quality notes live here.
    Info,
    Low,
    Medium,
    /// Something is broken and a human should look now.
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "med",
            Self::High => "high",
        }
    }

    pub fn from_tag(tag: &str) -> Option<Self> {
        Some(match tag {
            "info" => Self::Info,
            "low" => Self::Low,
            "med" | "medium" => Self::Medium,
            "high" => Self::High,
            _ => return None,
        })
    }
}

/// One thing worth telling the analyst.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable rule id, so a finding can be referenced
    /// and suppressed without matching on prose.
    pub rule: &'static str,
    /// One line, specific enough to act on.
    pub detail: String,
    /// A view-filter expression that shows the evidence, when one exists.
    /// This is what turns a finding into a next step rather than a claim.
    pub filter: Option<String>,
}

// Thresholds. Each is a judgement call; each is named so it can be argued
// with rather than discovered by reading code.

/// Retransmission rate above which a conversation is called unhealthy.
const RETRANSMIT_PCT_HIGH: f64 = 5.0;
const RETRANSMIT_PCT_MED: f64 = 2.0;
/// Below this, a percentage is noise — three retransmits out of twenty
/// packets is 15% and means nothing.
const MIN_PACKETS_FOR_RATE: u64 = 100;
/// A zero-window stall at least this long is a real stall, not a blip.
const ZERO_WINDOW_STALL_US: i64 = 1_000_000;
/// Fraction of DNS responses that may fail before it is worth reporting.
const DNS_FAILURE_PCT: f64 = 10.0;
/// Flows reported individually before the list is summarized.
const MAX_PER_RULE: usize = 5;

/// Run every rule over an indexed capture, most severe first.
pub fn evaluate(idx: &CaptureIndex) -> Vec<Finding> {
    let mut out = Vec::new();

    mtu_black_hole(idx, &mut out);
    zero_window_stalls(idx, &mut out);
    retransmission(idx, &mut out);
    refused_and_unanswered(idx, &mut out);
    duplicate_addresses(idx, &mut out);
    dns_health(idx, &mut out);
    tls_failures(idx, &mut out);
    http_errors(idx, &mut out);
    routing_loops(idx, &mut out);
    capture_quality(idx, &mut out);

    // Severity first, then rule id, so the order is stable across runs.
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.rule.cmp(b.rule)));
    out
}

/// ICMP fragmentation-needed with DF set: the classic MTU black hole,
/// where a tunnel or a mis-set interface silently drops full-size frames
/// and only large transfers break.
fn mtu_black_hole(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let n = idx.stats.icmp.frag_needed;
    if n == 0 {
        return;
    }
    let mtus = &idx.stats.icmp.frag_needed_mtus;
    let mtu_text = if mtus.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = mtus.iter().take(4).map(|m| m.to_string()).collect();
        format!(", next-hop MTU {}", list.join("/"))
    };
    out.push(Finding {
        severity: Severity::High,
        rule: "mtu-black-hole",
        detail: format!(
            "{n} ICMP fragmentation-needed messages{mtu_text}. A path MTU is smaller than the \
             sender is using and the Don't Fragment bit is set — large transfers will stall while \
             small ones succeed."
        ),
        filter: Some("icmp.type == 3 and icmp.code == 4".into()),
    });
}

/// A receiver advertising a zero window is telling the sender to stop.
/// A long one is an application that stopped reading its socket.
fn zero_window_stalls(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let mut stalled: Vec<_> = idx
        .flows
        .iter()
        .filter(|f| f.max_zero_window_us >= ZERO_WINDOW_STALL_US)
        .collect();
    stalled.sort_by_key(|f| std::cmp::Reverse(f.max_zero_window_us));

    for f in stalled.iter().take(MAX_PER_RULE) {
        out.push(Finding {
            severity: Severity::High,
            rule: "tcp-zero-window-stall",
            detail: format!(
                "{} stalled for {:.1}s on a zero receive window — the receiving application \
                 stopped reading from its socket.",
                f.key.render(),
                f.max_zero_window_us as f64 / 1e6
            ),
            filter: Some(format!(
                "ip.src == {} and ip.dst == {} and tcp.window == 0",
                f.key.b_ip, f.key.a_ip
            )),
        });
    }
    if stalled.len() > MAX_PER_RULE {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "tcp-zero-window-stall-more",
            detail: format!(
                "{} further conversations also stalled on a zero window.",
                stalled.len() - MAX_PER_RULE
            ),
            filter: Some("tcp.window == 0".into()),
        });
    }
}

/// Retransmission rate, per conversation and capture-wide.
fn retransmission(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let mut bad: Vec<_> = idx
        .flows
        .iter()
        .filter(|f| f.packets() >= MIN_PACKETS_FOR_RATE && f.retransmit_pct() >= RETRANSMIT_PCT_MED)
        .collect();
    bad.sort_by(|a, b| {
        b.retransmit_pct()
            .partial_cmp(&a.retransmit_pct())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for f in bad.iter().take(MAX_PER_RULE) {
        let pct = f.retransmit_pct();
        out.push(Finding {
            severity: if pct >= RETRANSMIT_PCT_HIGH {
                Severity::High
            } else {
                Severity::Medium
            },
            rule: "tcp-retransmission",
            detail: format!(
                "{} retransmitted {:.1}% of its packets ({} of {}) — packet loss or a congested \
                 path.",
                f.key.render(),
                pct,
                f.retransmits,
                f.packets()
            ),
            filter: Some(format!(
                "ip.src == {} and ip.dst == {} and tcp.analysis.retransmission",
                f.key.a_ip, f.key.b_ip
            )),
        });
    }

    let health = idx.tcp_health();
    if health.packets >= MIN_PACKETS_FOR_RATE && health.retransmit_pct() >= RETRANSMIT_PCT_MED {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "tcp-retransmission-overall",
            detail: format!(
                "Capture-wide TCP retransmission rate is {:.1}% ({} of {} TCP packets).",
                health.retransmit_pct(),
                health.retransmits,
                health.packets
            ),
            filter: Some("tcp.analysis.retransmission".into()),
        });
    }
}

/// Connections that were refused, or that never got an answer at all.
/// The distinction matters: refused means something was listening and
/// said no; unanswered means nothing replied, which is a firewall or a
/// routing problem.
fn refused_and_unanswered(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let refused: Vec<_> = idx.flows.iter().filter(|f| f.is_refused()).collect();
    let unanswered: Vec<_> = idx.flows.iter().filter(|f| f.is_unanswered()).collect();

    if !refused.is_empty() {
        let sample = refused
            .iter()
            .take(3)
            .map(|f| f.key.render())
            .collect::<Vec<_>>()
            .join(", ");
        out.push(Finding {
            severity: Severity::Medium,
            rule: "tcp-connection-refused",
            detail: format!(
                "{} connection attempt(s) were refused with a RST: {sample}. Something answered \
                 and declined — the port is closed or an ACL rejected it.",
                refused.len()
            ),
            filter: Some("tcp.flags.reset == 1".into()),
        });
    }
    if !unanswered.is_empty() {
        let sample = unanswered
            .iter()
            .take(3)
            .map(|f| f.key.render())
            .collect::<Vec<_>>()
            .join(", ");
        out.push(Finding {
            severity: Severity::High,
            rule: "tcp-connection-unanswered",
            detail: format!(
                "{} connection attempt(s) got no reply at all: {sample}. Nothing answered — a \
                 dropped SYN, a black-holed route, or a silently-discarding firewall.",
                unanswered.len()
            ),
            filter: Some("tcp.flags.syn == 1 and tcp.flags.ack == 0".into()),
        });
    }
}

/// Two MAC addresses claiming one IP. A commonly-missed cause of
/// intermittent, direction-dependent connectivity failures.
fn duplicate_addresses(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    for (ip, macs) in &idx.stats.arp.claims {
        if macs.len() < 2 {
            continue;
        }
        let list: Vec<String> = macs
            .iter()
            .take(4)
            .map(|m| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            })
            .collect();
        out.push(Finding {
            severity: Severity::High,
            rule: "duplicate-ip-address",
            detail: format!(
                "{ip} is claimed by {} different MAC addresses ({}). Two hosts share one address; \
                 connectivity will fail intermittently and asymmetrically.",
                macs.len(),
                list.join(", ")
            ),
            filter: Some(format!("arp and arp.src.proto_ipv4 == {ip}")),
        });
    }
}

/// DNS failure rate, unanswered queries, and slow responses.
fn dns_health(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let dns = &idx.stats.dns;
    let failures = dns.nxdomain + dns.servfail + dns.refused;
    if dns.responses > 0 {
        let pct = failures as f64 * 100.0 / dns.responses as f64;
        if pct >= DNS_FAILURE_PCT && failures >= 5 {
            let top = dns.failing_names.top(3);
            let names = top
                .iter()
                .map(|(n, c)| format!("{n} ×{c}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(Finding {
                severity: Severity::Medium,
                rule: "dns-failure-rate",
                detail: format!(
                    "{:.0}% of DNS responses failed ({failures} of {}): {} NXDOMAIN, {} SERVFAIL, \
                     {} REFUSED. Most frequent: {names}",
                    pct, dns.responses, dns.nxdomain, dns.servfail, dns.refused
                ),
                filter: Some("dns.rcode != 0".into()),
            });
        }
    }
    if dns.unanswered >= 5 {
        out.push(Finding {
            severity: Severity::High,
            rule: "dns-unanswered",
            detail: format!(
                "{} DNS queries never received a response (>{}s). The resolver is unreachable or \
                 dropping requests.",
                dns.unanswered,
                DNS_UNANSWERED_US / 1_000_000
            ),
            filter: Some("dns and dns.flags.response == 0".into()),
        });
    }
    if dns.slowest_us > 2_000_000 {
        out.push(Finding {
            severity: Severity::Low,
            rule: "dns-slow",
            detail: format!(
                "Slowest DNS response took {:.1}s (mean {:.0}ms).",
                dns.slowest_us as f64 / 1e6,
                dns.mean_response_us().unwrap_or(0) as f64 / 1e3
            ),
            filter: Some("dns.flags.response == 1".into()),
        });
    }
}

/// Fatal TLS alerts — the direct answer to "why did the connection fail".
fn tls_failures(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let tls = &idx.stats.tls;
    if tls.fatal_alerts == 0 {
        return;
    }
    let reasons = tls
        .alert_reasons
        .top(3)
        .iter()
        .map(|(r, c)| format!("{r} ×{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push(Finding {
        severity: Severity::High,
        rule: "tls-fatal-alert",
        detail: format!(
            "{} fatal TLS alert(s): {reasons}. The handshake was rejected — the named reason is \
             the cause.",
            tls.fatal_alerts
        ),
        filter: Some("tls.alert.level == 2".into()),
    });
}

/// HTTP server errors. Client errors are noisier and rarely the network's
/// fault, so only 5xx earns a finding on its own.
fn http_errors(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let http = &idx.stats.http;
    let server_errors: u64 = http
        .status
        .iter()
        .filter(|(c, _)| **c >= 500)
        .map(|(_, n)| *n)
        .sum();
    if server_errors >= 5 {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "http-server-errors",
            detail: format!(
                "{server_errors} HTTP 5xx responses out of {} — the server is failing, not the \
                 network.",
                http.responses
            ),
            filter: Some("http.response.code >= 500".into()),
        });
    }
    if http.authenticated_requests > 0 {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "http-cleartext-credentials",
            detail: format!(
                "{} cleartext HTTP request(s) carried an Authorization header or a session \
                 cookie. Transit redacted the values, but they crossed the wire unencrypted and \
                 anyone on this segment could read them.",
                http.authenticated_requests
            ),
            filter: Some("http.request.method".into()),
        });
    }
}

/// ICMP time-exceeded in quantity means packets are going round in
/// circles — a routing loop, or a traceroute someone forgot to mention.
fn routing_loops(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    let n = idx.stats.icmp.time_exceeded;
    if n >= 10 {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "icmp-ttl-exceeded",
            detail: format!(
                "{n} ICMP time-exceeded messages. Either a routing loop is consuming TTL, or a \
                 traceroute was running during the capture."
            ),
            filter: Some("icmp.type == 11".into()),
        });
    }
}

/// Capture-quality notes. Not problems with the network — problems with
/// the evidence, which an analyst needs to know before trusting the rest.
fn capture_quality(idx: &CaptureIndex, out: &mut Vec<Finding>) {
    if idx.limits_hit.packet_cap {
        out.push(Finding {
            severity: Severity::Info,
            rule: "index-truncated",
            detail: format!(
                "Only the first {} packets were indexed; the capture is longer. Every count below \
                 covers the indexed portion only.",
                idx.records.len()
            ),
            filter: None,
        });
    }
    if idx.limits_hit.flow_cap {
        out.push(Finding {
            severity: Severity::Info,
            rule: "flow-table-truncated",
            detail: format!(
                "The conversation table hit its ceiling; {} further packets ({} bytes) were not \
                 attributed to a conversation.",
                idx.flow_overflow.0, idx.flow_overflow.1
            ),
            filter: None,
        });
    }
    if idx.snapped > 0 {
        let pct = idx.snapped as f64 * 100.0 / idx.records.len().max(1) as f64;
        out.push(Finding {
            severity: Severity::Info,
            rule: "capture-snapped",
            detail: format!(
                "{:.0}% of packets were truncated by the capture snaplen ({} of {}). Payload-level \
                 analysis is limited to what was stored.",
                pct,
                idx.snapped,
                idx.records.len()
            ),
            filter: None,
        });
    }
    if idx.scan.stopped_on_error {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "capture-corrupt",
            detail: format!(
                "The capture file is damaged after byte {}. Packets past that point could not be \
                 read.",
                idx.scan.end_offset
            ),
            filter: None,
        });
    }
    // A capture consisting entirely of one conversation is usually a
    // filter someone forgot they set, and it changes what conclusions are
    // available.
    if idx.flows.len() == 1 && idx.records.len() > 100 {
        out.push(Finding {
            severity: Severity::Info,
            rule: "single-conversation",
            detail:
                "The capture contains exactly one conversation — a capture filter was probably \
                     in effect, so absence of other traffic is not evidence."
                    .into(),
            filter: None,
        });
    }
    // No IP traffic at all usually means the capture was taken on the
    // wrong interface.
    let ip_flows = idx
        .flows
        .iter()
        .filter(|f| f.key.proto != IpProto::Other(0))
        .count();
    if idx.records.len() > 50 && ip_flows == 0 {
        out.push(Finding {
            severity: Severity::Medium,
            rule: "no-ip-traffic",
            detail: "No IP conversations were seen at all. The capture may have been taken on the \
                     wrong interface, or the interface sees only broadcast traffic."
                .into(),
            filter: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_high_above_info() {
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_tags_round_trip() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
        ] {
            assert_eq!(Severity::from_tag(s.as_str()), Some(s));
        }
        assert_eq!(Severity::from_tag("medium"), Some(Severity::Medium));
        assert_eq!(Severity::from_tag("catastrophic"), None);
    }
}
