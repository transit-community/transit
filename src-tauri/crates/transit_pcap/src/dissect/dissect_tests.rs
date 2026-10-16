//! Dissector corpus.
//!
//! Packets are built byte-by-byte from the RFC field layouts — no
//! third-party sample captures (plan §11). The builders below are shared
//! with the index and filter tests.
//!
//! Two groups:
//!
//! 1. **Shape** — a packet we constructed dissects to the fields we
//!    encoded, at every layer, with the summary the index will store.
//! 2. **Hostility** — truncation at every possible offset, and arbitrary
//!    bytes, must never panic and never produce a field claiming to be
//!    something it is not.

use super::*;
use crate::types::{LinkType, RawPacket};

// ---------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------

pub(crate) const SRC_MAC: [u8; 6] = [0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e];
pub(crate) const DST_MAC: [u8; 6] = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];

/// Ethernet II frame around `payload`.
pub(crate) fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&DST_MAC);
    p.extend_from_slice(&SRC_MAC);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// Ethernet II with one 802.1Q tag.
pub(crate) fn eth_vlan(vid: u16, inner_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut tagged = Vec::new();
    tagged.extend_from_slice(&vid.to_be_bytes());
    tagged.extend_from_slice(&inner_type.to_be_bytes());
    tagged.extend_from_slice(payload);
    eth(0x8100, &tagged)
}

/// IPv4 header + payload. Checksum is left zero: nothing in Transit
/// validates it, and a capture full of NIC-offloaded checksums has bogus
/// values anyway.
pub(crate) fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // identification
    p.extend_from_slice(&[0x40, 0x00]); // flags: DF, no offset
    p.push(64); // ttl
    p.push(proto);
    p.extend_from_slice(&[0, 0]); // checksum
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

pub(crate) fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_seq(sport, dport, flags, 1000, payload)
}

/// TCP with an explicit sequence number.
///
/// Worth having as its own builder: a fixture that reuses one sequence
/// number for every packet generates what the TCP tracker correctly reads
/// as a 100%-retransmission storm, which quietly poisons any test that
/// then looks at flow health. Traffic meant to be *healthy* must advance
/// its sequence space like real traffic does.
pub(crate) fn tcp_seq(sport: u16, dport: u16, flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&2000u32.to_be_bytes()); // ack
    p.push(0x50); // data offset 5, no options
    p.push(flags);
    p.extend_from_slice(&8192u16.to_be_bytes()); // window
    p.extend_from_slice(&[0, 0]); // checksum
    p.extend_from_slice(&[0, 0]); // urgent pointer
    p.extend_from_slice(payload);
    p
}

pub(crate) fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]); // checksum
    p.extend_from_slice(payload);
    p
}

/// A DNS query message for `name`.
pub(crate) fn dns_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    p.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an / ns / ar
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // class IN
    p
}

/// A DNS response carrying `rcode`, echoing the question.
pub(crate) fn dns_response(id: u16, name: &str, rcode: u8) -> Vec<u8> {
    let mut p = dns_query(id, name, 1);
    p[2] = 0x81; // QR=1, RD=1
    p[3] = 0x80 | rcode; // RA + rcode
    p
}

/// Dissect a whole Ethernet frame.
pub(crate) fn dissect_eth(frame: &[u8]) -> Dissection {
    let raw = RawPacket {
        number: 1,
        ts_us: 1_700_000_000_000_000,
        caplen: frame.len() as u32,
        orig_len: frame.len() as u32,
        offset: 0,
        data: frame,
        link_type: LinkType::Ethernet,
    };
    dissect(&raw, Detail::Full)
}

// ---------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------

#[test]
fn ethernet_ipv4_tcp_dissects_every_layer() {
    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp(52344, 443, TCP_SYN, &[]),
        ),
    );
    let d = dissect_eth(&frame);

    assert_eq!(d.field("eth.src"), Some(&FieldValue::Mac(SRC_MAC)));
    assert_eq!(d.field("eth.dst"), Some(&FieldValue::Mac(DST_MAC)));
    assert_eq!(
        d.field("ip.src"),
        Some(&FieldValue::Ip("10.0.0.1".parse().unwrap()))
    );
    assert_eq!(d.field("ip.ttl"), Some(&FieldValue::U64(64)));
    assert_eq!(d.field("tcp.srcport"), Some(&FieldValue::U64(52344)));
    assert_eq!(d.field("tcp.dstport"), Some(&FieldValue::U64(443)));
    assert_eq!(d.field("tcp.flags.syn"), Some(&FieldValue::Bool(true)));
    assert_eq!(d.field("tcp.flags.ack"), Some(&FieldValue::Bool(false)));

    let s = d.summary;
    assert_eq!(s.src_port, Some(52344));
    assert_eq!(s.dst_port, Some(443));
    assert_eq!(s.tcp_flags, TCP_SYN);
    assert_eq!(s.top, Proto::Tcp);
    assert!(s.protos.contains(Proto::Ipv4));
    assert!(s.protos.contains(Proto::Tcp));
    assert!(!s.malformed);
    assert!(d.info.contains("52344 → 443"));
    assert!(d.info.contains("[SYN]"));
}

#[test]
fn the_df_flag_survives_because_mtu_hunts_need_it() {
    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp(1, 2, TCP_ACK, &[0; 100]),
        ),
    );
    let d = dissect_eth(&frame);
    assert_eq!(d.field("ip.flags.df"), Some(&FieldValue::Bool(true)));
    assert_eq!(d.field("ip.flags.mf"), Some(&FieldValue::Bool(false)));
}

#[test]
fn a_vlan_tag_is_decoded_and_indexed() {
    let frame = eth_vlan(
        142,
        0x0800,
        &ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &udp(1234, 5678, &[0; 8])),
    );
    let d = dissect_eth(&frame);
    assert_eq!(d.field("vlan.id"), Some(&FieldValue::U64(142)));
    assert_eq!(d.summary.vlan, Some(142));
    assert_eq!(d.summary.src_port, Some(1234));
}

#[test]
fn arp_names_who_has_and_is_at() {
    // Ethernet/IPv4 ARP request: who has 10.0.0.99, tell 10.0.0.1.
    let mut arp = Vec::new();
    arp.extend_from_slice(&1u16.to_be_bytes()); // hw type: ethernet
    arp.extend_from_slice(&0x0800u16.to_be_bytes()); // proto: ipv4
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&1u16.to_be_bytes()); // operation: request
    arp.extend_from_slice(&SRC_MAC);
    arp.extend_from_slice(&[10, 0, 0, 1]);
    arp.extend_from_slice(&[0u8; 6]);
    arp.extend_from_slice(&[10, 0, 0, 99]);

    let d = dissect_eth(&eth(0x0806, &arp));
    assert_eq!(d.summary.top, Proto::Arp);
    assert_eq!(d.field("arp.opcode"), Some(&FieldValue::U64(1)));
    assert_eq!(
        d.field("arp.dst.proto_ipv4"),
        Some(&FieldValue::Ip("10.0.0.99".parse().unwrap()))
    );
    assert_eq!(d.field("arp.isgratuitous"), Some(&FieldValue::Bool(false)));
    assert!(d.info.contains("Who has 10.0.0.99"), "info: {}", d.info);
}

#[test]
fn a_gratuitous_arp_is_flagged() {
    let mut arp = Vec::new();
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&0x0800u16.to_be_bytes());
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&2u16.to_be_bytes()); // reply
    arp.extend_from_slice(&SRC_MAC);
    arp.extend_from_slice(&[10, 0, 0, 50]);
    arp.extend_from_slice(&DST_MAC);
    arp.extend_from_slice(&[10, 0, 0, 50]); // sender == target
    let d = dissect_eth(&eth(0x0806, &arp));
    assert_eq!(d.field("arp.isgratuitous"), Some(&FieldValue::Bool(true)));
}

#[test]
fn dns_query_and_response_decode_name_and_rcode() {
    let q = eth(
        0x0800,
        &ipv4(
            17,
            [10, 0, 0, 5],
            [10, 0, 0, 53],
            &udp(51234, 53, &dns_query(0x1234, "www.example.com", 1)),
        ),
    );
    let d = dissect_eth(&q);
    assert_eq!(d.summary.top, Proto::Dns);
    assert_eq!(
        d.field("dns.qry.name"),
        Some(&FieldValue::Str("www.example.com".into()))
    );
    assert_eq!(d.field("dns.rcode"), Some(&FieldValue::U64(0)));
    assert_eq!(
        d.field("dns.flags.response"),
        Some(&FieldValue::Bool(false))
    );
    assert!(d.info.contains("A www.example.com"), "info: {}", d.info);

    // NXDOMAIN — the response the digest counts.
    let r = eth(
        0x0800,
        &ipv4(
            17,
            [10, 0, 0, 53],
            [10, 0, 0, 5],
            &udp(53, 51234, &dns_response(0x1234, "nope.example.com", 3)),
        ),
    );
    let d = dissect_eth(&r);
    assert_eq!(d.field("dns.rcode"), Some(&FieldValue::U64(3)));
    assert_eq!(
        d.field("dns.rcode.name"),
        Some(&FieldValue::Str("No such name".into()))
    );
    assert_eq!(d.field("dns.flags.response"), Some(&FieldValue::Bool(true)));
}

#[test]
fn mdns_is_dns_under_a_different_name() {
    let frame = eth(
        0x0800,
        &ipv4(
            17,
            [10, 0, 0, 5],
            [224, 0, 0, 251],
            &udp(5353, 5353, &dns_query(0, "_printer._tcp.local", 12)),
        ),
    );
    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Mdns);
    assert!(d.summary.protos.contains(Proto::Mdns));
}

#[test]
fn icmp_frag_needed_surfaces_the_next_hop_mtu() {
    // Type 3 code 4, next-hop MTU 1400 in the second half of word 2.
    let mut icmp = vec![3u8, 4, 0, 0, 0, 0];
    icmp.extend_from_slice(&1400u16.to_be_bytes());
    icmp.extend_from_slice(&[0u8; 28]); // the quoted original header
    let frame = eth(0x0800, &ipv4(1, [10, 0, 0, 1], [10, 0, 0, 9], &icmp));

    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Icmp);
    assert_eq!(d.field("icmp.type"), Some(&FieldValue::U64(3)));
    assert_eq!(d.field("icmp.mtu"), Some(&FieldValue::U64(1400)));
    assert!(
        d.info.contains("fragmentation needed"),
        "info should name the black hole: {}",
        d.info
    );
}

#[test]
fn summary_only_builds_no_layers_but_the_same_summary() {
    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp(80, 40000, TCP_ACK, &[1, 2, 3]),
        ),
    );
    let raw = RawPacket {
        number: 7,
        ts_us: 5,
        caplen: frame.len() as u32,
        orig_len: frame.len() as u32,
        offset: 0,
        data: &frame,
        link_type: LinkType::Ethernet,
    };
    let fast = dissect(&raw, Detail::SummaryOnly);
    let full = dissect(&raw, Detail::Full);

    assert!(fast.layers.is_empty(), "the index path allocates no layers");
    assert!(fast.info.is_empty());
    // The summary is what the index stores, so the two paths must agree
    // exactly — a divergence would make filters disagree with the list.
    assert_eq!(fast.summary, full.summary);
    assert_eq!(fast.summary.payload_len, 3);
}

#[test]
fn tcp_flag_rendering_reads_like_an_engineer_expects() {
    assert_eq!(tcp_flag_names(TCP_SYN), "SYN");
    assert_eq!(tcp_flag_names(TCP_SYN | TCP_ACK), "SYN, ACK");
    assert_eq!(tcp_flag_names(TCP_FIN | TCP_ACK), "ACK, FIN");
    assert_eq!(tcp_flag_names(0), "");
}

#[test]
fn protocol_tags_round_trip() {
    for p in Proto::ALL {
        assert_eq!(Proto::from_tag(p.as_str()), Some(*p), "tag {}", p.as_str());
    }
    assert_eq!(Proto::from_tag("definitely-not-a-protocol"), None);
}

#[test]
fn the_protocol_bitset_holds_every_named_protocol() {
    // ProtoSet is a u64 keyed on the discriminant; if the enum ever grows
    // past 64 variants the shift silently wraps and every stored index
    // becomes wrong. Catch that here rather than in the field.
    let mut set = ProtoSet::default();
    for p in Proto::ALL {
        assert!((*p as u8) < 64, "{p:?} would overflow ProtoSet");
        set.insert(*p);
    }
    for p in Proto::ALL {
        assert!(set.contains(*p));
    }
    assert_eq!(set.iter().count(), Proto::ALL.len());
}

// ---------------------------------------------------------------------
// Hostility
// ---------------------------------------------------------------------

#[test]
fn an_unsupported_link_layer_is_named_not_guessed() {
    let raw = RawPacket {
        number: 1,
        ts_us: 0,
        caplen: 4,
        orig_len: 4,
        offset: 0,
        data: &[1, 2, 3, 4],
        link_type: LinkType::Other(147),
    };
    let d = dissect(&raw, Detail::Full);
    assert!(d.summary.malformed);
    assert!(
        d.layers.iter().any(|l| l.proto == Proto::Unknown),
        "must produce an explicit unknown layer rather than fake fields"
    );
}

/// Every prefix of a real frame — every way a snaplen can cut it — must
/// dissect without panicking, and must not invent fields for layers whose
/// bytes are missing.
#[test]
fn every_truncation_of_a_real_frame_is_safe() {
    let frame = eth(
        0x0800,
        &ipv4(
            17,
            [10, 0, 0, 5],
            [10, 0, 0, 53],
            &udp(51234, 53, &dns_query(0x1234, "www.example.com", 1)),
        ),
    );
    for n in 0..=frame.len() {
        let raw = RawPacket {
            number: 1,
            ts_us: 0,
            caplen: n as u32,
            orig_len: frame.len() as u32,
            offset: 0,
            data: &frame[..n],
            link_type: LinkType::Ethernet,
        };
        let d = dissect(&raw, Detail::Full);
        // If the TCP/UDP header was cut off, there must be no port field
        // claiming otherwise.
        if n < 14 + 20 + 4 {
            assert!(
                d.summary.src_port.is_none(),
                "invented a port from {n} bytes"
            );
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic_at_any_link_type() {
    proptest::proptest!(|(data: Vec<u8>, lt: u8)| {
        let link_type = match lt % 6 {
            0 => LinkType::Ethernet,
            1 => LinkType::RawIp,
            2 => LinkType::LinuxSll,
            3 => LinkType::Null,
            4 => LinkType::Loop,
            _ => LinkType::Other(999),
        };
        let raw = RawPacket {
            number: 1,
            ts_us: 0,
            caplen: data.len() as u32,
            orig_len: data.len() as u32,
            offset: 0,
            data: &data,
            link_type,
        };
        let d = dissect(&raw, Detail::Full);
        // Whatever came out, every string field is sanitized. This is the
        // T45 invariant stated at the level it has to hold: not "the DNS
        // dissector sanitizes", but "no dissector, on any input, can put
        // a control byte in a field".
        for layer in &d.layers {
            for f in &layer.fields {
                if let FieldValue::Str(s) = &f.value {
                    assert!(
                        !s.chars().any(char::is_control),
                        "field {} carried a control byte: {s:?}",
                        f.name
                    );
                }
            }
        }
    });
}

/// The T45 property at the dissector layer: no matter what an attacker
/// puts in a DNS name, it cannot carry control bytes into a field.
#[test]
fn a_hostile_dns_name_cannot_carry_control_bytes() {
    let mut q = Vec::new();
    q.extend_from_slice(&0x4242u16.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // A label containing an ANSI erase-line and a newline.
    let evil = b"\x1b[2Kevil\nrow";
    q.push(evil.len() as u8);
    q.extend_from_slice(evil);
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes());

    let frame = eth(
        0x0800,
        &ipv4(17, [10, 0, 0, 5], [10, 0, 0, 53], &udp(51234, 53, &q)),
    );
    let d = dissect_eth(&frame);
    let name = d.field("dns.qry.name").unwrap().render();
    assert!(!name.contains('\u{1b}'), "escape survived: {name:?}");
    assert!(!name.contains('\n'), "newline survived: {name:?}");
    assert!(!d.info.contains('\u{1b}'), "escape reached the info line");
}
