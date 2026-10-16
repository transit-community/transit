//! Filter evaluation corpus.

use std::path::PathBuf;

use super::*;
use crate::dissect::tests::{dns_query, eth, ipv4, tcp, tcp_seq, udp};
use crate::dissect::{dissect, Detail, TCP_ACK, TCP_RST, TCP_SYN};
use crate::index::{build, IndexLimits};
use crate::reader::CaptureFile;
use crate::types::{LinkType, RawPacket};
use crate::writer::PcapWriter;

/// A small, varied capture: two TCP conversations, a DNS query, and an
/// ARP request — enough for every field family to be exercised.
fn fixture() -> (tempfile::TempDir, CaptureIndex, Vec<Vec<u8>>) {
    let frames = vec![
        // 0: 10.0.0.1:52344 → 10.0.0.2:443 SYN
        eth(
            0x0800,
            &ipv4(
                6,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                &tcp(52344, 443, TCP_SYN, &[]),
            ),
        ),
        // 1: the SYN/ACK back
        eth(
            0x0800,
            &ipv4(
                6,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                &tcp(443, 52344, TCP_SYN | TCP_ACK, &[]),
            ),
        ),
        // 2: data, 100 bytes
        eth(
            0x0800,
            &ipv4(
                6,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                &tcp_seq(52344, 443, TCP_ACK, 2000, &[0u8; 100]),
            ),
        ),
        // 3: an unrelated conversation on port 22, from another subnet
        eth(
            0x0800,
            &ipv4(
                6,
                [192, 168, 5, 9],
                [10, 0, 0, 2],
                &tcp(40001, 22, TCP_RST, &[]),
            ),
        ),
        // 4: a DNS query
        eth(
            0x0800,
            &ipv4(
                17,
                [10, 0, 0, 5],
                [10, 0, 0, 53],
                &udp(51234, 53, &dns_query(0x1234, "www.example.com", 1)),
            ),
        ),
        // 5: ARP — no IP layer at all, which is what makes the
        //    "absent fields never match" tests meaningful
        {
            let mut a = Vec::new();
            a.extend_from_slice(&1u16.to_be_bytes());
            a.extend_from_slice(&0x0800u16.to_be_bytes());
            a.push(6);
            a.push(4);
            a.extend_from_slice(&1u16.to_be_bytes());
            a.extend_from_slice(&[0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]);
            a.extend_from_slice(&[10, 0, 0, 1]);
            a.extend_from_slice(&[0u8; 6]);
            a.extend_from_slice(&[10, 0, 0, 99]);
            eth(0x0806, &a)
        },
    ];

    let dir = tempfile::tempdir().unwrap();
    let path: PathBuf = dir.path().join("f.pcap");
    let mut w = PcapWriter::create(&path, LinkType::Ethernet, 262_144).unwrap();
    for (i, f) in frames.iter().enumerate() {
        w.write_packet((i as i64 + 1) * 100_000, f.len() as u32, f)
            .unwrap();
    }
    w.finish().unwrap();
    let file = CaptureFile::open(&path).unwrap();
    let idx = build(&file, IndexLimits::default()).unwrap();
    (dir, idx, frames)
}

/// Which packet numbers (1-based) match `expr`.
fn matching(idx: &CaptureIndex, frames: &[Vec<u8>], expr: &str) -> Vec<usize> {
    let f = Filter::compile(expr).unwrap_or_else(|e| panic!("{expr:?}: {e}"));
    (0..idx.records.len())
        .filter(|i| {
            let d = if f.needs_dissection {
                let raw = RawPacket {
                    number: *i as u64 + 1,
                    ts_us: idx.records[*i].ts_us,
                    caplen: idx.records[*i].caplen,
                    orig_len: idx.records[*i].orig_len,
                    offset: idx.records[*i].offset,
                    data: &frames[*i],
                    link_type: LinkType::Ethernet,
                };
                Some(dissect(&raw, Detail::Full))
            } else {
                None
            };
            f.matches(idx, *i, d.as_ref())
        })
        .map(|i| i + 1)
        .collect()
}

// ---------------------------------------------------------------------
// Fast path — index only
// ---------------------------------------------------------------------

#[test]
fn index_only_filters_do_not_need_dissection() {
    for expr in [
        "tcp",
        "tcp.port == 443",
        "ip.src == 10.0.0.1",
        "tcp.flags.syn == 1",
        "frame.len > 100",
        "vlan.id == 10",
    ] {
        let f = Filter::compile(expr).unwrap();
        assert!(
            !f.needs_dissection,
            "{expr} should be answerable from the index"
        );
    }
    for expr in [
        "dns.qry.name contains example",
        "http.response.code >= 500",
        "eth.src == aa:bb:cc:dd:ee:ff",
    ] {
        let f = Filter::compile(expr).unwrap();
        assert!(f.needs_dissection, "{expr} needs the packet re-read");
    }
}

#[test]
fn protocol_presence_selects_the_right_packets() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "tcp"), vec![1, 2, 3, 4]);
    assert_eq!(matching(&idx, &fr, "udp"), vec![5]);
    assert_eq!(matching(&idx, &fr, "arp"), vec![6]);
    assert_eq!(matching(&idx, &fr, "dns"), vec![5]);
}

#[test]
fn either_side_port_fields_match_both_directions() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "tcp.port == 443"), vec![1, 2, 3]);
    assert_eq!(matching(&idx, &fr, "tcp.srcport == 443"), vec![2]);
    assert_eq!(matching(&idx, &fr, "tcp.dstport == 443"), vec![1, 3]);
}

/// The subtle one. `tcp.port != 443` must not match a packet whose OTHER
/// port happens to differ — otherwise every packet on 443 matches "not
/// 443" and the filter is worse than useless.
#[test]
fn not_equal_on_an_either_side_field_requires_all_sides_to_differ() {
    let (_d, idx, fr) = fixture();
    assert_eq!(
        matching(&idx, &fr, "tcp.port != 443"),
        vec![4],
        "only the port-22 conversation has neither side on 443"
    );
}

#[test]
fn ip_addresses_and_cidr_containment_work() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "ip.src == 10.0.0.1"), vec![1, 3]);
    assert_eq!(matching(&idx, &fr, "ip.addr == 192.168.5.9"), vec![4]);
    assert_eq!(
        matching(&idx, &fr, "ip.src == 10.0.0.0/24"),
        vec![1, 2, 3, 5],
        "CIDR equality means containment"
    );
    assert_eq!(matching(&idx, &fr, "ip.src == 192.168.0.0/16"), vec![4]);
    assert_eq!(
        matching(&idx, &fr, "ip.src == 0.0.0.0/0"),
        vec![1, 2, 3, 4, 5],
        "a /0 contains every IPv4 address"
    );
}

#[test]
fn a_v4_address_is_not_inside_a_v6_network() {
    let (_d, idx, fr) = fixture();
    assert!(matching(&idx, &fr, "ip.src == 2001:db8::/32").is_empty());
}

#[test]
fn tcp_flag_and_analysis_fields_filter() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "tcp.flags.syn == 1"), vec![1, 2]);
    assert_eq!(matching(&idx, &fr, "tcp.flags.reset == 1"), vec![4]);
    assert_eq!(matching(&idx, &fr, "tcp.flags.syn == true"), vec![1, 2]);
    assert!(matching(&idx, &fr, "tcp.analysis.retransmission").is_empty());
}

#[test]
fn frame_fields_filter_on_size_and_time() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "frame.number == 3"), vec![3]);
    assert_eq!(matching(&idx, &fr, "frame.len > 100"), vec![3]);
    // Packets are 100 ms apart, so every packet after the first has a
    // 100,000 µs delta and `> 0.05` (seconds) selects them all.
    assert_eq!(
        matching(&idx, &fr, "frame.time_delta > 0.05"),
        vec![2, 3, 4, 5, 6]
    );
}

#[test]
fn boolean_composition_and_precedence_behave() {
    let (_d, idx, fr) = fixture();
    assert_eq!(
        matching(&idx, &fr, "tcp.port == 443 and tcp.flags.syn == 1"),
        vec![1, 2]
    );
    assert_eq!(matching(&idx, &fr, "arp or udp"), vec![5, 6]);
    assert_eq!(matching(&idx, &fr, "not tcp"), vec![5, 6]);
    assert_eq!(
        matching(&idx, &fr, "(arp or udp) and ip.src == 10.0.0.5"),
        vec![5]
    );
    assert_eq!(
        matching(&idx, &fr, "tcp.port in {22, 443}"),
        vec![1, 2, 3, 4]
    );
}

/// A field absent from a packet must not match — including on `!=`. An
/// ARP frame has no TCP port, so it is neither "port 443" nor "not port
/// 443"; treating absence as "not equal" would sweep every unrelated
/// frame into the result.
#[test]
fn an_absent_field_never_matches_in_either_direction() {
    let (_d, idx, fr) = fixture();
    let eq = matching(&idx, &fr, "tcp.port == 443");
    let ne = matching(&idx, &fr, "tcp.port != 443");
    assert!(!eq.contains(&6), "ARP has no TCP port");
    assert!(!ne.contains(&6), "ARP still has no TCP port");
    assert!(!ne.contains(&5), "the DNS packet is UDP, not TCP");
}

// ---------------------------------------------------------------------
// Slow path — application fields
// ---------------------------------------------------------------------

#[test]
fn application_fields_filter_through_the_dissection() {
    let (_d, idx, fr) = fixture();
    assert_eq!(
        matching(&idx, &fr, "dns.qry.name == \"www.example.com\""),
        vec![5]
    );
    assert_eq!(
        matching(&idx, &fr, "dns.qry.name contains example"),
        vec![5]
    );
    assert_eq!(matching(&idx, &fr, "dns.rcode == 0"), vec![5]);
    assert_eq!(matching(&idx, &fr, "arp.opcode == 1"), vec![6]);
    assert_eq!(
        matching(&idx, &fr, "arp.src.proto_ipv4 == 10.0.0.1"),
        vec![6]
    );
}

#[test]
fn contains_is_case_insensitive() {
    let (_d, idx, fr) = fixture();
    assert_eq!(
        matching(&idx, &fr, "dns.qry.name contains EXAMPLE"),
        vec![5]
    );
    assert_eq!(
        matching(&idx, &fr, "dns.qry.name contains \"WWW.\""),
        vec![5]
    );
}

#[test]
fn field_presence_alone_selects_packets_that_have_it() {
    let (_d, idx, fr) = fixture();
    assert_eq!(matching(&idx, &fr, "dns.qry.name"), vec![5]);
    assert_eq!(matching(&idx, &fr, "icmp.mtu"), Vec::<usize>::new());
}

// ---------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------

/// A typo must be an error with a suggestion, not an empty result. An
/// empty result reads as "there is no such traffic", which is the wrong
/// conclusion to hand an engineer chasing an outage.
#[test]
fn an_unknown_field_is_refused_with_a_suggestion() {
    let e = Filter::compile("tcp.prot == 443").unwrap_err();
    assert!(e.message.contains("unknown field"), "{}", e.message);
    assert!(
        e.message.contains("tcp.port"),
        "expected a suggestion: {}",
        e.message
    );

    let e = Filter::compile("dns.name == x").unwrap_err();
    assert!(
        e.message.contains("dns.qry.name"),
        "same last segment should suggest: {}",
        e.message
    );

    let e = Filter::compile("completely.made.up == 1").unwrap_err();
    assert!(e.message.contains("unknown field"));
}

/// A protocol Transit names but has not written a dissector for must be
/// REFUSED, not silently matched against nothing. `bgp` returning an
/// empty packet list reads as "there is no BGP traffic in this capture" —
/// the wrong conclusion to hand someone chasing a flapping session, and
/// the same failure mode the unknown-field refusal exists to prevent.
#[test]
fn an_undissected_protocol_atom_is_refused_not_silently_empty() {
    // What remains after dissector batch 2. Each is named by the enum
    // because it is on the roadmap, and each is refused until something
    // can actually set it.
    for tag in ["gre", "esp", "sctp", "dhcpv6"] {
        let err = Filter::compile(tag)
            .err()
            .unwrap_or_else(|| panic!("`{tag}` must be refused while undissected"));
        assert!(err.message.contains(tag), "{}", err.message);
        assert!(
            err.message.contains("does not dissect it yet"),
            "the reason must be specific: {}",
            err.message
        );
        // And it must say what DOES work, so the user has a next step.
        assert!(err.message.contains("tcp"), "{}", err.message);
    }
}

/// Every protocol that IS dissected must compile as a filter — the two
/// lists cannot drift apart in the other direction either.
#[test]
fn every_dissected_protocol_compiles_as_a_filter() {
    for p in crate::dissect::Proto::DISSECTED {
        Filter::compile(p.as_str())
            .unwrap_or_else(|e| panic!("dissected protocol `{}` must filter: {e}", p.as_str()));
    }
}

/// The guard against adding a dissector and forgetting to widen
/// `DISSECTED`: anything a dissector can mark must be filterable.
#[test]
fn the_dissected_list_covers_what_the_fixture_actually_produces() {
    let (_d, idx, _fr) = fixture();
    let mut seen = crate::dissect::ProtoSet::default();
    for r in &idx.records {
        seen.0 |= r.protos;
    }
    for p in seen.iter() {
        assert!(
            p.is_dissected(),
            "`{}` was set on a packet but is not in Proto::DISSECTED — filtering it would be \
             refused even though the traffic exists",
            p.as_str()
        );
    }
}

#[test]
fn the_registry_has_no_duplicate_names() {
    let mut names: Vec<&str> = REGISTRY.iter().map(|f| f.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        before,
        names.len(),
        "a duplicate field name shadows one entry"
    );
}

#[test]
fn every_registry_field_resolves_or_is_absent_without_panicking() {
    let (_d, idx, fr) = fixture();
    for f in REGISTRY {
        let expr = format!("{} == 1", f.name);
        // Compiling must succeed for every registered field, and running
        // it over every packet must not panic.
        let filter = Filter::compile(&expr)
            .unwrap_or_else(|e| panic!("registry field {} does not compile: {e}", f.name));
        for (i, frame) in fr.iter().enumerate() {
            let d = if filter.needs_dissection {
                let raw = RawPacket {
                    number: i as u64 + 1,
                    ts_us: idx.records[i].ts_us,
                    caplen: idx.records[i].caplen,
                    orig_len: idx.records[i].orig_len,
                    offset: idx.records[i].offset,
                    data: frame,
                    link_type: LinkType::Ethernet,
                };
                Some(dissect(&raw, Detail::Full))
            } else {
                None
            };
            let _ = filter.matches(&idx, i, d.as_ref());
        }
    }
}

/// Filters reach this evaluator from three places: a user typing, a
/// finding's suggested filter, and a model proposing one while reasoning
/// about untrusted packet contents. None may panic it.
#[test]
fn arbitrary_filter_text_never_panics_the_compiler() {
    proptest::proptest!(|(s: String)| {
        let _ = Filter::compile(&s);
    });
}

#[test]
fn every_findings_filter_actually_compiles() {
    // A finding's filter is offered to the user as a next step and to the
    // model as a drill-down. One that does not compile is a dead end
    // presented as a lead.
    for expr in [
        "icmp.type == 3 and icmp.code == 4",
        "tcp.window == 0",
        "tcp.analysis.retransmission",
        "tcp.flags.reset == 1",
        "tcp.flags.syn == 1 and tcp.flags.ack == 0",
        "dns.rcode != 0",
        "dns and dns.flags.response == 0",
        "dns.flags.response == 1",
        "tls.alert.level == 2",
        "http.response.code >= 500",
        "http.request.method",
        "icmp.type == 11",
        "arp and arp.src.proto_ipv4 == 10.0.0.50",
        "ip.src == 10.0.0.1 and ip.dst == 10.0.0.2 and tcp.window == 0",
        "ip.src == 10.0.0.1 and ip.dst == 10.0.0.2 and tcp.analysis.retransmission",
    ] {
        Filter::compile(expr).unwrap_or_else(|e| panic!("findings filter {expr:?} is broken: {e}"));
    }
}

/// Every filter a Finding offers as "show me" must actually select the
/// evidence, because the alternative is silent and misleading: an empty
/// packet list reads as "there is no such traffic", which is the opposite
/// of what the finding just said. A one-click filter that finds nothing is
/// worse than no filter at all.
#[test]
fn the_filters_findings_link_to_are_valid_and_select_their_evidence() {
    let (_d, idx, frames) = fixture();

    // The DNS query in the fixture is a query, not a response — exactly
    // what the "queries never answered" finding links to.
    assert_eq!(
        matching(&idx, &frames, "dns and dns.flags.response == 0"),
        vec![5],
        "the unanswered-DNS finding's filter must select the query"
    );
    assert_eq!(
        matching(&idx, &frames, "dns.flags.response == 1"),
        Vec::<usize>::new(),
        "no responses in the fixture"
    );
    assert_eq!(
        matching(&idx, &frames, "dns.rcode != 0"),
        Vec::<usize>::new()
    );
}
