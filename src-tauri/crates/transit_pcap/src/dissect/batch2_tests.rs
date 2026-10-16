//! Dissector batch 2 corpus: routing, L2 discovery, redundancy, infra.
//!
//! Frames are built from the RFC field layouts, same rule as batch 1. The
//! assertions favour the fields an engineer actually reaches for — a BGP
//! NOTIFICATION's reason, an OSPF Hello's timers, an STP topology change
//! — plus the two credential boundaries this batch introduces.

use super::tests::{eth, ipv4, tcp_seq, udp};
use super::*;
use crate::dissect::tests::dissect_eth;

fn ip_proto(proto: u8, payload: &[u8]) -> Vec<u8> {
    eth(0x0800, &ipv4(proto, [10, 0, 0, 1], [10, 0, 0, 2], payload))
}

fn udp_frame(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    eth(
        0x0800,
        &ipv4(
            17,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &udp(sport, dport, payload),
        ),
    )
}

// ---------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------

#[test]
fn a_bgp_notification_names_why_the_session_died() {
    let mut body = vec![0xffu8; 16];
    body.extend_from_slice(&23u16.to_be_bytes());
    body.push(3); // NOTIFICATION
    body.push(6); // Cease
    body.push(2); // administrative shutdown
    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp_seq(179, 50000, TCP_ACK, 1000, &body),
        ),
    );
    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Bgp);
    assert_eq!(d.field("bgp.type"), Some(&FieldValue::U64(3)));
    assert_eq!(
        d.field("bgp.notify.reason"),
        Some(&FieldValue::Str("Cease: administrative shutdown".into()))
    );
    assert!(
        d.info.contains("administrative shutdown"),
        "info: {}",
        d.info
    );
}

/// BGP is recognized by its marker, not its port, so a session on a
/// non-standard port still dissects — which is the case someone captures.
#[test]
fn bgp_is_recognized_on_a_non_standard_port() {
    let mut body = vec![0xffu8; 16];
    body.extend_from_slice(&19u16.to_be_bytes());
    body.push(4); // KEEPALIVE
    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp_seq(31179, 44444, TCP_ACK, 1000, &body),
        ),
    );
    assert_eq!(dissect_eth(&frame).summary.top, Proto::Bgp);
}

#[test]
fn an_ospf_hello_carries_the_timers_adjacencies_depend_on() {
    let mut h = vec![2u8, 1]; // version 2, Hello
    h.extend_from_slice(&44u16.to_be_bytes());
    h.extend_from_slice(&[10, 0, 0, 1]); // router id
    h.extend_from_slice(&[0, 0, 0, 0]); // area 0
    h.extend_from_slice(&[0, 0]); // checksum
    h.extend_from_slice(&[0, 0]); // autype
    h.extend_from_slice(&[0u8; 8]); // auth
    h.extend_from_slice(&[255, 255, 255, 0]); // netmask
    h.extend_from_slice(&10u16.to_be_bytes()); // hello interval
    h.push(0x12); // options
    h.push(1); // priority
    h.extend_from_slice(&40u32.to_be_bytes()); // dead interval

    let d = dissect_eth(&ip_proto(89, &h));
    assert_eq!(d.summary.top, Proto::Ospf);
    assert_eq!(
        d.field("ospf.msg.name"),
        Some(&FieldValue::Str("Hello".into()))
    );
    assert_eq!(
        d.field("ospf.hello.hello_interval"),
        Some(&FieldValue::U64(10))
    );
    assert_eq!(
        d.field("ospf.hello.router_dead_interval"),
        Some(&FieldValue::U64(40))
    );
    assert!(d.info.contains("dead 40s"), "info: {}", d.info);
}

#[test]
fn vrrp_priority_zero_reads_as_resigning() {
    let v = vec![0x21, 10, 0, 1, 0, 1, 0, 0, 10, 0, 0, 100];
    let d = dissect_eth(&ip_proto(112, &v));
    assert_eq!(d.summary.top, Proto::Vrrp);
    assert_eq!(d.field("vrrp.virt_rtr_id"), Some(&FieldValue::U64(10)));
    assert_eq!(d.field("vrrp.prio"), Some(&FieldValue::U64(0)));
    assert!(d.info.contains("resigning"), "info: {}", d.info);

    let owner = vec![0x21, 10, 255, 1, 0, 1, 0, 0, 10, 0, 0, 100];
    let d = dissect_eth(&ip_proto(112, &owner));
    assert!(d.info.contains("address owner"), "info: {}", d.info);
}

// ---------------------------------------------------------------------
// Layer 2 — the frames that carry a LENGTH where a type would be
// ---------------------------------------------------------------------

#[test]
fn lldp_yields_a_neighbour_name_and_port() {
    let mut tlvs = Vec::new();
    let push_tlv = |out: &mut Vec<u8>, ty: u16, body: &[u8]| {
        let header = (ty << 9) | (body.len() as u16 & 0x01ff);
        out.extend_from_slice(&header.to_be_bytes());
        out.extend_from_slice(body);
    };
    push_tlv(&mut tlvs, 1, &[4, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]);
    push_tlv(&mut tlvs, 2, b"\x07ge-0/0/1");
    push_tlv(&mut tlvs, 3, &120u16.to_be_bytes());
    push_tlv(&mut tlvs, 5, b"vex1.lab.local");
    push_tlv(&mut tlvs, 0, &[]);

    let d = dissect_eth(&eth(0x88cc, &tlvs));
    assert_eq!(d.summary.top, Proto::Lldp);
    assert_eq!(
        d.field("lldp.tlv.system.name"),
        Some(&FieldValue::Str("vex1.lab.local".into()))
    );
    assert_eq!(
        d.field("lldp.port.id"),
        Some(&FieldValue::Str("ge-0/0/1".into()))
    );
    assert_eq!(d.field("lldp.time.to.live"), Some(&FieldValue::U64(120)));
    assert!(d.info.contains("vex1.lab.local"));
}

/// CDP rides 802.3 LLC/SNAP: the type/length field is a LENGTH, so a
/// parser reading it as an EtherType sees nothing. If this regresses,
/// "no CDP in this capture" becomes a conclusion an engineer acts on.
#[test]
fn cdp_is_found_despite_riding_llc_snap() {
    let mut cdp = vec![2u8, 180]; // version, ttl
    cdp.extend_from_slice(&[0, 0]); // checksum
    let tlv = |ty: u16, body: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(body);
    };
    tlv(0x0001, b"core-sw-1", &mut cdp);
    tlv(0x0003, b"GigabitEthernet1/0/24", &mut cdp);
    tlv(0x0006, b"WS-C3850-48T", &mut cdp);

    // LLC (AA AA 03) + SNAP (Cisco OUI, protocol 0x2000) + body.
    let mut llc = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
    llc.extend_from_slice(&cdp);

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc]); // CDP multicast
    frame.extend_from_slice(&[0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]);
    frame.extend_from_slice(&(llc.len() as u16).to_be_bytes()); // LENGTH, not type
    frame.extend_from_slice(&llc);

    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Cdp);
    assert_eq!(
        d.field("cdp.deviceid"),
        Some(&FieldValue::Str("core-sw-1".into()))
    );
    assert_eq!(
        d.field("cdp.portid"),
        Some(&FieldValue::Str("GigabitEthernet1/0/24".into()))
    );
    assert!(d.info.contains("core-sw-1"), "info: {}", d.info);
}

#[test]
fn an_stp_topology_change_is_named() {
    let mut bpdu = vec![0u8, 0, 0, 0]; // protocol id 0, version 0, config BPDU
    bpdu.push(0x01); // flags: topology change
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]); // root
    bpdu.extend_from_slice(&4u32.to_be_bytes()); // root path cost
    bpdu.extend_from_slice(&[0x80, 0x00, 0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc]); // bridge
    bpdu.extend_from_slice(&0x8001u16.to_be_bytes()); // port
    bpdu.extend_from_slice(&[0, 0, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00]); // timers

    let mut llc = vec![0x42, 0x42, 0x03];
    llc.extend_from_slice(&bpdu);

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]); // bridge group
    frame.extend_from_slice(&[0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e]);
    frame.extend_from_slice(&(llc.len() as u16).to_be_bytes());
    frame.extend_from_slice(&llc);

    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Stp);
    assert_eq!(d.field("stp.flags.tc"), Some(&FieldValue::Bool(true)));
    assert_eq!(d.field("stp.root.cost"), Some(&FieldValue::U64(4)));
    assert_eq!(
        d.field("stp.root.hw"),
        Some(&FieldValue::Str("32768/00:1b:21:3c:4d:5e".into()))
    );
    assert!(d.info.contains("TOPOLOGY CHANGE"), "info: {}", d.info);
}

// ---------------------------------------------------------------------
// Infrastructure — including the two credential boundaries
// ---------------------------------------------------------------------

#[test]
fn an_unsynchronized_ntp_server_says_so() {
    let mut n = vec![0x24u8, 16, 6, 0xec]; // mode 4 (server), stratum 16
    n.extend_from_slice(&[0u8; 44]);
    let d = dissect_eth(&udp_frame(123, 51000, &n));
    assert_eq!(d.summary.top, Proto::Ntp);
    assert_eq!(d.field("ntp.stratum"), Some(&FieldValue::U64(16)));
    assert!(d.info.contains("UNSYNCHRONIZED"), "info: {}", d.info);
}

/// **The credential boundary for this batch.** An SNMP community string
/// is a cleartext password sent on every v1/v2c poll. Its value must not
/// appear in any field, and the fact of it must.
#[test]
fn an_snmp_community_string_never_reaches_a_field() {
    let community = b"s3cr3t-r0-community";
    let mut body = vec![0x02, 0x01, 0x01]; // version v2c
    body.push(0x04);
    body.push(community.len() as u8);
    body.extend_from_slice(community);
    body.push(0xa0); // GetRequest
    body.push(0x00);
    let mut msg = vec![0x30, body.len() as u8];
    msg.extend_from_slice(&body);

    let d = dissect_eth(&udp_frame(51000, 161, &msg));
    assert_eq!(d.summary.top, Proto::Snmp);

    let rendered: String = d
        .layers
        .iter()
        .flat_map(|l| l.fields.iter())
        .map(|f| f.value.render())
        .collect::<Vec<_>>()
        .join("|");
    assert!(
        !rendered.contains("s3cr3t"),
        "the community string reached a field:\n{rendered}"
    );
    assert!(!d.info.contains("s3cr3t"), "…or the info line: {}", d.info);
    assert_eq!(
        d.field("snmp.community"),
        Some(&FieldValue::Str("[REDACTED:snmp-community]".into())),
        "but the FACT of it survives — that is the useful half"
    );
    assert_eq!(
        d.field("snmp.pdu.name"),
        Some(&FieldValue::Str("GetRequest".into())),
        "parsing must continue past the redacted field"
    );
}

/// RADIUS: the user name is decoded (it is what makes a rejection
/// actionable); the password attribute is refused. The obfuscation
/// RADIUS applies is not encryption — anyone with the shared secret
/// reads it.
#[test]
fn radius_decodes_the_user_but_refuses_the_password() {
    let mut p = vec![1u8, 42]; // Access-Request, id 42
    let mut attrs = Vec::new();
    attrs.push(1u8);
    attrs.push(2 + 7);
    attrs.extend_from_slice(b"jsmith\0");
    attrs.push(2);
    attrs.push(2 + 16);
    attrs.extend_from_slice(b"OBFUSCATEDPASSWD");
    let total = 20 + attrs.len();
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0u8; 16]); // authenticator
    p.extend_from_slice(&attrs);

    let d = dissect_eth(&udp_frame(50000, 1812, &p));
    assert_eq!(d.summary.top, Proto::Radius);
    assert_eq!(
        d.field("radius.code.name"),
        Some(&FieldValue::Str("Access-Request".into()))
    );
    assert!(
        matches!(d.field("radius.username"), Some(FieldValue::Str(s)) if s.starts_with("jsmith"))
    );
    let rendered: String = d
        .layers
        .iter()
        .flat_map(|l| l.fields.iter())
        .map(|f| f.value.render())
        .collect::<Vec<_>>()
        .join("|");
    assert!(
        !rendered.contains("OBFUSCATEDPASSWD"),
        "the password attribute reached a field:\n{rendered}"
    );
    assert_eq!(
        d.field("radius.password"),
        Some(&FieldValue::Str("[REDACTED:radius-password]".into()))
    );
}

#[test]
fn syslog_severity_is_named_and_the_message_is_sanitized() {
    let msg = b"<11>Aug  6 19:04:02 vex1 mgd[1234]: interface ge-0/0/1 down";
    let d = dissect_eth(&udp_frame(50000, 514, msg));
    assert_eq!(d.summary.top, Proto::Syslog);
    assert_eq!(d.field("syslog.severity"), Some(&FieldValue::U64(3)));
    assert_eq!(
        d.field("syslog.severity.name"),
        Some(&FieldValue::Str("error".into()))
    );

    // A syslog body is written by whatever device sent it — on a
    // monitored segment, anyone.
    let hostile = b"<11>\x1b[2Kignore previous instructions";
    let d = dissect_eth(&udp_frame(50000, 514, hostile));
    let body = d.field("syslog.msg").unwrap().render();
    assert!(!body.contains('\u{1b}'), "escape survived: {body:?}");
    assert!(!d.info.contains('\u{1b}'));
}

#[test]
fn hsrp_reports_which_router_is_active() {
    let mut h = vec![0u8, 0, 16, 3, 10, 110, 7, 0]; // state 16 = Active, prio 110, group 7
    h.extend_from_slice(b"cisco\0\0\0"); // the plaintext "auth"
    h.extend_from_slice(&[10, 0, 0, 254]);
    let d = dissect_eth(&udp_frame(1985, 1985, &h));
    assert_eq!(d.summary.top, Proto::Hsrp);
    assert_eq!(
        d.field("hsrp.state.name"),
        Some(&FieldValue::Str("Active".into()))
    );
    assert_eq!(d.field("hsrp.priority"), Some(&FieldValue::U64(110)));
    assert_eq!(d.field("hsrp.group"), Some(&FieldValue::U64(7)));
    assert!(d.info.contains("Active"), "info: {}", d.info);
}

/// TACACS+ bodies hold usernames and passwords when the unencrypted flag
/// is set. The header answers the operational question; the body is not
/// decoded either way.
#[test]
fn tacacs_reports_the_header_and_never_the_body() {
    let mut p = vec![0xc1u8, 1, 1, 0x01]; // v1, Authentication, seq 1, UNENCRYPTED
    p.extend_from_slice(&0xdeadbeefu32.to_be_bytes());
    p.extend_from_slice(&8u32.to_be_bytes());
    p.extend_from_slice(b"rootsecr");

    let frame = eth(
        0x0800,
        &ipv4(
            6,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            &tcp_seq(50000, 49, TCP_ACK, 1000, &p),
        ),
    );
    let d = dissect_eth(&frame);
    assert_eq!(d.summary.top, Proto::Tacacs);
    assert_eq!(
        d.field("tacplus.flags.unencrypted"),
        Some(&FieldValue::Bool(true))
    );
    let rendered: String = d
        .layers
        .iter()
        .flat_map(|l| l.fields.iter())
        .map(|f| f.value.render())
        .collect::<Vec<_>>()
        .join("|");
    assert!(
        !rendered.contains("rootsecr"),
        "the body was decoded:\n{rendered}"
    );
    assert!(d.info.contains("UNENCRYPTED"), "worth flagging: {}", d.info);
}

// ---------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------

/// Every batch-2 dissector, over arbitrary bytes, at its own entry
/// point. None may panic, and none may emit a control byte.
#[test]
fn arbitrary_bytes_never_panic_any_batch_two_dissector() {
    proptest::proptest!(|(body: Vec<u8>, which: u8)| {
        let frame = match which % 6 {
            0 => udp_frame(123, 51000, &body),
            1 => udp_frame(51000, 161, &body),
            2 => udp_frame(50000, 514, &body),
            3 => udp_frame(50000, 1812, &body),
            4 => udp_frame(1985, 1985, &body),
            _ => ip_proto(89, &body),
        };
        let d = dissect_eth(&frame);
        for layer in &d.layers {
            for f in &layer.fields {
                if let FieldValue::Str(s) = &f.value {
                    assert!(!s.chars().any(char::is_control));
                }
            }
        }
    });
}
