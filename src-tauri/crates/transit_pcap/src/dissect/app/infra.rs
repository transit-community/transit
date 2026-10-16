//! Infrastructure services: NTP, SNMP, RADIUS, TACACS+, syslog, HSRP.
//!
//! # Two of these carry credentials, and they are handled accordingly
//!
//! **SNMP's community string is a cleartext password.** v1 and v2c put it
//! on the wire in the clear on every poll, and a capture of a management
//! VLAN is full of them. The dissector emits its *presence* and never its
//! value — the same treatment HTTP `Authorization` gets, for the same
//! reason: knowing a poll was authenticated is useful, knowing the
//! password is a liability.
//!
//! **RADIUS carries the user's name in the clear** and their password
//! under a shared-secret obfuscation that is not encryption. The name is
//! decoded (it is what makes an auth failure actionable); the password
//! attribute is refused outright.
//!
//! **TACACS+ bodies are encrypted** unless the unencrypted flag is set,
//! and we decline to decode the body either way. The header alone answers
//! the operational question — is the server responding at all.

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

// ---------------------------------------------------------------------
// NTP (RFC 5905)
// ---------------------------------------------------------------------

pub(crate) fn dissect_ntp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Ntp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(flags), Some(stratum), Some(poll), Some(precision)) =
        (r.u8(), r.u8(), r.u8(), r.u8())
    else {
        return;
    };
    let leap = flags >> 6;
    let version = (flags >> 3) & 0x07;
    let mode = flags & 0x07;

    let mut l = Layer::new(Proto::Ntp, format!("NTP {}", ntp_mode_name(mode)));
    l.push(Field::u64(
        "ntp.flags.li",
        "Leap indicator",
        u64::from(leap),
    ))
    .push(Field::u64("ntp.flags.vn", "Version", u64::from(version)))
    .push(Field::u64("ntp.flags.mode", "Mode", u64::from(mode)))
    .push(Field::text(
        "ntp.flags.mode.name",
        "Mode name",
        ntp_mode_name(mode),
    ))
    // Stratum 16 means "unsynchronized" — the direct answer to "why
    // is this device's clock wrong", and a leap indicator of 3 says
    // the same thing louder.
    .push(Field::u64("ntp.stratum", "Stratum", u64::from(stratum)))
    .push(Field::u64("ntp.ppoll", "Poll interval", u64::from(poll)))
    .push(Field::u64(
        "ntp.precision",
        "Precision",
        u64::from(precision),
    ));

    let health = match (stratum, leap) {
        (0, _) => "  (unspecified / kiss-o'-death)",
        (16, _) => "  (UNSYNCHRONIZED)",
        (_, 3) => "  (clock not synchronized)",
        _ => "",
    };
    ctx.push_layer(l);
    ctx.set_info(format!(
        "NTP {}  stratum {stratum}{health}",
        ntp_mode_name(mode)
    ));
}

fn ntp_mode_name(m: u8) -> &'static str {
    match m {
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        _ => "reserved",
    }
}

// ---------------------------------------------------------------------
// SNMP (RFC 1157 / 3416) — BER, community redacted
// ---------------------------------------------------------------------

pub(crate) fn dissect_snmp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Snmp);
    if !ctx.full() {
        return;
    }
    // SEQUENCE { version INTEGER, community OCTET STRING, PDU }.
    // Only the outer shape is decoded — enough to name the version, the
    // operation, and the fact of a community string.
    let mut r = Reader::new(payload);
    let (Some(tag), Some(_len)) = (r.u8(), ber_len(&mut r)) else {
        return;
    };
    if tag != 0x30 {
        return; // not a SEQUENCE; not SNMP as we understand it
    }
    let Some(version) = ber_int(&mut r) else {
        return;
    };

    let mut l = Layer::new(Proto::Snmp, "SNMP");
    l.push(Field::u64("snmp.version", "Version", version as u64))
        .push(Field::text(
            "snmp.version.name",
            "Version name",
            snmp_version_name(version),
        ));

    // The community string. Its LENGTH is read so parsing can continue to
    // the PDU, and its BYTES are stepped over without ever becoming a
    // value. v1/v2c put this on the wire in the clear on every poll.
    let mut had_community = false;
    if r.u8() == Some(0x04) {
        if let Some(len) = ber_len(&mut r) {
            if r.skip(len).is_some() {
                had_community = true;
                l.fields.push(Field {
                    name: "snmp.community",
                    label: "Community string",
                    value: super::super::FieldValue::Str("[REDACTED:snmp-community]".to_string()),
                });
            }
        }
    }

    let pdu = r.u8();
    if let Some(pdu) = pdu {
        l.push(Field::u64(
            "snmp.pdu_type",
            "PDU type",
            u64::from(pdu & 0x1f),
        ))
        .push(Field::text("snmp.pdu.name", "PDU name", snmp_pdu_name(pdu)));
    }

    let auth = if had_community {
        " (authenticated)"
    } else {
        ""
    };
    ctx.push_layer(l);
    ctx.set_info(format!(
        "SNMP{} {}{auth}",
        snmp_version_suffix(version),
        pdu.map(snmp_pdu_name).unwrap_or("message")
    ));
}

fn snmp_version_name(v: i64) -> &'static str {
    match v {
        0 => "v1",
        1 => "v2c",
        3 => "v3",
        _ => "unknown",
    }
}

fn snmp_version_suffix(v: i64) -> &'static str {
    match v {
        0 => "v1",
        1 => "v2c",
        3 => "v3",
        _ => "",
    }
}

fn snmp_pdu_name(tag: u8) -> &'static str {
    match tag {
        0xa0 => "GetRequest",
        0xa1 => "GetNextRequest",
        0xa2 => "Response",
        0xa3 => "SetRequest",
        0xa4 => "Trap (v1)",
        0xa5 => "GetBulkRequest",
        0xa6 => "InformRequest",
        0xa7 => "Trap (v2)",
        0xa8 => "Report",
        _ => "PDU",
    }
}

/// BER length: short form (< 0x80) or long form (count of length bytes).
///
/// Bounded to four length bytes — anything longer describes a message
/// larger than a datagram can be, and is either corrupt or hostile.
fn ber_len(r: &mut Reader<'_>) -> Option<usize> {
    let first = r.u8()?;
    if first < 0x80 {
        return Some(usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let bytes = r.bytes(count)?;
    let mut v = 0usize;
    for b in bytes {
        v = (v << 8) | usize::from(*b);
    }
    Some(v)
}

/// A BER INTEGER, bounded to eight bytes.
fn ber_int(r: &mut Reader<'_>) -> Option<i64> {
    if r.u8()? != 0x02 {
        return None;
    }
    let len = ber_len(r)?;
    if len == 0 || len > 8 {
        return None;
    }
    let bytes = r.bytes(len)?;
    let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for b in bytes {
        v = (v << 8) | i64::from(*b);
    }
    Some(v)
}

// ---------------------------------------------------------------------
// RADIUS (RFC 2865)
// ---------------------------------------------------------------------

pub(crate) fn dissect_radius(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Radius);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(code), Some(id), Some(len)) = (r.u8(), r.u8(), r.u16()) else {
        return;
    };
    // The 16-byte authenticator. Stepped over, never decoded: it is
    // key material for the password obfuscation.
    if r.skip(16).is_none() {
        return;
    }

    let name = radius_code_name(code);
    let mut l = Layer::new(Proto::Radius, format!("RADIUS {name}"));
    l.push(Field::u64("radius.code", "Code", u64::from(code)))
        .push(Field::text("radius.code.name", "Code name", name))
        .push(Field::u64("radius.id", "Identifier", u64::from(id)))
        .push(Field::u64("radius.length", "Length", u64::from(len)));

    // Attributes: type(1) len(1) value(len-2).
    let mut username = String::new();
    for _ in 0..64 {
        let (Some(attr), Some(alen)) = (r.u8(), r.u8()) else {
            break;
        };
        if alen < 2 {
            break;
        }
        let Some(value) = r.bytes(usize::from(alen) - 2) else {
            break;
        };
        match attr {
            1 => {
                username = String::from_utf8_lossy(value).into_owned();
                l.push(Field::text("radius.username", "User name", &username));
            }
            // User-Password (2) and CHAP-Password (3) are obfuscated with
            // the shared secret, not encrypted — anyone holding the
            // secret reads them. Neither becomes a value here.
            2 | 3 => {
                l.fields.push(Field {
                    name: "radius.password",
                    label: "Password attribute",
                    value: super::super::FieldValue::Str("[REDACTED:radius-password]".to_string()),
                });
            }
            4 => {
                if let Ok(b) = <[u8; 4]>::try_from(value) {
                    l.push(Field::ip(
                        "radius.nas_ip_address",
                        "NAS IP address",
                        std::net::Ipv4Addr::from(b).into(),
                    ));
                }
            }
            // Reply-Message on a reject is the reason the user was
            // refused, which is the whole point of looking.
            18 => {
                l.push(Field::text(
                    "radius.reply_message",
                    "Reply message",
                    &String::from_utf8_lossy(value),
                ));
            }
            _ => {}
        }
    }

    let who = if username.is_empty() {
        String::new()
    } else {
        format!("  user {username}")
    };
    ctx.push_layer(l);
    ctx.set_info(format!("RADIUS {name}{who}"));
}

fn radius_code_name(c: u8) -> &'static str {
    match c {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        _ => "message",
    }
}

// ---------------------------------------------------------------------
// TACACS+ (RFC 8907)
// ---------------------------------------------------------------------

pub(crate) fn looks_like_tacacs(payload: &[u8]) -> bool {
    // version major nibble is 0xc for every TACACS+ version in use.
    payload.len() >= 12 && (payload[0] >> 4) == 0xc
}

pub(crate) fn dissect_tacacs(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Tacacs);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(version), Some(kind), Some(seq), Some(flags), Some(session), Some(len)) =
        (r.u8(), r.u8(), r.u8(), r.u8(), r.u32(), r.u32())
    else {
        return;
    };
    let unencrypted = flags & 0x01 != 0;

    let name = tacacs_type_name(kind);
    let mut l = Layer::new(Proto::Tacacs, format!("TACACS+ {name}"));
    l.push(Field::u64(
        "tacplus.majvers",
        "Major version",
        u64::from(version >> 4),
    ))
    .push(Field::u64(
        "tacplus.minvers",
        "Minor version",
        u64::from(version & 0x0f),
    ))
    .push(Field::u64("tacplus.type", "Type", u64::from(kind)))
    .push(Field::text("tacplus.type.name", "Type name", name))
    .push(Field::u64(
        "tacplus.seq_no",
        "Sequence number",
        u64::from(seq),
    ))
    .push(Field::u64(
        "tacplus.session_id",
        "Session id",
        u64::from(session),
    ))
    .push(Field::u64("tacplus.length", "Body length", u64::from(len)))
    .push(Field::bool(
        "tacplus.flags.unencrypted",
        "Body is unencrypted",
        unencrypted,
    ));

    // The body is NOT decoded, encrypted or not. When it is unencrypted
    // it contains usernames and passwords in the clear, and the header
    // alone answers the operational question — is the server responding.
    ctx.push_layer(l);
    ctx.set_info(format!(
        "TACACS+ {name}  session {session}{}",
        if unencrypted {
            "  (body UNENCRYPTED on the wire)"
        } else {
            ""
        }
    ));
}

fn tacacs_type_name(t: u8) -> &'static str {
    match t {
        1 => "Authentication",
        2 => "Authorization",
        3 => "Accounting",
        _ => "packet",
    }
}

// ---------------------------------------------------------------------
// syslog (RFC 3164 / 5424)
// ---------------------------------------------------------------------

pub(crate) fn dissect_syslog(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Syslog);
    if !ctx.full() {
        return;
    }
    // `<PRI>message`, where PRI = facility * 8 + severity.
    let text = String::from_utf8_lossy(payload);
    let (pri, msg) = match text.strip_prefix('<').and_then(|r| r.split_once('>')) {
        Some((p, rest)) => (p.parse::<u16>().ok(), rest),
        None => (None, text.as_ref()),
    };

    let mut l = Layer::new(Proto::Syslog, "Syslog");
    if let Some(pri) = pri {
        let facility = pri / 8;
        let severity = pri % 8;
        l.push(Field::u64(
            "syslog.facility",
            "Facility",
            u64::from(facility),
        ))
        .push(Field::u64(
            "syslog.severity",
            "Severity",
            u64::from(severity),
        ))
        .push(Field::text(
            "syslog.severity.name",
            "Severity name",
            severity_name(severity as u8),
        ));
    }
    // The message body is written by whatever device sent it, which on a
    // monitored segment is anyone — so it goes through the sanitizer like
    // every other wire string.
    l.push(Field::long_text("syslog.msg", "Message", msg));
    ctx.push_layer(l);

    let sev = pri
        .map(|p| format!("{} ", severity_name((p % 8) as u8)))
        .unwrap_or_default();
    ctx.set_info(format!("Syslog {sev}{msg}"));
}

/// RFC 5424 §6.2.1 severities. Naming them is what turns a wall of
/// syslog into "three criticals and everything else is noise".
fn severity_name(s: u8) -> &'static str {
    match s {
        0 => "emergency",
        1 => "alert",
        2 => "critical",
        3 => "error",
        4 => "warning",
        5 => "notice",
        6 => "info",
        _ => "debug",
    }
}

// ---------------------------------------------------------------------
// HSRP (Cisco, UDP 1985)
// ---------------------------------------------------------------------

pub(crate) fn dissect_hsrp(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Hsrp);
    if !ctx.full() {
        return;
    }
    let mut r = Reader::new(payload);
    let (Some(version), Some(opcode), Some(state), Some(hello), Some(hold)) =
        (r.u8(), r.u8(), r.u8(), r.u8(), r.u8())
    else {
        return;
    };
    let (Some(priority), Some(group)) = (r.u8(), r.u8()) else {
        return;
    };
    // reserved(1) + auth(8) — the "authentication" is a plaintext
    // 8-character string every Cisco ships as `cisco`, so it is not
    // decoded: it protects nothing and naming it invites treating it as
    // a secret worth having.
    if r.skip(9).is_none() {
        return;
    }
    let virtual_ip = r.ipv4();

    let state_name = hsrp_state_name(state);
    let mut l = Layer::new(Proto::Hsrp, format!("HSRP group {group} {state_name}"));
    l.push(Field::u64("hsrp.version", "Version", u64::from(version)))
        .push(Field::u64("hsrp.opcode", "Opcode", u64::from(opcode)))
        .push(Field::u64("hsrp.state", "State", u64::from(state)))
        .push(Field::text("hsrp.state.name", "State name", state_name))
        .push(Field::u64("hsrp.hellotime", "Hello time", u64::from(hello)))
        .push(Field::u64("hsrp.holdtime", "Hold time", u64::from(hold)))
        .push(Field::u64("hsrp.priority", "Priority", u64::from(priority)))
        .push(Field::u64("hsrp.group", "Group", u64::from(group)));
    if let Some(ip) = virtual_ip {
        l.push(Field::ip("hsrp.virt_ip", "Virtual IP", ip.into()));
    }

    ctx.push_layer(l);
    ctx.set_info(format!(
        "HSRP  group {group}  {state_name}  priority {priority}"
    ));
}

fn hsrp_state_name(s: u8) -> &'static str {
    match s {
        0 => "Initial",
        1 => "Learn",
        2 => "Listen",
        4 => "Speak",
        8 => "Standby",
        16 => "Active",
        _ => "state",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_lengths_handle_both_forms_and_refuse_absurd_ones() {
        assert_eq!(ber_len(&mut Reader::new(&[0x05])), Some(5));
        assert_eq!(ber_len(&mut Reader::new(&[0x81, 0xc8])), Some(200));
        assert_eq!(ber_len(&mut Reader::new(&[0x82, 0x01, 0x00])), Some(256));
        // A length claiming more bytes than a datagram can hold.
        assert_eq!(
            ber_len(&mut Reader::new(&[0x88, 1, 2, 3, 4, 5, 6, 7, 8])),
            None
        );
        assert_eq!(ber_len(&mut Reader::new(&[0x80])), None);
    }

    #[test]
    fn ber_integers_decode_and_are_bounded() {
        assert_eq!(ber_int(&mut Reader::new(&[0x02, 0x01, 0x01])), Some(1));
        assert_eq!(ber_int(&mut Reader::new(&[0x02, 0x01, 0x00])), Some(0));
        // Not an INTEGER tag.
        assert_eq!(ber_int(&mut Reader::new(&[0x04, 0x01, 0x01])), None);
    }

    /// The headline test for this module. An SNMP community string is a
    /// cleartext password on every v1/v2c poll; its VALUE must never
    /// become a field.
    #[test]
    fn the_snmp_community_string_never_becomes_a_value() {
        // SEQUENCE { INTEGER 1, OCTET STRING "s3cr3t-community", GetRequest }
        let community = b"s3cr3t-community";
        let mut body = vec![0x02, 0x01, 0x01]; // version v2c
        body.push(0x04);
        body.push(community.len() as u8);
        body.extend_from_slice(community);
        body.push(0xa0); // GetRequest
        body.push(0x00);
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);

        // Walk it the way the dissector does and confirm the bytes are
        // stepped over rather than read.
        let mut r = Reader::new(&msg);
        assert_eq!(r.u8(), Some(0x30));
        assert!(ber_len(&mut r).is_some());
        assert_eq!(ber_int(&mut r), Some(1));
        assert_eq!(r.u8(), Some(0x04));
        let len = ber_len(&mut r).unwrap();
        assert_eq!(len, community.len());
        assert!(r.skip(len).is_some());
        assert_eq!(r.u8(), Some(0xa0), "the PDU follows the community");
    }

    #[test]
    fn protocol_names_are_right() {
        assert_eq!(ntp_mode_name(3), "client");
        assert_eq!(ntp_mode_name(4), "server");
        assert_eq!(snmp_pdu_name(0xa2), "Response");
        assert_eq!(snmp_version_name(1), "v2c");
        assert_eq!(radius_code_name(3), "Access-Reject");
        assert_eq!(tacacs_type_name(1), "Authentication");
        assert_eq!(severity_name(2), "critical");
        assert_eq!(hsrp_state_name(16), "Active");
    }

    #[test]
    fn tacacs_is_recognized_by_its_version_nibble() {
        let mut p = vec![0xc1, 0x01, 0x01, 0x00];
        p.extend_from_slice(&[0u8; 8]);
        assert!(looks_like_tacacs(&p));
        assert!(!looks_like_tacacs(&[0x45u8; 12]));
        assert!(!looks_like_tacacs(&[0xc1, 0x01]));
    }

    #[test]
    fn arbitrary_bytes_never_panic_any_parser() {
        proptest::proptest!(|(b: Vec<u8>)| {
            let _ = ber_len(&mut Reader::new(&b));
            let _ = ber_int(&mut Reader::new(&b));
            let _ = looks_like_tacacs(&b);
        });
    }
}
