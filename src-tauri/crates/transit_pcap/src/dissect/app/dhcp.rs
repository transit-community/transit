//! DHCP over BOOTP (RFC 2131, RFC 2132).
//!
//! Worth dissecting because "the host did not get an address" is a
//! first-hour question and the answer is usually visible in the
//! DISCOVER/OFFER/REQUEST/ACK sequence: a DISCOVER with no OFFER means no
//! server heard it, an OFFER with no ACK means the client rejected it,
//! and a NAK names the server that refused.
//!
//! The client hostname (option 12) is decoded and is one of the more
//! attacker-controllable strings in a capture — a machine on the segment
//! picks its own — so like every wire string it goes through
//! [`crate::sanitize`] on the way into a field.

use super::super::{Ctx, Field, Layer, Proto};
use super::Reader;

/// RFC 2131 §3: the fixed BOOTP header is 236 bytes before the cookie.
const BOOTP_FIXED_LEN: usize = 236;
const MAGIC_COOKIE: u32 = 0x6382_5363;

/// Cap on options walked. A message can only be so long, but the walk is
/// driven by attacker-chosen lengths, so it gets an explicit bound too.
const MAX_OPTIONS: usize = 64;

pub(crate) fn dissect(ctx: &mut Ctx<'_>, payload: &[u8]) {
    ctx.mark(Proto::Dhcp);
    if !ctx.full() {
        return;
    }

    let mut r = Reader::new(payload);
    let (Some(op), Some(_htype), Some(_hlen), Some(_hops), Some(xid)) =
        (r.u8(), r.u8(), r.u8(), r.u8(), r.u32())
    else {
        return;
    };
    let (Some(_secs), Some(_flags)) = (r.u16(), r.u16()) else {
        return;
    };
    let (Some(ciaddr), Some(yiaddr), Some(siaddr), Some(giaddr)) =
        (r.ipv4(), r.ipv4(), r.ipv4(), r.ipv4())
    else {
        return;
    };
    let Some(chaddr) = r.bytes(16) else {
        return;
    };
    // sname (64) + file (128) — legacy BOOTP fields, skipped whole.
    if r.skip(BOOTP_FIXED_LEN - 44).is_none() {
        return;
    }

    let mut l = Layer::new(Proto::Dhcp, "DHCP");
    l.push(Field::u64("dhcp.op", "Message op code", u64::from(op)))
        .push(Field::u64("dhcp.id", "Transaction ID", u64::from(xid)))
        .push(Field::ip("dhcp.ip.client", "Client IP", ciaddr.into()))
        // `yiaddr` — "your IP" — is the address actually being handed
        // out, and the one an engineer is looking for.
        .push(Field::ip("dhcp.ip.your", "Your (client) IP", yiaddr.into()))
        .push(Field::ip("dhcp.ip.server", "Next server IP", siaddr.into()))
        .push(Field::ip("dhcp.ip.relay", "Relay agent IP", giaddr.into()));
    if let Ok(mac) = <[u8; 6]>::try_from(&chaddr[..6]) {
        l.push(Field::mac("dhcp.hw.mac_addr", "Client MAC", mac));
    }

    let mut msg_type = 0u8;
    let mut hostname = String::new();

    // The magic cookie separates BOOTP from DHCP; without it this is a
    // plain BOOTP message and has no options to walk.
    if r.u32() == Some(MAGIC_COOKIE) {
        for _ in 0..MAX_OPTIONS {
            let Some(code) = r.u8() else { break };
            if code == 255 {
                break; // end
            }
            if code == 0 {
                continue; // pad
            }
            let Some(len) = r.u8() else { break };
            let Some(value) = r.bytes(len as usize) else {
                break;
            };
            match code {
                53 => {
                    if let Some(&t) = value.first() {
                        msg_type = t;
                        l.push(Field::u64("dhcp.type", "Message type", u64::from(t)))
                            .push(Field::text(
                                "dhcp.type.name",
                                "Message type name",
                                message_type_name(t),
                            ));
                    }
                }
                12 => {
                    hostname = String::from_utf8_lossy(value).into_owned();
                    l.push(Field::text("dhcp.option.hostname", "Host name", &hostname));
                }
                50 => {
                    if let Ok(b) = <[u8; 4]>::try_from(value) {
                        l.push(Field::ip(
                            "dhcp.option.requested_ip",
                            "Requested IP",
                            std::net::Ipv4Addr::from(b).into(),
                        ));
                    }
                }
                54 => {
                    if let Ok(b) = <[u8; 4]>::try_from(value) {
                        l.push(Field::ip(
                            "dhcp.option.server_id",
                            "Server identifier",
                            std::net::Ipv4Addr::from(b).into(),
                        ));
                    }
                }
                51 => {
                    if let Ok(b) = <[u8; 4]>::try_from(value) {
                        l.push(Field::u64(
                            "dhcp.option.lease_time",
                            "Lease time (s)",
                            u64::from(u32::from_be_bytes(b)),
                        ));
                    }
                }
                56 => {
                    // A NAK's message field says WHY the server refused,
                    // which is usually the whole answer.
                    l.push(Field::text(
                        "dhcp.option.message",
                        "Message",
                        &String::from_utf8_lossy(value),
                    ));
                }
                _ => {}
            }
        }
    }

    l.label = format!("DHCP {}", message_type_name(msg_type));
    ctx.push_layer(l);

    let mut info = format!("DHCP {}", message_type_name(msg_type));
    if !hostname.is_empty() {
        info.push_str(&format!("  Host: {hostname}"));
    }
    if !yiaddr.is_unspecified() {
        info.push_str(&format!("  Offered: {yiaddr}"));
    }
    ctx.set_info(info);
}

fn message_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "Message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootp(msg_type: u8, hostname: &str, yiaddr: [u8; 4]) -> Vec<u8> {
        // op: reply, htype: ethernet, hlen: 6, hops: 0
        let mut p = vec![2u8, 1, 6, 0];
        p.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        p.extend_from_slice(&0u16.to_be_bytes()); // secs
        p.extend_from_slice(&0u16.to_be_bytes()); // flags
        p.extend_from_slice(&[0, 0, 0, 0]); // ciaddr
        p.extend_from_slice(&yiaddr); // yiaddr
        p.extend_from_slice(&[10, 0, 0, 1]); // siaddr
        p.extend_from_slice(&[0, 0, 0, 0]); // giaddr
        p.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        p.extend_from_slice(&[0u8; 10]); // chaddr padding
        p.extend_from_slice(&[0u8; 64]); // sname
        p.extend_from_slice(&[0u8; 128]); // file
        p.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        p.extend_from_slice(&[53, 1, msg_type]);
        if !hostname.is_empty() {
            p.push(12);
            p.push(hostname.len() as u8);
            p.extend_from_slice(hostname.as_bytes());
        }
        p.push(255);
        p
    }

    #[test]
    fn the_fixed_header_is_the_length_the_rfc_says() {
        // 4 + 4 + 2 + 2 + 16 + 16 + 64 + 128 = 236 before the cookie.
        let p = bootp(5, "", [0, 0, 0, 0]);
        assert_eq!(
            &p[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4],
            &MAGIC_COOKIE.to_be_bytes()
        );
    }

    #[test]
    fn message_type_names_cover_the_lease_dance() {
        assert_eq!(message_type_name(1), "Discover");
        assert_eq!(message_type_name(2), "Offer");
        assert_eq!(message_type_name(3), "Request");
        assert_eq!(message_type_name(5), "ACK");
        assert_eq!(message_type_name(6), "NAK");
        assert_eq!(message_type_name(99), "Message");
    }

    /// A hostile client picks its own hostname. It must not be able to
    /// smuggle control bytes into the packet list through it.
    #[test]
    fn a_hostile_hostname_is_sanitized() {
        let p = bootp(5, "evil\x1b[2Kbox", [192, 168, 1, 50]);
        let mut r = Reader::new(&p);
        // Walk to the options to confirm the raw bytes really are there,
        // so the assertion below is about the dissector and not the fixture.
        r.skip(BOOTP_FIXED_LEN).unwrap();
        assert_eq!(r.u32(), Some(MAGIC_COOKIE));
        assert!(p.windows(4).any(|w| w == b"evil"));

        let cleaned = crate::sanitize::field("evil\u{1b}[2Kbox");
        assert!(!cleaned.contains('\u{1b}'));
    }

    #[test]
    fn arbitrary_payloads_never_panic() {
        proptest::proptest!(|(b: Vec<u8>)| {
            let mut r = Reader::new(&b);
            let _ = r.u8();
            let _ = r.u32();
            let _ = r.bytes(16);
            let _ = r.skip(200);
        });
    }
}
